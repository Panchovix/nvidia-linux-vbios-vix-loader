"""Synthetic roots and injected operations; no real system or GPU actions."""
import copy
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tests'))
from test_lifecycle import FakeOperations, OLD, VERSION
from nvidia_vbios.bootstrap import Bootstrap, BootstrapOperations, BootstrapError, BASE, RUNTIME, CONFIG, STATE, ENABLED, ACTION_TARGETS
from nvidia_vbios.lifecycle import Reconciler
from nvidia_vbios.lifecycle.security import atomic_write, digest, json_write


class Operations(FakeOperations):
    def __init__(self, root, config):
        super().__init__(root, config)
        self.enabled = False
        self.plugin = True
        self.fail_triggers = False
        self.partial = False
        self.service_active = False

    def triggers(self, enabled):
        self.events.append('triggers:' + str(enabled))
        self.enabled = enabled
        if enabled and self.fail_triggers:
            raise BootstrapError('injected trigger failure')

    def triggers_enabled(self):
        return self.enabled

    def triggers_any_active(self):
        return self.enabled or self.partial or self.service_active

    def reconcile_active(self):
        return self.service_active

    def current_kernel(self):
        return OLD

    def plugin_available(self, provider):
        return self.plugin

    def inspect_source(self, path):
        return dict(super().inspect_source(path), capabilities={})

    def archive_identity(self, archive, payload, device):
        if not archive.startswith(b'REVIEWED ROM') or archive != payload:
            raise BootstrapError('invalid synthetic archive')
        self.validate_payload(payload, device)

    def archive_architecture(self, device):
        return 'ada' if device.get('architecture') == 'ada' else 'blackwell-gb20x'


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.private').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / '.private')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for directory in ('inputs', 'usr/lib/modules/' + OLD, 'boot/loader/entries'):
            (self.root / directory).mkdir(parents=True, exist_ok=True, mode=0o755)
        atomic_write(self.root / f'boot/vmlinuz-{OLD}', b'KERNEL')
        atomic_write(self.root / f'boot/initramfs-{OLD}.img', b'NORMAL IMAGE')
        self.normal = f'normal-{OLD}'
        atomic_write(self.root / f'boot/loader/entries/{self.normal}.conf',
                     f'title Fedora\nversion {OLD}\nlinux /vmlinuz-{OLD}\ninitrd /initramfs-{OLD}.img $tuned_initrd\noptions root=UUID=synthetic $tuned_params\n'.encode())
        self.source = self.root / 'inputs/source'
        atomic_write(self.source / 'version.mk', VERSION.encode())
        atomic_write(self.source / 'Makefile', b'REVIEWED build source with P2P changes')
        self.profile = {'devices': [self.device(0)], 'driver_sources': [{'path': str(self.source), 'p2p_preferred': True}],
                        'fallback_entry': self.normal, 'userspace': {'provider': 'rpm'}, 'jobs': 1}
        self.ops = Operations(self.root, self.profile)
        self.worker = Bootstrap(self.root, self.ops)
        self.repository = self.root / 'inputs/runtime'
        package = self.repository / 'src/nvidia_vbios'
        for name in ('__init__.py', 'bootstrap.py', 'lifecycle/__main__.py', 'gui/__init__.py'):
            atomic_write(package / name, b'def main(argv=None):\n    return 0\n', 0o644)
        atomic_write(package / 'cli.py', b'def main(argv=None):\n    print("TRUSTED_RUNTIME_OUTSIDE_CHECKOUT")\n    return 0\n', 0o644)
        atomic_write(package / 'lifecycle/hook_templates.json', (ROOT / 'src/nvidia_vbios/lifecycle/hook_templates.json').read_bytes(), 0o644)
        for name in ('kernel-install/99-nvidia-vbios.install', 'systemd/nvidia-vbios-reconcile.service',
                     'systemd/nvidia-vbios-reconcile.path', 'systemd/nvidia-vbios-reconcile.timer',
                     'dnf5/nvidia-vbios.actions', 'dnf4/nvidia-vbios.action'):
            atomic_write(self.repository / 'packaging' / name, (ROOT / 'packaging' / name).read_bytes(), 0o644)
        self.inspect = patch('nvidia_vbios.driver.inspect_source', self.ops.inspect_source)
        self.inspect.start(); self.addCleanup(self.inspect.stop)

    def device(self, index):
        payload = b'REVIEWED ROM payload ' + str(index).encode()
        file = self.root / f'inputs/gpu{index}.rom'
        atomic_write(file, payload)
        return {'uuid': f'GPU-00000000-0000-0000-0000-{index + 1:012x}', 'bdf': f'0000:{index + 3:02x}:00.0',
                'vendor': 0x10de, 'device': 0x2bb4, 'architecture': 'blackwell-gb20x',
                'archive': str(file), 'payload': str(file), 'source_sha256': digest(payload),
                'sha256': digest(payload), 'source_size': len(payload), 'size': len(payload)}

    def enroll(self):
        result = self.worker.enroll(self.profile)
        self.ops.config = json.loads((self.root / CONFIG.lstrip('/')).read_text())
        return result

    def ready(self):
        return Reconciler(self.root, self.ops).reconcile(OLD)

    def snapshot(self):
        return {str(file.relative_to(self.root)): file.read_bytes() for file in self.root.rglob('*') if file.is_file()}

    def test_alternate_root_requires_operations(self):
        with self.assertRaisesRegex(BootstrapError, 'injected'):
            Bootstrap(self.root)

    def test_candidate_resource_cannot_publish_arbitrary_system_path(self):
        path = self.repository / 'src/nvidia_vbios/lifecycle/hook_templates.json'
        bundle = json.loads(path.read_bytes())
        bundle['templates'][0]['destination'] = '/etc/shadow'
        path.write_text(json.dumps(bundle))
        before = self.snapshot()
        with self.assertRaisesRegex(BootstrapError, 'destination'):
            self.worker.install(self.repository)
        self.assertEqual(self.snapshot(), before)

    def test_package_resources_install_without_repository_packaging_directory(self):
        import shutil
        shutil.rmtree(self.repository / 'packaging')
        report = self.worker.install(self.repository)
        release = self.worker.path(report['runtime'])
        self.assertTrue((release / 'nvidia_vbios/lifecycle/hook_templates.json').is_file())
        self.assertTrue((self.root / 'usr/lib/systemd/system/nvidia-vbios-reconcile.path').is_file())

    def test_real_packaging_runtime_dry_run_is_read_only(self):
        before = self.snapshot()
        result = self.worker.install(ROOT, dry_run=True)
        self.assertEqual(result['state'], 'planned')
        self.assertEqual(self.snapshot(), before)

    def test_install_and_enrollment_dry_runs_write_nothing(self):
        before = self.snapshot()
        self.worker.install(self.repository, dry_run=True)
        self.worker.enroll(self.profile, dry_run=True)
        self.assertEqual(self.snapshot(), before)
        self.assertFalse(self.ops.enabled)

    def test_runtime_import_works_outside_checkout_without_site_packages(self):
        report = self.worker.install(self.repository)
        package = self.root / report['runtime'].lstrip('/')
        launcher = (self.root / 'usr/local/bin/nvbios').read_text().replace(RUNTIME, str(self.root / RUNTIME.lstrip('/')))
        launcher = launcher.replace('for part in [*reversed(path.parents), path]:', f'for part in [item for item in [*reversed(path.parents), path] if item.is_relative_to(Path({str(self.root)!r}))]:')
        if os.geteuid() != 0:
            launcher = launcher.replace('value.st_uid != 0', f'value.st_uid != {os.geteuid()}')
        script = self.root / 'trusted-runtime.py'
        script.write_text(launcher)
        shutil_path = self.repository
        import shutil
        shutil.rmtree(shutil_path)
        completed = subprocess.run([sys.executable, '-I', str(script)], cwd='/tmp', capture_output=True, check=True)
        self.assertIn(b'TRUSTED_RUNTIME_OUTSIDE_CHECKOUT', completed.stdout)
        self.assertTrue(package.is_dir())
        self.assertTrue(self.worker.status()['installed'])
        self.assertFalse(self.worker.status()['triggers_enabled'])

    def test_install_foreign_file_requires_reviewed_hash_and_backup(self):
        path = self.root / 'usr/local/bin/nvbios'
        atomic_write(path, b'FOREIGN CLI', 0o755)
        with self.assertRaisesRegex(BootstrapError, 'foreign'):
            self.worker.install(self.repository)
        report = self.worker.install(self.repository, replace_hashes={'/usr/local/bin/nvbios': digest(b'FOREIGN CLI')})
        self.worker.rollback(report['transaction_id'])
        self.assertEqual(path.read_bytes(), b'FOREIGN CLI')

    def test_rollback_refuses_foreign_changes_and_preserves_later_ownership(self):
        report = self.worker.install(self.repository)
        self.enroll()
        later_config = (self.root / CONFIG.lstrip('/')).read_bytes()
        self.worker.rollback(report['transaction_id'])
        owners = self.worker._owners()['files']
        self.assertEqual(owners[CONFIG], digest(later_config))
        report = self.worker.install(self.repository)
        path = self.root / 'usr/local/bin/nvbios'
        path.write_bytes(b'FOREIGN CHANGE')
        with self.assertRaisesRegex(BootstrapError, 'foreign edit'):
            self.worker.rollback(report['transaction_id'])
        self.assertEqual(path.read_bytes(), b'FOREIGN CHANGE')

    def test_installer_write_failure_restores_prior_files(self):
        path = self.root / 'usr/local/bin/nvbios'
        atomic_write(path, b'REVIEWED PRIOR CLI', 0o755)
        import nvidia_vbios.bootstrap as module
        write = module.atomic_write
        def fail_after_write(target, data, mode=0o600):
            write(target, data, mode)
            if target == self.root / 'usr/libexec/nvidia-vbios':
                raise OSError('injected publication failure')
        with patch.object(module, 'atomic_write', fail_after_write):
            with self.assertRaisesRegex(OSError, 'publication failure'):
                self.worker.install(self.repository, replace_hashes={'/usr/local/bin/nvbios': digest(b'REVIEWED PRIOR CLI')})
        self.assertEqual(path.read_bytes(), b'REVIEWED PRIOR CLI')
        self.assertFalse((self.root / 'usr/libexec/nvidia-vbios').exists())

    def test_source_directory_link_and_runtime_selector_tamper_refused(self):
        link = self.root / 'inputs/source-link'; link.symlink_to(self.source)
        altered = copy.deepcopy(self.profile); altered['driver_sources'][0]['path'] = str(link)
        with self.assertRaisesRegex(BootstrapError, 'symlink'):
            self.worker.enroll(altered, dry_run=True)
        self.worker.install(self.repository)
        selector = self.worker._read(RUNTIME + '/current.json'); selector['files'] = {}
        json_write(self.worker.path(RUNTIME + '/current.json'), selector)
        self.assertFalse(self.worker.status()['installed'])

    def test_symlinks_and_writable_output_ancestors_rejected(self):
        path = self.root / 'inputs/link.rom'; path.symlink_to(self.profile['devices'][0]['archive'])
        changed = copy.deepcopy(self.profile); changed['devices'][0]['archive'] = str(path)
        with self.assertRaisesRegex(BootstrapError, 'symlink'):
            self.worker.enroll(changed)
        directory = self.root / 'usr/local/bin'; directory.mkdir(parents=True, mode=0o755)
        directory.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, 'untrusted'):
            self.worker.install(self.repository)

    def test_enroll_one_eight_17_and_32_devices_preserves_absent_fields_and_evidence(self):
        for count in (1, 8, 17, 32):
            self.profile['devices'] = [self.device(index) for index in range(count)]
            self.ops.config = self.profile
            self.profile['devices'][-1]['architecture'] = 'ada'
            self.profile['devices'][-1]['evidence'] = {'boot': 'verified', 'application': 'not-applied',
                'fields': {'power_max_w': {'requested': 100, 'observed': 70, 'state': 'not-applied'}}}
            self.enroll()
            config = self.ops.config
            self.assertEqual(len(config['devices']), count)
            self.assertNotIn('msvdd', config['devices'][-1]['evidence']['fields'])
            self.assertEqual(config['devices'][-1]['evidence']['fields']['power_max_w']['observed'], 70)
            source = self.root / config['sources'][0]['path'].lstrip('/')
            self.assertEqual((source / 'Makefile').read_bytes(), b'REVIEWED build source with P2P changes')
            self.assertTrue(config['sources'][0]['p2p_preferred'])

    def test_33_selected_devices_are_rejected_before_enrollment(self):
        self.profile['devices'] = [self.device(index) for index in range(33)]
        with self.assertRaisesRegex(BootstrapError, 'one through 32'):
            self.worker.enroll(self.profile)
        self.assertFalse((self.root / CONFIG.lstrip('/')).exists())

    def test_source_changed_during_snapshot_rejected_before_config_publication(self):
        original = self.worker._snapshot
        def mutation(records, files, destination, **kwargs):
            if '/sources/' in destination:
                (self.source / 'Makefile').write_bytes(b'CHANGED source')
            return original(records, files, destination, **kwargs)
        with patch.object(self.worker, '_snapshot', mutation):
            with self.assertRaisesRegex(BootstrapError, 'changed'):
                self.worker.enroll(self.profile)
        self.assertFalse((self.root / CONFIG.lstrip('/')).exists())

    def test_restrictive_umask_runtime_remains_readable_and_enable_idempotent(self):
        previous = os.umask(0o077)
        try:
            report = self.worker.install(self.repository)
        finally:
            os.umask(previous)
        runtime = self.worker.path(report['runtime'])
        for directory in (runtime, runtime.parent, runtime / 'nvidia_vbios', self.root / 'usr/local/bin'):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o755)
        self.enroll(); self.ready(); self.worker.enable(OLD)
        self.assertEqual(self.worker.enable(OLD)['state'], 'already-enabled')

    def test_invalid_profile_and_missing_plugin_publish_nothing_active(self):
        changed = copy.deepcopy(self.profile); changed['devices'] = ['malformed']
        with self.assertRaisesRegex(BootstrapError, 'JSON object'):
            self.worker.enroll(changed)
        self.worker.install(self.repository); self.enroll(); self.ready()
        self.ops.plugin = False
        with self.assertRaisesRegex(BootstrapError, 'plugin'):
            self.worker.enable(OLD)
        self.assertFalse(self.ops.enabled)
        self.assertFalse(self.worker.path(ACTION_TARGETS['dnf5']).exists())

    def test_production_activity_probe_includes_single_enabled_unit_and_service_transitions(self):
        for enabled, active in (({'nvidia-vbios-reconcile.path'}, {}),
                                ({'nvidia-vbios-reconcile.timer'}, {}),
                                (set(), {'nvidia-vbios-reconcile.path': 'active'}),
                                (set(), {'nvidia-vbios-reconcile.service': 'activating'}),
                                (set(), {'nvidia-vbios-reconcile.service': 'deactivating'}),
                                (set(), {})):
            class Probe:
                def _run(self, command, **kwargs):
                    name = command[-1]
                    if command[1] == 'is-enabled':
                        return subprocess.CompletedProcess(command, 0 if name in enabled else 1, b'', b'')
                    return subprocess.CompletedProcess(command, 0, active.get(name, 'inactive').encode(), b'')
            operations = BootstrapOperations.__new__(BootstrapOperations)
            operations.system = Probe()
            self.assertEqual(operations.triggers_any_active(), bool(enabled or active))

    def test_partial_trigger_and_active_service_block_install_and_enrollment(self):
        for partial, service in ((True, False), (False, True)):
            self.ops.partial, self.ops.service_active = partial, service
            before = self.snapshot()
            with self.assertRaisesRegex(BootstrapError, 'every enabled/active'):
                self.worker.install(self.repository)
            with self.assertRaisesRegex(BootstrapError, 'every enabled/active'):
                self.worker.enroll(self.profile)
            self.assertEqual(self.snapshot(), before)

    def test_trigger_start_runs_after_reconciliation_lock_is_released(self):
        self.worker.install(self.repository); self.enroll(); self.ready()
        original = self.ops.triggers
        def start(enabled):
            if enabled:
                with self.worker.path(STATE + '/reconcile.lock').open('ab') as lock:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            original(enabled)
        with patch.object(self.ops, 'triggers', start):
            self.worker.enable(OLD)
        self.assertTrue(self.ops.enabled)

    def test_busy_reconciliation_prevents_disable_or_enable_rollback_mutation(self):
        self.worker.install(self.repository); self.enroll(); self.ready()
        enabled = self.worker.enable(OLD)
        before = self.snapshot(); events = list(self.ops.events)
        path = self.worker.path(STATE + '/reconcile.lock')
        with path.open('ab') as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(RuntimeError, 'lock busy'):
                self.worker.disable()
            with self.assertRaisesRegex(RuntimeError, 'lock busy'):
                self.worker.rollback(enabled['transaction_id'])
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.ops.events, events)
        self.assertTrue(self.ops.enabled)
        self.ops.service_active = True
        with self.assertRaisesRegex(BootstrapError, 'service is active'):
            self.worker.disable()
        self.assertEqual(self.snapshot(), before)

    def test_disable_blocks_late_reconcile_and_validated_reenable_is_transactional(self):
        self.worker.install(self.repository); self.enroll(); self.ready(); self.worker.enable(OLD)
        self.worker.disable()
        self.assertFalse(json.loads(self.worker.path(CONFIG).read_bytes())['enabled'])
        default = self.ops.environment['saved_entry']
        with self.assertRaisesRegex(RuntimeError, 'disabled'):
            Reconciler(self.root, self.ops).reconcile(OLD)
        self.assertEqual(self.ops.environment['saved_entry'], default)
        result = self.worker.enable(OLD, dry_run=True)
        self.assertTrue(result['ready'])
        self.assertFalse(json.loads(self.worker.path(CONFIG).read_bytes())['enabled'])
        enabled = self.worker.enable(OLD)
        self.assertTrue(json.loads(self.worker.path(CONFIG).read_bytes())['enabled'])
        self.assertTrue(self.ops.enabled)
        self.assertEqual(self.ops.environment['saved_entry'], enabled['default_selection']['target'])
        builds = self.ops.builds
        self.assertEqual(Reconciler(self.root, self.ops).reconcile(OLD)['state'], 'ready')
        self.assertEqual(self.ops.builds, builds)

    def test_reenable_preserves_foreign_and_one_time_boot_choices(self):
        self.worker.install(self.repository); self.enroll(); self.ready(); self.worker.enable(OLD)
        for choices in ({'saved_entry': 'another-os'},
                        {'saved_entry': self.normal, 'next_entry': 'one-time-os'},
                        {'saved_entry': self.normal, 'prev_saved_entry': 'another-transition'}):
            self.worker.disable()
            self.ops.environment = dict(choices)
            result = self.worker.enable(OLD)
            self.assertEqual(result['default_selection']['state'], 'preserved')
            self.assertEqual(self.ops.environment, choices)
            self.assertTrue(self.ops.enabled)

    def test_reenable_rejects_changed_normal_fallback_before_publication(self):
        self.worker.install(self.repository); self.enroll(); self.ready(); self.worker.enable(OLD)
        self.worker.disable()
        path = self.root / f'boot/initramfs-{OLD}.img'
        path.write_bytes(b'CHANGED NORMAL IMAGE')
        before = self.snapshot(); environment = dict(self.ops.environment)
        with self.assertRaisesRegex(BootstrapError, 'normal recovery artifact changed'):
            self.worker.enable(OLD)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(self.ops.environment, environment)
        self.assertFalse(self.ops.enabled)

    def test_reenable_trigger_start_failure_restores_normal_default_and_disabled_profile(self):
        self.worker.install(self.repository); self.enroll(); self.ready(); self.worker.enable(OLD)
        self.worker.disable()
        environment = dict(self.ops.environment)
        self.ops.fail_triggers = True
        with self.assertRaisesRegex(BootstrapError, 'trigger failure'):
            self.worker.enable(OLD)
        self.assertEqual(self.ops.environment, environment)
        self.assertFalse(json.loads(self.worker.path(CONFIG).read_bytes())['enabled'])
        self.assertFalse(self.ops.enabled)
        self.assertFalse(self.worker.path(ENABLED).exists())
        self.assertFalse(self.worker.path(ACTION_TARGETS['dnf5']).exists())

    def test_reenable_default_command_failure_rolls_back_config_and_selection(self):
        self.worker.install(self.repository); self.enroll(); self.ready(); self.worker.enable(OLD)
        self.worker.disable()
        environment = dict(self.ops.environment)
        self.ops.fault = 'default'
        with self.assertRaisesRegex(RuntimeError, 'grub wrote then failed'):
            self.worker.enable(OLD)
        self.assertEqual(self.ops.environment, environment)
        self.assertFalse(json.loads(self.worker.path(CONFIG).read_bytes())['enabled'])
        self.assertFalse(self.ops.enabled)
        self.assertFalse(self.worker.path(ENABLED).exists())

    def test_no_triggers_before_actual_reconcile_and_ready_tamper_refused(self):
        self.worker.install(self.repository); self.enroll()
        with self.assertRaises(RuntimeError):
            self.worker.enable(OLD)
        self.assertFalse(self.ops.enabled)
        self.assertFalse((self.root / ACTION_TARGETS['dnf5'].lstrip('/')).exists())
        self.ready()
        self.worker.enable(OLD)
        self.assertTrue(self.ops.enabled)
        status = self.worker.status()
        self.assertTrue(status['ready']); self.assertTrue(status['triggers_enabled'])
        record = json.loads((self.root / STATE.lstrip('/') / f'status-{OLD}.json').read_text())['deployment'][0]
        (self.root / record['path'].lstrip('/')).write_bytes(b'FOREIGN DEPLOYMENT')
        with self.assertRaises(RuntimeError):
            self.worker.enable(OLD)

    def test_disable_preserves_foreign_or_one_time_choices_and_active_modules(self):
        self.worker.install(self.repository); self.enroll(); self.ready(); self.worker.enable(OLD)
        modules = {str(path): path.read_bytes() for path in (self.root / 'usr/lib/modules').rglob('*.ko')}
        self.ops.environment.update(saved_entry='another-os', next_entry='one-time-os')
        result = self.worker.disable()
        self.assertEqual(result['default_restoration']['state'], 'preserved')
        self.assertEqual(self.ops.environment['saved_entry'], 'another-os')
        self.assertEqual(self.ops.environment['next_entry'], 'one-time-os')
        self.assertEqual(modules, {str(path): path.read_bytes() for path in (self.root / 'usr/lib/modules').rglob('*.ko')})
        self.assertFalse((self.root / ENABLED.lstrip('/')).exists())

    def legacy(self):
        bundle = self.root / 'inputs/bundle'; bundle.mkdir()
        selected = self.profile['devices'][0]
        data = Path(selected['payload']).read_bytes()
        atomic_write(bundle / 'firmware/gpu.bin', data)
        manifest = {'driver': VERSION, 'kernel': OLD, 'runtime_tested': True,
                    'devices': [dict(selected, source_image=selected['archive'], bundle_image='firmware/gpu.bin')]}
        json_write(bundle / 'manifest.json', manifest)
        entry = 'synthetic-' + OLD + '-vbios-test-reviewed'
        entry_name = f'/boot/loader/entries/{entry}.conf'
        image_name = f'/boot/initramfs-{OLD}-vbios-test-reviewed.img'
        atomic_write(self.root / entry_name.lstrip('/'), b'LEGACY WORKING ENTRY')
        atomic_write(self.root / image_name.lstrip('/'), b'LEGACY WORKING IMAGE')
        old_module = '/usr/lib/modules/' + OLD + '/updates/vbios-override/nvidia.ko'
        atomic_write(self.root / old_module.lstrip('/'), b'LEGACY MODULE')
        dracut = '/etc/dracut.conf.d/99-vbios-override.conf'
        atomic_write(self.root / dracut.lstrip('/'), b'LEGACY FORCED ROMS')
        (self.root / 'lib').symlink_to('usr/lib')
        state = {'phase': 'persistent-enabled', 'bundle': str(bundle), 'kernel': OLD,
                 'test_boot': {'entry_id': entry, 'entry': entry_name, 'initramfs': image_name,
                               'base_entry': str(self.root / f'boot/loader/entries/{self.normal}.conf'),
                               'saved_entry': self.normal, 'manifest_sha256': digest((bundle / 'manifest.json').read_bytes())},
                 'files': [{'target': name, 'after_sha256': digest(self.worker._trusted_bytes(name)), 'backup': None}
                           for name in (entry_name, image_name, dracut)]}
        state['files'].append({'target': old_module.replace('/usr/lib/', '/lib/'), 'after_sha256': digest(b'LEGACY MODULE'), 'backup': None})
        file = self.root / 'var/lib/vbios-override/state.json'; json_write(file, state)
        self.ops.environment['saved_entry'] = entry
        return file, entry_name, image_name, dracut

    def test_migration_retains_working_boot_and_retires_stale_manager_only_after_ready(self):
        self.worker.install(self.repository)
        file, entry, image, dracut = self.legacy()
        working = {name: self.worker._trusted_bytes(name) for name in (entry, image)}
        self.worker.migrate_legacy(file, self.profile['driver_sources'], userspace={'provider': 'rpm'})
        self.ops.config = json.loads((self.root / CONFIG.lstrip('/')).read_text())
        self.assertEqual(self.ops.config['seed_previous_ready']['entry'], Path(entry).stem)
        self.assertTrue(file.exists()); self.assertTrue(self.worker.path(dracut).exists())
        self.ready(); report = self.worker.enable(OLD)
        self.assertFalse(file.exists()); self.assertTrue(file.with_name('state.migrated.json').exists())
        self.assertFalse(self.worker.path(dracut).exists())
        self.assertEqual(working, {name: self.worker._trusted_bytes(name) for name in working})
        self.worker.rollback(report['transaction_id'])
        self.assertTrue(file.exists()); self.assertTrue(self.worker.path(dracut).exists())

    def test_trigger_failure_restores_legacy_state_and_dracut(self):
        self.worker.install(self.repository)
        file, _, _, dracut = self.legacy()
        self.worker.migrate_legacy(file, self.profile['driver_sources'], userspace={'provider': 'rpm'})
        self.ops.config = json.loads((self.root / CONFIG.lstrip('/')).read_text()); self.ready()
        self.ops.fail_triggers = True
        with self.assertRaisesRegex(BootstrapError, 'trigger failure'):
            self.worker.enable(OLD)
        self.assertTrue(file.exists()); self.assertTrue(self.worker.path(dracut).exists())
        self.assertFalse(self.ops.enabled)
        self.assertFalse(self.worker.path(ENABLED).exists())


if __name__ == '__main__':
    unittest.main()
