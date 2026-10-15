"""Portable retention operates entirely beneath a synthetic filesystem root."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nvidia_vbios.lifecycle.boot import BootAdapter
from nvidia_vbios.lifecycle import portable_retention as subject
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write, checked_path, digest, json_write


class Ops:
    def __init__(self):
        self.environment = {}
        self.changed = False
        self.calls = 0

    def grub_environment(self):
        self.calls += 1
        if self.changed and self.calls > 1:
            return dict(self.environment, saved_entry='foreign-entry')
        return dict(self.environment)


class Worker:
    def __init__(self, root, backend):
        self.root = root
        self.ops = Ops()
        boot = {'backend': backend, 'initramfs': 'mkinitcpio'}
        if backend != 'grub':
            boot['esp'] = '/efi'
        self.boot = BootAdapter(root, {'boot': boot})
        self.state = root / 'var/lib/nvidia-vbios/lifecycle'
        self.state.mkdir(parents=True, mode=0o700)

    def path(self, name):
        return self.root / name.lstrip('/')

    def trusted(self, path, *, missing=False):
        return checked_path(path, self.root, missing=missing)

    def _json(self, path, default=None):
        return json.loads(path.read_text()) if path.exists() else (default or {})


class PortableRetentionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.worker = None
        self.status = None

    def tearDown(self):
        self.temporary.cleanup()

    def setup(self, backend='grub', count=4):
        worker = self.worker = Worker(self.root, backend)
        fleet = {'boot_generations': {}, 'normal_fallback': {'entry': 'normal'}, 'shared_boot_files': {}}
        for number in range(count):
            kernel = f'6.14.{number}'
            managed = f'vbios-{kernel}-{number:020x}'
            entry = managed + {'grub': '', 'systemd-boot': '.conf', 'uki': '.efi'}[backend]
            boot_root = '/boot' if backend == 'grub' else '/efi'
            base = f'{boot_root}/nvidia-vbios/{managed}'
            descriptor = (f'/boot/grub/nvidia-vbios-entries/{managed}.cfg' if backend == 'grub'
                          else f'/efi/loader/entries/{managed}.conf' if backend == 'systemd-boot'
                          else f'/efi/EFI/Linux/{managed}.efi')
            roles = {base + '/vmlinuz': 'kernel', base + '/initramfs.img': 'initramfs',
                     base + '/microcode-0-intel-ucode.img': 'supplemental-initrd',
                     descriptor: 'uki' if backend == 'uki' else 'entry'}
            files = []
            for name, role in roles.items():
                data = f'OWNED {number} {role}\n'.encode()
                atomic_write(worker.path(name), data)
                files.append({'path': name, 'sha256': digest(data)})
            fleet['boot_generations'][entry] = {'kernel': kernel, 'managed_id': managed, 'backend': backend,
                                               'boot': worker.boot.config, 'files': files, 'roles': roles,
                                               'created_ns': number, 'state': 'active'}
        current = next(reversed(fleet['boot_generations']))
        record = fleet['boot_generations'][current]
        fleet['last_ready'] = {'entry': current}
        worker.ops.environment = {'saved_entry': current}
        if backend == 'grub':
            ids = [record['managed_id'] for record in fleet['boot_generations'].values()]
            for name, data in worker.boot.visibility_files(ids).items():
                atomic_write(worker.path(name), data, 0o755 if name.startswith('/etc') else 0o644)
                fleet['shared_boot_files'][name] = digest(data)
            atomic_write(worker.path('/boot/grub/grub.cfg'), b'source $prefix/nvidia-vbios.cfg\n# NORMAL OS MENU\n')
        atomic_write(worker.path('/boot/vmlinuz-normal'), b'NORMAL KERNEL')
        atomic_write(worker.path('/boot/initramfs-normal.img'), b'NORMAL INITRAMFS')
        params = {'NVreg_RegistryDwords': 'RmLinuxVbiosOverride=2',
                  'NVreg_RegistryDwordsPerDevice': 'pci=0000:01:00.0;',
                  'NVreg_RegistryBinaryFilePerDevice': 'pci=0000:01:00.0,file=nvidia/test.bin;'}
        self.status = {'state': 'ready', 'entry': current, 'kernel': record['kernel'], 'driver': '610.57.04',
                       'module_metadata': {'nvidia.ko': {'srcversion': 'LOADED-MATCH'}}, 'module_parameters': params}
        atomic_write(worker.path('/proc/sys/kernel/osrelease'), record['kernel'].encode())
        atomic_write(worker.path('/sys/module/nvidia/version'), b'610.57.04')
        atomic_write(worker.path('/sys/module/nvidia/srcversion'), b'LOADED-MATCH')
        for name, value in params.items():
            atomic_write(worker.path('/sys/module/nvidia/parameters/' + name), value.encode())
        json_write(worker.state / 'fleet.json', fleet)
        json_write(worker.state / 'transaction.json', {'phase': 'ready'})
        return fleet

    def fleet(self):
        return self.worker._json(self.worker.state / 'fleet.json')

    def prune(self, keep=3):
        return subject.prune(self.worker, self.status, keep)

    def test_prunes_oldest_for_all_backends_preserving_normal_current_and_shared_grub(self):
        for backend in ('grub', 'systemd-boot', 'uki'):
            with self.subTest(backend=backend):
                # Each backend receives a fresh isolated subtree.
                self.root = Path(self.temporary.name) / backend
                self.root.mkdir(mode=0o700)
                before = self.setup(backend)
                oldest = next(iter(before['boot_generations']))
                current = self.status['entry']
                result = self.prune()
                self.assertEqual(result['state'], 'complete')
                self.assertEqual(result['removed'], [oldest])
                self.assertEqual(result['retained'], 3)
                after = self.fleet()
                self.assertEqual(after['boot_generations'][oldest]['state'], 'removed')
                for item in before['boot_generations'][oldest]['files']:
                    self.assertFalse(self.worker.path(item['path']).exists())
                for item in before['boot_generations'][current]['files']:
                    self.assertTrue(self.worker.path(item['path']).exists())
                self.assertEqual(self.worker.path('/boot/vmlinuz-normal').read_bytes(), b'NORMAL KERNEL')
                self.assertEqual(self.worker.path('/boot/initramfs-normal.img').read_bytes(), b'NORMAL INITRAMFS')
                self.assertNotIn('_validated', after['boot_generations'][oldest])
                if backend == 'grub':
                    data = self.worker.path('/boot/grub/nvidia-vbios.cfg').read_bytes()
                    self.assertNotIn(oldest.encode(), data)
                    self.assertIn(current.encode(), data)
                    self.assertEqual(after['shared_boot_files']['/boot/grub/nvidia-vbios.cfg'], digest(data))
                    self.assertEqual(self.worker.path('/boot/grub/grub.cfg').read_bytes(), b'source $prefix/nvidia-vbios.cfg\n# NORMAL OS MENU\n')
                self.assertEqual(self.prune()['removed'], [])

    def test_keep_two_and_selected_older_generation_is_protected(self):
        fleet = self.setup('systemd-boot')
        selected = list(fleet['boot_generations'])[0]
        record = fleet['boot_generations'][selected]
        fleet['last_ready']['entry'] = selected
        self.status['entry'], self.status['kernel'] = selected, record['kernel']
        self.worker.ops.environment['saved_entry'] = selected
        atomic_write(self.worker.path('/proc/sys/kernel/osrelease'), record['kernel'].encode())
        json_write(self.worker.state / 'fleet.json', fleet)
        result = self.prune(2)
        self.assertEqual(result['retained'], 2)
        remaining = [entry for entry, record in self.fleet()['boot_generations'].items() if record['state'] == 'active']
        self.assertEqual(set(remaining), {selected, list(fleet['boot_generations'])[-1]})

    def test_pending_selection_and_incomplete_transactions_defer(self):
        fleet = self.setup()
        for key in ('next_entry', 'prev_saved_entry'):
            self.worker.ops.environment[key] = next(iter(fleet['boot_generations']))
            self.assertEqual(self.prune()['reason'], 'pending-boot-transition')
            del self.worker.ops.environment[key]
        json_write(self.worker.state / 'transaction.json', {'phase': 'installing'})
        self.assertEqual(self.prune()['reason'], 'transaction-not-complete')
        self.assertEqual(self.fleet(), fleet)

    def test_running_identity_or_parameters_must_match_ready(self):
        self.setup()
        atomic_write(self.worker.path('/sys/module/nvidia/srcversion'), b'FOREIGN-MODULE')
        self.assertEqual(self.prune()['reason'], 'awaiting-matching-running-ready')
        self.assertTrue(all(record['state'] == 'active' for record in self.fleet()['boot_generations'].values()))

    def test_changed_missing_symlink_or_untrusted_owned_files_are_preserved(self):
        for fault in ('changed', 'missing', 'symlink', 'writable'):
            with self.subTest(fault=fault):
                self.root = Path(self.temporary.name) / fault
                self.root.mkdir(mode=0o700)
                fleet = self.setup('systemd-boot')
                oldest = next(iter(fleet['boot_generations']))
                target = self.worker.path(fleet['boot_generations'][oldest]['files'][0]['path'])
                if fault == 'changed':
                    atomic_write(target, b'EXTERNAL EDIT')
                elif fault == 'missing':
                    target.unlink()
                elif fault == 'symlink':
                    target.unlink(); target.symlink_to('/etc/passwd')
                else:
                    target.chmod(0o666)
                result = self.prune()
                self.assertEqual(result['state'], 'deferred')
                self.assertEqual(result['removed'], [])
                self.assertEqual(self.fleet()['boot_generations'][oldest]['state'], 'active')

    def test_foreign_bls_grub_and_uki_references_defer_deletion(self):
        for backend, foreign, content_prefix in (
                ('grub', '/boot/grub/foreign.cfg', 'initrd /nvidia-vbios/'),
                ('systemd-boot', '/efi/loader/entries/foreign.conf', 'linux /nvidia-vbios/'),
                ('uki', '/efi/EFI/Linux/foreign.efi', 'EMBEDDED /nvidia-vbios/')):
            with self.subTest(backend=backend):
                self.root = Path(self.temporary.name) / backend
                self.root.mkdir(mode=0o700)
                fleet = self.setup(backend)
                oldest = next(iter(fleet['boot_generations']))
                managed = fleet['boot_generations'][oldest]['managed_id']
                atomic_write(self.worker.path(foreign), (content_prefix + managed + '/vmlinuz').encode())
                result = self.prune()
                self.assertEqual(result['state'], 'deferred')
                self.assertIn('referenced', result['warnings'][0])
                self.assertEqual(result['removed'], [])

    def test_wrong_namespace_role_layout_or_normal_path_never_grants_authority(self):
        self.setup()
        original = self.fleet()
        for fault in ('id', 'role', 'path', 'layout', 'shared'):
            with self.subTest(fault=fault):
                fleet = json.loads(json.dumps(original))
                oldest = next(iter(fleet['boot_generations']))
                record = fleet['boot_generations'][oldest]
                if fault == 'id':
                    record['managed_id'] = 'normal-recovery'
                elif fault == 'role':
                    record['roles'][record['files'][0]['path']] = 'entry'
                elif fault == 'path':
                    old = record['files'][0]['path']
                    record['files'][0]['path'] = '/boot/vmlinuz-normal'
                    record['roles']['/boot/vmlinuz-normal'] = record['roles'].pop(old)
                elif fault == 'layout':
                    record['boot']['grub_config'] = '/boot/other/grub.cfg'
                else:
                    second = list(fleet['boot_generations'])[1]
                    fleet['boot_generations'][second] = json.loads(json.dumps(record))
                json_write(self.worker.state / 'fleet.json', fleet)
                with self.assertRaises(LifecycleError):
                    self.prune()
        json_write(self.worker.state / 'fleet.json', original)

    def test_shared_grub_edit_prevents_visibility_change_or_deletion(self):
        fleet = self.setup()
        path = self.worker.path('/boot/grub/nvidia-vbios.cfg')
        atomic_write(path, b'FOREIGN SOURCE')
        result = self.prune()
        self.assertEqual(result['removed'], [])
        self.assertIn('changed externally', result['warnings'][0])
        self.assertEqual(self.fleet(), fleet)
        self.assertEqual(path.read_bytes(), b'FOREIGN SOURCE')

    def test_selection_change_during_validation_preserves_artifacts(self):
        fleet = self.setup('systemd-boot')
        self.worker.ops.changed = True
        result = self.prune()
        self.assertEqual(result['removed'], [])
        self.assertEqual(self.fleet(), fleet)

    def test_interrupted_unlink_retries_only_after_durable_retirement(self):
        fleet = self.setup('systemd-boot')
        oldest = next(iter(fleet['boot_generations']))
        kernel = self.worker.path(fleet['boot_generations'][oldest]['files'][0]['path'])
        original = Path.unlink
        def fail(path, *args, **kwargs):
            if path == kernel:
                raise OSError('simulated interruption')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'unlink', fail):
            result = self.prune()
        self.assertEqual(result['state'], 'deferred')
        self.assertEqual(self.fleet()['boot_generations'][oldest]['state'], 'retiring')
        descriptor = next(name for name, role in fleet['boot_generations'][oldest]['roles'].items() if role == 'entry')
        self.assertFalse(self.worker.path(descriptor).exists())
        self.assertTrue(kernel.exists())
        self.assertEqual(self.prune()['removed'], [oldest])

    def test_interrupted_shared_write_recovers_before_and_after_bytes(self):
        fleet = self.setup()
        oldest = next(iter(fleet['boot_generations']))
        original = subject.atomic_write
        failed = False
        def fail(path, data, *args, **kwargs):
            nonlocal failed
            original(path, data, *args, **kwargs)
            if path == self.worker.path('/boot/grub/nvidia-vbios.cfg') and not failed:
                failed = True
                raise OSError('simulated interruption after replacing include')
        with patch.object(subject, 'atomic_write', fail):
            result = self.prune()
        self.assertEqual(result['state'], 'deferred')
        state = self.fleet()
        self.assertEqual(state['retention_pending']['entry'], oldest)
        self.assertEqual(state['boot_generations'][oldest]['state'], 'retiring')
        for item in fleet['boot_generations'][oldest]['files']:
            self.assertTrue(self.worker.path(item['path']).exists())
        self.assertEqual(self.prune()['removed'], [oldest])
        self.assertNotIn('retention_pending', self.fleet())

    def test_retiring_changed_file_blocks_restart_without_adopting_it(self):
        fleet = self.setup('uki')
        oldest = next(iter(fleet['boot_generations']))
        fleet['boot_generations'][oldest]['state'] = 'retiring'
        target = self.worker.path(fleet['boot_generations'][oldest]['files'][0]['path'])
        atomic_write(target, b'FOREIGN AFTER RETIREMENT')
        json_write(self.worker.state / 'fleet.json', fleet)
        result = self.prune()
        self.assertEqual(result['removed'], [])
        self.assertEqual(target.read_bytes(), b'FOREIGN AFTER RETIREMENT')

    def test_missing_current_authority_and_malformed_pending_intent_fail_closed(self):
        fleet = self.setup()
        current = self.status['entry']
        original = json.loads(json.dumps(fleet))
        del fleet['boot_generations'][current]
        json_write(self.worker.state / 'fleet.json', fleet)
        self.assertEqual(self.prune()['reason'], 'current-ready-generation-not-owned')
        original['retention_pending'] = []
        json_write(self.worker.state / 'fleet.json', original)
        with self.assertRaisesRegex(LifecycleError, 'intent'):
            self.prune()

    def test_shared_hash_commit_interruption_preserves_intent_for_retry(self):
        fleet = self.setup()
        oldest = next(iter(fleet['boot_generations']))
        original = subject._save
        saves = 0
        def fail(worker, data):
            nonlocal saves
            saves += 1
            if saves == 2:
                raise OSError('interrupted ownership hash commit')
            return original(worker, data)
        with patch.object(subject, '_save', fail):
            result = self.prune()
        self.assertEqual(result['state'], 'deferred')
        self.assertEqual(self.fleet()['retention_pending']['entry'], oldest)
        self.assertEqual(self.prune()['removed'], [oldest])
        self.assertNotIn('retention_pending', self.fleet())

    def test_invalid_keep_does_not_change_fleet(self):
        fleet = self.setup()
        for keep in (1, 4, True, '3'):
            with self.subTest(keep=keep), self.assertRaises(LifecycleError):
                self.prune(keep)
        self.assertEqual(self.fleet(), fleet)


if __name__ == '__main__':
    unittest.main()
