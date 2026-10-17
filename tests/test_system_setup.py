"""`nvbios system setup` with injected steps, operations, euid and a synthetic root; nothing runs on the host."""
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import signal
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tests'))
import test_bootstrap
from test_lifecycle import OLD, VERSION
from test_payload import RTX_2000_ADA, legacy_image
from nvidia_vbios import cli, system_setup
from nvidia_vbios.bootstrap import CONFIG, RUNTIME, STATE
from nvidia_vbios.lifecycle import Reconciler
from nvidia_vbios.lifecycle.platform import DEBIAN_PLATFORM
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write, digest, json_write, locked, source_tree_hash
from nvidia_vbios.lifecycle.source_fetch import Rejected

BDF0, BDF1 = '0000:03:00.0', '0000:04:00.0'
GPUS = {bdf: {'bdf': bdf, 'uuid': f'GPU-00000000-0000-0000-0000-{index:012x}', 'vendor': 0x10de, 'device': 0x2bb4,
              'architecture': 'blackwell-gb20x'} for index, bdf in enumerate((BDF0, BDF1), 1)}
NORMAL = f'normal-{OLD}'
ENTRY = f'vbios-{OLD}-0123456789abcdef0123'
LAUNCHER = '/checkout/nvbios'
EVIDENCE = {'boot': 'unverified', 'application': 'unverified', 'fields': {}}


def write_profile(options, gpus, fallback):
    """What `nvbios system prepare` writes for the --device files it is given."""
    value = lambda flag: options[options.index(flag) + 1]
    p2p = '--p2p-preferred' in options
    devices = []
    for index, option in enumerate(options):
        if option == '--device':
            bdf, rom = options[index + 1:index + 3]
            data = Path(rom).read_bytes()
            devices.append(dict(gpus[bdf], archive=rom, payload=rom, source_sha256=digest(data), sha256=digest(data),
                                source_size=len(data), size=len(data), evidence=EVIDENCE))
    profile = {'devices': devices, 'driver_sources': [{'path': value('--driver-source'), 'p2p_preferred': p2p}],
               'userspace': {'provider': value('--userspace')}, 'fallback_entry': fallback, 'jobs': int(value('--jobs')),
               'auto_source': value('--userspace') != 'manual' and not p2p}
    if p2p:
        profile['require_p2p_source'] = True
    output = Path(value('--output'))
    output.mkdir(mode=0o700)
    json_write(output / 'profile.json', profile)
    return {'state': 'prepared', 'profile': str(output / 'profile.json'), 'version': VERSION, 'device_count': len(devices)}


class Operations:
    """The root-side answers setup itself reads; every one can be changed by a test."""
    def __init__(self):
        self.kernel, self.active, self.triggers, self.plugin, self.problem = OLD, False, False, True, None
        self.environment = {'saved_entry': NORMAL}

    def current_kernel(self):
        return self.kernel

    def reconcile_active(self):
        return self.active

    def triggers_any_active(self):
        return self.triggers

    def plugin_available(self, provider):
        return self.plugin

    def prerequisites(self, kernel, config):
        if self.problem:
            raise LifecycleError(self.problem)

    def grub_environment(self):
        return dict(self.environment)

    def installed_version(self, config):
        return VERSION

    def inspect_source(self, path):
        data = (path / 'version.mk').read_bytes()
        return {'version': data.decode().strip(), 'supported': True, 'reasons': [], 'capabilities': {},
                'source_hashes': {'version.mk': digest(data)}}


class Steps:
    """Stands in for the child verbs: records argv and answers like them."""
    def __init__(self):
        self.calls, self.fail, self.during = [], {}, {}
        self.results = {'disable': {'state': 'disabled', 'default_restoration': {'state': 'normal', 'entry': NORMAL}},
                        'install': {'release': 'a' * 64}, 'enroll': {'state': 'enrolled'},
                        'reconcile': {'state': 'ready', 'marker': 'VBIOS_READY', 'entry': ENTRY},
                        'enable': {'ready': True, 'triggers_enabled': True, 'default_selection': {'state': 'selected', 'entry': ENTRY}}}

    def verbs(self):
        return [argv[2] for argv in self.calls]

    def __call__(self, argv, poll=None):
        self.calls.append(argv)
        verb = argv[2]
        if verb in self.during:
            self.during[verb](poll)
        if verb in self.fail:
            return 1, '', 'Traceback (most recent call last):\n  ...\n' + self.fail[verb] + '\n'
        result = write_profile(argv[3:], GPUS, NORMAL) if verb == 'prepare' else self.results[verb]
        return 0, json.dumps(result, indent=2), ''


class SetupTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.private').mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(dir=ROOT / '.private')
        self.addCleanup(directory.cleanup)
        self.addCleanup(signal.signal, signal.SIGHUP, signal.getsignal(signal.SIGHUP))
        self.root = Path(directory.name)
        self.ops, self.steps, self.euid, self.cpus = Operations(), Steps(), 0, 24
        self.roms = []
        for index in range(2):
            rom = self.root / f'inputs/gpu{index}.bin'
            atomic_write(rom, b'REVIEWED ROM payload %d' % index)
            self.roms.append((str(rom), digest(rom.read_bytes())))
        self.source = self.root / 'inputs/source'
        atomic_write(self.source / 'version.mk', VERSION.encode())
        self.current = self.root / RUNTIME.lstrip('/') / 'current.json'
        self.installed()

    def installed(self, files=('nvidia_vbios/system_setup.py',)):
        json_write(self.current, {'schema_version': 1, 'release': 'b' * 64, 'files': {name: {} for name in files}})

    def fetch(self, version, work):
        tree = work / 'tree' / f'open-gpu-kernel-modules-{version}'
        atomic_write(tree / 'version.mk', version.encode())
        return tree, {'url': 'https://example.invalid/tag', 'archive_sha256': '0' * 64, 'size': 1, 'kind': 'github-tag'}

    def new_file(self, index=0, bdf=BDF0):
        return ['--device', bdf, *self.roms[index]]

    def call(self, argv):
        # Always with injected fakes: even an argument list that parses by mistake never reaches the host.
        return system_setup.main(argv, root=self.root, operations=self.ops, euid=self.euid, run=self.steps,
                                 fetch=self.fetch, launcher=LAUNCHER, cpu_count=lambda: self.cpus)

    def setup(self, *argv, progress=True, stdout=None):
        output, error = stdout or io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = self.call([*(['--progress'] if progress else []), '--kernel', OLD, '--userspace', 'rpm', *argv])
        self.stderr, self.stdout = error.getvalue(), output.getvalue() if stdout is None else ''
        self.events = [json.loads(line) for line in self.stdout.splitlines()] if progress else []
        return code

    def load(self, *argv, **options):
        return self.setup(*self.new_file(), '--driver-source', str(self.source), *argv, **options)

    def event(self, name):
        return next(event for event in self.events if event['event'] == name)

    def assert_blocked(self, step, message):
        self.assertRegex(self.stderr.strip().splitlines()[-1], f'^SETUP_BLOCKED: {step}: .*{message}')
        self.assertEqual((self.event('failed')['step'], self.event('failed')['cleanup']),
                         (step, {'ran': False, 'ok': None, 'message': None}))

    def enroll(self, devices=(BDF0,), **policy):
        """A valid enrolled configuration with its payloads and a P2P source snapshot under the synthetic root."""
        source = self.root / 'var/lib/nvidia-vbios/sources/p2p'
        atomic_write(source / 'version.mk', VERSION.encode())
        records = []
        for bdf in devices:
            data = b'REVIEWED ROM payload %d' % list(GPUS).index(bdf)
            path = f'/var/lib/nvidia-vbios/roms/{digest(data)}.bin'
            atomic_write(self.root / path.lstrip('/'), data)
            records.append(dict(GPUS[bdf], structurally_validated=True, evidence=EVIDENCE, sha256=digest(data),
                                source_sha256=digest(b'full archive'), size=len(data), payload_path=path))
        json_write(self.root / CONFIG.lstrip('/'), {
            'schema_version': 1, 'enabled': True, 'devices': records, 'fallback_entry': NORMAL, 'fallback_sha256': '0' * 64,
            'fallback_files': {f'/boot/vmlinuz-{OLD}': '0' * 64, f'/boot/initramfs-{OLD}.img': '0' * 64},
            'sources': [{'version': VERSION, 'path': '/var/lib/nvidia-vbios/sources/p2p', 'p2p_preferred': True,
                         'source_hashes': {'version.mk': digest(VERSION.encode())}, 'tree_sha256': source_tree_hash(source, self.root)}],
            **policy})
        return records

    def keep_profile(self):
        """Keep the profile setup hands to enroll; setup removes its work directory afterwards."""
        def capture(poll):
            argv = self.steps.calls[-1]
            self.enrolled_profile = json.loads(Path(argv[argv.index('--profile') + 1]).read_text())
        self.steps.during['enroll'] = capture

    def test_first_load_runs_each_step_with_exact_arguments_and_reports_done(self):
        self.current.unlink()
        self.assertEqual(self.load('--repository', '/checkout'), 0, self.stderr)
        output = self.steps.calls[0][self.steps.calls[0].index('--output') + 1]
        self.assertTrue(output.startswith(str(self.root / 'var/lib/nvidia-vbios/setup')))
        self.assertEqual(self.steps.calls, [
            [LAUNCHER, 'system', 'prepare', '--device', BDF0, self.roms[0][0], '--driver-source', str(self.source),
             '--userspace', 'rpm', '--output', output, '--jobs', '8'],
            [LAUNCHER, 'system', 'install', '--repository', '/checkout'],
            ['/usr/local/bin/nvbios', 'system', 'enroll', '--profile', output + '/profile.json'],
            ['/usr/local/bin/nvbios', 'system', 'reconcile', '--kernel', OLD, '--select-default'],
            ['/usr/local/bin/nvbios', 'system', 'enable', '--kernel', OLD]])
        steps = ['prepare', 'preflight', 'install', 'enroll', 'reconcile', 'enable']
        self.assertEqual(self.events[0], {'event': 'start', 'protocol': 1, 'kernel': OLD, 'steps': steps})
        self.assertEqual([(event['step'], event['index'], event['total']) for event in self.events if event['event'] == 'step'],
                         [(step, index, 6) for index, step in enumerate(steps, 1)])
        self.assertEqual([event['step'] for event in self.events if event['event'] == 'result'], steps)
        self.assertEqual(self.event('result')['result']['state'], 'prepared')
        self.assertEqual(self.events[-1], {'event': 'done', 'ok': True, 'kernel': OLD, 'entry': ENTRY, 'default': 'selected',
                                           'default_reason': None, 'devices': [{'bdf': BDF0, 'sha256': self.roms[0][1],
                                                                                'architecture': 'blackwell-gb20x', 'kept': False}]})
        self.assertFalse(Path(output).parent.exists())

    def test_without_progress_prints_only_the_done_document(self):
        self.assertEqual(self.load(progress=False), 0)
        self.assertEqual(json.loads(self.stdout)['default'], 'selected')
        self.assertTrue(self.stdout.startswith('{\n'))
        self.steps.fail['reconcile'] = 'VBIOS_BLOCKED: make failed; see build.log'
        self.assertEqual(self.load(progress=False), 1)
        self.assertEqual((self.stdout, self.stderr), ('', 'SETUP_BLOCKED: reconcile: VBIOS_BLOCKED: make failed; see build.log\n'))

    def test_second_load_disables_first_carries_policy_and_keeps_a_payload(self):
        enrolled = self.enroll(jobs=3, auto_source=False, retain_boot_generations=2, stock_builder='dkms', retain_build_tree=True,
                               parameters={'NVreg_RegistryDwords': 'RmTestOption=1'}, signing={'key': '/k', 'certificate': '/c'})
        self.keep_profile()
        self.assertEqual(self.setup('--keep', BDF0, *self.new_file(1, BDF1), '--driver-source', str(self.source)), 0, self.stderr)
        self.assertEqual(self.steps.verbs(), ['prepare', 'disable', 'enroll', 'reconcile', 'enable'])
        prepare = self.steps.calls[0]
        self.assertEqual(prepare[3:9], ['--device', BDF0, str(self.root / enrolled[0]['payload_path'].lstrip('/')),
                                        '--device', BDF1, self.roms[1][0]])
        self.assertEqual(prepare[prepare.index('--jobs') + 1], '3')
        profile = self.enrolled_profile
        self.assertEqual({key: profile.get(key) for key in ('jobs', 'auto_source', 'retain_boot_generations', 'stock_builder',
                                                             'retain_build_tree', 'parameters', 'signing')},
                         {'jobs': 3, 'auto_source': False, 'retain_boot_generations': 2, 'stock_builder': 'dkms',
                          'retain_build_tree': True, 'parameters': {'NVreg_RegistryDwords': 'RmTestOption=1'}, 'signing': None})
        self.assertNotIn('require_p2p_source', profile)
        self.assertEqual([device['bdf'] for device in profile['devices']], [BDF0, BDF1])
        self.assertEqual(self.events[-1]['devices'], [
            {'bdf': BDF0, 'sha256': enrolled[0]['sha256'], 'architecture': 'blackwell-gb20x', 'kept': True},
            {'bdf': BDF1, 'sha256': self.roms[1][1], 'architecture': 'blackwell-gb20x', 'kept': False}])

    def test_required_p2p_source_is_kept_or_the_load_is_refused(self):
        self.enroll(require_p2p_source=True)
        self.assertEqual(self.setup(*self.new_file(), '--download-source', VERSION), 1)
        self.assert_blocked('preflight', 'requires a P2P source')
        self.assertEqual(self.load(), 1)
        self.assert_blocked('preflight', 'requires a P2P source')
        self.assertEqual(self.steps.calls, [])
        self.keep_profile()
        self.assertEqual(self.setup(*self.new_file(), '--keep-source'), 0, self.stderr)
        prepare = self.steps.calls[0]
        self.assertEqual(prepare[prepare.index('--driver-source') + 1], str(self.root / 'var/lib/nvidia-vbios/sources/p2p'))
        self.assertIn('--p2p-preferred', prepare)
        self.assertIs(self.enrolled_profile['require_p2p_source'], True)

    def test_keep_source_carries_the_enrolled_p2p_requirement_as_it_was(self):
        self.enroll()                                   # the kept snapshot is P2P, the requirement is unset
        self.keep_profile()
        self.assertEqual(self.setup(*self.new_file(), '--keep-source'), 0, self.stderr)
        self.assertNotIn('require_p2p_source', self.enrolled_profile)

    def test_state_parents_stay_readable_and_the_setup_directory_root_only(self):
        self.assertEqual(self.load(), 0, self.stderr)
        state = self.root / 'var/lib/nvidia-vbios'
        self.assertEqual(((state).stat().st_mode & 0o777, (state / 'setup').stat().st_mode & 0o777), (0o755, 0o700))

    def ada_at(self, bdf):
        atomic_write(self.root / f'sys/bus/pci/devices/{bdf}/device', b'0x28b0\n')

    @unittest.skipUnless(system_setup.optional_editor(), 'internal build only')
    def test_a_new_ada_full_rom_is_relocated_by_prepare_and_its_loader_file_refused(self):
        self.ada_at(BDF0)
        self.assertEqual(self.load(), 0, self.stderr)          # not a loadable payload: the full ROM is relocated
        prepare = self.steps.calls[0]
        self.assertEqual(prepare[prepare.index('--representation'):][:3], ['--representation', BDF0, 'ada-relocated-v2'])
        loader = self.root / 'inputs/gpu0-loader.bin'
        atomic_write(loader, legacy_image(RTX_2000_ADA))
        self.steps = Steps()
        self.assertEqual(self.setup('--device', BDF0, str(loader), digest(loader.read_bytes()),
                                    '--driver-source', str(self.source)), 1)
        self.assert_blocked('preflight', 'choose the .rom the editor saved')
        self.assertEqual(self.steps.calls, [])

    @unittest.skipUnless(system_setup.optional_editor(), 'internal build only')
    def test_keeping_an_archive_verified_gpu_relocates_its_archived_rom_again(self):
        self.ada_at(BDF0)
        self.enroll()
        configuration = json.loads((self.root / CONFIG.lstrip('/')).read_text())
        device = configuration['devices'][0]
        archive = f"/var/lib/nvidia-vbios/roms/{device['source_sha256']}.rom"
        device.update(architecture='ada', device=0x28B0, representation='ada-relocated-v2', archive_path=archive)
        json_write(self.root / CONFIG.lstrip('/'), configuration)
        self.assertEqual(self.setup('--keep', BDF0, '--keep-source'), 1)      # the full ROM was not kept
        self.assert_blocked('preflight', 'full ROM was not kept')
        atomic_write(self.root / archive.lstrip('/'), b'full archived ROM')
        self.steps = Steps()
        self.setup('--keep', BDF0, '--keep-source')
        prepare = self.steps.calls[0]
        self.assertEqual(prepare[prepare.index('--device'):][:3], ['--device', BDF0, str(self.root / archive.lstrip('/'))])
        self.assertEqual(prepare[prepare.index('--representation'):][:3], ['--representation', BDF0, 'ada-relocated-v2'])

    def test_registry_parameters_that_no_longer_fit_block_before_any_change(self):
        self.enroll(parameters={'NVreg_RegistryDwords': 'RmTestOption=' + '1' * 4090})
        self.assertEqual(self.load(), 1)
        self.assert_blocked('prepare', 'registry parameters cannot be kept')
        self.assertEqual(self.steps.verbs(), ['prepare'])

    def test_changed_file_or_kept_identity_blocks_after_prepare(self):
        self.assertEqual(self.setup('--device', BDF0, self.roms[0][0], 'f' * 64, '--driver-source', str(self.source)), 1)
        self.assert_blocked('prepare', 'file changed after it was checked')
        self.enroll()
        for change in ({'uuid': 'GPU-00000000-0000-0000-0000-0000000000ff'}, {'device': 0x2bb5}):
            self.steps.calls.clear()
            with self.subTest(change=change), patch.dict(GPUS, {BDF0: dict(GPUS[BDF0], **change)}):
                self.assertEqual(self.setup('--keep', BDF0, '--keep-source'), 1)
                self.assert_blocked('prepare', 'differs from the enrollment')
                self.assertEqual(self.steps.verbs(), ['prepare'])

    def test_keep_needs_an_enrolled_payload_and_a_build_that_can_verify_it(self):
        self.assertEqual(self.setup('--keep', BDF0, '--driver-source', str(self.source)), 1)
        self.assert_blocked('preflight', 'no enrolled payload to keep')
        self.assertEqual(self.setup('--keep', BDF0, '--keep-source'), 1)
        self.assert_blocked('preflight', 'no enrolled payload to keep')
        records = self.enroll()
        config = json.loads((self.root / CONFIG.lstrip('/')).read_text())
        config['devices'][0].update(architecture='ada', device=0x28b0, representation='ada-relocated-v1')
        json_write(self.root / CONFIG.lstrip('/'), config)
        with patch.object(system_setup, 'optional_editor', return_value=None):
            self.assertEqual(self.setup('--keep', BDF0, '--keep-source'), 1)
        self.assert_blocked('preflight', 'ada-relocated-v1 representation, which this build cannot verify')
        checked = []
        editor = SimpleNamespace(validate_strict=lambda data, device: checked.append((data, device['representation'])))
        self.keep_profile()
        with patch.object(system_setup, 'optional_editor', return_value=editor), \
                patch.dict(GPUS, {BDF0: dict(GPUS[BDF0], architecture='ada', device=0x28b0)}):
            self.assertEqual(self.setup('--keep', BDF0, '--keep-source'), 0, self.stderr)
        payload = (self.root / records[0]['payload_path'].lstrip('/')).read_bytes()
        self.assertEqual(checked, [(payload, 'ada-relocated-v1')])
        self.assertEqual(self.enrolled_profile['devices'][0]['representation'], 'ada-relocated-v1')

    def test_root_preflight_blocks_before_the_first_change(self):
        cases = {'next_entry': lambda: self.ops.environment.update(next_entry='one-time-os'),
                 'foreign or unrelated GRUB default': lambda: self.ops.environment.update(saved_entry='another-os'),
                 'plugin prerequisites are unavailable': lambda: setattr(self.ops, 'plugin', False),
                 'kernel-devel missing': lambda: setattr(self.ops, 'problem', 'matching kernel-devel missing')}
        for message, change in cases.items():
            self.ops, self.steps = Operations(), Steps()
            change()
            with self.subTest(message=message):
                self.assertEqual(self.load(), 1)
                self.assert_blocked('preflight', message)
                self.assertEqual(self.steps.verbs(), ['prepare'])

    def test_the_override_entry_is_an_allowed_default_only_for_this_kernel(self):
        self.enroll()
        fleet = self.root / STATE.lstrip('/') / 'fleet.json'
        self.ops.environment = {'saved_entry': ENTRY}
        for kernel, code in (('6.1.0-1.fc44.x86_64', 1), (OLD, 0)):
            self.steps.calls.clear()
            json_write(fleet, {'last_ready': {'entry': ENTRY, 'kernel': kernel}})
            with self.subTest(kernel=kernel):
                self.assertEqual(self.load(), code, self.stderr)
                self.assertEqual(self.steps.verbs(), ['prepare'] if code else ['prepare', 'disable', 'enroll', 'reconcile', 'enable'])

    def test_read_only_refusals_run_no_step(self):
        def held_lock():
            stack = locked(self.root / 'var/lib/nvidia-vbios/setup/setup.lock', self.root)
            stack.__enter__()
            self.addCleanup(stack.__exit__, None, None, None)
        cases = {'requires root': (lambda: setattr(self, 'euid', 1000), ()),
                 'not the running kernel': (lambda: setattr(self.ops, 'kernel', '6.1.0-1.fc44.x86_64'), ()),
                 'reconciliation service is active': (lambda: setattr(self.ops, 'active', True), ()),
                 'Fedora/RHEL family': (lambda: setattr(self.ops, 'platform', DEBIAN_PLATFORM), ()),
                 'loader is not installed': (self.current.unlink, ()),
                 'no enrolled driver source to keep': (lambda: None, ('--keep-source',)),
                 'another setup is running': (held_lock, ())}
        for message, (change, extra) in cases.items():
            self.ops, self.euid = Operations(), 0
            self.installed()
            change()
            with self.subTest(message=message):
                source = () if '--keep-source' in extra else ('--driver-source', str(self.source))
                self.assertEqual(self.setup(*self.new_file(), *source, *extra), 1)
                self.assert_blocked('preflight', message)
                self.assertNotIn('start', [event['event'] for event in self.events])
                self.assertEqual(self.steps.calls, [])

    def test_install_keeps_the_flavor_of_the_installed_release(self):
        clone = self.root / 'inputs/clone'
        (clone / 'src').mkdir(parents=True)
        self.assertEqual(self.load('--repository', str(clone)), 0, self.stderr)
        self.installed([system_setup.EDITOR_MARKER])
        self.assertEqual(self.load('--repository', str(clone)), 1)
        self.assert_blocked('preflight', 'installed release differs from this clone')
        atomic_write(clone / 'src' / system_setup.EDITOR_MARKER, b'')
        self.assertEqual(self.load('--repository', str(clone)), 0, self.stderr)

    def test_reconcile_must_end_ready(self):
        self.steps.results['reconcile'] = {'state': 'driver-drift', 'marker': 'VBIOS_DRIFT', 'error': 'make failed'}
        self.assertEqual(self.load(), 1)
        self.assert_blocked('reconcile', "state 'driver-drift': make failed")
        self.assertNotIn('enable', self.steps.verbs())

    def test_enable_failure_runs_disable_and_reports_both_outcomes(self):
        self.steps.fail['enable'] = 'BOOTSTRAP_BLOCKED: path/timer enable verification failed'
        self.assertEqual(self.load(), 1)
        self.assertEqual(self.steps.verbs()[-2:], ['enable', 'disable'])
        self.assertEqual(self.event('failed'), {'event': 'failed', 'step': 'enable',
                                                'message': 'BOOTSTRAP_BLOCKED: path/timer enable verification failed',
                                                'cleanup': {'ran': True, 'ok': True, 'message': None}})
        self.assertIn('disable ran', self.stderr)
        self.steps = Steps()
        self.steps.results['enable'] = {'ready': True, 'triggers_enabled': True, 'default_selection': {}}
        self.steps.fail['disable'] = 'BOOTSTRAP_BLOCKED: normal recovery BLS changed; disable selection requires review'
        self.assertEqual(self.load(), 1)
        cleanup = self.event('failed')['cleanup']
        self.assertEqual((cleanup['ran'], cleanup['ok']), (True, False))
        self.assertIn('normal recovery BLS changed', cleanup['message'])
        self.assertRegex(self.stderr, 'enable: enable ended with boot selection None; disable also failed, the default may '
                                      'still be the override')
        self.steps = Steps()
        self.steps.fail['enable'] = 'BOOTSTRAP_BLOCKED: x'
        self.steps.results['disable'] = {'state': 'disabled', 'default_restoration': {'state': 'preserved', 'reason': 'pending GRUB transition'}}
        self.assertEqual(self.load(), 1)
        self.assertEqual(self.event('failed')['cleanup'], {'ran': True, 'ok': False, 'message': 'default kept: pending GRUB transition'})

    def test_a_preserved_default_is_not_a_successful_load(self):
        # Success needs the override entry selected; a respected foreign default fails and is cleaned up.
        self.steps.results['enable'] = {'ready': True, 'triggers_enabled': True,
                                        'default_selection': {'state': 'preserved', 'reason': 'pending GRUB transition'}}
        self.assertEqual(self.load(), 1)
        self.assertEqual(self.steps.verbs()[-2:], ['enable', 'disable'])
        failed = self.event('failed')
        self.assertEqual(failed['step'], 'enable')
        self.assertIn('kept the existing default boot entry (pending GRUB transition)', failed['message'])
        self.assertFalse(any(event['event'] == 'done' for event in self.events))

    def test_every_enrolled_gpu_must_be_named(self):
        self.enroll(devices=(BDF0, BDF1))
        # The prepared-but-not-booted case: the window only knew about GPU1.
        self.assertEqual(self.setup(*self.new_file(1, BDF1), '--keep-source'), 1)
        self.assert_blocked('preflight', f'enrolled GPU\\(s\\) {BDF0} not named')
        self.assertEqual(self.steps.calls, [])
        self.keep_profile()
        self.assertEqual(self.setup(*self.new_file(1, BDF1), '--remove', BDF0, '--keep-source'), 0, self.stderr)
        self.assertEqual([device['bdf'] for device in self.enrolled_profile['devices']], [BDF1])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.call(['--kernel', OLD, '--userspace', 'rpm', '--keep', BDF0, '--remove', BDF0, '--keep-source'])

    def test_an_uncommitted_migration_blocks_before_any_change(self):
        self.enroll(adopt_existing={f'/usr/lib/modules/{OLD}/extra/nvidia.ko': 'a' * 64})
        self.assertEqual(self.setup(*self.new_file(), '--keep-source'), 1)
        self.assert_blocked('preflight', 'depends on a migration')
        self.assertEqual(self.steps.calls, [])
        json_write(self.root / 'var/lib/nvidia-vbios/lifecycle/fleet.json',
                   {'last_ready': {'kernel': OLD, 'entry': NORMAL}})
        self.assertEqual(self.setup(*self.new_file(), '--keep-source'), 0, self.stderr)

    def test_the_enrolled_summary_is_world_readable_after_enroll(self):
        self.assertEqual(self.load(), 0, self.stderr)
        summary = self.root / 'var/lib/nvidia-vbios/enrolled-devices.json'
        self.assertEqual(summary.stat().st_mode & 0o777, 0o644)
        self.assertEqual(json.loads(summary.read_text())['devices'],
                         [{'bdf': BDF0, 'sha256': self.roms[0][1], 'architecture': GPUS[BDF0]['architecture']}])

    def test_a_closed_window_does_not_stop_the_steps(self):
        class Closed(io.StringIO):
            def write(self, text):
                raise BrokenPipeError(32, 'Broken pipe')
        self.assertEqual(self.load(stdout=Closed()), 0)
        self.assertEqual(self.steps.verbs(), ['prepare', 'enroll', 'reconcile', 'enable'])

    def test_reconcile_phases_come_from_its_transaction_files(self):
        state = self.root / STATE.lstrip('/')
        atomic_write(state / f'transactions/{OLD}-1/build.log', b'an earlier run')
        def reconcile(poll):
            run = state / f'transactions/{OLD}-{time.time_ns()}'
            run.mkdir(parents=True)
            poll()
            atomic_write(run / 'build.log', b'CC [M]')
            poll(); poll()
            for phase in ('installing', 'selecting', 'ready'):
                json_write(state / 'transaction.json', {'id': run.name, 'phase': phase})
                poll()
        self.steps.during['reconcile'] = reconcile
        self.assertEqual(self.load(), 0, self.stderr)
        self.assertEqual([event['phase'] for event in self.events if event['event'] == 'phase'],
                         ['source', 'build', 'initramfs', 'boot-entry'])
        self.assertTrue(all(event['step'] == 'reconcile' for event in self.events if event['event'] == 'phase'))

    def test_download_is_checked_before_prepare_and_removed_after(self):
        self.assertEqual(self.setup(*self.new_file(), '--download-source', VERSION), 0, self.stderr)
        result = self.event('result')
        self.assertEqual((result['step'], result['result']['cross_check'], result['result']['version']), ('download', 'unavailable', VERSION))
        prepare = self.steps.calls[0]
        tree = prepare[prepare.index('--driver-source') + 1]
        self.assertTrue(tree.endswith(f'/fetch/tree/open-gpu-kernel-modules-{VERSION}'))
        self.assertFalse(Path(tree).exists())
        self.assertEqual(self.events[0]['steps'][:2], ['download', 'prepare'])
        def rejected(version, work):
            raise Rejected('tag differs from the packaged source (tree) in 1 files, first Makefile')
        self.fetch, self.steps.calls = rejected, []
        self.assertEqual(self.setup(*self.new_file(), '--download-source', VERSION), 1)
        self.assert_blocked('download', 'tag differs from the packaged source')
        self.assertEqual(self.steps.calls, [])
        self.fetch = lambda version, work: SetupTests.fetch(self, '615.1.1', work)
        self.assertEqual(self.setup(*self.new_file(), '--download-source', VERSION), 1)
        self.assert_blocked('download', 'not a supported unpatched')

    def test_jobs_keep_the_enrolled_value_and_a_first_install_uses_up_to_eight(self):
        def jobs(*argv):
            self.steps.calls.clear()
            self.assertEqual(self.load(*argv), 0, self.stderr)
            return self.steps.calls[0][self.steps.calls[0].index('--jobs') + 1]
        self.assertEqual(jobs(), '8')
        self.cpus = 2
        self.assertEqual((jobs(), jobs('--jobs', '12')), ('2', '12'))
        self.enroll(jobs=5)
        self.assertEqual((jobs(), jobs('--jobs', '1')), ('5', '1'))

    def test_arguments_follow_the_contract(self):
        source = ('--driver-source', '/source')
        bad = [(*source,), ('--device', BDF0, '/a.bin', 'A' * 64, *source), ('--device', BDF0, 'a.bin', 'a' * 64, *source),
               ('--device', 'gpu0', '/a.bin', 'a' * 64, *source), ('--keep', BDF0, '--keep', '0000:03:00.0', *source),
               ('--keep', BDF0, '--download-source', VERSION, '--p2p-preferred'), ('--keep', BDF0, '--keep-source', *source),
               ('--keep', BDF0, '--download-source', '615.78'), ('--keep', BDF0, *source, '--jobs', '0'), ('--keep', BDF0)]
        for argv in bad:
            with self.subTest(argv=argv), redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit:
                self.call(['--kernel', OLD, '--userspace', 'rpm', *argv])
            self.assertEqual(exit.exception.code, 2)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.call(['--userspace', 'rpm', '--keep', BDF0, *source])
        self.assertEqual(self.steps.calls, [])

    def test_children_drain_both_pipes_while_polling(self):
        polls = []
        code = 'import sys, time; sys.stderr.write("e" * (1 << 20)); sys.stdout.write("o" * (1 << 20)); sys.stdout.flush(); time.sleep(0.7)'
        result = system_setup.run_child([sys.executable, '-c', code], lambda: polls.append(1))
        self.assertEqual(result, (0, 'o' * (1 << 20), 'e' * (1 << 20)))
        self.assertTrue(polls)

    def test_launcher_and_child_error_lines(self):
        self.assertEqual(system_setup.default_launcher(RUNTIME + '/releases/' + 'c' * 64 + '/nvidia_vbios/system_setup.py'),
                         '/usr/local/bin/nvbios')
        self.assertEqual(system_setup.default_launcher(), str(ROOT / 'nvbios'))
        self.assertEqual(system_setup.last_error('noise\nPREPARE_BLOCKED: output already exists\n\n', 1),
                         'PREPARE_BLOCKED: output already exists')
        self.assertEqual(system_setup.last_error('Traceback (most recent call last):\nKeyError: 1\n', 1), 'KeyError: 1')
        self.assertEqual(system_setup.last_error('', 2), 'exit status 2')

    def test_system_routes_setup_and_reconcile_takes_select_default_only_with_a_kernel(self):
        usage = io.StringIO()
        with redirect_stdout(usage):
            self.assertEqual(cli.main(['system', '--help']), 0)
        self.assertIn('  setup ', usage.getvalue())
        with patch('nvidia_vbios.system_setup.main', return_value=0) as setup:
            self.assertEqual(cli.main(['system', 'setup', '--progress']), 0)
        setup.assert_called_once_with(['--progress'])
        from nvidia_vbios.lifecycle import __main__ as lifecycle
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as exit:
            lifecycle.main(['reconcile', '--select-default'])
        self.assertEqual(exit.exception.code, 2)
        calls = []
        worker = SimpleNamespace(ops=SimpleNamespace(), reconcile=lambda kernel, **options: calls.append((kernel, options)) or {})
        with patch.object(lifecycle, 'Reconciler', return_value=worker), patch.object(lifecycle, 'installed_kernels', return_value=[OLD]), \
                redirect_stdout(io.StringIO()):
            self.assertEqual(lifecycle.main(['reconcile', '--kernel', OLD, '--select-default', '--dry-run']), 0)
            self.assertEqual(lifecycle.main(['reconcile', '--dry-run']), 0)
        self.assertEqual(calls, [(OLD, {'dry_run': True, 'select_default': True}), (OLD, {'dry_run': True, 'select_default': False})])


class SetupWithLifecycleTests(unittest.TestCase):
    """The real install, enroll, reconcile, enable and disable code on a synthetic root, behind setup."""
    def setUp(self):
        self.fixture = test_bootstrap.BootstrapTests('test_alternate_root_requires_operations')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.addCleanup(signal.signal, signal.SIGHUP, signal.getsignal(signal.SIGHUP))
        fixture = self.fixture
        self.gpus = {device['bdf']: device for device in (fixture.device(0), fixture.device(1))}
        fixture.ops.inventory = lambda: {bdf: {key: device[key] for key in ('bdf', 'uuid', 'vendor', 'device')}
                                         for bdf, device in self.gpus.items()}
        self.calls = []

    def child(self, argv, poll=None):
        fixture, options = self.fixture, argv[3:]
        value = lambda flag: options[options.index(flag) + 1]
        self.calls.append(argv[2])
        try:
            result = {'prepare': lambda: write_profile(options, self.gpus, fixture.normal),
                      'disable': fixture.worker.disable,
                      'install': lambda: fixture.worker.install(Path(value('--repository'))),
                      'enroll': lambda: fixture.worker.enroll(Path(value('--profile'))),
                      'reconcile': lambda: Reconciler(fixture.root, fixture.ops).reconcile(
                          value('--kernel'), select_default='--select-default' in options),
                      'enable': lambda: fixture.worker.enable(value('--kernel'))}[argv[2]]()
        except LifecycleError as exc:
            return 1, '', f'BOOTSTRAP_BLOCKED: {exc}\n'
        return 0, json.dumps(result), ''

    def setup(self, *argv):
        self.calls.clear()
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = system_setup.main(['--progress', '--kernel', OLD, '--userspace', 'rpm', *argv], root=self.fixture.root,
                                     operations=self.fixture.ops, euid=0, run=self.child, launcher=LAUNCHER, cpu_count=lambda: 24)
        self.stderr = error.getvalue()
        return code, [json.loads(line) for line in output.getvalue().splitlines()]

    def file(self, bdf):
        device = self.gpus[bdf]
        return ['--device', bdf, device['payload'], device['sha256']]

    def first_load(self):
        fixture = self.fixture
        code, events = self.setup('--repository', str(fixture.repository), *self.file(BDF0),
                                  '--driver-source', str(fixture.source), '--p2p-preferred')
        self.assertEqual(code, 0, self.stderr)
        self.assertEqual((events[-1]['default'], fixture.ops.environment['saved_entry']), ('ready', events[-1]['entry']))
        fixture.worker.update_parameters(lambda current: {'NVreg_RegistryDwords': 'RmTestOption=1'})
        return events[-1]

    def test_loads_on_the_same_kernel_rebuild_or_reuse_and_keep_the_policy(self):
        fixture = self.fixture
        first = self.first_load()
        code, events = self.setup('--keep', BDF0, *self.file(BDF1), '--keep-source')
        self.assertEqual(code, 0, self.stderr)
        self.assertEqual(self.calls, ['prepare', 'disable', 'enroll', 'reconcile', 'enable'])
        second = events[-1]
        self.assertNotEqual(second['entry'], first['entry'])
        self.assertEqual((fixture.ops.environment['saved_entry'], fixture.ops.enabled), (second['entry'], True))
        config = json.loads((fixture.root / CONFIG.lstrip('/')).read_text())
        self.assertEqual([device['bdf'] for device in config['devices']], [BDF0, BDF1])
        self.assertEqual((config['parameters'], config['require_p2p_source'], config['jobs']),
                         ({'NVreg_RegistryDwords': 'RmTestOption=1'}, True, 8))
        # Remove, then Load the same payloads again: the build is reused and enable selects it.
        fixture.worker.disable()
        builds = fixture.ops.builds
        code, events = self.setup('--keep', BDF1, '--keep', BDF0, '--keep-source')
        self.assertEqual(code, 0, self.stderr)
        self.assertEqual((events[-1]['entry'], events[-1]['default'], fixture.ops.builds), (second['entry'], 'selected', builds))
        self.assertEqual(fixture.ops.environment['saved_entry'], second['entry'])

    def test_failed_build_or_enable_leaves_the_normal_entry_without_rebuilds(self):
        fixture = self.fixture
        self.first_load()
        for step in ('reconcile', 'enable'):
            fixture.ops.fault = 'build' if step == 'reconcile' else None
            fixture.ops.fail_triggers = step == 'enable'
            code, events = self.setup('--keep', BDF0, *self.file(BDF1), '--keep-source')
            with self.subTest(step=step):
                self.assertEqual((code, events[-1]['event'], events[-1]['step']), (1, 'failed', step))
                self.assertEqual(events[-1]['cleanup']['ok'], True if step == 'enable' else None)
                self.assertEqual((fixture.ops.environment['saved_entry'], fixture.ops.enabled), (fixture.normal, False))


if __name__ == '__main__':
    unittest.main()
