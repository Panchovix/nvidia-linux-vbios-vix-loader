"""`nvbios system uninstall` on synthetic roots with injected operations: no host command, boot change or GPU query."""
import contextlib
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, call, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tests'))
import test_bootstrap as bootstrap_fixtures
import test_bootstrap_portable as portable_fixtures
from test_bootstrap import Operations, OLD, VERSION
from test_bootstrap_portable import PortableBootstrapOperations
from test_lifecycle_portable import pe_image
from nvidia_vbios import cli
from nvidia_vbios.bootstrap import (ACTION_TARGETS, Bootstrap, BootstrapError, BootstrapOperations, CONFIG, ENABLED,
                                    RUNTIME, STATE, UNITS)
from nvidia_vbios.lifecycle.boot import BootAdapter
from nvidia_vbios.lifecycle.platform import ARCH_PLATFORM, DEBIAN_PLATFORM
from nvidia_vbios.lifecycle.portable import EFI_GUID
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write, digest
from nvidia_vbios.lifecycle.system import COMMANDS, SystemOperations
from nvidia_vbios.uninstall import FOREIGN, Uninstall

NEW = '6.19.10-200.fc44.x86_64'
LOCKS = {'run/akmods/akmods.lock', 'usr/lib/sysimage/rpm/.rpm.lock'}  # coordination locks stay, as after reconcile


class Removal:
    """What uninstall adds to the bootstrap fakes; depmod and the module selection follow the synthetic files."""
    def __init__(self, *args):
        super().__init__(*args)
        self.regenerated, self.normal_images = [], None

    def retire_triggers(self):
        self.events.append('retire-triggers')
        self.enabled = False

    def daemon_reload(self):
        self.events.append('daemon-reload')

    def depmod(self, kernel):
        self.events.append('depmod:' + kernel)

    def selected_module(self, kernel, name):
        # `modinfo -k KERNEL -F filename NAME`: the loader's build (updates/) first, then the stock one, else an error.
        for leaf in ('updates/vbios-override', 'extra'):
            path = self.root / f'usr/lib/modules/{kernel}/{leaf}/{name}.ko'
            if path.is_file() and not (leaf == 'extra' and self.fault == 'stock'):
                return str(path)
        raise LifecycleError(f'modinfo: ERROR: Module {name} not found.')

    def regenerate_initramfs(self, kernel, raw, image=None):
        # The builder writes `image` (dracut), else its own images: one per kernel, every preset with mkinitcpio -P.
        self.events.append('regenerate:' + kernel)
        self.regenerated.append((kernel, raw.get('boot', {}).get('initramfs', 'dracut'), image))
        if self.fault == 'regenerate':
            raise LifecycleError('dracut failed')
        for name in [image] if image else self.normal_images or [f'/boot/initramfs-{kernel}.img']:
            atomic_write(self.root / name.lstrip('/'), b'REBUILT NORMAL IMAGE')


class UninstallOperations(Removal, Operations):
    pass


class PortableUninstallOperations(Removal, PortableBootstrapOperations):
    pass


def directories(root, *names):
    for name in names:  # 0755 whatever the umask: trusted like a distribution's directory
        (root / name).mkdir(mode=0o755)


class FedoraUninstallTests(unittest.TestCase):
    def setUp(self):
        self.fixture = bootstrap_fixtures.BootstrapTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.ops = self.fixture.ops = UninstallOperations(self.root, self.fixture.profile)
        self.worker = self.fixture.worker = Bootstrap(self.root, self.ops)
        directories(self.root, f'usr/lib/modules/{OLD}/kernel')  # an installed kernel package

    def stock(self, kernel=OLD):
        """The distribution's (akmods, DKMS) nvidia.ko of `kernel`."""
        atomic_write(self.root / f'usr/lib/modules/{kernel}/extra/nvidia.ko', json.dumps({'version': VERSION}).encode())

    def full(self):
        self.worker.install(self.fixture.repository)
        self.fixture.enroll()
        ready = self.fixture.ready()
        self.worker.enable(OLD)
        self.assertTrue(self.ops.enabled)
        return ready

    def uninstall(self, **options):
        return Uninstall(self.root, self.ops).uninstall(**options)

    def since(self, event):
        return self.ops.events[self.ops.events.index(event):]

    def embed_override(self):
        image = self.root / f'boot/initramfs-{OLD}.img'
        image.write_text(json.dumps({f'usr/lib/modules/{OLD}/updates/vbios-override/nvidia.ko': ''}))
        return image

    def test_removes_every_trace_and_boots_the_normal_entry(self):
        self.stock()
        before = self.fixture.snapshot()
        self.full()
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual({name: data for name, data in self.fixture.snapshot().items() if name not in LOCKS}, before)
        for name in ('var/lib/nvidia-vbios', 'etc/nvidia-vbios', 'usr/local/lib/nvidia-vbios-tools', 'usr/lib/firmware/nvidia',
                     f'usr/lib/modules/{OLD}/updates/vbios-override'):
            self.assertFalse((self.root / name).exists(), name)
        self.assertFalse(list((self.root / 'boot').rglob('*vbios*')))
        self.assertEqual((self.ops.environment['saved_entry'], self.ops.enabled), (f'normal-{OLD}', False))
        self.assertEqual(self.since('retire-triggers'), ['retire-triggers', 'daemon-reload', f'default:normal-{OLD}', f'depmod:{OLD}'])
        self.assertIn(ACTION_TARGETS['dnf5'], report['removed']['automation'])
        self.assertEqual((report['kernels'][OLD]['nvidia_module'], report['kernels'][OLD]['nvidia_module_version']),
                         (f'/usr/lib/modules/{OLD}/extra/nvidia.ko', VERSION))
        self.assertTrue(report['next_steps'][-1].startswith('reboot'))

    def test_dry_run_changes_nothing_and_reports_the_plan(self):
        self.stock()
        ready = self.full()
        before, events = self.fixture.snapshot(), list(self.ops.events)
        report = self.uninstall(dry_run=True)
        self.assertEqual((report['state'], report['dry_run']), ('planned', True))
        self.assertEqual((self.fixture.snapshot(), self.ops.events), (before, events))
        remove = report['remove']
        self.assertIn(f'/boot/loader/entries/{ready["entry"]}.conf', remove['boot'])
        self.assertTrue(any(name.startswith(f'/boot/initramfs-{OLD}-vbios-') for name in remove['boot']))
        self.assertEqual(remove['modules'], [f'/usr/lib/modules/{OLD}/updates/vbios-override'])
        self.assertEqual(remove['firmware'], [f'/usr/lib/firmware/nvidia/{VERSION}/vbios-override'])
        self.assertEqual(remove['runtime'], ['/usr/local/bin/nvbios', '/usr/local/bin/nvbios-editor', '/usr/libexec/nvidia-vbios', RUNTIME])
        self.assertIn(CONFIG, remove['state'])
        self.assertEqual(report['default']['grub'], {'from': ready['entry'], 'to': f'normal-{OLD}', 'state': 'planned'})
        self.assertEqual(report['kernels'][OLD]['nvidia_module'], f'/usr/lib/modules/{OLD}/extra/nvidia.ko')

    def test_kernel_with_only_the_loader_modules_blocks_unless_allowed(self):
        self.full()
        before, events = self.fixture.snapshot(), list(self.ops.events)
        report = self.uninstall()
        self.assertEqual(report['state'], 'blocked')
        self.assertIn(OLD, report['blocked'][0])
        # DKMS installs over the loader's module only with --force; after the removal autoinstall is enough.
        for text in ('--allow-missing-module', f'dkms install --force NAME/VERSION -k {OLD}'):
            self.assertIn(text, report['blocked'][0])
        self.assertEqual((self.fixture.snapshot(), self.ops.events, self.ops.enabled), (before, events, True))
        report = self.uninstall(allow_missing_module=True)
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual(report['kernels'][OLD]['nvidia_module'], 'missing')
        self.assertTrue(any(step.startswith(f'{OLD} has no NVIDIA kernel module') and f'dkms autoinstall -k {OLD}' in step
                            for step in report['next_steps']), report['next_steps'])

    def test_default_is_the_booted_kernel_unless_only_another_keeps_an_nvidia_module(self):
        self.stock()
        self.full()
        atomic_write(self.root / f'boot/vmlinuz-{NEW}', b'KERNEL NEW')
        atomic_write(self.root / f'boot/initramfs-{NEW}.img', b'NORMAL IMAGE NEW')
        atomic_write(self.root / f'boot/loader/entries/normal-{NEW}.conf',
                     f'title Fedora\nversion {NEW}\nlinux /vmlinuz-{NEW}\ninitrd /initramfs-{NEW}.img $tuned_initrd\n'
                     f'options root=UUID=synthetic $tuned_params\n'.encode())
        directories(self.root, f'usr/lib/modules/{NEW}', f'usr/lib/modules/{NEW}/kernel')
        self.stock(NEW)
        self.assertEqual(self.uninstall(dry_run=True)['default']['grub']['to'], f'normal-{OLD}')  # not the newest kernel
        (self.root / f'usr/lib/modules/{OLD}/extra/nvidia.ko').unlink()
        report = self.uninstall(allow_missing_module=True)
        self.assertEqual((report['state'], report['default']['grub']['to']), ('uninstalled', f'normal-{NEW}'), report)
        self.assertEqual(self.ops.environment['saved_entry'], f'normal-{NEW}')

    def test_normal_initramfs_embedding_the_loader_module_is_rebuilt_after_depmod(self):
        self.stock()
        self.full()
        image = self.embed_override()
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        events = self.since('retire-triggers')
        self.assertLess(events.index(f'depmod:{OLD}'), events.index(f'regenerate:{OLD}'))
        self.assertEqual((image.read_bytes(), self.ops.regenerated), (b'REBUILT NORMAL IMAGE', [(OLD, 'dracut', None)]))
        self.assertEqual((report['kernels'][OLD]['rebuild'], report['kernels'][OLD]['normal_initramfs']),
                         (f'dracut -f --kver {OLD}', 'without-override'))

    def test_failed_rebuild_is_incomplete_and_a_second_run_finishes(self):
        self.stock()
        self.full()
        self.embed_override()
        self.ops.fault = 'regenerate'
        report = self.uninstall()
        self.assertEqual(report['state'], 'incomplete')
        self.assertTrue(any(f'normal initramfs of {OLD}' in problem for problem in report['problems']), report['problems'])
        for name in (ACTION_TARGETS['dnf5'], '/usr/lib/kernel/install.d/99-nvidia-vbios.install', ENABLED,
                     '/usr/lib/systemd/system/nvidia-vbios-reconcile.path', f'/usr/lib/modules/{OLD}/updates/vbios-override'):
            self.assertFalse(self.worker.path(name).exists(), name)
        self.assertEqual(self.ops.environment['saved_entry'], f'normal-{OLD}')
        for name in (CONFIG, STATE + '/fleet.json', '/usr/local/bin/nvbios', RUNTIME):  # what the second run needs
            self.assertTrue(self.worker.path(name).exists(), name)
        self.ops.fault = None
        events = len(self.ops.events)
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual(self.ops.events[events:], [f'regenerate:{OLD}'])
        self.assertFalse(self.worker.path(RUNTIME).exists())

    def test_second_run_finds_nothing_and_creates_nothing(self):
        self.stock()
        self.full()
        self.assertEqual(self.uninstall()['state'], 'uninstalled')
        paths, events = sorted(self.root.rglob('*')), list(self.ops.events)
        report = self.uninstall()
        self.assertEqual(report['state'], 'not-installed', report)
        self.assertEqual((sorted(self.root.rglob('*')), self.ops.events), (paths, events))

    def test_partial_or_masked_units_and_enable_links_go_by_name(self):
        self.stock()
        self.full()
        (self.root / 'usr/lib/systemd/system/nvidia-vbios-reconcile.timer').unlink()  # removed by hand
        etc = self.root / 'etc/systemd/system'
        directories(self.root, 'etc/systemd', 'etc/systemd/system', 'etc/systemd/system/multi-user.target.wants',
                    'etc/systemd/system/timers.target.wants')
        for link in ('multi-user.target.wants/nvidia-vbios-reconcile.path', 'timers.target.wants/nvidia-vbios-reconcile.timer',
                     'multi-user.target.wants/other.service'):
            (etc / link).symlink_to('/usr/lib/systemd/system/' + Path(link).name)
        (etc / 'nvidia-vbios-reconcile.service').symlink_to('/dev/null')  # masked to stop a rebuild loop
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual([path.name for path in etc.rglob('*') if path.is_symlink()], ['other.service'])
        self.assertIn('/etc/systemd/system/nvidia-vbios-reconcile.service', report['removed']['automation'])

    def test_foreign_and_one_time_boot_choices_are_kept(self):
        self.stock()
        self.full()
        choices = {'saved_entry': 'another-os', 'next_entry': 'one-time-os'}
        self.ops.environment = dict(choices)
        events = len(self.ops.events)
        report = self.uninstall()
        self.assertEqual((report['state'], report['default']['grub']), ('uninstalled', {'from': 'another-os', 'state': 'kept'}))
        self.assertEqual(self.ops.environment, choices)
        self.assertFalse([event for event in self.ops.events[events:] if event.startswith('default:')])

    def test_unresolvable_normal_entry_falls_back_to_the_first_grub_entry(self):
        self.stock()
        ready = self.full()
        (self.root / f'boot/loader/entries/normal-{OLD}.conf').unlink()
        report = self.uninstall()
        self.assertEqual(report['default']['grub'], {'from': ready['entry'], 'to': '0', 'state': 'selected'})
        self.assertEqual(self.ops.environment['saved_entry'], '0')

    def test_edited_hooks_go_while_replaced_hooks_and_unknown_files_stay(self):
        self.stock()
        self.full()
        action = self.worker.path(ACTION_TARGETS['dnf5'])
        action.write_text('# disabled by hand after a failed transaction\n# ' + action.read_text())  # still names the runner
        hook = self.worker.path('/usr/lib/kernel/install.d/99-nvidia-vbios.install')
        hook.write_text('#!/bin/sh\nexit 0\n')  # replaced: no loader marker
        atomic_write(self.worker.path('/var/lib/nvidia-vbios/boot-archive/old.img'), b'KEPT BY HAND')
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertFalse(action.exists())
        self.assertEqual(hook.read_text(), '#!/bin/sh\nexit 0\n')
        kept = {item['path'] for item in report['kept']}
        self.assertTrue({'/usr/lib/kernel/install.d/99-nvidia-vbios.install', '/var/lib/nvidia-vbios/boot-archive'} <= kept, kept)
        self.assertEqual([path.name for path in self.worker.path('/var/lib/nvidia-vbios').iterdir()], ['boot-archive'])

    def test_signing_keys_in_loader_directories_stay(self):
        self.stock()
        key, certificate = '/etc/nvidia-vbios/MOK.priv', '/var/lib/nvidia-vbios/roms/MOK.der'
        for name in (key, certificate):
            atomic_write(self.worker.path(name), b'USER KEY ' + name.encode())
        self.fixture.profile['signing'] = {'key': key, 'certificate': certificate}
        self.full()
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        for name in (key, certificate):
            self.assertEqual(self.worker.path(name).read_bytes(), b'USER KEY ' + name.encode())
        self.assertFalse(self.worker.path(CONFIG).exists())
        kept = {item['path'] for item in report['kept']}
        self.assertTrue({key, '/var/lib/nvidia-vbios/roms'} <= kept, kept)
        self.assertEqual([path.name for path in self.worker.path('/var/lib/nvidia-vbios').iterdir()], ['roms'])

    def test_active_service_or_busy_locks_refuse_without_changes(self):
        self.stock()
        self.full()
        before, events = self.fixture.snapshot(), list(self.ops.events)
        self.ops.service_active = True
        with self.assertRaisesRegex(BootstrapError, 'the reconcile service is running: wait until it ends'):
            self.uninstall()
        self.ops.service_active = False
        with self.worker.path(STATE + '/reconcile.lock').open('ab') as held:
            fcntl.flock(held.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(BootstrapError, 'lock busy'):
                self.uninstall()
        # RPM holds a record lock; another process must own it to conflict.
        child = subprocess.Popen([sys.executable, '-c', 'import fcntl,sys; f=open(sys.argv[1],"a"); fcntl.lockf(f,fcntl.LOCK_EX); '
                                  'print("locked",flush=True); sys.stdin.read()', str(self.worker.path('/usr/lib/sysimage/rpm/.rpm.lock'))],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'locked')
            with self.assertRaisesRegex(BootstrapError, 'lock busy'):
                self.uninstall()
        finally:
            child.communicate(timeout=10)
        self.assertEqual((self.fixture.snapshot(), self.ops.events), (before, events))

    def test_leftovers_go_by_name_and_boot_files_by_record(self):
        self.stock()
        self.full()
        removed = '6.1.0-removed'
        retained, unrecorded = f'vbios-{removed}-{"b" * 20}', f'vbios-{removed}-{"c" * 20}'
        boot = lambda identity: [f'boot/initramfs-{removed}-vbios-{identity[-20:]}.img', f'boot/loader/entries/{identity}.conf']
        leftovers = [f'usr/lib/modules/.vbios-parked-{OLD}-1/nvidia.ko', f'usr/lib/modules/.vbios-modules-{OLD}-2/nvidia.ko',
                     f'usr/lib/modules/{removed}/updates/vbios-override/nvidia.ko',
                     f'usr/lib/firmware/nvidia/600.10.00/vbios-override/0000:03:00.0-{"a" * 16}.bin',
                     'boot/.vbios-initramfs-x.img', *boot(retained)]
        for name in leftovers + boot(unrecorded):
            atomic_write(self.root / name, b'LEFTOVER')
        history = self.root / STATE.lstrip('/') / 'boot-history.json'  # a generation retention keeps
        value = json.loads(history.read_bytes())
        value['generations'][retained] = {'kernel': removed, 'created_ns': 1, 'state': 'active',
                                          'files': {'/' + name: digest(b'LEFTOVER') for name in boot(retained)}}
        atomic_write(history, json.dumps(value).encode())
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        for name in (*leftovers, f'usr/lib/modules/{removed}', 'usr/lib/firmware/nvidia'):
            self.assertFalse((self.root / name).exists(), name)
        # A BLS entry has no machine-id: without a record it can be another system's on a shared /boot.
        for name in boot(unrecorded):
            self.assertEqual((self.root / name).read_bytes(), b'LEFTOVER')
            self.assertIn({'path': '/' + name, 'reason': FOREIGN}, report['kept'])
        self.assertEqual([event for event in self.since('retire-triggers') if event.startswith('depmod:')], [f'depmod:{OLD}'])

    def test_depmod_check_puts_the_modules_back_when_no_other_module_is_selected(self):
        self.stock()
        self.full()
        live = self.root / f'usr/lib/modules/{OLD}/updates/vbios-override'
        modules = {path.name: path.read_bytes() for path in live.iterdir()}
        self.ops.fault = 'stock'  # the file is there, but depmod and modinfo cannot use it
        report = self.uninstall()
        self.assertEqual(report['state'], 'incomplete')
        self.assertEqual({path.name: path.read_bytes() for path in live.iterdir()}, modules)
        self.assertFalse(list((self.root / 'usr/lib/modules').glob('.vbios-*')))
        self.assertEqual([event for event in self.since('retire-triggers') if event.startswith('depmod:')], [f'depmod:{OLD}'] * 2)
        for name in (CONFIG, RUNTIME, '/usr/local/bin/nvbios'):
            self.assertTrue(self.worker.path(name).exists(), name)
        self.assertEqual(self.uninstall(allow_missing_module=True)['state'], 'uninstalled')
        self.assertFalse(live.exists())

    def test_a_run_stopped_after_parking_the_modules_finishes(self):
        self.stock()
        self.full()
        parked = self.root / f'usr/lib/modules/.vbios-uninstall-{OLD}-1'
        os.rename(self.root / f'usr/lib/modules/{OLD}/updates/vbios-override', parked)
        self.assertEqual(self.uninstall(dry_run=True)['kernels'][OLD]['loader_modules'], ['/' + str(parked.relative_to(self.root))])
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertFalse(parked.exists())
        self.assertIn(f'depmod:{OLD}', self.since('retire-triggers'))


class PortableUninstallTests(unittest.TestCase):
    def setUp(self):
        self.case = portable_fixtures.PortableBootstrapTests(methodName='runTest')
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root

    def setup(self, platform, backend):
        self.case.setup_platform(platform, backend)
        self.ops = self.case.ops = PortableUninstallOperations(self.root, self.case.profile, platform)
        self.case.worker = Bootstrap(self.root, self.ops)
        directories(self.root, f'usr/lib/modules/{OLD}/kernel')
        atomic_write(self.root / f'usr/lib/modules/{OLD}/extra/nvidia.ko', json.dumps({'version': VERSION}).encode())

    def uninstall(self, **options):
        return Uninstall(self.root, self.ops).uninstall(**options)

    def efi(self, entry=None):
        path = self.root / f'sys/firmware/efi/efivars/LoaderEntryDefault-{EFI_GUID}'
        if entry is not None:
            atomic_write(path, b'\x07\x00\x00\x00' + (entry + '\0').encode('utf-16-le'))
        return path

    def bootctl(self):
        def command(arguments, **kwargs):
            if arguments != ['bootctl', '--esp-path=/efi', 'set-default', '']:
                raise AssertionError('unexpected system operation: ' + repr(arguments))
            self.efi().unlink()
            return subprocess.CompletedProcess(arguments, 0, stdout=b'', stderr=b'')
        self.ops._run = MagicMock(side_effect=command)

    def generated(self):
        """What grub-mkconfig puts in grub.cfg for the loader's 41_nvidia_vbios: the output of running it."""
        hook = BootAdapter(self.root, {'boot': self.case.profile['boot']}).visibility_files()['/etc/grub.d/41_nvidia_vbios']
        return (b'### BEGIN /etc/grub.d/41_nvidia_vbios ###\n' + subprocess.run(['sh'], input=hook, capture_output=True, check=True).stdout
                + b'### END /etc/grub.d/41_nvidia_vbios ###\n')

    def embed(self, image, kernel=OLD):
        """A normal image whose initrd early-loads the loader's module (the portable fakes list its JSON keys)."""
        atomic_write(self.root / image.lstrip('/'), json.dumps({f'usr/lib/modules/{kernel}/updates/vbios-override/nvidia.ko': ''}).encode())

    def profile(self, change):
        path = self.root / CONFIG.lstrip('/')
        raw = json.loads(path.read_bytes())
        change(raw['boot'])
        atomic_write(path, json.dumps(raw).encode())

    def kernel(self, kernel, boot):
        """Another installed kernel with its distribution module, kernel and normal image under `boot`."""
        directories(self.root, f'usr/lib/modules/{kernel}', f'usr/lib/modules/{kernel}/kernel')
        atomic_write(self.root / f'usr/lib/modules/{kernel}/extra/nvidia.ko', json.dumps({'version': VERSION}).encode())
        atomic_write(self.root / f'{boot}/vmlinuz-{kernel}', b'KERNEL ' + kernel.encode())
        atomic_write(self.root / f'{boot}/initramfs-{kernel}.img', b'NORMAL IMAGE ' + kernel.encode())

    def test_debian_generated_grub_menu_stays_and_everything_else_goes(self):
        self.setup(DEBIAN_PLATFORM, 'grub')
        menu = self.root / 'boot/grub/grub.cfg'
        menu.write_bytes(menu.read_bytes().replace(b'source $prefix/nvidia-vbios.cfg\n', self.generated()))
        self.case.fresh_flow()
        text = menu.read_bytes()
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        for name in ('etc/apt/apt.conf.d/99-nvidia-vbios', 'etc/kernel/postinst.d/zz-nvidia-vbios', 'etc/kernel/postrm.d/zz-nvidia-vbios',
                     'usr/lib/kernel/install.d/99-nvidia-vbios.install', 'usr/lib/systemd/system/nvidia-vbios-reconcile.service',
                     'boot/nvidia-vbios', 'boot/grub/nvidia-vbios-entries', 'boot/grub/nvidia-vbios.cfg', 'etc/grub.d/41_nvidia_vbios',
                     f'usr/lib/modules/{OLD}/updates/vbios-override', 'usr/lib/firmware/nvidia', 'var/lib/nvidia-vbios'):
            self.assertFalse((self.root / name).exists(), name)
        self.assertEqual(self.ops.environment['saved_entry'], 'debian-normal')
        self.assertEqual(menu.read_bytes(), text)  # its leftover block is inert; update-grub drops it
        self.assertTrue(any('update-grub' in step for step in report['next_steps']), report['next_steps'])
        self.assertTrue((self.root / 'var/lib/dpkg/lock-frontend').exists() and (self.root / 'var/lib/dpkg/lock').exists())

    def test_debian_hand_written_grub_menu_keeps_an_empty_include(self):
        self.setup(DEBIAN_PLATFORM, 'grub')
        self.case.fresh_flow()
        menu = self.root / 'boot/grub/grub.cfg'
        text = menu.read_bytes()
        apt = self.root / 'etc/apt/apt.conf.d/99-nvidia-vbios'
        apt.write_text('\n'.join('// ' + line for line in apt.read_text().splitlines()) + '\n')  # commented out after an apt error
        hook = self.root / 'etc/kernel/postinst.d/zz-nvidia-vbios'
        hook.write_text('#!/bin/sh\nexit 0\n')
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual(menu.read_bytes(), text)
        self.assertEqual((self.root / 'boot/grub/nvidia-vbios.cfg').read_bytes(), b'# Managed by nvidia-vbios lifecycle.\n')
        for name in ('etc/grub.d/41_nvidia_vbios', 'boot/grub/nvidia-vbios-entries', 'boot/nvidia-vbios', 'etc/apt/apt.conf.d/99-nvidia-vbios'):
            self.assertFalse((self.root / name).exists(), name)
        self.assertEqual(hook.read_text(), '#!/bin/sh\nexit 0\n')
        self.assertTrue(any('source $prefix/nvidia-vbios.cfg' in step for step in report['next_steps']), report['next_steps'])
        self.assertEqual(self.uninstall()['state'], 'not-installed')

    def test_arch_systemd_boot_clears_its_efi_default_and_keeps_the_normal_entry(self):
        self.setup(ARCH_PLATFORM, 'systemd-boot')
        ready = self.case.fresh_flow()
        atomic_write(self.root / 'efi/loader/loader.conf', b'timeout 3\n')
        normal = {name: (self.root / name).read_bytes() for name in ('efi/loader/entries/cachyos-normal.conf', 'efi/loader/loader.conf')}
        self.efi(ready['entry'])
        self.bootctl()
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual(report['default']['efi'], {'from': ready['entry'], 'to': '', 'state': 'cleared'})
        self.assertFalse(self.efi().exists())
        self.assertEqual({name: (self.root / name).read_bytes() for name in normal}, normal)
        for name in ('efi/nvidia-vbios', 'etc/pacman.d/hooks/99-nvidia-vbios.hook', 'var/lib/pacman/db.lck'):
            self.assertFalse((self.root / name).exists(), name)
        self.assertFalse(list((self.root / 'efi/loader/entries').glob('vbios-*')))

    def test_without_a_profile_the_recorded_generations_still_go(self):
        self.setup(ARCH_PLATFORM, 'systemd-boot')
        ready = self.case.fresh_flow()
        (self.root / CONFIG.lstrip('/')).unlink()  # an enrollment rollback, or a run that stopped while deleting state
        self.efi(ready['entry'])
        self.bootctl()
        report = self.uninstall()
        self.assertEqual((report['state'], report['boot_backend']), ('uninstalled', 'systemd-boot'), report)
        self.assertFalse(self.efi().exists())
        self.assertFalse((self.root / 'efi/nvidia-vbios').exists())
        self.assertFalse(list((self.root / 'efi/loader/entries').glob('vbios-*')))

    def test_install_only_needs_no_boot_selection(self):
        self.setup(ARCH_PLATFORM, 'systemd-boot')
        self.case.worker.install(self.case.fixture.repository)
        self.ops.grub_environment = MagicMock(side_effect=AssertionError('no GRUB on this system'))
        report = self.uninstall()
        self.assertEqual((report['state'], report['boot_backend'], report['default']), ('uninstalled', None, {}), report)
        for name in ('usr/lib/kernel/install.d/99-nvidia-vbios.install', 'usr/lib/systemd/system/nvidia-vbios-reconcile.service',
                     'usr/local/bin/nvbios', 'var/lib/nvidia-vbios', 'usr/local/lib/nvidia-vbios-tools'):
            self.assertFalse((self.root / name).exists(), name)

    def test_arch_uki_goes_and_user_keys_stay(self):
        self.setup(ARCH_PLATFORM, 'uki')
        keys = {f'secure/{name}': f'USER KEY {name}'.encode() for name in ('module.key', 'module.der', 'efi.key', 'efi.pem')}
        for name, data in keys.items():
            atomic_write(self.root / name, data)
        self.case.profile['signing'] = {'key': '/secure/module.key', 'certificate': '/secure/module.der'}
        self.case.profile['boot']['uki'] = {'signing': {'key': '/secure/efi.key', 'certificate': '/secure/efi.pem', 'trust': 'firmware-db'}}
        self.case.fresh_flow()
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertFalse(list((self.root / 'efi/EFI/Linux').glob('vbios-*')))
        self.assertFalse((self.root / 'efi/nvidia-vbios').exists())
        self.assertEqual({name: (self.root / name).read_bytes() for name in keys}, keys)

    def test_an_unmounted_esp_blocks_before_any_change(self):
        self.setup(ARCH_PLATFORM, 'systemd-boot')
        self.case.fresh_flow()
        os.rename(self.root / 'efi', self.root / 'esp-elsewhere')
        directories(self.root, 'efi')
        before, events = self.case.fixture.snapshot(), list(self.ops.events)
        report = self.uninstall()
        self.assertEqual(report['state'], 'blocked')
        self.assertTrue(any(message.startswith('/efi looks unmounted') for message in report['blocked']), report['blocked'])
        self.assertEqual((self.case.fixture.snapshot(), self.ops.events), (before, events))

    def test_a_recorded_entry_the_names_cannot_reach_keeps_the_run_incomplete(self):
        self.setup(ARCH_PLATFORM, 'systemd-boot')
        ready = self.case.fresh_flow()
        entries = self.root / 'efi/loader/entries'
        entries.chmod(0o777)  # untrusted now: discovery skips it, the fleet still names the entry
        report = self.uninstall()
        self.assertEqual(report['state'], 'incomplete')
        self.assertTrue(any(problem.startswith('files the loader recorded remain: ') and ready['entry'] in problem
                            for problem in report['problems']), report['problems'])
        self.assertTrue((entries / ready['entry']).exists())
        self.assertTrue((self.root / CONFIG.lstrip('/')).exists())
        entries.chmod(0o755)
        self.assertEqual(self.uninstall()['state'], 'uninstalled')
        self.assertFalse((entries / ready['entry']).exists())

    def test_foreign_pacman_lock_refuses_and_stays(self):
        self.setup(ARCH_PLATFORM, 'systemd-boot')
        self.case.fresh_flow()
        lock = self.root / 'var/lib/pacman/db.lck'
        lock.write_text('pacman is running\n')
        before = self.case.fixture.snapshot()
        with self.assertRaisesRegex(BootstrapError, 'lock busy'):
            self.uninstall()
        self.assertEqual(self.case.fixture.snapshot(), before)

    def test_another_systems_loader_files_on_a_shared_efi_partition_stay(self):
        self.setup(ARCH_PLATFORM, 'systemd-boot')
        ready = self.case.fresh_flow()
        machine = '0123456789abcdef0123456789abcdef'
        atomic_write(self.root / 'etc/machine-id', machine.encode() + b'\n')
        other, mine = f'vbios-6.6.1-lts-{"f" * 20}', f'vbios-{OLD}-{"e" * 20}'  # mine: of this system, but unrecorded
        for identity, owner in ((other, 'fedcba9876543210fedcba9876543210'), (mine, machine)):
            atomic_write(self.root / f'efi/loader/entries/{identity}.conf', f'title Override\nmachine-id {owner}\n'.encode())
            atomic_write(self.root / f'efi/nvidia-vbios/{identity}/vmlinuz', b'KERNEL COPY')
        self.efi(other + '.conf')  # the firmware default is the other system's override: no bootctl call
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual([path.name for path in (self.root / 'efi/nvidia-vbios').iterdir()], [other])
        self.assertEqual([path.name for path in (self.root / 'efi/loader/entries').glob('vbios-*')], [other + '.conf'])
        self.assertEqual((self.efi().exists(), report['default']), (True, {}))
        kept = [item['path'] for item in report['kept'] if item['reason'] == FOREIGN]
        self.assertEqual(kept, [f'/efi/loader/entries/{other}.conf', f'/efi/nvidia-vbios/{other}'])
        self.assertTrue(any(step.endswith(', '.join(kept)) for step in report['next_steps']), report['next_steps'])
        self.assertIn(f'/efi/loader/entries/{ready["entry"]}', report['removed']['boot'])

    def test_an_unmounted_esp_at_the_default_boot_root_blocks(self):
        self.setup(ARCH_PLATFORM, 'systemd-boot')
        self.case.fresh_flow()
        self.profile(lambda boot: [boot.pop(key) for key in ('boot_root', 'esp')])  # prepared without --esp: /boot
        os.rename(self.root / 'boot', self.root / 'boot-elsewhere')
        directories(self.root, 'boot')
        before, events = self.case.fixture.snapshot(), list(self.ops.events)
        report = self.uninstall()
        self.assertEqual(report['state'], 'blocked')
        self.assertTrue(any(message.startswith('/boot looks unmounted') for message in report['blocked']), report['blocked'])
        self.assertEqual((self.case.fixture.snapshot(), self.ops.events), (before, events))

    def test_generated_grub_menu_defaults_to_the_newest_kernel(self):
        self.setup(DEBIAN_PLATFORM, 'grub')
        self.case.fresh_flow()
        self.kernel(NEW, 'boot')
        stanza = lambda title, identity, kernel: (f"menuentry '{title}' --class ubuntu --id '{identity}' {{\n    linux "
                                                  f"/vmlinuz-{kernel} root=UUID=reviewed rw\n    initrd /initramfs-{kernel}.img\n}}\n")
        (self.root / 'boot/grub/grub.cfg').write_bytes((stanza('Ubuntu', 'gnulinux-simple-u1', NEW)
                                                        + "submenu 'Advanced options for Ubuntu' --id 'gnulinux-advanced-u1' {\n"
                                                        + stanza(f'Ubuntu, with Linux {NEW}', f'gnulinux-{NEW}-advanced-u1', NEW)
                                                        + stanza(f'Ubuntu, with Linux {OLD}', f'gnulinux-{OLD}-advanced-u1', OLD)
                                                        + '}\n').encode() + self.generated())
        atomic_write(self.root / 'etc/default/grub', b'GRUB_DEFAULT=saved\nGRUB_TIMEOUT=5\n')
        report = self.uninstall()
        # The top-level entry follows later kernels; the override's kernel, an Advanced entry, would stay pinned.
        self.assertEqual((report['state'], report['default']['grub']['to']), ('uninstalled', 'gnulinux-simple-u1'), report)
        self.assertEqual(self.ops.environment['saved_entry'], 'gnulinux-simple-u1')
        self.assertTrue(any('GRUB_DEFAULT=0' in step for step in report['next_steps']), report['next_steps'])

    def test_debian_initramfs_tools_rebuilds_the_normal_image_after_depmod(self):
        self.setup(DEBIAN_PLATFORM, 'grub')
        self.case.fresh_flow()
        self.embed(f'/boot/initramfs-{OLD}.img')
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual(self.ops.regenerated, [(OLD, 'initramfs-tools', None)])
        self.assertEqual((report['kernels'][OLD]['rebuild'], report['kernels'][OLD]['normal_initramfs']),
                         (f'update-initramfs -u -k {OLD}', 'without-override'))
        events = self.ops.events[self.ops.events.index('retire-triggers'):]
        self.assertLess(events.index(f'depmod:{OLD}'), events.index(f'regenerate:{OLD}'))

    def test_debian_dracut_writes_the_discovered_initrd_img(self):
        self.setup(DEBIAN_PLATFORM, 'grub')
        self.case.fresh_flow()
        menu = self.root / 'boot/grub/grub.cfg'
        menu.write_bytes(menu.read_bytes().replace(f'initrd /initramfs-{OLD}.img'.encode(), f'initrd /initrd.img-{OLD}'.encode()))
        self.embed(f'/boot/initrd.img-{OLD}')
        self.profile(lambda boot: boot.update(initramfs='dracut'))
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual(self.ops.regenerated, [(OLD, 'dracut', f'/boot/initrd.img-{OLD}')])
        self.assertEqual((report['kernels'][OLD]['rebuild'], report['kernels'][OLD]['normal_initramfs']),
                         (f'dracut -f /boot/initrd.img-{OLD} {OLD}', 'without-override'))

    def test_arch_mkinitcpio_rebuilds_every_kernel_in_one_run(self):
        self.setup(ARCH_PLATFORM, 'systemd-boot')
        self.case.fresh_flow()
        self.kernel(NEW, 'efi')
        atomic_write(self.root / f'efi/loader/entries/normal-{NEW}.conf', f'title Arch\nversion {NEW}\nlinux /vmlinuz-{NEW}\n'
                     f'initrd /initramfs-{NEW}.img\noptions root=UUID=reviewed rw\n'.encode())
        self.ops.normal_images = [f'/efi/initramfs-{kernel}.img' for kernel in (OLD, NEW)]  # mkinitcpio -P: every preset
        for kernel in (OLD, NEW):
            self.embed(f'/efi/initramfs-{kernel}.img', kernel)
        report = self.uninstall()
        self.assertEqual(report['state'], 'uninstalled', report)
        self.assertEqual([item[1:] for item in self.ops.regenerated], [('mkinitcpio', None)])
        self.assertEqual({kernel: (report['kernels'][kernel]['rebuild'], report['kernels'][kernel]['normal_initramfs']) for kernel in (OLD, NEW)},
                         dict.fromkeys((OLD, NEW), ('mkinitcpio -P', 'without-override')))

    def test_a_normal_uki_is_left_to_the_tool_that_made_it(self):
        self.setup(ARCH_PLATFORM, 'uki')
        self.case.fresh_flow()
        (self.root / 'efi/loader/entries/cachyos-normal.conf').unlink()
        uki = self.root / 'efi/EFI/Linux/arch-linux.efi'  # made by kernel-install and ukify, with dracut
        atomic_write(uki, pe_image({'.linux': b'KERNEL', '.initrd': b'INITRD', '.uname': OLD.encode(), '.cmdline': b'root=UUID=reviewed rw'}))
        self.profile(lambda boot: boot.update(initramfs='dracut'))
        members = self.ops.portable_members
        self.ops.portable_members = lambda path: ([f'usr/lib/modules/{OLD}/updates/vbios-override/nvidia.ko'] if path.suffix == '.efi'
                                                  else members(path))
        data = uki.read_bytes()
        report = self.uninstall()
        self.assertEqual(report['state'], 'incomplete')
        self.assertEqual((self.ops.regenerated, uki.read_bytes()), ([], data))  # dracut -f would write a bare initramfs there
        command = f'kernel-install add {OLD} /usr/lib/modules/{OLD}/vmlinuz'
        self.assertEqual(report['kernels'][OLD]['rebuild'], command)
        self.assertTrue(any(problem.startswith('the normal UKI /efi/EFI/Linux/arch-linux.efi still embeds') and command in problem
                            for problem in report['problems']), report['problems'])
        self.assertFalse((self.root / f'usr/lib/modules/{OLD}/updates/vbios-override').exists())
        self.assertTrue((self.root / CONFIG.lstrip('/')).exists())  # what the second run needs
        self.ops.portable_members = members  # regenerated by its own tool
        self.assertEqual(self.uninstall()['state'], 'uninstalled')


class UninstallCliTests(unittest.TestCase):
    def run_cli(self, argv, result=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch('nvidia_vbios.uninstall.Uninstall') as worker, contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            worker.return_value.uninstall.return_value = result
            code = cli.main(argv)
        return code, stdout.getvalue(), stderr.getvalue(), worker

    def test_system_help_lists_uninstall_and_routes_it(self):
        code, output, _, _ = self.run_cli(['system', '--help'])
        self.assertEqual(code, 0)
        self.assertIn('  uninstall ', output)
        code, output, error, worker = self.run_cli(['system', 'uninstall', '--dry-run'], {'state': 'planned', 'dry_run': True})
        self.assertEqual((code, json.loads(output)['state'], error), (0, 'planned', ''))
        worker.return_value.uninstall.assert_called_once_with(dry_run=True, allow_missing_module=False)
        code, _, error, worker = self.run_cli(['system', 'uninstall', '--dry-run', '--allow-missing-module'],
                                              {'state': 'blocked', 'blocked': ['/efi looks unmounted']})
        self.assertEqual(code, 1)
        self.assertEqual(error, 'UNINSTALL_BLOCKED: nothing was changed: /efi looks unmounted\n')
        worker.return_value.uninstall.assert_called_once_with(dry_run=True, allow_missing_module=True)

    def test_production_commands_tolerate_missing_units_and_write_the_discovered_image(self):
        operations = BootstrapOperations.__new__(BootstrapOperations)
        operations.system = MagicMock()
        for running in (True, False):  # without a running systemd (a chroot without /run) nothing runs
            operations.system._run.reset_mock()
            with patch.object(Path, 'is_dir', return_value=running):
                operations.retire_triggers()
                operations.daemon_reload()
            self.assertEqual(operations.system._run.call_args_list, [
                call(['systemctl', 'stop', *UNITS, 'nvidia-vbios-reconcile.service'], allow_failure=True),
                call(['systemctl', 'disable', *UNITS], allow_failure=True),
                call(['systemctl', 'daemon-reload'], allow_failure=True)] if running else [])
        system = SystemOperations.__new__(SystemOperations)
        system._run = MagicMock()
        for raw, image, argv in (({'boot': {'initramfs': 'initramfs-tools'}}, None, ['update-initramfs', '-u', '-k', OLD]),
                                 ({'boot': {'initramfs': 'mkinitcpio'}}, None, ['mkinitcpio', '-P']),
                                 ({'boot': {'initramfs': 'dracut'}}, f'/boot/initrd.img-{OLD}', ['dracut', '-f', f'/boot/initrd.img-{OLD}', OLD]),
                                 ({}, None, ['dracut', '-f', '--kver', OLD])):
            system.regenerate_initramfs(OLD, raw, image)
            system._run.assert_called_with(argv, timeout=3600)
        self.assertEqual(COMMANDS['update-initramfs'], '/usr/sbin/update-initramfs')


if __name__ == '__main__':
    unittest.main()
