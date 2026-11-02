"""Fresh portable bootstrap flows use synthetic roots and injected operations."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import copy
import io
import os
from pathlib import Path
import json
import re
import sys
import subprocess
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'tests'))
import test_bootstrap as bootstrap_fixtures
from test_bootstrap import Operations, OLD
from test_lifecycle_portable import PortableFakeOperations, pe_image
from nvidia_vbios.bootstrap import Bootstrap, BootstrapError, CONFIG, BASE, STATE, ACTION_TARGETS
from nvidia_vbios.driver_update import DriverUpdate
from nvidia_vbios.lifecycle import Reconciler
from nvidia_vbios.lifecycle import __main__ as lifecycle_main
from nvidia_vbios.lifecycle.platform import DEBIAN_PLATFORM, ARCH_PLATFORM
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write, digest, hash_file
from nvidia_vbios.lifecycle.config import load_config
from nvidia_vbios.lifecycle.portable import EFI_GUID


class PortableBootstrapOperations(PortableFakeOperations, Operations):
    """Keep bootstrap trigger/archive mocks and portable image/lock mocks."""
    pass


class PortableBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.fixture = bootstrap_fixtures.BootstrapTests(methodName='runTest')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.profile = self.fixture.profile

    def setup_platform(self, platform, backend):
        self.platform, self.backend = platform, backend
        self.profile['userspace'] = {'provider': platform.package_provider}
        self.profile['boot'] = {'backend': backend, 'initramfs': 'initramfs-tools' if platform.family == 'debian' else 'mkinitcpio'}
        if backend == 'grub':
            self.profile['fallback_entry'] = 'debian-normal'
            atomic_write(self.root / 'boot/grub/grub.cfg', f"source $prefix/nvidia-vbios.cfg\nmenuentry 'Debian normal' --class debian --id 'debian-normal' {{\n    linux /vmlinuz-{OLD} root=UUID=reviewed rw pcie_aspm=off\n    initrd /initramfs-{OLD}.img\n}}\n".encode())
        else:
            self.profile['boot'].update(boot_root='/efi', esp='/efi')
            self.profile['fallback_entry'] = 'cachyos-normal.conf'
            atomic_write(self.root / f'efi/vmlinuz-{OLD}', b'REVIEWED ARCH KERNEL')
            atomic_write(self.root / f'efi/initramfs-{OLD}.img', b'REVIEWED ARCH NORMAL IMAGE')
            atomic_write(self.root / 'efi/loader/entries/cachyos-normal.conf', f'title CachyOS\nversion {OLD}\nlinux /vmlinuz-{OLD}\ninitrd /initramfs-{OLD}.img\noptions root=UUID=reviewed rw pcie_aspm=off\n'.encode())
        (self.root / ('var/lib/dpkg' if platform.family == 'debian' else 'var/lib/pacman')).mkdir(parents=True, exist_ok=True)
        self.ops = PortableBootstrapOperations(self.root, self.profile, platform)
        self.worker = Bootstrap(self.root, self.ops)

    def configuration(self):
        return json.loads((self.root / CONFIG.lstrip('/')).read_bytes())

    def fresh_flow(self):
        provider = self.platform.hook_provider
        installed = self.worker.install(self.fixture.repository)
        self.assertEqual(installed['state'], 'published')
        self.assertTrue((self.root / f'{BASE.lstrip("/")}/actions/{provider}').exists())
        for other in ('dnf4', 'dnf5'):
            self.assertFalse((self.root / f'{BASE.lstrip("/")}/actions/{other}').exists())
            self.assertFalse((self.root / ACTION_TARGETS[other].lstrip('/')).exists())
        self.assertFalse((self.root / ACTION_TARGETS[provider].lstrip('/')).exists())
        self.worker.enroll(self.profile)
        raw = self.configuration()
        self.ops.config = raw
        self.assertEqual(raw['userspace']['provider'], self.platform.package_provider)
        self.assertEqual(raw['normal_boot']['entry'], self.profile['fallback_entry'])
        self.assertEqual(raw['fallback_files'], raw['normal_boot']['boot_files'])
        ready = Reconciler(self.root, self.ops).reconcile(OLD)
        self.assertEqual(ready['state'], 'ready')
        enabled = self.worker.enable(OLD)
        self.assertTrue(enabled['triggers_enabled'])
        callback = self.root / ACTION_TARGETS[provider].lstrip('/')
        self.assertIn(b'lifecycle post-transaction --defer', callback.read_bytes())
        self.assertEqual(self.ops.environment['saved_entry'], ready['entry'])
        service = (self.root / 'usr/lib/systemd/system/nvidia-vbios-reconcile.service').read_text()
        self.assertNotIn('Fedora', service)
        self.assertNotIn('akmods.service', service)
        self.assertIn('/var/lib/dpkg' if provider == 'apt' else '/var/lib/pacman', service)
        if self.backend != 'grub':
            self.assertIn('/efi', service)
        if provider == 'apt':
            self.assertTrue((self.root / 'etc/kernel/postinst.d/zz-nvidia-vbios').exists())
            self.assertTrue((self.root / 'etc/kernel/postrm.d/zz-nvidia-vbios').exists())
        disabled = self.worker.disable()
        self.assertEqual(disabled['state'], 'disabled')
        self.assertFalse(self.ops.enabled)
        self.assertFalse(self.configuration()['enabled'])
        self.assertFalse(callback.exists())
        self.assertEqual(self.ops.environment['saved_entry'], self.profile['fallback_entry'])
        self.assertEqual(disabled['default_restoration']['state'], 'normal')
        resumed = self.worker.enable(OLD)
        self.assertTrue(resumed['triggers_enabled'])
        self.assertEqual(self.ops.environment['saved_entry'], ready['entry'])
        return ready

    def test_fresh_debian_apt_install_enroll_reconcile_enable_disable_resume(self):
        self.setup_platform(DEBIAN_PLATFORM, 'grub')
        self.fresh_flow()

    def test_fresh_arch_pacman_install_enroll_reconcile_enable_disable_resume(self):
        self.setup_platform(ARCH_PLATFORM, 'systemd-boot')
        self.fresh_flow()

    def test_fresh_arch_uki_flow_keeps_explicit_boot_and_module_signing_profiles(self):
        self.setup_platform(ARCH_PLATFORM, 'uki')
        self.profile['signing'] = {'key': '/secure/module.key', 'certificate': '/secure/module.der'}
        self.profile['boot']['uki'] = {'signing': {'key': '/secure/efi.key', 'certificate': '/secure/efi.pem', 'trust': 'firmware-db'}}
        self.fresh_flow()
        raw = self.configuration()
        self.assertEqual(raw['signing'], self.profile['signing'])
        self.assertEqual(raw['boot']['uki'], self.profile['boot']['uki'])
        self.assertFalse((self.root / 'secure').exists())

    def prepare_efi_reactivation(self, *, fail_after_selection=False):
        self.setup_platform(ARCH_PLATFORM, 'systemd-boot')
        self.worker.install(self.fixture.repository)
        self.worker.enroll(self.profile)
        self.ops.config = self.configuration()
        ready = Reconciler(self.root, self.ops).reconcile(OLD)
        efi = self.root / f'sys/firmware/efi/efivars/LoaderEntryDefault-{EFI_GUID}'
        def set_efi(entry):
            atomic_write(efi, b'\x07\x00\x00\x00' + (entry + '\0').encode('utf-16-le'))
        set_efi(self.profile['fallback_entry'])
        # Production base operations expose GRUB; the portable wrapper owns EFI.
        self.ops.environment = {'saved_entry': 'foreign-grub-selection'}
        self.ops.grub_environment = MagicMock(wraps=self.ops.grub_environment)
        self.ops.set_default = MagicMock(wraps=self.ops.set_default)
        failed = False
        def command(arguments, **kwargs):
            nonlocal failed
            if arguments[:3] != ['bootctl', '--esp-path=/efi', 'set-default']:
                raise AssertionError('unexpected system operation: ' + repr(arguments))
            set_efi(arguments[3])
            if fail_after_selection and not failed:
                failed = True
                raise LifecycleError('mock bootctl wrote then failed')
            return subprocess.CompletedProcess(arguments, 0, stdout=b'', stderr=b'')
        self.ops._run = MagicMock(side_effect=command)
        configuration = load_config(self.root / CONFIG.lstrip('/'), self.root)
        plan = self.worker._ready_default_plan(configuration, ready)
        self.assertEqual(plan['state'], 'planned')
        return ready, plan, efi

    def test_systemd_boot_reactivation_uses_efi_adapter_and_preserves_grub_selection(self):
        ready, plan, efi = self.prepare_efi_reactivation()
        result = self.worker._select_ready_default_locked(plan)
        self.assertEqual(result['state'], 'selected')
        self.assertEqual(efi.read_bytes()[4:].decode('utf-16-le').rstrip('\0'), ready['entry'])
        self.ops._run.assert_called_once_with(['bootctl', '--esp-path=/efi', 'set-default', ready['entry']])
        self.ops.grub_environment.assert_not_called()
        self.ops.set_default.assert_not_called()
        self.assertEqual(self.ops.environment['saved_entry'], 'foreign-grub-selection')

    def test_systemd_boot_reactivation_failure_restores_efi_default_through_adapter(self):
        ready, plan, efi = self.prepare_efi_reactivation(fail_after_selection=True)
        with self.assertRaisesRegex(LifecycleError, 'bootctl wrote then failed'):
            self.worker._select_ready_default_locked(plan)
        self.assertEqual(efi.read_bytes()[4:].decode('utf-16-le').rstrip('\0'), self.profile['fallback_entry'])
        self.assertEqual([call.args[0][-1] for call in self.ops._run.call_args_list], [ready['entry'], self.profile['fallback_entry']])
        self.ops.grub_environment.assert_not_called()
        self.ops.set_default.assert_not_called()
        self.assertEqual(self.ops.environment['saved_entry'], 'foreign-grub-selection')

    def test_portable_bootstrap_dry_runs_leave_every_file_and_trigger_unchanged(self):
        self.setup_platform(DEBIAN_PLATFORM, 'grub')
        before = self.fixture.snapshot()
        self.worker.install(self.fixture.repository, dry_run=True)
        self.worker.enroll(self.profile, dry_run=True)
        self.assertEqual(before, self.fixture.snapshot())
        self.assertFalse(self.ops.enabled)

    def test_native_callback_unavailable_blocks_enable_without_activating_triggers(self):
        self.setup_platform(ARCH_PLATFORM, 'systemd-boot')
        self.worker.install(self.fixture.repository)
        self.worker.enroll(self.profile)
        self.ops.config = self.configuration()
        Reconciler(self.root, self.ops).reconcile(OLD)
        self.ops.plugin = False
        with self.assertRaisesRegex(BootstrapError, 'prerequisites|plugin'):
            self.worker.enable(OLD)
        self.assertFalse(self.ops.enabled)
        self.assertFalse((self.root / ACTION_TARGETS['pacman'].lstrip('/')).exists())


class AddGpuTests(unittest.TestCase):
    """The README's order for adding a GPU to a loaded setup: pre-install, enroll, reconcile, enable."""
    def portable(self, platform, backend):
        case = PortableBootstrapTests('test_fresh_debian_apt_install_enroll_reconcile_enable_disable_resume')
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.setup_platform(platform, backend)
        return case.worker, case.ops, case.root, case.fixture, case.profile

    def fedora(self):
        fixture = bootstrap_fixtures.BootstrapTests('runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        return fixture.worker, fixture.ops, fixture.root, fixture, fixture.profile

    def test_pre_install_keeps_the_override_default_while_a_gpu_is_added(self):
        for label, make in (('Debian GRUB', lambda: self.portable(DEBIAN_PLATFORM, 'grub')),
                            ('Arch systemd-boot', lambda: self.portable(ARCH_PLATFORM, 'systemd-boot')),
                            ('Fedora BLS', self.fedora)):
            with self.subTest(label):
                worker, ops, root, fixture, profile = make()
                configuration = lambda: json.loads((root / CONFIG.lstrip('/')).read_bytes())
                worker.install(fixture.repository)
                worker.enroll(profile)
                ops.config = configuration()
                ready = Reconciler(root, ops).reconcile(OLD)
                worker.enable(OLD)
                self.assertEqual(ops.environment['saved_entry'], ready['entry'])
                # Rebuilds off, as enroll needs, with the current override entry still the default.
                self.assertEqual(DriverUpdate(root, ops).pre_install()['state'], 'suspended')
                self.assertEqual((ops.enabled, ops.environment['saved_entry']), (False, ready['entry']))
                bigger = copy.deepcopy(profile)
                bigger['devices'].append(fixture.device(1))
                ops.config = bigger
                worker.enroll(bigger)
                ops.config = configuration()
                self.assertEqual(len(ops.config['devices']), 2)
                rebuilt = Reconciler(root, ops).reconcile(OLD)
                self.assertEqual(rebuilt['state'], 'ready')
                self.assertNotEqual(rebuilt['entry'], ready['entry'])
                enabled = worker.enable(OLD)
                self.assertTrue(enabled['triggers_enabled'])
                self.assertEqual(ops.environment['saved_entry'], rebuilt['entry'])


OLDER = '6.19.8-200.fc44.x86_64'
UUID = '6f1c2a9e-0b7d-4e55-9a3c-2d8e41f7b05c'
ARCH_OPTIONS = 'root=UUID=reviewed rw pcie_aspm=off'
ACTIVATION = 'nvidia.NVreg_RegistryDwords=RmLinuxVbiosOverride=2'


def ubuntu_menu(kernels):
    """grub.cfg as grub-mkconfig writes it on Ubuntu, oldest kernel first: the newest kernel at the top level, each
    kernel and its recovery entry under Advanced options, then the loader's include."""
    def entry(title, identity, kernel, options, indent=''):
        return (f"{indent}menuentry '{title}' --class ubuntu --class gnu-linux --class gnu --class os "
                f"$menuentry_id_option '{identity}' {{\n{indent}\trecordfail\n{indent}\tload_video\n"
                f"{indent}\tsearch --no-floppy --fs-uuid --set=root {UUID}\n"
                f"{indent}\tlinux\t/boot/vmlinuz-{kernel} root=UUID={UUID} ro {options}\n"
                f"{indent}\tinitrd\t/boot/initrd.img-{kernel}\n{indent}}}\n")
    options = 'quiet splash $vt_handoff'
    menu = 'set vt_handoff=vt.handoff=7\n' + entry('Ubuntu', f'gnulinux-simple-{UUID}', kernels[-1], options)
    menu += f"submenu 'Advanced options for Ubuntu' $menuentry_id_option 'gnulinux-advanced-{UUID}' {{\n"
    for kernel in reversed(kernels):
        menu += entry(f'Ubuntu, with Linux {kernel}', f'gnulinux-{kernel}-advanced-{UUID}', kernel, options, '\t')
        menu += entry(f'Ubuntu, with Linux {kernel} (recovery mode)', f'gnulinux-{kernel}-recovery-{UUID}', kernel,
                      'recovery nomodeset dis_ucode_ldr', '\t')
    return (menu + '}\n### BEGIN /etc/grub.d/41_nvidia_vbios ###\nif [ -f $prefix/nvidia-vbios.cfg ]; then\n'
            '  source $prefix/nvidia-vbios.cfg\nfi\n### END /etc/grub.d/41_nvidia_vbios ###\n').encode()


class EfiOperations(PortableBootstrapOperations):
    """systemd-boot keeps its default and one-time entry in EFI variables and only bootctl changes them, so the boot
    adapter reads and writes them as on a real system. GRUB's saved_entry stays what it was."""
    def __init__(self, root, config, platform):
        super().__init__(root, config, platform)
        self.environment = {'saved_entry': 'foreign-grub-selection'}
        for name in ('make', 'modinfo', 'depmod', 'mokutil'):
            atomic_write(root / 'usr/bin' / name, b'', 0o755)
        atomic_write(root / f'usr/lib/modules/{OLD}/build/Makefile', b'REVIEWED KERNEL HEADERS', 0o644)
        (root / 'sys/firmware/efi/efivars').mkdir(parents=True, exist_ok=True)

    def efi(self, name, value=None):
        """The text of EFI variable `name` ('' when unset); a `value` sets it first, and '' removes it."""
        path = self.root / f'sys/firmware/efi/efivars/{name}-{EFI_GUID}'
        if value:
            atomic_write(path, b'\x07\x00\x00\x00' + (value + '\0').encode('utf-16-le'), 0o644)
        elif value is not None:
            path.unlink(missing_ok=True)
        return path.read_bytes()[4:].decode('utf-16-le').rstrip('\0') if path.exists() else ''

    def command_path(self, name):
        return str(self.root / 'usr/bin' / name)

    def _text(self, arguments):
        if arguments != ['mokutil', '--sb-state']:
            raise AssertionError('unexpected system query: ' + repr(arguments))
        return 'SecureBoot disabled\n'

    def _run(self, arguments, **options):
        if arguments[:3] != ['bootctl', '--esp-path=/efi', 'set-default'] or len(arguments) != 4:
            raise AssertionError('unexpected system operation: ' + repr(arguments))
        self.events.append('bootctl:' + arguments[3])
        self.efi('LoaderEntryDefault', arguments[3])
        if self.fault == 'default' and arguments[3].startswith('vbios-'):
            self.fault = None
            raise LifecycleError('bootctl wrote then failed')
        return subprocess.CompletedProcess(arguments, 0, stdout=b'', stderr=b'')


class Boot:
    """One boot setup on a synthetic root: its normal entry and files, and its default where the boot loader keeps it."""
    LABELS = ('Debian GRUB', 'Ubuntu GRUB', 'Arch systemd-boot', 'Arch UKI from a Type 1 entry',
              'Arch UKI from a normal UKI', 'Fedora BLS')

    def __init__(self, test, label):
        self.label, self.efi = label, label.startswith('Arch')
        if label == 'Fedora BLS':
            fixture = bootstrap_fixtures.BootstrapTests('runTest')
            fixture.setUp()
            test.addCleanup(fixture.doCleanups)
            self.profile, self.ops = fixture.profile, fixture.ops
        else:
            case = PortableBootstrapTests('runTest')
            case.setUp()
            test.addCleanup(case.doCleanups)
            grub = label.endswith('GRUB')
            case.setup_platform(DEBIAN_PLATFORM if grub else ARCH_PLATFORM,
                                'grub' if grub else 'systemd-boot' if label == 'Arch systemd-boot' else 'uki')
            fixture, self.profile = case.fixture, case.profile
            if label == 'Ubuntu GRUB':
                atomic_write(fixture.root / f'boot/initrd.img-{OLD}', b'NORMAL IMAGE')
                atomic_write(fixture.root / 'boot/grub/grub.cfg', ubuntu_menu([OLD]))
                self.profile['fallback_entry'] = f'gnulinux-simple-{UUID}'
            elif label.endswith('normal UKI'):
                (fixture.root / 'efi/loader/entries/cachyos-normal.conf').unlink()
                atomic_write(fixture.root / 'efi/EFI/Linux/arch-normal.efi', self.uki(OLD))
                self.profile['fallback_entry'] = 'arch-normal.efi'
            self.ops = (EfiOperations if self.efi else PortableBootstrapOperations)(fixture.root, self.profile, case.platform)
        self.fixture, self.root, self.normal = fixture, fixture.root, self.profile['fallback_entry']
        self.worker = Bootstrap(self.root, self.ops)
        # The normal entry's descriptor, the start of its kernel options, and its initramfs (inside a normal UKI).
        self.descriptor, self.options, self.image = {
            'Debian GRUB': ('boot/grub/grub.cfg', 'root=UUID=reviewed', f'boot/initramfs-{OLD}.img'),
            'Ubuntu GRUB': ('boot/grub/grub.cfg', 'quiet splash', f'boot/initrd.img-{OLD}'),
            'Arch UKI from a normal UKI': ('efi/EFI/Linux/arch-normal.efi', ARCH_OPTIONS, None),
            'Fedora BLS': (f'boot/loader/entries/{self.normal}.conf', 'root=UUID=synthetic', f'boot/initramfs-{OLD}.img'),
        }.get(label, ('efi/loader/entries/cachyos-normal.conf', 'root=UUID=reviewed', f'efi/initramfs-{OLD}.img'))

    @staticmethod
    def uki(kernel, options=ARCH_OPTIONS, image=b'REVIEWED ARCH NORMAL IMAGE'):
        return pe_image({'.linux': b'REVIEWED ARCH KERNEL', '.initrd': image, '.uname': kernel.encode(),
                         '.cmdline': options.encode()})

    def configuration(self):
        return json.loads((self.root / CONFIG.lstrip('/')).read_bytes())

    def default(self):
        """GRUB's saved_entry, or systemd-boot's LoaderEntryDefault."""
        return self.ops.efi('LoaderEntryDefault') if self.efi else self.ops.environment.get('saved_entry')

    def choose(self, saved, once='', previous=''):
        """The default and a pending one-time entry, as grub-set-default and grub-reboot leave them (prev_saved_entry
        is GRUB's own), or bootctl set-default and set-oneshot."""
        if self.efi:
            self.ops.efi('LoaderEntryDefault', saved)
            self.ops.efi('LoaderEntryOneShot', once)
        else:
            self.ops.environment = {name: value for name, value in
                                    (('saved_entry', saved), ('next_entry', once), ('prev_saved_entry', previous)) if value}

    def choices(self):
        """Every boot choice that a selection could change."""
        if self.efi:
            return self.default(), self.ops.efi('LoaderEntryOneShot'), dict(self.ops.environment)
        return dict(self.ops.environment)

    def add_kernel(self, kernel):
        """Install an older kernel with its normal entry; returns the ID of that entry."""
        (self.root / f'usr/lib/modules/{kernel}').mkdir(mode=0o755)
        if self.image is None:
            atomic_write(self.root / f'efi/EFI/Linux/arch-{kernel}.efi', self.uki(kernel))
            return f'arch-{kernel}.efi'
        boot = 'efi' if self.efi else 'boot'
        image = f'initrd.img-{kernel}' if self.label == 'Ubuntu GRUB' else f'initramfs-{kernel}.img'
        atomic_write(self.root / f'{boot}/vmlinuz-{kernel}', ('KERNEL ' + kernel).encode())
        atomic_write(self.root / f'{boot}/{image}', ('NORMAL IMAGE ' + kernel).encode())
        if self.label == 'Ubuntu GRUB':
            atomic_write(self.root / self.descriptor, ubuntu_menu([kernel, OLD]))
            return f'gnulinux-advanced-{UUID}>gnulinux-{kernel}-advanced-{UUID}'
        if self.label == 'Debian GRUB':
            menu = self.root / self.descriptor
            atomic_write(menu, menu.read_bytes() + (f"menuentry 'Debian {kernel}' --class debian --id 'debian-{kernel}' {{\n"
                                                    f"    linux /vmlinuz-{kernel} root=UUID=reviewed rw pcie_aspm=off\n"
                                                    f"    initrd /{image}\n}}\n").encode())
            return f'debian-{kernel}'
        if self.label == 'Fedora BLS':
            atomic_write(self.root / f'boot/loader/entries/normal-{kernel}.conf', (
                f'title Fedora\nversion {kernel}\nlinux /vmlinuz-{kernel}\ninitrd /{image} $tuned_initrd\n'
                'options root=UUID=synthetic $tuned_params\n').encode())
            return f'normal-{kernel}'
        atomic_write(self.root / f'efi/loader/entries/arch-{kernel}.conf', (
            f'title Arch Linux\nversion {kernel}\nlinux /vmlinuz-{kernel}\ninitrd /{image}\noptions {ARCH_OPTIONS}\n').encode())
        return f'arch-{kernel}.conf'

    def update(self, kernel):
        """A kernel package update to `kernel`, newer than OLD: the normal entry ID that the loader recorded now starts
        it, as a rolling entry does (Ubuntu's and Debian's top GRUB entry, an Arch entry or UKI that the package
        rewrites). On GRUB the menu keeps an entry for OLD."""
        (self.root / f'usr/lib/modules/{kernel}').mkdir(mode=0o755)
        if self.efi:
            atomic_write(self.root / f'usr/lib/modules/{kernel}/build/Makefile', b'REVIEWED KERNEL HEADERS', 0o644)
        path = self.root / self.descriptor
        if self.image is None:  # the same UKI file now holds the new kernel
            atomic_write(path, self.uki(kernel), 0o644)
            return
        boot = 'efi' if self.efi else 'boot'
        image = f'initrd.img-{kernel}' if self.label == 'Ubuntu GRUB' else f'initramfs-{kernel}.img'
        atomic_write(self.root / f'{boot}/vmlinuz-{kernel}', ('KERNEL ' + kernel).encode())
        atomic_write(self.root / f'{boot}/{image}', ('NORMAL IMAGE ' + kernel).encode())
        if self.label == 'Ubuntu GRUB':
            atomic_write(path, ubuntu_menu([OLD, kernel]), 0o644)
        elif self.label == 'Debian GRUB':
            old = (f"menuentry 'Debian {OLD}' --class debian --id 'debian-{OLD}' {{\n"
                   f"    linux /vmlinuz-{OLD} root=UUID=reviewed rw pcie_aspm=off\n    initrd /initramfs-{OLD}.img\n}}\n")
            atomic_write(path, path.read_bytes().replace(OLD.encode(), kernel.encode()) + old.encode(), 0o644)
        else:
            atomic_write(path, path.read_bytes().replace(OLD.encode(), kernel.encode()), 0o644)

    def changed_normal(self, kind):
        """(file, bytes) that change the normal entry: a VBIOS activation in its kernel options, or its initramfs."""
        if self.image is None:  # a normal UKI holds both
            return self.root / self.descriptor, (self.uki(OLD, f'{ARCH_OPTIONS} {ACTIVATION}') if kind == 'options'
                                                 else self.uki(OLD, image=b'CHANGED NORMAL IMAGE'))
        if kind == 'image':
            return self.root / self.image, b'CHANGED NORMAL IMAGE'
        # Ubuntu's menu repeats the options in the kernel's Advanced entry, and update-grub changes both.
        path = self.root / self.descriptor
        return path, path.read_bytes().replace(self.options.encode(), f'{self.options} {ACTIVATION}'.encode())


NEWER = '6.19.20-200.fc44.x86_64'  # newer than OLD in kernel order
PORTABLE = Boot.LABELS[:-1]


def plain_refusal(boot):
    """What reconcile without --select-default says about the normal default that disable left."""
    return 'foreign or unrelated' if boot.label == 'Fedora BLS' else 'normal boot default preserved.*--select-default'


@contextmanager
def lossy_restore(boot):
    """Selecting an override entry writes it and then fails, and putting any other default back exits without effect,
    as a grub-editenv or bootctl that does not persist."""
    if boot.efi:
        def run(arguments, **options):
            if arguments[-1].startswith('vbios-'):
                boot.ops.efi('LoaderEntryDefault', arguments[-1])
                raise LifecycleError('bootctl wrote then failed')
            return subprocess.CompletedProcess(arguments, 0, stdout=b'', stderr=b'')
        with patch.object(boot.ops, '_run', run):
            yield
    else:
        def set_default(entry):
            if entry.startswith('vbios-'):
                boot.ops.environment['saved_entry'] = entry
                raise LifecycleError('grub wrote then failed')
        with patch.object(boot.ops, 'set_default', set_default):
            yield


class AfterDisableTests(unittest.TestCase):
    """The README's way back after `disable`, on every boot setup: enroll, `reconcile --kernel K --select-default`,
    enable. Only that explicit flag takes the normal entry of K as the previous default."""
    def disabled(self, boot, gpus=2):
        """One GPU loaded, then disable and enroll `gpus` GPUs, as when adding one; returns the first READY build."""
        worker, ops = boot.worker, boot.ops
        worker.install(boot.fixture.repository)
        worker.enroll(boot.profile)
        ops.config = boot.configuration()
        first = Reconciler(boot.root, ops).reconcile(OLD)
        worker.enable(OLD)
        self.assertEqual(boot.default(), first['entry'])
        profile = copy.deepcopy(boot.profile)
        profile['devices'] += [boot.fixture.device(index) for index in range(1, gpus)]
        ops.config = profile
        with self.assertRaisesRegex(BootstrapError, 'disable every enabled'):
            worker.enroll(profile)
        self.assertEqual(worker.disable()['default_restoration'], {'state': 'normal', 'entry': boot.normal})
        self.assertEqual(boot.default(), boot.normal)
        worker.enroll(profile)
        ops.config = boot.configuration()
        self.assertEqual((len(ops.config['devices']), ops.builds, ops.enabled), (gpus, 1, False))
        return first

    @staticmethod
    def select(boot, kernel=OLD):
        return Reconciler(boot.root, boot.ops).reconcile(kernel, select_default=True)

    @staticmethod
    def state(boot, name):
        return json.loads((boot.root / STATE.lstrip('/') / name).read_bytes())

    def loaded(self, boot):
        """One GPU loaded and enabled; returns the READY build, the default."""
        boot.worker.install(boot.fixture.repository)
        boot.worker.enroll(boot.profile)
        boot.ops.config = boot.configuration()
        ready = Reconciler(boot.root, boot.ops).reconcile(OLD)
        boot.worker.enable(OLD)
        self.assertEqual(boot.default(), ready['entry'])
        return ready

    def test_select_default_after_disable_builds_the_new_profile_and_enable_keeps_it(self):
        for label in Boot.LABELS:
            with self.subTest(label):
                boot = Boot(self, label)
                first = self.disabled(boot)
                with self.assertRaisesRegex(LifecycleError, plain_refusal(boot)):
                    Reconciler(boot.root, boot.ops).reconcile(OLD)  # without the flag the normal default is a choice
                self.assertEqual((boot.default(), boot.ops.builds), (boot.normal, 1))
                rebuilt = self.select(boot)
                self.assertEqual(rebuilt['state'], 'ready')
                self.assertNotEqual(rebuilt['entry'], first['entry'])
                self.assertEqual(boot.default(), rebuilt['entry'])
                # What a failed build or selection restores.
                self.assertEqual(self.state(boot, 'transaction.json')['previous_default'], boot.normal)
                enabled = boot.worker.enable(OLD)
                self.assertEqual((enabled['triggers_enabled'], enabled['default_selection']['state']), (True, 'ready'))
                self.assertEqual(boot.default(), rebuilt['entry'])
                if boot.efi:
                    self.assertEqual(boot.ops.environment, {'saved_entry': 'foreign-grub-selection'})

    def test_select_default_reuses_an_unchanged_build_and_enable_selects_it(self):
        for label in Boot.LABELS:
            with self.subTest(label):
                boot = Boot(self, label)
                first = self.disabled(boot, gpus=1)
                reused = self.select(boot)
                self.assertEqual((reused['entry'], boot.ops.builds, boot.default()), (first['entry'], 1, boot.normal))
                self.assertEqual(boot.worker.enable(OLD)['default_selection']['state'], 'selected')
                self.assertEqual(boot.default(), first['entry'])

    def test_select_default_keeps_every_other_default_and_pending_choice(self):
        for label in Boot.LABELS:
            with self.subTest(label):
                boot = Boot(self, label)
                self.disabled(boot)
                other = boot.add_kernel(OLDER)
                foreign = 'another-os.conf' if boot.efi else 'another-os'
                fedora = label == 'Fedora BLS'
                only = 'foreign or unrelated' if fedora else 'foreign or unrelated.*replaces only ' + re.escape(boot.normal)
                pending = 'transition is pending' if fedora else 'transition is pending.*reboot once first'
                refusals = [(OLD, {'saved': foreign}, only),
                            (OLD, {'saved': other}, only),  # another kernel's normal entry
                            # --kernel names another kernel than the one the normal entry starts
                            (OLDER, {'saved': boot.normal}, 'foreign or unrelated' if fedora else
                             f'starts {OLD}, not {OLDER}: use --kernel {OLD}'),
                            (OLD, {'saved': boot.normal, 'once': foreign}, pending)]
                if not boot.efi:
                    refusals.append((OLD, {'saved': boot.normal, 'previous': foreign}, pending))
                for kernel, choice, message in refusals:
                    boot.choose(**choice)
                    before = boot.choices()
                    with self.assertRaisesRegex(LifecycleError, message):
                        self.select(boot, kernel)
                    self.assertEqual((boot.choices(), boot.ops.builds), (before, 1))
                boot.choose(boot.normal)
                rebuilt = self.select(boot)
                self.assertEqual((rebuilt['state'], boot.default()), ('ready', rebuilt['entry']))

    def test_select_default_takes_a_rebuilt_normal_initramfs_but_no_activation_or_changed_ready_image(self):
        for label in Boot.LABELS:
            with self.subTest(label):
                boot = Boot(self, label)
                self.disabled(boot)
                image = next(record['path'] for record in self.state(boot, 'fleet.json')['last_ready']['boot_files']
                             if 'initramfs' in record['path'].rsplit('/', 1)[-1])
                portable = label != 'Fedora BLS'
                changes = [(boot.root / image.lstrip('/'), b'CHANGED READY IMAGE', 'last ready boot artifact changed'),
                           # plan() refuses a VBIOS activation in the normal entry, also in the one disable restored
                           (*boot.changed_normal('options'),
                            'normal entry contains foreign VBIOS activation' if portable else 'foreign or unrelated')]
                for path, data, message in changes:
                    original, mode = path.read_bytes(), path.stat().st_mode & 0o777
                    atomic_write(path, data, mode)
                    with self.assertRaisesRegex(LifecycleError, message):
                        self.select(boot)
                    self.assertEqual((boot.default(), boot.ops.builds), (boot.normal, 1))
                    atomic_write(path, original, mode)
                # An update rebuilt the normal initramfs after disable (update-initramfs, mkinitcpio): the normal entry
                # disable restored is still the default, so the new build keeps it as the previous default.
                path, data = boot.changed_normal('image')
                atomic_write(path, data, path.stat().st_mode & 0o777)
                rebuilt = self.select(boot)
                self.assertEqual((rebuilt['state'], boot.default()), ('ready', rebuilt['entry']))
                self.assertEqual(self.state(boot, 'transaction.json')['previous_default'], boot.normal)
                self.assertIn(digest(data), self.state(boot, 'fleet.json')['normal_fallback']['boot_files'].values())
                self.assertEqual(boot.worker.enable(OLD)['default_selection']['state'], 'ready')
                self.assertEqual(boot.worker.disable()['default_restoration'], {'state': 'normal', 'entry': boot.normal})

    def test_select_default_failures_put_the_normal_entry_back(self):
        for label in Boot.LABELS:
            with self.subTest(label):
                boot = Boot(self, label)
                self.disabled(boot)
                for fault, message in (('build', 'make failed'), ('default', 'wrote then failed')):
                    boot.ops.fault = fault
                    with self.assertRaisesRegex(LifecycleError, message):
                        self.select(boot)
                    self.assertEqual(boot.default(), boot.normal)
                boot.ops.fault = None
                rebuilt = self.select(boot)
                self.assertEqual((rebuilt['state'], boot.default(), boot.ops.enabled), ('ready', rebuilt['entry'], False))

    def test_a_restore_that_did_not_persist_keeps_the_new_entry_complete_until_the_next_reconcile(self):
        for label in Boot.LABELS:
            with self.subTest(label):
                boot = Boot(self, label)
                self.disabled(boot)
                with lossy_restore(boot), self.assertRaisesRegex(
                        LifecycleError, 'wrote then failed; rollback requires review: the previous boot default did not persist'):
                    self.select(boot)
                journal = self.state(boot, 'transaction.json')
                self.assertEqual((journal['phase'], boot.default()), ('rollback-failed', journal['entry']))
                for record in journal['files']:  # nothing the default names was deleted
                    self.assertEqual(hash_file(boot.root / record['path'].lstrip('/')), record['after_sha256'])
                rebuilt = self.select(boot)  # finishes the rollback, then builds and selects again
                self.assertEqual((rebuilt['state'], boot.default()), ('ready', rebuilt['entry']))

    def test_enable_reports_a_normal_default_that_did_not_come_back(self):
        for label in Boot.LABELS:
            with self.subTest(label):
                boot = Boot(self, label)
                first = self.disabled(boot, gpus=1)
                self.assertEqual(self.select(boot)['entry'], first['entry'])  # reused; enable selects it
                with lossy_restore(boot), self.assertRaisesRegex(BootstrapError, 'normal boot default did not persist'):
                    boot.worker.enable(OLD)
                self.assertEqual((boot.default(), boot.ops.enabled), (first['entry'], False))

    def test_a_kernel_update_after_disable_keeps_the_normal_default_until_the_kernel_it_starts_is_selected(self):
        """The recorded normal entry starts a newer kernel after an update while disabled (a rolling entry). Nothing
        moves the default before a build: neither reconcile, nor --select-default for the old kernel, nor a failed
        build, so the normal entry stays the default and disable still finds it."""
        for label in PORTABLE:
            with self.subTest(label):
                boot = Boot(self, label)
                first = self.disabled(boot)
                boot.update(NEWER)
                for kernel in (OLD, NEWER):
                    with self.assertRaisesRegex(LifecycleError, 'normal boot default preserved.*--select-default'):
                        Reconciler(boot.root, boot.ops).reconcile(kernel)
                with self.assertRaisesRegex(LifecycleError, f'starts {NEWER}, not {OLD}: use --kernel {NEWER}'):
                    self.select(boot, OLD)
                self.assertEqual((boot.default(), boot.ops.builds), (boot.normal, 1))
                boot.ops.fault = 'build'
                with self.assertRaisesRegex(LifecycleError, 'make failed'):
                    self.select(boot, NEWER)
                self.assertEqual((boot.default(), boot.ops.builds), (boot.normal, 2))
                boot.ops.fault = None
                rebuilt = self.select(boot, NEWER)
                self.assertEqual((rebuilt['state'], rebuilt['kernel'], boot.default()), ('ready', NEWER, rebuilt['entry']))
                self.assertNotEqual(rebuilt['entry'], first['entry'])
                self.assertEqual(self.state(boot, 'transaction.json')['previous_default'], boot.normal)
                normal = self.state(boot, 'fleet.json')['normal_fallback']
                self.assertEqual((normal['entry'], normal['kernel']), (boot.normal, NEWER))
                boot.ops.current_kernel = lambda: NEWER  # the reboot into the new build
                self.assertEqual(boot.worker.enable(NEWER)['default_selection']['state'], 'ready')
                self.assertEqual(boot.worker.disable()['default_restoration'], {'state': 'normal', 'entry': boot.normal})

    def test_a_kernel_update_with_the_ready_default_is_built_and_selected_without_the_flag(self):
        """The enabled update path: the package hook keeps the READY default and the service builds and selects the
        new kernel; the refusal of a normal default never applies to it."""
        for label in PORTABLE:
            with self.subTest(label):
                boot = Boot(self, label)
                first = self.loaded(boot)
                boot.update(NEWER)
                event = lifecycle_main.queue_event('add', NEWER, boot.root, boot.ops)  # the kernel package hook
                self.assertEqual((event['retained_default'], boot.default()), (first['entry'], first['entry']))
                worker, calls = Reconciler(boot.root, boot.ops), []
                service = SimpleNamespace(ops=SimpleNamespace(), reconcile=lambda kernel, **options:
                                          calls.append((kernel, options)) or worker.reconcile(kernel, **options))
                with tempfile.TemporaryDirectory() as state, patch.object(lifecycle_main, 'STATE', state), \
                        patch.object(lifecycle_main, 'Reconciler', return_value=service), \
                        patch.object(lifecycle_main, 'installed_kernels', return_value=[OLD, NEWER]), \
                        redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(lifecycle_main.main(['reconcile']), 0)  # the service of the path unit and timer
                result = json.loads(output.getvalue())
                self.assertEqual(calls, [(NEWER, {'dry_run': False, 'select_default': False})])
                self.assertEqual((result['state'], result['kernel'], boot.default()), ('ready', NEWER, result['entry']))
                self.assertEqual(self.state(boot, 'transaction.json')['previous_default'], first['entry'])

    def test_a_normal_default_chosen_by_hand_stays_through_a_kernel_update(self):
        """A rolling normal entry chosen while enabled (grub-set-default, bootctl set-default, GRUB_SAVEDEFAULT) is
        kept when it starts a newer kernel, as one that keeps its kernel is."""
        for label in PORTABLE:
            with self.subTest(label):
                boot = Boot(self, label)
                self.loaded(boot)
                boot.choose(boot.normal)
                boot.update(NEWER)
                with self.assertRaisesRegex(LifecycleError, 'normal boot default preserved.*--select-default'):
                    lifecycle_main.queue_event('add', NEWER, boot.root, boot.ops)
                with self.assertRaisesRegex(LifecycleError, 'normal boot default preserved'):
                    Reconciler(boot.root, boot.ops).reconcile(NEWER)
                self.assertEqual((boot.default(), boot.ops.builds), (boot.normal, 1))

    def test_select_default_reports_why_it_cannot_confirm_the_normal_entry(self):
        debug = (f'title CachyOS debug\nversion {OLD}\nlinux /vmlinuz-{OLD}\ninitrd /initramfs-{OLD}.img\n'
                 'options root=UUID=reviewed rw debug\n').encode()
        signed = pe_image({'.linux': b'K', '.initrd': b'I', '.uname': b'6.1.0-other', '.cmdline': b'root=UUID=other',
                           '.pcrsig': b'{}'})
        cases = (('Arch systemd-boot', 'efi/loader/entries/cachyos-debug.conf', debug, 'found 2'),
                 ('Arch UKI from a normal UKI', 'efi/EFI/Linux/other-distribution.efi', signed,
                  'unsupported rebuild metadata: .pcrsig'),
                 ('Arch UKI from a normal UKI', 'efi/EFI/Linux/arch-linux.efi', None, 'symlink'))
        for label, name, data, reason in cases:
            with self.subTest(label=label, reason=reason):
                boot = Boot(self, label)
                self.disabled(boot)
                extra = boot.root / name
                if data is None:
                    os.symlink('arch-normal.efi', extra)
                else:
                    atomic_write(extra, data, 0o644)
                with self.assertRaisesRegex(LifecycleError, f'cannot confirm {re.escape(boot.normal)} as the normal entry '
                                                            f'of {OLD}: .*{re.escape(reason)}.*boot default preserved'):
                    self.select(boot)
                self.assertEqual((boot.default(), boot.ops.builds), (boot.normal, 1))
                extra.unlink()
                self.assertEqual(self.select(boot)['state'], 'ready')

    def test_select_default_and_disable_refuse_a_grub_default_that_names_another_entry_too(self):
        """GRUB boots the first menu entry whose ID or title is the saved default."""
        other = '6.19.1-200.fc44.x86_64'
        variants = {
            'a chainloader with the same ID': "menuentry 'Windows Boot Manager' --class windows --id 'debian-normal' {\n"
                                              "    insmod chain\n    chainloader /EFI/Microsoft/Boot/bootmgfw.efi\n}\n",
            'a title equal to the ID': "menuentry 'debian-normal' --class windows --id 'windows-bootmgr' {\n"
                                       "    insmod chain\n    chainloader /EFI/Microsoft/Boot/bootmgfw.efi\n}\n",
            'another kernel with the same ID': f"menuentry 'Debian custom' --class debian --id 'debian-normal' {{\n"
                                               f"    linux /vmlinuz-{other} root=UUID=reviewed rw nomodeset\n"
                                               f"    initrd /initramfs-{other}.img\n}}\n"}
        for variant, stanza in variants.items():
            with self.subTest(variant):
                boot = Boot(self, 'Debian GRUB')
                self.disabled(boot)
                atomic_write(boot.root / f'boot/vmlinuz-{other}', b'KERNEL OTHER')
                atomic_write(boot.root / f'boot/initramfs-{other}.img', b'IMAGE OTHER')
                menu = boot.root / boot.descriptor
                original = menu.read_bytes()
                include, rest = original.split(b'\n', 1)  # before the normal entry, after the loader's include
                ambiguous = include + b'\n' + stanza.encode() + rest
                atomic_write(menu, ambiguous, 0o644)
                with self.assertRaisesRegex(LifecycleError, 'ambiguous GRUB default debian-normal.*boot default preserved'):
                    self.select(boot)
                self.assertEqual((boot.default(), boot.ops.builds), (boot.normal, 1))
                atomic_write(menu, original, 0o644)
                rebuilt = self.select(boot)
                boot.worker.enable(OLD)
                atomic_write(menu, ambiguous, 0o644)
                with self.assertRaisesRegex(LifecycleError, 'ambiguous GRUB default debian-normal'):
                    boot.worker.disable()
                self.assertEqual(boot.default(), rebuilt['entry'])  # the complete override entry stays

    def test_disable_keeps_the_ready_default_when_the_normal_entry_changed(self):
        """disable selects the normal entry only as recorded: its GRUB stanza or Type 1 entry, its options, also those
        a GRUB variable gives, and its kernel and initramfs."""
        changes = (('Ubuntu GRUB', f'--set=root {UUID}', '--set=root 0000-other-root'),
                   ('Ubuntu GRUB', 'set vt_handoff=vt.handoff=7', 'set vt_handoff=vt.handoff=1'),
                   ('Arch systemd-boot', 'title CachyOS', 'title CachyOS edited'),
                   ('Arch systemd-boot', None, 'image'))
        for label, old, new in changes:
            with self.subTest(label=label, change=new):
                boot = Boot(self, label)
                ready = self.loaded(boot)
                if old is None:
                    path, changed = boot.changed_normal(new)
                else:
                    path = boot.root / boot.descriptor
                    changed = path.read_bytes().replace(old.encode(), new.encode())
                self.assertNotEqual(changed, path.read_bytes())
                atomic_write(path, changed, path.stat().st_mode & 0o777)
                with self.assertRaisesRegex(LifecycleError, 'normal recovery entry or artifacts changed'):
                    boot.worker.disable()
                self.assertEqual(boot.default(), ready['entry'])

    def test_disable_again_reports_the_normal_default_it_already_has(self):
        """Nothing to select, so nothing to refuse: a kernel update may have moved a rolling normal entry to a newer
        kernel, or an update rebuilt the normal initramfs, since disable restored it."""
        for label in PORTABLE:
            for change in ('kernel', 'image'):
                with self.subTest(label=label, change=change):
                    boot = Boot(self, label)
                    self.disabled(boot)
                    if change == 'kernel':
                        boot.update(NEWER)
                    else:
                        path, data = boot.changed_normal('image')
                        atomic_write(path, data, path.stat().st_mode & 0o777)
                    before = boot.choices()
                    self.assertEqual(boot.worker.disable()['default_restoration'], {'state': 'normal', 'entry': boot.normal})
                    self.assertEqual(boot.choices(), before)

    def test_hooks_and_the_timer_never_select(self):
        for label in Boot.LABELS:
            with self.subTest(label):
                boot = Boot(self, label)
                self.disabled(boot)
                with self.assertRaisesRegex(LifecycleError, plain_refusal(boot)):
                    Reconciler(boot.root, boot.ops).guard_default()  # `lifecycle guard`
                with self.assertRaisesRegex(LifecycleError, plain_refusal(boot)):
                    lifecycle_main.queue_event('changed', 'userspace', boot.root, boot.ops)  # the package callbacks
                worker, calls = Reconciler(boot.root, boot.ops), []
                service = SimpleNamespace(ops=SimpleNamespace(), reconcile=lambda kernel, **options:
                                          calls.append(options) or worker.reconcile(kernel, **options))
                with tempfile.TemporaryDirectory() as state, patch.object(lifecycle_main, 'STATE', state), \
                        patch.object(lifecycle_main, 'Reconciler', return_value=service), \
                        patch.object(lifecycle_main, 'installed_kernels', return_value=[OLD]), \
                        redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(lifecycle_main.main(['reconcile']), 1)  # the service of the path unit and timer
                self.assertRegex(error.getvalue(), plain_refusal(boot))
                self.assertEqual(calls, [{'dry_run': False, 'select_default': False}])
                self.assertEqual((boot.default(), boot.ops.builds), (boot.normal, 1))
                rebuilt = self.select(boot)
                boot.worker.enable(OLD)
                self.assertEqual(boot.default(), rebuilt['entry'])
                installed = [path.read_bytes() for path in boot.root.rglob('*')
                             if path.is_file() and b'nvidia-vbios lifecycle ' in path.read_bytes()]
                self.assertTrue(any(b'lifecycle reconcile' in data for data in installed))
                self.assertFalse([data for data in installed if b'select-default' in data])


if __name__ == '__main__':
    unittest.main()
