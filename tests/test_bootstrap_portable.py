"""Fresh portable bootstrap flows use synthetic roots and injected operations."""
from pathlib import Path
import json
import sys
import subprocess
from unittest.mock import MagicMock
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'tests'))
import test_bootstrap as bootstrap_fixtures
from test_bootstrap import Operations, OLD
from test_lifecycle_portable import PortableFakeOperations
from nvidia_vbios.bootstrap import Bootstrap, BootstrapError, CONFIG, BASE, ACTION_TARGETS
from nvidia_vbios.lifecycle import Reconciler
from nvidia_vbios.lifecycle.platform import DEBIAN_PLATFORM, ARCH_PLATFORM
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write
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


if __name__ == '__main__':
    unittest.main()
