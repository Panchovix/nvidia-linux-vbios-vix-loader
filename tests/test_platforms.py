"""Synthetic distribution identities and native coordination protocols."""
from dataclasses import FrozenInstanceError
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from nvidia_vbios.lifecycle.platform import (
    ARCH_PLATFORM, DEBIAN_PLATFORM, FEDORA_PLATFORM, RHEL_PLATFORM,
    detect_platform, package_transaction_lock, rpm_lock_path,
)
from nvidia_vbios.lifecycle.security import LifecycleError
from nvidia_vbios.lifecycle.system import SystemOperations


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / 'etc').mkdir()

    def release(self, text):
        (self.root / 'etc/os-release').write_text(text)

    def test_explicit_supported_ids_and_immutable_specifications(self):
        cases = {'fedora': ('fedora', 'rpm', 'dnf4'),
                 **{name: ('rhel', 'rpm', 'dnf4') for name in ('rhel', 'rocky', 'almalinux', 'centos')},
                 **{name: ('debian', 'deb', 'apt') for name in ('debian', 'ubuntu')},
                 **{name: ('arch', 'pacman', 'pacman') for name in ('arch', 'cachyos', 'endeavouros')}}
        for identity, expected in cases.items():
            self.release(f'NAME="Test Distribution"\nID="{identity}"\n')
            spec = detect_platform(self.root)
            with self.subTest(identity=identity):
                self.assertEqual((spec.family, spec.package_provider, spec.hook_provider), expected)
                self.assertEqual(spec.id, identity)
                self.assertTrue(spec.library_paths)
                with self.assertRaises(FrozenInstanceError):
                    spec.family = 'other'

    def test_fedora_hook_feature_detection(self):
        self.release('ID=fedora\n')
        (self.root / 'usr/bin').mkdir(parents=True)
        (self.root / 'usr/bin/dnf5').touch()
        self.assertEqual(detect_platform(self.root).hook_provider, 'dnf5')

    def test_distribution_owned_os_release_symlink(self):
        (self.root / 'usr/lib').mkdir(parents=True)
        (self.root / 'usr/lib/os-release').write_text('ID=ubuntu\n')
        (self.root / 'etc/os-release').symlink_to('/usr/lib/os-release')
        self.assertEqual(detect_platform(self.root).id, 'ubuntu')

    def test_unknown_ostree_duplicate_and_unsafe_identity_refused(self):
        for text in ('ID=unknown\nID_LIKE="fedora rhel"\n', 'ID=fedora\nID=arch\n', 'ID="unterminated\n'):
            self.release(text)
            with self.subTest(text=text), self.assertRaises(LifecycleError):
                detect_platform(self.root)
        self.release('ID=fedora\n')
        (self.root / 'run').mkdir()
        (self.root / 'run/ostree-booted').touch()
        with self.assertRaisesRegex(LifecycleError, 'ostree'):
            detect_platform(self.root)

    def test_legacy_new_adapter_defaults_to_fedora(self):
        self.assertEqual(SystemOperations.__new__(SystemOperations).platform, FEDORA_PLATFORM)

    def test_arch_resolves_merged_usr_commands_without_path_search(self):
        ops = SystemOperations.__new__(SystemOperations)
        ops._platform = ARCH_PLATFORM
        with patch('nvidia_vbios.lifecycle.system.Path.exists', return_value=False):
            self.assertEqual(ops.command_path('modinfo'), '/usr/bin/modinfo')
            self.assertEqual(ops.command_path('dkms'), '/usr/bin/dkms')
            self.assertEqual(ops.command_path('unknown'), 'unknown')

    def test_native_rpm_locations(self):
        self.assertEqual(rpm_lock_path(self.root), self.root / 'var/lib/rpm/.rpm.lock')
        (self.root / 'usr/lib/sysimage/rpm').mkdir(parents=True)
        self.assertEqual(rpm_lock_path(self.root), self.root / 'usr/lib/sysimage/rpm/.rpm.lock')

    def test_pacman_uses_exclusive_lockfile_and_never_steals_existing_lock(self):
        directory = self.root / 'var/lib/pacman'
        directory.mkdir(parents=True)
        path = directory / 'db.lck'
        with package_transaction_lock(ARCH_PLATFORM, self.root):
            self.assertTrue(path.is_file())
            with self.assertRaisesRegex(LifecycleError, 'busy'):
                with package_transaction_lock(ARCH_PLATFORM, self.root):
                    pass
        self.assertFalse(path.exists())
        path.write_text('existing pacman transaction\n')
        with self.assertRaisesRegex(LifecycleError, 'busy'):
            with package_transaction_lock(ARCH_PLATFORM, self.root):
                pass
        self.assertEqual(path.read_text(), 'existing pacman transaction\n')

    def test_pacman_only_unlinks_its_own_inode_on_exit(self):
        directory = self.root / 'var/lib/pacman'
        directory.mkdir(parents=True)
        path = directory / 'db.lck'
        with package_transaction_lock(ARCH_PLATFORM, self.root):
            path.rename(directory / 'original')
            path.write_text('replacement lock\n')
        self.assertEqual(path.read_text(), 'replacement lock\n')

    def test_debian_locks_interoperate_with_record_locks_and_persist(self):
        directory = self.root / 'var/lib/dpkg'
        directory.mkdir(parents=True)
        path = directory / 'lock'
        child = subprocess.Popen([sys.executable, '-c',
            'import fcntl,sys; f=open(sys.argv[1],"w"); fcntl.lockf(f,fcntl.LOCK_EX); print("locked",flush=True); sys.stdin.read()', str(path)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(child.stdout.readline().strip(), 'locked')
            with self.assertRaisesRegex(LifecycleError, 'busy'):
                with package_transaction_lock(DEBIAN_PLATFORM, self.root):
                    pass
        finally:
            child.communicate(timeout=10)
        with package_transaction_lock(DEBIAN_PLATFORM, self.root):
            self.assertTrue((directory / 'lock-frontend').exists())
        self.assertTrue(path.exists())

    def test_stock_builder_calls_are_mocked_and_manual_is_independent(self):
        ops = SystemOperations.__new__(SystemOperations)
        ops._platform = RHEL_PLATFORM
        ops._run = MagicMock()
        ops.coordinate_stock_build('6.12.0-test', {'userspace': {'provider': 'manual'}})
        ops._run.assert_not_called()
        ops.coordinate_stock_build('6.12.0-test', {'userspace': {'provider': 'rpm'}})
        ops._run.assert_not_called()
        ops.coordinate_stock_build('6.12.0-test', {'stock_builder': 'dkms'})
        ops._run.assert_called_once_with(['dkms', 'autoinstall', '-k', '6.12.0-test'], timeout=3600)


if __name__ == '__main__':
    unittest.main()
