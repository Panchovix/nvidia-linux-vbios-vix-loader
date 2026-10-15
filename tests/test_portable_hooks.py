"""Portable callbacks and provider discovery remain offline and read-only."""
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from nvidia_vbios.lifecycle.platform import FEDORA_PLATFORM, RHEL_PLATFORM, DEBIAN_PLATFORM, ARCH_PLATFORM
from nvidia_vbios.lifecycle.portable_hooks import (
    APT_TARGET, PACMAN_TARGET, DNF_TARGETS, SERVICE_TARGET, KERNEL_INSTALL_TARGET,
    hook_templates_for, activation_provider, activation_templates, returnactivationtemplates,
    provider_available,
)
from nvidia_vbios.lifecycle.security import LifecycleError
from nvidia_vbios.lifecycle.templates import hook_templates


class PortableHookTests(unittest.TestCase):
    def test_legacy_fedora_bundle_remains_exact(self):
        self.assertEqual(hook_templates_for(FEDORA_PLATFORM), hook_templates())
        self.assertEqual(hook_templates_for(replace(FEDORA_PLATFORM, hook_provider='dnf4')), hook_templates())

    def test_native_provider_catalogs_are_single_activation_files(self):
        for provider, destination in {**DNF_TARGETS, 'apt': APT_TARGET, 'pacman': PACMAN_TARGET}.items():
            with self.subTest(provider=provider):
                templates = returnactivationtemplates(provider)
                self.assertEqual(set(templates), {destination})
                self.assertIsInstance(templates[destination], bytes)
                self.assertEqual(activation_templates(provider), templates)
        self.assertEqual(activation_provider(RHEL_PLATFORM), 'dnf4')
        with self.assertRaises(LifecycleError):
            returnactivationtemplates('other')

    def test_rhel_requires_only_dnf4_and_neutral_service(self):
        catalog = hook_templates_for(RHEL_PLATFORM)
        self.assertIn(DNF_TARGETS['dnf4'], catalog)
        self.assertNotIn(DNF_TARGETS['dnf5'], catalog)
        service = catalog[SERVICE_TARGET]['data'].decode()
        self.assertNotIn('Fedora', service)
        self.assertNotIn('akmods.service', service)
        self.assertIn('-/var/lib/rpm', service)
        self.assertIn('-/usr/lib/sysimage/rpm', service)

    def test_apt_deferred_callback_uses_documented_list_syntax(self):
        catalog = hook_templates_for(DEBIAN_PLATFORM)
        callback = catalog[APT_TARGET]['data'].decode()
        self.assertIn('DPkg::Post-Invoke { "/usr/libexec/nvidia-vbios lifecycle post-transaction --defer"; };', callback)
        self.assertNotIn('systemctl', callback)
        for directory, action in (('postinst', 'add'), ('postrm', 'remove')):
            hook = catalog[f'/etc/kernel/{directory}.d/zz-nvidia-vbios']
            self.assertEqual(hook['mode'], 0o755)
            self.assertIn(f'lifecycle queue {action} "${{1-}}"', hook['data'].decode())
            self.assertNotIn('eval', hook['data'].decode())
        self.assertIn(KERNEL_INSTALL_TARGET, catalog)
        self.assertNotIn(DNF_TARGETS['dnf4'], catalog)

    def test_pacman_has_package_triggers_and_one_fixed_deferred_action(self):
        text = hook_templates_for(ARCH_PLATFORM)[PACMAN_TARGET]['data'].decode()
        self.assertEqual(text.count('[Trigger]'), 1)
        self.assertEqual(text.count('[Action]'), 1)
        self.assertIn('Type = Package', text)
        for operation in ('Install', 'Upgrade', 'Remove'):
            self.assertIn('Operation = ' + operation, text)
        for target in ('linux*', 'nvidia*', 'lib32-nvidia*', 'opencl-nvidia*', 'lib32-opencl-nvidia*'):
            self.assertIn('Target = ' + target, text)
        self.assertIn('When = PostTransaction', text)
        self.assertIn('Exec = /usr/libexec/nvidia-vbios lifecycle post-transaction --defer', text)
        self.assertNotIn('NeedsTargets', text)
        self.assertNotIn('AbortOnFail', text)
        self.assertNotIn('/bin/sh', text)

    def test_units_allow_boot_layout_and_native_database_while_preserving_retry(self):
        for platform, database in ((DEBIAN_PLATFORM, '/var/lib/dpkg'), (ARCH_PLATFORM, '/var/lib/pacman')):
            with self.subTest(platform=platform.id):
                catalog = hook_templates_for(platform, {'backend': 'uki', 'boot_root': '/boot', 'esp': '/efi', 'xbootldr': '/xbootldr'})
                service = catalog[SERVICE_TARGET]['data'].decode()
                paths = next(line for line in service.splitlines() if line.startswith('ReadWritePaths=')).split('=', 1)[1].split()
                self.assertTrue({'/var/lib/nvidia-vbios', '/usr/lib/modules', '/usr/lib/firmware/nvidia', '/boot', '/efi', '/xbootldr', database}.issubset(paths))
                self.assertNotIn('/etc/grub.d', paths)
                self.assertIn('ProtectSystem=strict', service)
                self.assertIn('NoNewPrivileges=yes', service)
                self.assertIn('/usr/libexec/nvidia-vbios lifecycle reconcile', service)
                timer = catalog['/usr/lib/systemd/system/nvidia-vbios-reconcile.timer']['data']
                self.assertIn(b'OnUnitInactiveSec=15min', timer)
                self.assertEqual(timer, hook_templates()['/usr/lib/systemd/system/nvidia-vbios-reconcile.timer']['data'])
        catalog = hook_templates_for(ARCH_PLATFORM, {'backend': 'grub', 'grub_config': '/boot/grub/grub.cfg'})
        self.assertIn(b'-/etc/grub.d', catalog[SERVICE_TARGET]['data'])

    def test_boot_environment_object_and_enrollment_are_accepted(self):
        for boot in (SimpleNamespace(config={'backend': 'systemd-boot', 'esp': '/efi'}),
                     SimpleNamespace(raw={'boot': {'backend': 'systemd-boot', 'esp': '/efi'}})):
            self.assertIn(b'/efi', hook_templates_for(ARCH_PLATFORM, boot)[SERVICE_TARGET]['data'])

    def test_untrusted_boot_path_cannot_inject_unit_directives_or_expand_writable_scope(self):
        for value in ('/', '/efi\nExecStart=/bin/false', '/efi other', '/boot/../etc', '/efi%S', '//etc', '/boot/./efi'):
            with self.subTest(value=value), self.assertRaises(LifecycleError):
                hook_templates_for(ARCH_PLATFORM, {'backend': 'uki', 'esp': value})
        with self.assertRaises(LifecycleError):
            hook_templates_for(ARCH_PLATFORM, {'backend': 'grub', 'grub_config': '/etc/grub.cfg'})


class ProviderAvailabilityTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'usr/bin'
        self.bin.mkdir(parents=True)
        self.ops = SimpleNamespace(filesystem_root=self.root, _run=MagicMock())

    def executable(self, name):
        path = self.bin / name
        path.write_bytes(b'\x7fELFsynthetic')
        path.chmod(0o755)
        return path

    def response(self, text='', code=0):
        self.ops._run.return_value = subprocess.CompletedProcess([], code, stdout=text.encode(), stderr=b'')

    def test_missing_nonexecutable_or_untrusted_frontend_is_unavailable_without_query(self):
        self.assertFalse(provider_available(self.ops, 'apt'))
        path = self.executable('apt-get')
        self.executable('dpkg-query')
        path.chmod(0o644)
        self.assertFalse(provider_available(self.ops, 'apt'))
        path.chmod(0o777)
        self.assertFalse(provider_available(self.ops, 'apt'))
        self.ops._run.assert_not_called()

    def test_dnf_plugins_are_read_only_rpm_queries(self):
        self.executable('rpm')
        for provider, frontend, package in (('dnf5', 'dnf5', 'libdnf5-plugin-actions'),
                                             ('dnf4', 'dnf', 'python3-dnf-plugin-post-transaction-actions')):
            self.executable(frontend)
            self.response()
            self.assertTrue(provider_available(self.ops, provider))
            self.ops._run.assert_called_with(['rpm', '--nosignature', '-q', package], allow_failure=True)
            self.response(code=1)
            self.assertFalse(provider_available(self.ops, provider))

    def test_apt_requires_both_fully_installed_package_records(self):
        self.executable('apt-get')
        self.executable('dpkg-query')
        self.response('apt\tinstalled\tok\ndpkg\tinstalled\tok\n')
        self.assertTrue(provider_available(SimpleNamespace(system=self.ops), 'apt'))
        for text in ('apt\tunpacked\tok\ndpkg\tinstalled\tok\n', 'apt\tinstalled\tok\n',
                     'apt\tinstalled\tok\napt\tinstalled\tok\ndpkg\tinstalled\tok\n'):
            self.response(text)
            with self.subTest(text=text):
                self.assertFalse(provider_available(self.ops, 'apt'))
        self.assertEqual(self.ops._run.call_args.args[0][0:2], ['dpkg-query', '-W'])

    def test_pacman_checks_only_local_package_metadata(self):
        self.executable('pacman')
        self.response('pacman 7.1.0-1\n')
        self.assertTrue(provider_available(self.ops, 'pacman'))
        self.ops._run.assert_called_once_with(['pacman', '-Q', 'pacman'], allow_failure=True)
        self.response('pacman 7.1.0-1\nextra record\n')
        self.assertFalse(provider_available(self.ops, 'pacman'))


if __name__ == '__main__':
    unittest.main()
