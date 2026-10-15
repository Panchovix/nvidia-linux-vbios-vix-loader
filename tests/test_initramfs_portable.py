"""Portable builders exercise private inputs only; commands are always mocked."""
from __future__ import annotations

import os
import shlex
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
import uuid

from nvidia_vbios.lifecycle import initramfs as subject
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write


def pe_image(sections, *, subsystem=10):
    """Minimal structurally valid EFI PE with file padding unlike section bytes."""
    offset, optional_size, table = 0x80, 240, 0x80 + 24 + 240
    start = ((table + len(sections) * 40 + 511) // 512) * 512
    image = bytearray(start)
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 60, offset)
    image[offset:offset + 4] = b'PE\0\0'
    struct.pack_into('<HH', image, offset + 4, 0x8664, len(sections))
    struct.pack_into('<H', image, offset + 20, optional_size)
    struct.pack_into('<H', image, offset + 24, 0x20b)
    struct.pack_into('<H', image, offset + 24 + 68, subsystem)
    for number, (name, value) in enumerate(sections.items()):
        entry = table + number * 40
        size = ((len(value) + 511) // 512) * 512
        image[entry:entry + 8] = name.encode().ljust(8, b'\0')
        struct.pack_into('<IIII', image, entry + 8, len(value), (number + 1) * 4096, size, len(image))
        image.extend(value + b'\0' * (size - len(value)))
    return bytes(image)


class FakeOps:
    def __init__(self, root):
        self.filesystem_root = root
        self.commands = []
        self.snapshots = {}
        self.files = {}
        self.listing = None
        self.secure_state = b'SecureBoot disabled\n'
        self.der = b'\x30\x03der'
        self.database = None
        self.uki_fault = None
        self.command_fault = None
        self.arch_mode = 'busybox'
        self.arch_fault = None
        self.links = {}

    def _run(self, command, **kwargs):
        command = [str(value) for value in command]
        self.commands.append((command, kwargs))
        executable = Path(command[0]).name
        if self.command_fault == executable:
            raise LifecycleError('mock command failure')
        if executable == 'dracut':
            atomic_write(Path(command[-1]), b'PORTABLE DRACUT IMAGE')
        elif executable == 'lsinitrd':
            name = command[command.index('--file') + 1]
            return subprocess.CompletedProcess(command, 0 if name in self.files else 1, stdout=self.files.get(name, b''), stderr=b'')
        elif executable == 'mkinitramfs':
            private = Path(command[command.index('-d') + 1])
            self.snapshots['config'] = {str(path.relative_to(private)): path.read_bytes()
                                        for path in private.rglob('*') if path.is_file()}
            atomic_write(Path(command[command.index('-o') + 1]), b'DEBIAN IMAGE')
        elif executable == 'mkinitcpio':
            private = Path(command[command.index('-c') + 1])
            self.snapshots['config'] = private.read_bytes()
            hooks = Path(command[command.index('-D') + 1])
            self.snapshots['hooks'] = {str(path.relative_to(hooks)): path.read_bytes()
                                       for path in hooks.rglob('*') if path.is_file()}
            self.snapshots['raw'] = [Path(shlex.split(line)[1]).read_bytes()
                                     for line in self.snapshots['hooks']['install/vbios_override'].decode().splitlines()
                                     if line.lstrip().startswith('add_file ')]
            atomic_write(Path(command[command.index('-g') + 1]), b'ARCH IMAGE')
            self.files = {'init': (self.filesystem_root / 'usr/lib/initcpio/init').read_bytes(), 'config': b'MODULES="ext4 nvidia nvidia_modeset nvidia_drm nvidia_uvm"\nEARLYHOOKS="udev vbios_override"\nHOOKS="encrypt"\nLATEHOOKS=""\nCLEANUPHOOKS=""\nEMERGENCYHOOKS=""\n'}
            self.links = {}
            if self.arch_mode == 'systemd':
                self.files.pop('init')
                self.files.pop('config')
                self.links['init'] = 'usr/lib/systemd/systemd'
                self.links[subject.SYSTEMD_WANT_PATH] = '../systemd-modules-load.service'
                self.files.update({member: (self.filesystem_root / member).read_bytes()
                                   for member in (subject.SYSTEMD_INIT_PATH, subject.SYSTEMD_UNIT_PATH, subject.SYSTEMD_LOAD_BINARY)})
                self.files[subject.LOAD_PATH] = subject.LOAD_BYTES
                if self.arch_fault == 'disabled':
                    self.links.pop(subject.SYSTEMD_WANT_PATH)
                elif self.arch_fault == 'foreign-link':
                    self.links[subject.SYSTEMD_WANT_PATH] = '../foreign.service'
                elif self.arch_fault == 'wrong-unit':
                    self.files[subject.SYSTEMD_UNIT_PATH] = b'[Service]\nExecStart=/usr/bin/false\n'
                elif self.arch_fault == 'wrong-load':
                    self.files[subject.LOAD_PATH] = b'foreign\n'
                elif self.arch_fault == 'masked':
                    self.links['etc/systemd/system/systemd-modules-load.service'] = '/dev/null'
                elif self.arch_fault == 'drop-in':
                    self.files['etc/systemd/system/systemd-modules-load.service.d/override.conf'] = b'[Service]\nExecStart=\n'
                elif self.arch_fault == 'regular-wants':
                    self.links.pop(subject.SYSTEMD_WANT_PATH)
                    self.files[subject.SYSTEMD_WANT_PATH] = self.files[subject.SYSTEMD_UNIT_PATH]
        elif executable in ('lsinitramfs', 'lsinitcpio') and '--extract' not in command:
            return subprocess.CompletedProcess(command, 0, stdout=self.listing if self.listing is not None else ('\n'.join([*self.files, *self.links]) + '\n').encode(), stderr=b'')
        elif executable in ('unmkinitramfs', 'lsinitcpio'):
            destination = Path(command[-1]) / 'main' if executable == 'unmkinitramfs' else Path(kwargs['cwd'])
            destination.mkdir(parents=True, exist_ok=True)
            for name, data in self.files.items():
                atomic_write(destination / name, data)
            for name, target in self.links.items():
                link = destination / name
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(target)
        elif executable == 'mokutil':
            return subprocess.CompletedProcess(command, 0, stdout=self.secure_state, stderr=b'')
        elif executable == 'openssl':
            atomic_write(Path(command[command.index('-out') + 1]), b'-----BEGIN CERTIFICATE-----\nMAM=\n-----END CERTIFICATE-----\n')
        elif executable == 'efi-readvar':
            if self.database is None:
                guid = uuid.UUID('a5c059a1-94e4-4aa7-87b5-ab155c2bf072').bytes_le
                entry = b'\0' * 16 + self.der
                self.database = guid + struct.pack('<III', 28 + len(entry), 0, len(entry)) + entry
            atomic_write(Path(command[command.index('-o') + 1]), self.database)
        elif executable == 'ukify':
            sections = {'.linux': Path(command[command.index('--linux') + 1]).read_bytes(),
                        '.initrd': Path(command[command.index('--initrd') + 1]).read_bytes(),
                        '.cmdline': Path(command[command.index('--cmdline') + 1][1:]).read_bytes()}
            if self.uki_fault:
                sections[self.uki_fault] += b'WRONG'
            atomic_write(Path(command[command.index('--output') + 1]), pe_image(sections))
        return subprocess.CompletedProcess(command, 0, stdout=b'', stderr=b'')


class PortableInitramfsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.ops = FakeOps(self.root)
        self.kernel = '6.14.1-test'
        self.module = self.root / f'usr/lib/modules/{self.kernel}/updates/vbios-override/nvidia.ko'
        self.firmware = self.root / 'usr/lib/firmware/nvidia/vbios/test.bin'
        atomic_write(self.module, b'\x7fELF rawmodule~Module signature appended~\nPKCS7')
        atomic_write(self.firmware, b'FIRMWARE BYTES')
        self.activation, self.force = self.root / 'scratch/activation.conf', self.root / 'scratch/force.conf'
        atomic_write(self.activation, b'options nvidia NVreg_RegistryDwords=RmLinuxVbiosOverride=2\n')
        atomic_write(self.force, b'rd.driver.pre=nvidia\n')
        self.destination = self.root / 'scratch/image.img'
        atomic_write(self.root / 'etc/initramfs-tools/initramfs.conf', b'MODULES=most\n')
        atomic_write(self.root / 'etc/initramfs-tools/hooks/rootfs', b'#!/bin/sh\n# existing root support\n', 0o755)
        atomic_write(self.root / 'etc/mkinitcpio.conf', b'HOOKS=(base udev autodetect modconf block encrypt filesystems fsck)\nMODULES=(ext4)\nFILES=()\n')
        atomic_write(self.root / 'etc/mkinitcpio.conf.d/50-local.conf', b'HOOKS+=(lvm2)\n')
        atomic_write(self.root / 'usr/lib/initcpio/init', b'#!/bin/ash\n# native busybox init\n')
        atomic_write(self.root / subject.SYSTEMD_INIT_PATH, b'\x7fELF native systemd')
        atomic_write(self.root / subject.SYSTEMD_LOAD_BINARY, b'\x7fELF native modules-load')
        atomic_write(self.root / subject.SYSTEMD_UNIT_PATH, b'[Unit]\nBefore=sysinit.target shutdown.target\n[Service]\nExecStart=/usr/lib/systemd/systemd-modules-load\n')
        atomic_write(self.root / 'usr/lib/initcpio/install/base', b'# existing base\n', 0o755)
        atomic_write(self.root / 'etc/initcpio/install/custom', b'# existing local\n', 0o755)

    def tearDown(self):
        self.temporary.cleanup()

    def build(self, name):
        return subject.build(self.ops, self.kernel, self.destination, [self.module, self.firmware],
                             activation_config=self.activation, force_config=self.force,
                             config={'boot': {'initramfs': name}})

    def test_debian_uses_private_config_with_force_load_and_exact_runtime_script(self):
        before = (self.root / 'etc/initramfs-tools/initramfs.conf').read_bytes()
        evidence = self.build('initramfs-tools')
        config = self.ops.snapshots['config']
        self.assertIn(b'force_load nvidia', config['hooks/zzzz_vbios_override'])
        self.assertIn(b'cp --', config['hooks/zzzz_vbios_override'])
        self.assertEqual(config[subject.DEBIAN_LOAD_PATH], subject.DEBIAN_LOAD_BYTES)
        self.assertEqual(evidence[subject.DEBIAN_LOAD_PATH], subject.DEBIAN_LOAD_BYTES)
        self.assertEqual(evidence[subject.ACTIVATION_PATH], self.activation.read_bytes())
        self.assertEqual((self.root / 'etc/initramfs-tools/initramfs.conf').read_bytes(), before)
        command = self.ops.commands[0][0]
        self.assertEqual(command[0], '/usr/sbin/mkinitramfs')
        self.assertEqual(command[-1], self.kernel)
        self.assertFalse(list(self.destination.parent.glob('.vbios-build-*')))

    def test_portable_dracut_preserves_force_loading_and_separate_include_arguments(self):
        path = self.firmware.with_name('0000:03:00.0-1234567890abcdef.bin')
        atomic_write(path, b'BDF FIRMWARE')
        self.firmware = path
        evidence = self.build('dracut')
        command = self.ops.commands[0][0]
        self.assertEqual(command[0], '/usr/bin/dracut')
        self.assertIn('--nostrip', command)
        self.assertIn('--force-drivers', command)
        self.assertNotIn('--install', command)
        self.assertIn(str(path), command)
        self.ops.files = evidence
        result = subject.extract(self.ops, self.destination, list(evidence), config={'boot': {'initramfs': 'dracut'}})
        self.assertEqual(result, evidence)
        self.assertTrue(all(Path(c[0]).name == 'lsinitrd' for c, _ in self.ops.commands[1:]))

    def test_arch_preserves_root_hooks_dropins_and_raw_signed_bytes(self):
        before = (self.root / 'etc/mkinitcpio.conf').read_bytes()
        evidence = self.build('mkinitcpio')
        text = self.ops.snapshots['config']
        self.assertTrue(text.startswith(before))
        self.assertIn(b'HOOKS+=(lvm2)', text)
        self.assertIn(b'MODULES+=(nvidia', text)
        self.assertIn(b'MODULES_DECOMPRESS=no', text)
        hooks = self.ops.snapshots['hooks']
        self.assertIn('install/base', hooks)
        self.assertIn('install/custom', hooks)
        self.assertEqual(hooks['hooks/vbios_override'], evidence[subject.ARCH_LOAD_PATH])
        command = self.ops.commands[0][0]
        self.assertIn('--nopost', command)
        self.assertNotIn('-P', command)
        self.assertNotIn('-U', command)
        self.assertIn(self.module.read_bytes(), self.ops.snapshots['raw'])
        self.assertIn(self.firmware.read_bytes(), self.ops.snapshots['raw'])
        self.assertEqual((self.root / 'etc/mkinitcpio.conf').read_bytes(), before)
        self.assertEqual(evidence['config'], self.ops.files['config'])

    def test_arch_systemd_uses_enabled_native_unit_and_exact_modules_load_request(self):
        atomic_write(self.root / 'etc/mkinitcpio.conf', b'HOOKS=(base systemd autodetect modconf block filesystems fsck)\nMODULES=()\nFILES=()\n')
        self.ops.arch_mode = 'systemd'
        evidence = self.build('mkinitcpio')
        self.assertNotIn(subject.ARCH_LOAD_PATH, evidence)
        self.assertNotIn('config', evidence)
        self.assertEqual(evidence[subject.SYSTEMD_WANT_PATH], subject._LINK_PROOF + b'../systemd-modules-load.service')
        self.assertEqual(evidence[subject.INIT_PATH], subject._LINK_PROOF + b'usr/lib/systemd/systemd')
        self.assertEqual(evidence[subject.SYSTEMD_UNIT_PATH], (self.root / subject.SYSTEMD_UNIT_PATH).read_bytes())
        self.assertEqual(evidence[subject.LOAD_PATH], subject.LOAD_BYTES)

    def test_arch_systemd_rejects_unused_hook_as_proof_for_disabled_or_wrong_service(self):
        self.ops.arch_mode = 'systemd'
        for fault in ('disabled', 'foreign-link', 'wrong-unit', 'wrong-load', 'regular-wants', 'masked', 'drop-in'):
            with self.subTest(fault=fault):
                self.ops.arch_fault = fault
                with self.assertRaises(LifecycleError):
                    self.build('mkinitcpio')

    def test_systemd_wants_proof_handles_usrmerge_without_following_link(self):
        tree = self.root / 'scratch/usrmerge'
        tree.mkdir()
        (tree / 'lib').symlink_to('usr/lib')
        link = tree / subject.SYSTEMD_WANT_PATH
        link.parent.mkdir(parents=True)
        link.symlink_to('../systemd-modules-load.service')
        self.assertEqual(subject._read_extracted(tree, subject.SYSTEMD_WANT_PATH.removeprefix('usr/')),
                         subject._LINK_PROOF + b'../systemd-modules-load.service')

    def test_private_config_rejects_untrusted_source_and_symlink(self):
        source = self.root / 'etc/mkinitcpio.conf'
        source.chmod(0o666)
        with self.assertRaisesRegex(LifecycleError, 'untrusted'):
            self.build('mkinitcpio')
        source.chmod(0o600)
        source.unlink()
        source.symlink_to('mkinitcpio.conf.d/50-local.conf')
        with self.assertRaisesRegex(LifecycleError, 'symlink'):
            self.build('mkinitcpio')

    def test_rejects_unknown_backend_and_input_output_alias_before_commands(self):
        with self.assertRaisesRegex(LifecycleError, 'explicitly'):
            self.build('unsupported-builder')
        self.destination = self.module
        with self.assertRaisesRegex(LifecycleError, 'aliases'):
            self.build('mkinitcpio')
        self.assertEqual(self.ops.commands, [])

    def test_real_bdf_firmware_names_are_preserved_for_debian_and_arch(self):
        path = self.firmware.with_name('0000:03:00.0-1234567890abcdef.bin')
        atomic_write(path, b'ENROLLED BDF FIRMWARE')
        self.firmware = path
        self.build('initramfs-tools')
        hook = self.ops.snapshots['config']['hooks/zzzz_vbios_override']
        self.assertIn(str(path).encode(), hook)
        self.build('mkinitcpio')
        hook = self.ops.snapshots['hooks']['install/vbios_override'].decode()
        mapping = [shlex.split(line) for line in hook.splitlines() if line.lstrip().startswith('add_file ')]
        self.assertIn(['add_file', str(path), '/' + str(path.relative_to(self.root)), '644'], mapping)
        self.assertIn(path.read_bytes(), self.ops.snapshots['raw'])
        self.assertNotIn('-I', self.ops.commands[1][0])

    def test_private_hook_handles_spaces_and_mapping_delimiters_literally(self):
        path = self.firmware.with_name("0000:03:00.0 firmware,quote'.bin")
        atomic_write(path, b'EXACT FIRMWARE')
        self.firmware = path
        self.build('mkinitcpio')
        hook = self.ops.snapshots['hooks']['install/vbios_override'].decode()
        mapping = [shlex.split(line) for line in hook.splitlines() if line.lstrip().startswith('add_file ')]
        self.assertIn(['add_file', str(path), '/' + str(path.relative_to(self.root)), '644'], mapping)
        self.assertIn(path.read_bytes(), self.ops.snapshots['raw'])

    def test_shell_quotes_managed_paths_without_interpolating_content(self):
        path = self.module.with_name("evil'$(touch BAD).ko")
        atomic_write(path, b'other raw module')
        subject.build(self.ops, self.kernel, self.destination, [self.module, path],
                      activation_config=self.activation, force_config=self.force,
                      config={'boot': {'initramfs': 'mkinitcpio'}})
        text = self.ops.snapshots['config'].decode()
        self.assertIn("'\"'\"'", text)
        self.assertFalse((self.root / 'BAD').exists())

    def test_extract_debian_main_and_usrmerge_alias_with_one_unpack(self):
        atomic_write(self.destination, b'mocked archive')
        self.ops.files = {'lib/modules/test/nvidia.ko': self.module.read_bytes(), subject.ACTIVATION_PATH: self.activation.read_bytes()}
        result = subject.extract(self.ops, self.destination, ['usr/lib/modules/test/nvidia.ko', subject.ACTIVATION_PATH, 'missing/file'],
                                 config={'boot': {'initramfs': 'initramfs-tools'}})
        self.assertEqual(result['usr/lib/modules/test/nvidia.ko'], self.module.read_bytes())
        self.assertIsNone(result['missing/file'])
        self.assertEqual(sum(Path(c[0]).name == 'unmkinitramfs' for c, _ in self.ops.commands), 1)
        self.assertFalse(list(self.destination.parent.glob('.vbios-extract-*')))

    def test_extract_arch_uses_cwd_and_rejects_conflicting_aliases(self):
        atomic_write(self.destination, b'mocked archive')
        self.ops.files = {'lib/module.ko': b'one', 'usr/lib/module.ko': b'two'}
        with self.assertRaisesRegex(LifecycleError, 'conflicting'):
            subject.extract(self.ops, self.destination, ['usr/lib/module.ko'], config={'boot': {'initramfs': 'mkinitcpio'}})
        self.assertIn('cwd', self.ops.commands[1][1])

    def test_extract_rejects_members_and_archive_traversal_before_unpack(self):
        atomic_write(self.destination, b'mocked archive')
        for member in ('../escape', '/absolute', 'a/../b', 'a//b', './file', 'a\\b'):
            with self.subTest(member=member), self.assertRaisesRegex(LifecycleError, 'member'):
                subject.extract(self.ops, self.destination, [member], config={'boot': {'initramfs': 'mkinitcpio'}})
        self.assertEqual(self.ops.commands, [])
        self.ops.listing = b'../../outside\n'
        with self.assertRaisesRegex(LifecycleError, 'member'):
            subject.extract(self.ops, self.destination, ['file'], config={'boot': {'initramfs': 'mkinitcpio'}})
        self.assertEqual(len(self.ops.commands), 1)

    def test_extracted_symlink_escape_is_rejected(self):
        tree = self.root / 'scratch/extracted'
        tree.mkdir()
        (tree / 'etc').symlink_to('/etc')
        with self.assertRaisesRegex(LifecycleError, 'escaping'):
            subject._read_extracted(tree, 'etc/passwd')

    def uki(self, signing=None):
        kernel, image = self.root / 'scratch/kernel', self.root / 'scratch/initrd'
        atomic_write(kernel, b'immutable kernel bytes')
        atomic_write(image, b'microcode\0initramfs')
        config = {'boot': {'uki': {}}}
        if signing:
            config['boot']['uki']['signing'] = signing
        return subject.build_uki(self.ops, kernel, image, self.root / 'scratch/test.efi',
                                 cmdline='root=UUID=reviewed ro', config=config)

    def signing(self):
        atomic_write(self.root / 'etc/secureboot/key.pem', b'PRIVATE KEY')
        atomic_write(self.root / 'etc/secureboot/certificate.der', self.ops.der)
        return {'key': '/etc/secureboot/key.pem', 'certificate': '/etc/secureboot/certificate.der', 'trust': 'firmware-db'}

    def test_uki_preserves_exact_sections_and_disables_kernel_resigning(self):
        evidence = self.uki()
        self.assertFalse(evidence['signed'])
        command = next(c for c, _ in self.ops.commands if Path(c[0]).name == 'ukify')
        self.assertEqual(command[0], '/usr/lib/systemd/ukify')
        self.assertIn('--no-sign-kernel', command)
        self.assertIn('--config', command)
        sections = subject.extract_uki_sections(self.root / 'scratch/test.efi')
        self.assertEqual(sections['.cmdline'], b'root=UUID=reviewed ro')
        self.assertEqual(sections['.initrd'], b'microcode\0initramfs')
        self.assertFalse(list(self.destination.parent.glob('.vbios-uki-*')))

    def test_secure_uki_converts_der_checks_firmware_db_and_verifies_signature(self):
        self.ops.secure_state = b'SecureBoot enabled\n'
        evidence = self.uki(self.signing())
        self.assertTrue(evidence['signed'])
        self.assertEqual(evidence['signing_trust'], 'firmware-db')
        commands = [Path(c[0]).name for c, _ in self.ops.commands]
        self.assertEqual(commands, ['mokutil', 'openssl', 'efi-readvar', 'ukify', 'sbverify'])

    def test_secure_uki_blocks_missing_or_untrusted_signer(self):
        self.ops.secure_state = b'SecureBoot enabled\n'
        with self.assertRaisesRegex(LifecycleError, 'PE signing'):
            self.uki()
        signing = self.signing()
        self.ops.database = b''
        with self.assertRaisesRegex(LifecycleError, 'firmware db'):
            self.uki(signing)
        signing['trust'] = 'shim-mok'
        with self.assertRaisesRegex(LifecycleError, 'MOK alone'):
            self.uki(signing)

    def test_uki_rejects_unknown_secure_boot_or_writable_key(self):
        self.ops.secure_state = b'unknown firmware state\n'
        with self.assertRaisesRegex(LifecycleError, 'determine'):
            self.uki()
        self.ops.secure_state = b'SecureBoot enabled\n'
        signing = self.signing()
        (self.root / 'etc/secureboot/key.pem').chmod(0o644)
        with self.assertRaisesRegex(LifecycleError, 'root-only'):
            self.uki(signing)

    def test_uki_rejects_each_wrong_embedded_component(self):
        for section in ('.linux', '.initrd', '.cmdline'):
            with self.subTest(section=section):
                self.ops.uki_fault = section
                with self.assertRaisesRegex(LifecycleError, 'immutable inputs'):
                    self.uki()

    def test_uki_signature_verification_failure_is_not_ready_evidence(self):
        self.ops.command_fault = 'sbverify'
        with self.assertRaisesRegex(LifecycleError, 'command failure'):
            self.uki(self.signing())

    def test_pe_section_parser_uses_virtual_size_and_supports_uname(self):
        sections = {'.linux': b'kernel', '.initrd': b'initrd', '.cmdline': b'ro\0', '.uname': b'6.14.1\0'}
        self.assertEqual(subject.extract_uki_sections(pe_image(sections), tuple(sections)), sections)
        for invalid in (b'not PE', pe_image(sections, subsystem=3), pe_image({'.linux': b'kernel'})):
            with self.subTest(invalid=invalid[:2]), self.assertRaisesRegex(LifecycleError, 'invalid UKI'):
                subject.extract_uki_sections(invalid)

    def test_arch_registration_requires_actual_module_and_hook_without_evaluation(self):
        for data in (None, b'MODULES="ext4"\nEARLYHOOKS="vbios_override"\n',
                     b'MODULES="nvidia"\nEARLYHOOKS="udev"\n',
                     b'MODULES="$(touch /tmp/escape)"\nEARLYHOOKS="vbios_override"\n'):
            with self.subTest(data=data), self.assertRaises(LifecycleError):
                subject._verify_arch_registration(data)

    def test_pe_parser_allows_uninitialized_stub_bss(self):
        sections = {'.linux': b'kernel', '.initrd': b'initrd', '.cmdline': b'ro', '.bss': b'x'}
        data = bytearray(pe_image(sections))
        entry = 0x80 + 24 + 240 + 3 * 40
        struct.pack_into('<IIII', data, entry + 8, 4096, 16384, 0, 0)
        self.assertEqual(subject.extract_uki_sections(bytes(data))['.linux'], b'kernel')

    def test_firmware_db_parser_rejects_truncated_signature_list(self):
        with self.assertRaisesRegex(LifecycleError, 'malformed'):
            subject._db_has_certificate(b'\0' * 27, self.ops.der)
        with self.assertRaisesRegex(LifecycleError, 'malformed'):
            subject._db_has_certificate(b'\0' * 16 + struct.pack('<III', 100, 0, 20), self.ops.der)


if __name__ == '__main__':
    unittest.main()
