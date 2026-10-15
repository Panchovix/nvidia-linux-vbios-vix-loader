"""Portable boot plans use synthetic roots and never execute bootloader text."""
import hashlib
from pathlib import Path
import struct
import tempfile
import unittest

from nvidia_vbios.lifecycle.boot import BootAdapter, entry_identity, validate_config
from nvidia_vbios.lifecycle.security import LifecycleError


KERNEL = '6.12.10-test'


def pe_image(sections):
    optional_size = 112
    table = 0x98 + optional_size
    position = table + len(sections) * 40
    data = bytearray(position)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x86, len(sections))
    struct.pack_into('<H', data, 0x94, optional_size)
    struct.pack_into('<H', data, 0x98, 0x20b)
    struct.pack_into('<H', data, 0x98 + 68, 10)
    for index, (name, payload) in enumerate(sections.items()):
        start = table + index * 40
        data[start:start + 8] = name.encode().ljust(8, b'\0')
        struct.pack_into('<IIII', data, start + 8, len(payload), 0, len(payload), position)
        data.extend(payload)
        position += len(payload)
    return bytes(data)


class PortableBootTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.write('/usr/lib/modules/' + KERNEL + '/pkgbase', b'linux\n')

    def write(self, name, data):
        path = self.root / name.lstrip('/')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def adapter(self, backend='grub', **layout):
        return BootAdapter(self.root, {'boot': {'backend': backend, 'initramfs': 'mkinitcpio', **layout}})

    def grub(self, identity='normal', kernel_path=None, options='root=UUID=reviewed rw quiet', command='linux', initrd='initrd'):
        kernel_path = kernel_path or '/vmlinuz-' + KERNEL
        self.write('/boot' + kernel_path, b'kernel')
        self.write('/boot/intel-ucode.img', b'microcode')
        self.write('/boot/initramfs-' + KERNEL + '.img', b'normal-initrd')
        stanza = f"""menuentry 'Reviewed Linux' --class gnu-linux $menuentry_id_option '{identity}' {{
    insmod part_gpt
    insmod ext2
    set root='hd0,gpt2'
    if [ x$feature_platform_search_hint = xy ]; then
      search --no-floppy --fs-uuid --set=root --hint-efi=hd0,gpt2 reviewed
    else
      search --no-floppy --fs-uuid --set=root reviewed
    fi
    cryptomount -u reviewedcrypt
    {command} {kernel_path} {options}
    {initrd} /intel-ucode.img /initramfs-{KERNEL}.img
}}
"""
        self.write('/boot/grub/grub.cfg', stanza.encode())
        return stanza

    def type1(self, boot_root='/efi', name='normal.conf', version=KERNEL):
        self.write(boot_root + '/vmlinuz-' + KERNEL, b'kernel')
        self.write(boot_root + '/intel-ucode.img', b'microcode')
        self.write(boot_root + '/normal.img', b'normal-initrd')
        self.write(boot_root + '/loader/entries/' + name,
                   f'title Reviewed Linux\nversion {version}\nlinux /vmlinuz-{KERNEL}\ninitrd /intel-ucode.img\ninitrd /normal.img\noptions root=UUID=reviewed rw\n'.encode())

    def test_kernel_package_affinity_excludes_other_flavors_and_missing_identity(self):
        self.write('/usr/lib/modules/6.14-newer/pkgbase', b'linux-lts\n')
        (self.root / 'usr/lib/modules/6.15-unknown').mkdir()
        adapter = self.adapter(kernel_package='linux')
        self.assertEqual(adapter.installed_kernels(), [KERNEL])
        for other in ('6.14-newer', '6.15-unknown'):
            with self.assertRaisesRegex(LifecycleError, 'enrolled kernel package'):
                adapter.discover(other)
        self.grub()
        self.assertEqual(adapter.discover(KERNEL).kernel, KERNEL)
        self.assertEqual(self.adapter(kernel_package='linux-lts').installed_kernels(), ['6.14-newer'])

    def test_grub_clone_preserves_setup_and_generation_owned_inputs(self):
        original = self.grub()
        adapter = self.adapter()
        entry = adapter.discover(KERNEL)
        plan = adapter.plan(entry, 'vbios-generation-one')
        rendered = plan.files[plan.entry_path].decode()
        for line in original.splitlines()[1:10]:
            self.assertIn(line, rendered)
        self.assertIn('--id vbios-generation-one', rendered)
        self.assertIn('linux /nvidia-vbios/vbios-generation-one/vmlinuz root=UUID=reviewed', rendered)
        self.assertIn('/nvidia-vbios/vbios-generation-one/microcode-0-intel-ucode.img', rendered)
        self.assertEqual(plan.copy_files[plan.kernel_path], b'kernel')
        self.assertEqual(plan.copy_files[plan.supplemental_paths[0]], b'microcode')
        self.assertEqual((self.root / 'boot/grub/grub.cfg').read_text(), original)
        self.assertFalse((self.root / plan.entry_path.lstrip('/')).exists())

    def test_linuxefi_and_initrdefi_supported(self):
        self.grub(command='linuxefi', initrd='initrdefi')
        adapter = self.adapter()
        plan = adapter.plan(adapter.discover(KERNEL), 'vbios-one')
        self.assertIn(b'linuxefi /nvidia-vbios/', plan.files[plan.entry_path])
        self.assertIn(b'initrdefi /nvidia-vbios/', plan.files[plan.entry_path])

    def test_submenu_selector_and_duplicate_recipe_top_level(self):
        stanza = self.grub()
        nested = stanza.replace("'normal'", "'nested'")
        data = stanza + "submenu 'Advanced options' --id advanced {\n" + nested + '}\n'
        self.write('/boot/grub/grub.cfg', data.encode())
        adapter = self.adapter()
        self.assertEqual(adapter.discover(KERNEL).entry_id, 'normal')
        entry = adapter.discover(KERNEL, 'advanced>nested')
        self.assertEqual(entry.entry_id, 'advanced>nested')
        self.assertEqual(entry.descriptor, nested.encode())
        self.assertEqual(entry_identity('advanced>nested'), 'advanced>nested')
        with self.assertRaises(LifecycleError):
            entry_identity('advanced>nested', 'systemd-boot')

    def test_different_recipes_require_explicit_selection(self):
        stanza = self.grub()
        self.write('/boot/grub/grub.cfg', (stanza + stanza.replace("'normal'", "'alternate'").replace('rw quiet', 'rw debug')).encode())
        adapter = self.adapter()
        with self.assertRaisesRegex(LifecycleError, 'unambiguous'):
            adapter.discover(KERNEL)
        self.assertEqual(adapter.discover(KERNEL, 'alternate').entry_id, 'alternate')

    def test_unresolved_variables_and_shell_commands_rejected(self):
        for options in ('root=UUID=reviewed $kernelopts', 'root=UUID=reviewed `touch /tmp/evil`', 'rw; echo dangerous'):
            with self.subTest(options=options):
                self.grub(options=options)
                with self.assertRaises(LifecycleError):
                    self.adapter().discover(KERNEL)

    def test_ubuntu_vt_handoff_derived_or_safely_omitted(self):
        stanza = self.grub(options='root=UUID=reviewed rw quiet $vt_handoff')
        self.write('/boot/grub/grub.cfg', ('set vt_handoff=vt.handoff=7\n' + stanza).encode())
        adapter = self.adapter()
        entry = adapter.discover(KERNEL)
        self.assertIn('vt.handoff=7', entry.options)
        plan = adapter.plan(entry, 'vbios-ubuntu')
        self.assertNotIn(b'$vt_handoff', plan.files[plan.entry_path])
        self.write('/boot/grub/grub.cfg', ('set vt_handoff=vt.handoff=7\nset vt_handoff=\n' + stanza).encode())
        self.assertNotIn('vt.handoff', adapter.discover(KERNEL).options)

    def test_explicit_reviewed_option_variables_expand_without_shell(self):
        self.grub(options='root=UUID=reviewed $reviewed ${vt_handoff}')
        adapter = self.adapter(option_variables={'reviewed': 'rw quiet', 'vt_handoff': 'vt.handoff=7'})
        entry = adapter.discover(KERNEL)
        self.assertEqual(entry.options, 'root=UUID=reviewed rw quiet vt.handoff=7')
        with self.assertRaises(LifecycleError):
            self.adapter().discover(KERNEL)
        with self.assertRaises(LifecycleError):
            self.adapter(option_variables={'reviewed': '$(touch /tmp/never)'})
        self.grub(options='root=UUID=reviewed prefix=$reviewed')
        with self.assertRaises(LifecycleError):
            adapter.discover(KERNEL)

    def test_ambiguous_commands_and_paths_rejected(self):
        stanza = self.grub()
        self.write('/boot/grub/grub.cfg', stanza.replace('    initrd ', '    linux /vmlinuz-' + KERNEL + ' rw\n    initrd ').encode())
        with self.assertRaises(LifecycleError):
            self.adapter().discover(KERNEL)
        self.grub()
        self.write('/vmlinuz-' + KERNEL, b'other-root-kernel')
        with self.assertRaisesRegex(LifecycleError, 'ambiguous GRUB image'):
            self.adapter().discover(KERNEL)

    def test_rolling_arch_kernel_requires_matching_installed_copy(self):
        self.grub(kernel_path='/vmlinuz-linux')
        with self.assertRaisesRegex(LifecycleError, 'rolling kernel'):
            self.adapter().discover(KERNEL)
        source = self.write('/usr/lib/modules/' + KERNEL + '/vmlinuz', b'kernel')
        entry = self.adapter().discover(KERNEL)
        plan = self.adapter().plan(entry, 'vbios-arch-one')
        self.write('/boot/vmlinuz-linux', b'future-kernel')
        self.assertEqual(plan.copy_files[plan.kernel_path], b'kernel')
        self.assertEqual(source.read_bytes(), b'kernel')

    def test_type1_esp_relative_paths_microcode_and_options(self):
        self.type1()
        adapter = self.adapter('systemd-boot', esp='/efi')
        entry = adapter.discover(KERNEL)
        self.assertEqual(entry.entry_id, 'normal.conf')
        self.assertEqual(entry.kernel_path, '/efi/vmlinuz-' + KERNEL)
        self.assertEqual(entry.supplemental_paths, ('/efi/intel-ucode.img',))
        plan = adapter.plan(entry, 'vbios-one')
        self.assertEqual(plan.entry_id, 'vbios-one.conf')
        self.assertEqual(plan.entry_path, '/efi/loader/entries/vbios-one.conf')
        text = plan.files[plan.entry_path].decode()
        self.assertIn('linux /nvidia-vbios/vbios-one/vmlinuz', text)
        self.assertLess(text.index('microcode-0'), text.index('initramfs.img'))
        self.assertTrue(all(name.startswith('/efi/') for name in plan.copy_files))

    def test_xbootldr_and_esp_discovery_and_ambiguity(self):
        self.type1('/boot')
        adapter = self.adapter('systemd-boot', esp='/efi', xbootldr='/boot')
        self.assertEqual(adapter.discover(KERNEL).kernel_path, '/boot/vmlinuz-' + KERNEL)
        self.type1('/efi', name='other.conf')
        with self.assertRaises(LifecycleError):
            adapter.discover(KERNEL)
        self.assertEqual(adapter.discover(KERNEL, 'other.conf').metadata['boot_root'], '/efi')

    def test_type1_traversal_variables_duplicate_linux_and_wrong_version(self):
        self.type1()
        path = self.root / 'efi/loader/entries/normal.conf'
        original = path.read_text()
        for changed in (original.replace('/normal.img', '/../normal.img'), original + 'linux /second\n', original + 'options $kernelopts\n'):
            path.write_text(changed)
            with self.assertRaises(LifecycleError):
                self.adapter('systemd-boot', esp='/efi').discover(KERNEL)
        path.write_text(original.replace('version ' + KERNEL, 'version wrong'))
        with self.assertRaises(LifecycleError):
            self.adapter('systemd-boot', esp='/efi').discover(KERNEL)

    def test_type2_uki_extracts_inputs_and_cmdline_without_commands(self):
        data = pe_image({'.linux': b'embedded-kernel', '.initrd': b'embedded-initrd', '.cmdline': b'root=UUID=reviewed rw\0', '.uname': KERNEL.encode() + b'\0', '.ucode': b'embedded-microcode'})
        self.write('/efi/EFI/Linux/normal.efi', data)
        adapter = self.adapter('uki', esp='/efi')
        entry = adapter.discover(KERNEL)
        self.assertEqual(entry.entry_id, 'normal.efi')
        self.assertEqual(entry.options, 'root=UUID=reviewed rw')
        plan = adapter.plan(entry, 'vbios-uki-one')
        self.assertEqual(plan.entry_id, 'vbios-uki-one.efi')
        self.assertEqual(plan.entry_path, '/efi/EFI/Linux/vbios-uki-one.efi')
        self.assertEqual(plan.copy_files[plan.kernel_path], b'embedded-kernel')
        self.assertEqual(plan.copy_files[plan.supplemental_paths[0]], b'embedded-microcode')
        self.assertIn(b'embedded-initrd', plan.copy_files.values())
        self.assertEqual(plan.files, {})
        with self.assertRaises(LifecycleError):
            adapter.render(entry, plan)

    def test_uki_missing_cmdline_requires_reviewed_value_and_pe_bounds(self):
        data = pe_image({'.linux': b'kernel', '.initrd': b'normal', '.uname': KERNEL.encode()})
        self.write('/efi/EFI/Linux/normal.efi', data)
        with self.assertRaisesRegex(LifecycleError, 'kernel options'):
            self.adapter('uki', esp='/efi').discover(KERNEL)
        entry = self.adapter('uki', esp='/efi', normal={'entry_id': 'normal.efi', 'options': 'root=UUID=reviewed rw'}).discover(KERNEL)
        self.assertEqual(entry.options, 'root=UUID=reviewed rw')
        self.write('/efi/EFI/Linux/normal.efi', data[:-4])
        with self.assertRaisesRegex(LifecycleError, 'PE image'):
            self.adapter('uki', esp='/efi').discover(KERNEL)

    def test_stanza_fingerprint_does_not_change_with_other_entries(self):
        stanza = self.grub()
        adapter = self.adapter()
        first = adapter.discover(KERNEL)
        record = adapter.fallback_record(first)
        self.write('/boot/grub/grub.cfg', (stanza + "menuentry 'Other OS' --id other {\n chainloader /boot/other.efi\n}\n").encode())
        second = adapter.discover(KERNEL)
        self.assertEqual(first.fingerprints(), second.fingerprints())
        self.assertEqual(record['sha256'], hashlib.sha256(stanza.encode()).hexdigest())
        self.assertEqual(len(record['boot_files']), 3)

    def test_grub_visibility_uses_only_owned_explicit_includes(self):
        self.grub()
        adapter = self.adapter()
        files = adapter.visibility_files(['vbios-two', 'vbios-one'])
        include = files['/boot/grub/nvidia-vbios.cfg']
        self.assertIn(b'source $prefix/nvidia-vbios-entries/vbios-one.cfg', include)
        self.assertEqual(set(files), {'/boot/grub/nvidia-vbios.cfg', '/etc/grub.d/41_nvidia_vbios'})
        with self.assertRaisesRegex(LifecycleError, 'not visible'):
            adapter.validate_visibility()
        with (self.root / 'boot/grub/grub.cfg').open('a') as stream:
            stream.write('source $prefix/nvidia-vbios.cfg\n')
        adapter.validate_visibility()
        with self.assertRaises(LifecycleError):
            adapter.visibility_files(['normal'])

    def test_grub2_custom_config_and_include_paths_match(self):
        stanza = self.grub()
        self.write('/boot/grub2/grub.cfg', stanza.encode())
        adapter = self.adapter(grub_config='/boot/grub2/grub.cfg')
        entry = adapter.discover(KERNEL)
        plan = adapter.plan(entry, 'vbios-grub2')
        self.assertEqual(plan.entry_path, '/boot/grub2/nvidia-vbios-entries/vbios-grub2.cfg')
        files = adapter.visibility_files(['vbios-grub2'])
        self.assertIn('/boot/grub2/nvidia-vbios.cfg', files)
        self.assertNotIn('/boot/grub/nvidia-vbios.cfg', files)
        self.assertIn(b'$prefix/nvidia-vbios-entries/vbios-grub2.cfg', files['/boot/grub2/nvidia-vbios.cfg'])

    def test_standard_uki_sbat_is_accepted_and_regenerated_by_builder(self):
        sbat = (b'sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md\n'
                b'uki,1,UKI,uki,1,https://uapi-group.org/specifications/specs/unified_kernel_image/\n'
                b'systemd-stub,1,systemd,systemd,257,https://systemd.io/\n')
        data = pe_image({'.linux': b'embedded-kernel', '.initrd': b'normal',
                         '.cmdline': b'root=UUID=reviewed rw', '.uname': KERNEL.encode(), '.sbat': sbat})
        self.write('/efi/EFI/Linux/normal.efi', data)
        adapter = self.adapter('uki', esp='/efi')
        entry = adapter.discover(KERNEL)
        self.assertEqual(entry.metadata['uki_sections']['.sbat'], sbat)
        plan = adapter.plan(entry, 'vbios-sbat')
        self.assertEqual(plan.copy_files[plan.kernel_path], b'embedded-kernel')
        # ukify derives output SBAT from the new stub plus this kernel. The
        # old outer-image record stays in discovery evidence, not builder input.
        self.assertNotIn(sbat, plan.copy_files.values())
        self.assertEqual(plan.entry_path, '/efi/EFI/Linux/vbios-sbat.efi')

    def test_uki_unsupported_rebuild_metadata_is_explicitly_rejected(self):
        basic = {'.linux': b'kernel', '.initrd': b'normal', '.cmdline': b'root=UUID=reviewed rw', '.uname': KERNEL.encode()}
        for section in ('.pcrsig', '.pcrpkey', '.dtb', '.dtbauto', '.hwids', '.efifw', '.profile', '.splash'):
            with self.subTest(section=section):
                self.write('/efi/EFI/Linux/normal.efi', pe_image({**basic, section: b'required-metadata'}))
                with self.assertRaisesRegex(LifecycleError, 'unsupported rebuild metadata'):
                    self.adapter('uki', esp='/efi').discover(KERNEL)
        self.write('/efi/EFI/Linux/normal.efi', pe_image(basic))
        self.write('/efi/EFI/Linux/normal.efi.extra.d/required.addon.efi', b'addon')
        with self.assertRaisesRegex(LifecycleError, 'runtime addons'):
            self.adapter('uki', esp='/efi').discover(KERNEL)

    def test_uki_requires_efi_app_and_complete_nonoverlapping_resources(self):
        basic = {'.linux': b'kernel', '.initrd': b'normal', '.cmdline': b'root=UUID=reviewed rw', '.uname': KERNEL.encode()}
        valid = pe_image(basic)
        cases = []
        data = bytearray(valid)
        struct.pack_into('<H', data, 0x98 + 68, 3)
        cases.append(data)
        data = bytearray(valid)
        struct.pack_into('<H', data, 0x94, 0)
        cases.append(data)
        table = 0x98 + 112
        data = bytearray(valid)
        struct.pack_into('<I', data, table + 8, 999999)
        cases.append(data)
        data = bytearray(valid)
        struct.pack_into('<I', data, table + 40 + 20, struct.unpack_from('<I', data, table + 20)[0])
        cases.append(data)
        data = bytearray(valid)
        struct.pack_into('<I', data, table + 8, 0)
        cases.append(data)
        for data in cases:
            with self.subTest(data=data[:8]):
                self.write('/efi/EFI/Linux/normal.efi', bytes(data))
                with self.assertRaisesRegex(LifecycleError, 'PE image'):
                    self.adapter('uki', esp='/efi').discover(KERNEL)
        # A stub .bss can be zero-filled rather than file-backed.
        data = bytearray(pe_image({**basic, '.bss': b''}))
        struct.pack_into('<I', data, table + 4 * 40 + 8, 4096)
        self.write('/efi/EFI/Linux/normal.efi', bytes(data))
        self.assertEqual(self.adapter('uki', esp='/efi').discover(KERNEL).entry_id, 'normal.efi')

    def test_configuration_and_identity_refuse_unsafe_paths(self):
        for identity in ('../unsafe', 'normal>..', 'normal;reboot', 'normal\nother'):
            with self.assertRaises(LifecycleError):
                entry_identity(identity)
        for layout in ({'backend': 'guess', 'initramfs': 'dracut'}, {'backend': 'grub', 'initramfs': 'guess'}, {'backend': 'uki', 'initramfs': 'dracut', 'esp': '/../efi'}):
            with self.assertRaises(LifecycleError):
                validate_config({'boot': layout})

    def test_installed_kernels_and_input_symlink_refusal(self):
        (self.root / "lib").symlink_to("usr/lib")
        self.assertEqual(self.adapter().installed_kernels(), [KERNEL])
        self.grub()
        path = self.root / ('boot/vmlinuz-' + KERNEL)
        path.unlink()
        path.symlink_to('/etc/passwd')
        with self.assertRaises(LifecycleError):
            self.adapter().discover(KERNEL)


if __name__ == '__main__':
    unittest.main()
