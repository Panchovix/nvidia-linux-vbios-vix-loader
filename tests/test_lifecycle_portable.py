"""Synthetic portable reconciliation: no host commands, loaders or GPU writes."""
from __future__ import annotations

import base64
from contextlib import contextmanager
import copy
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'tests'))
from test_lifecycle import FakeOperations, VERSION
from nvidia_vbios.lifecycle.boot import BootAdapter
from nvidia_vbios.lifecycle.engine import MODULES, STATE, modprobe_configuration
from nvidia_vbios.lifecycle import initramfs
from nvidia_vbios.lifecycle.platform import DEBIAN_PLATFORM, ARCH_PLATFORM, package_transaction_lock
from nvidia_vbios.lifecycle.portable import PortableReconciler
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write, digest, json_write, source_tree_hash


OPTIONS = 'root=UUID=reviewed rw quiet splash pcie_aspm=off nvidia_drm.modeset=1'
MICROCODE = b'REVIEWED MICROCODE ARCHIVE'


def pe_image(sections):
    """Minimal structurally valid EFI PE image for offline section readers."""
    optional_size = 0x70
    table = 0x98 + optional_size
    position = table + len(sections) * 40
    data = bytearray(position)
    data[:2] = b'MZ'
    struct.pack_into('<I', data, 0x3c, 0x80)
    data[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<H', data, 0x84, 0x8664)
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


class PortableFakeOperations(FakeOperations):
    """Reuse module/source mocks; portable image APIs operate inside root only."""
    def __init__(self, root, config, platform):
        super().__init__(root, config)
        self.platform = platform
        self.filesystem_root = root
        self.environment = {'saved_entry': config['fallback_entry']}
        self.corrupt_member = None
        self.uki_inputs = []
        self.early_evidence = {}
        self.fail_uki = False

    def assert_transaction_idle(self, root):
        self.events.append('probe:' + self.platform.package_provider)
        with package_transaction_lock(self.platform, root):
            pass

    def coordinate_stock_build(self, kernel, config):
        self.events.append('stock:' + kernel)

    @contextmanager
    def publication_locks(self, root):
        self.events.append('lock:' + self.platform.package_provider)
        with package_transaction_lock(self.platform, root):
            yield

    def portable_initramfs(self, kernel, destination, targets, *, activation_config, force_config, config):
        self.events.append('portable-image:' + config['boot']['initramfs'])
        evidence = {initramfs.ACTIVATION_PATH: activation_config.read_bytes(),
                    initramfs.FORCE_PATH: force_config.read_bytes(),
                    initramfs.LOAD_PATH: initramfs.LOAD_BYTES}
        if config['boot']['initramfs'] == 'initramfs-tools':
            evidence[initramfs.DEBIAN_LOAD_PATH] = initramfs.DEBIAN_LOAD_BYTES
        else:
            evidence[initramfs.ARCH_LOAD_PATH] = initramfs.ARCH_LOAD_BYTES
            evidence['config'] = b'MODULES="nvidia nvidia_modeset nvidia_drm nvidia_uvm"\nEARLYHOOKS="vbios_override"\n'
        self.early_evidence = dict(evidence)
        members = {str(path.relative_to(self.root)): path.read_bytes() for path in targets}
        members.update(evidence)
        atomic_write(destination, json.dumps({key: base64.b64encode(value).decode() for key, value in members.items()}, sort_keys=True).encode())
        if self.after_initramfs:
            self.after_initramfs()
        return evidence

    def portable_members(self, image):
        try:
            return list(json.loads(image.read_bytes()))
        except ValueError:
            return []  # a normal image written by the fixture

    def portable_extract(self, image, members):
        try:
            archive = json.loads(image.read_bytes())
        except ValueError:
            archive = {}  # a normal image written by the fixture
        result = {member: base64.b64decode(archive[member]) if member in archive else None for member in members}
        if self.corrupt_member:
            member = next((name for name in members if self.corrupt_member in name), None)
            if member is None:
                raise AssertionError('corruption target was not verified: ' + self.corrupt_member)
            result[member] = b'WRONG IMAGE BYTES'
        return result

    def portable_build_uki(self, kernel_image, image, destination, *, cmdline, config):
        self.events.append('portable-uki')
        if self.fail_uki:
            raise LifecycleError('mock UKI build failed')
        inputs = {'.linux': kernel_image.read_bytes(), '.initrd': image.read_bytes(), '.cmdline': cmdline.encode()}
        self.uki_inputs.append(inputs)
        atomic_write(destination, pe_image(inputs))
        return {'sha256': digest(destination.read_bytes())}


class PortableLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='portable-lifecycle-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.payload = b'REVIEWED ROM portable board payload'
        source = self.root / 'var/lib/nvidia-vbios/sources/p2p'
        atomic_write(source / 'version.mk', VERSION.encode())
        atomic_write(source / 'Makefile', b'REVIEWED portable source build script\n')
        atomic_write(self.root / 'var/lib/nvidia-vbios/roms/gpu0.bin', self.payload)
        self.config = {'schema_version': 1, 'enabled': True, 'jobs': 2,
            'devices': [{'bdf': '0000:03:00.0', 'uuid': 'GPU-00000000-0000-0000-0000-000000000001',
                         'vendor': 0x10de, 'device': 0x2bb4, 'architecture': 'blackwell-gb20x',
                         'structurally_validated': True, 'runtime_tested': True,
                         'payload_path': '/var/lib/nvidia-vbios/roms/gpu0.bin', 'size': len(self.payload),
                         'sha256': digest(self.payload), 'source_sha256': digest(self.payload)}],
            'sources': [{'version': VERSION, 'path': '/var/lib/nvidia-vbios/sources/p2p',
                         'source_hashes': {'version.mk': digest(VERSION.encode())},
                         'tree_sha256': source_tree_hash(source, self.root), 'p2p_preferred': True}]}
        self.normal_entries = {}

    def test_activation_generation_invalidates_portable_prepared_deployment(self):
        from unittest.mock import patch
        from nvidia_vbios.lifecycle import portable
        self.setup_profile('grub')
        with patch.object(portable, 'ACTIVATION_GENERATION', 3):
            old = self.worker.reconcile(self.new)
        with self.assertRaisesRegex(LifecycleError, 'current profile'):
            self.worker.ready_status(self.new)
        new = self.worker.reconcile(self.new)
        self.assertNotEqual(old['generation_sha256'], new['generation_sha256'])
        self.assertEqual(old['activation_config_sha256'], new['activation_config_sha256'])
        self.assertEqual(self.ops.builds, 2)

    def test_32_selected_gpus_use_complete_activation_in_portable_image(self):
        from nvidia_vbios.lifecycle.engine import firmware_filename
        self.setup_profile('grub')
        sample = self.config['devices'][0]
        devices = []
        for index in range(32):
            payload = self.payload + str(index).encode()
            path = f'/var/lib/nvidia-vbios/roms/board-{index}.bin'
            self.write(path, payload)
            devices.append(dict(sample, bdf=f'0000:{index+3:02x}:00.0',
                uuid=f'GPU-00000000-0000-0000-0000-{index+1:012x}',
                payload_path=path, sha256=digest(payload), source_sha256=digest(payload), size=len(payload)))
        self.config['devices'] = devices
        self.write_config()
        ready = self.worker.reconcile(self.new)
        expected = modprobe_configuration(devices, VERSION)
        self.assertGreater(len(ready['module_parameters']['NVreg_RegistryBinaryFilePerDevice']), 1024)
        roles = self.fleet()['boot_generations'][ready['entry']]['roles']
        image = self.root / next(name for name, role in roles.items() if role == 'initramfs').lstrip('/')
        self.assertEqual(self.ops.portable_extract(image, [initramfs.ACTIVATION_PATH])[initramfs.ACTIVATION_PATH], expected)
        for device in devices:
            member = f'usr/lib/firmware/nvidia/{VERSION}/vbios-override/{firmware_filename(device)}'
            self.assertEqual(digest(self.ops.portable_extract(image, [member])[member]), device['sha256'])

    def write(self, name, data):
        path = self.root / name.lstrip('/')
        atomic_write(path, data)
        return path

    def setup_profile(self, backend='grub', *, nested=False, rolling=False, true_uki=False):
        self.backend, self.nested, self.rolling, self.true_uki = backend, nested, rolling, true_uki
        platform = DEBIAN_PLATFORM if backend == 'grub' else ARCH_PLATFORM
        self.old = '6.12.9-amd64' if backend == 'grub' else '6.12.9-1-cachyos'
        self.new = '6.12.10-amd64' if backend == 'grub' else '6.12.10-1-cachyos'
        self.config['userspace'] = {'provider': platform.package_provider}
        self.config['boot'] = {'backend': backend, 'initramfs': 'initramfs-tools' if backend == 'grub' else 'mkinitcpio'}
        if backend != 'grub':
            self.config['boot'].update(boot_root='/efi', esp='/efi')
        (self.root / ('var/lib/dpkg' if backend == 'grub' else 'var/lib/pacman')).mkdir(parents=True)
        self.add_kernel(self.old)
        if not rolling:
            self.add_kernel(self.new)
        adapter = BootAdapter(self.root, self.config)
        entry = adapter.discover(self.old, self.normal_entries[self.old])
        normal = adapter.fallback_record(entry)
        self.config.update(normal_boot=normal, fallback_entry=normal['entry'], fallback_sha256=normal['sha256'], fallback_files=normal['boot_files'])
        self.write_config()
        self.ops = PortableFakeOperations(self.root, self.config, platform)
        self.worker = PortableReconciler(self.root, self.ops)
        return entry

    def add_kernel(self, kernel):
        kernel_data = ('REVIEWED KERNEL ' + kernel).encode()
        (self.root / f'usr/lib/modules/{kernel}').mkdir(parents=True, exist_ok=True)
        if self.backend == 'grub':
            self.write('/boot/vmlinuz-' + kernel, kernel_data)
            self.write('/boot/initrd.img-' + kernel, ('NORMAL INITRD ' + kernel).encode())
            self.write('/boot/intel-ucode.img', MICROCODE)
            identity = 'debian-' + kernel
            stanza = f"""menuentry 'Debian {kernel}' --class debian --class gnu-linux --id '{identity}' {{
    insmod part_gpt
    insmod ext2
    search --no-floppy --fs-uuid --set=root reviewed
    linux /vmlinuz-{kernel} {OPTIONS}
    initrd /intel-ucode.img /initrd.img-{kernel}
}}
"""
            config_path = self.root / 'boot/grub/grub.cfg'
            before = config_path.read_bytes() if config_path.exists() else b'source $prefix/nvidia-vbios.cfg\n'
            if self.nested:
                stanza = "submenu 'Advanced options for Debian' --id 'advanced' {\n" + stanza + '}\n'
                identity = 'advanced>' + identity
            self.write('/boot/grub/grub.cfg', before + stanza.encode())
        elif self.true_uki:
            identity = 'normal-' + kernel + '.efi'
            self.write('/efi/EFI/Linux/' + identity, pe_image({'.linux': kernel_data, '.initrd': ('NORMAL INITRD ' + kernel).encode(),
                        '.uname': kernel.encode(), '.cmdline': OPTIONS.encode(), '.ucode': MICROCODE}))
        else:
            identity = 'cachyos.conf' if self.rolling else 'normal-' + kernel + '.conf'
            loader_kernel = '/vmlinuz-linux-cachyos' if self.rolling else '/vmlinuz-' + kernel
            loader_initrd = '/initramfs-linux-cachyos.img' if self.rolling else '/initramfs-' + kernel + '.img'
            self.write('/efi' + loader_kernel, kernel_data)
            self.write('/efi' + loader_initrd, ('NORMAL INITRD ' + kernel).encode())
            self.write('/efi/intel-ucode.img', MICROCODE)
            if self.rolling:
                self.write(f'/usr/lib/modules/{kernel}/pkgbase', b'linux-cachyos\n')
                self.write(f'/usr/lib/modules/{kernel}/vmlinuz', kernel_data)
            self.write('/efi/loader/entries/' + identity,
                f'title CachyOS {kernel}\nversion {kernel}\nmachine-id reviewed\nsort-key cachyos\narchitecture x64\nlinux {loader_kernel}\ninitrd /intel-ucode.img\ninitrd {loader_initrd}\noptions {OPTIONS}\n'.encode())
        self.normal_entries[kernel] = identity

    def write_config(self):
        json_write(self.root / 'etc/nvidia-vbios/lifecycle.json', self.config)

    def fleet(self):
        return json.loads((self.root / STATE.lstrip('/') / 'fleet.json').read_bytes())

    def archive(self, path):
        return {name: base64.b64decode(value) for name, value in json.loads(path.read_bytes()).items()}

    def assert_success(self, kernel, *, preserved=None):
        source = self.worker.boot.discover(kernel)
        result = self.worker.reconcile(kernel)
        self.assertEqual(result['state'], 'ready')
        self.assertEqual(result['marker'], 'VBIOS_READY')
        self.assertEqual(self.ops.environment['saved_entry'], result['entry'])
        self.assertFalse(result['runtime_tested'])
        self.assertEqual(result['boot_verification'], 'unverified')
        generation = self.fleet()['boot_generations'][result['entry']]
        roles = generation['roles']
        paths = {role: self.root / name.lstrip('/') for name, role in roles.items() if role != 'supplemental-initrd'}
        self.assertEqual(paths['kernel'].read_bytes(), source.metadata.get('uki_sections', {}).get('.linux', self.root.joinpath(source.kernel_path.lstrip('/')).read_bytes()))
        archive = self.archive(paths['initramfs'])
        activation = modprobe_configuration(self.config['devices'], VERSION, self.config.get('parameters'))
        self.assertEqual(archive[initramfs.ACTIVATION_PATH], activation)
        self.assertEqual(result['activation_config_sha256'], digest(activation))
        for name, expected in self.ops.early_evidence.items():
            self.assertEqual(archive[name], expected)
        for name in MODULES:
            module = self.root / f'usr/lib/modules/{kernel}/updates/vbios-override/{name}'
            self.assertEqual(archive[str(module.relative_to(self.root))], module.read_bytes())
        firmware = [value for name, value in archive.items() if name.startswith('usr/lib/firmware/nvidia/')]
        self.assertEqual(firmware, [self.payload])
        supplements = [self.root / name.lstrip('/') for name, role in roles.items() if role == 'supplemental-initrd']
        self.assertEqual([path.read_bytes() for path in supplements], [MICROCODE])
        if self.backend == 'uki':
            sections = initramfs.extract_uki_sections(paths['uki'])
            self.assertEqual(sections['.linux'], paths['kernel'].read_bytes())
            self.assertEqual(sections['.initrd'], MICROCODE + paths['initramfs'].read_bytes())
            self.assertEqual(sections['.cmdline'], OPTIONS.encode())
            self.assertLess(self.ops.events.index('portable-uki'), self.ops.events.index('default:' + result['entry']))
        else:
            descriptor = paths['entry'].read_text()
            self.assertIn(OPTIONS, descriptor)
            self.assertNotIn('NVreg_Registry', descriptor)
            if self.backend == 'grub':
                self.assertIn('--class debian --class gnu-linux', descriptor)
                self.assertIn('search --no-floppy --fs-uuid --set=root reviewed', descriptor)
                self.assertIn('source $prefix/nvidia-vbios.cfg', (self.root / 'boot/grub/grub.cfg').read_text())
            else:
                for line in ('machine-id reviewed', 'sort-key cachyos', 'architecture x64'):
                    self.assertIn(line, descriptor)
        image_event = 'portable-image:' + self.config['boot']['initramfs']
        self.assertLess(self.ops.events.index(image_event), self.ops.events.index('default:' + result['entry']))
        self.assertEqual(self.worker.ready_status(kernel)['entry'], result['entry'])
        if preserved:
            self.assertEqual({path: path.read_bytes() for path in preserved}, preserved)
        return result, generation

    def normal_snapshot(self):
        normal = self.config['normal_boot']
        names = {normal['descriptor_path'], *normal['boot_files']}
        return {self.root / name.lstrip('/'): (self.root / name.lstrip('/')).read_bytes() for name in names}

    def test_debian_grub_full_publish_retains_flags_and_normal_boot(self):
        self.setup_profile()
        normal = self.normal_snapshot()
        self.assert_success(self.new, preserved=normal)
        self.assertEqual(self.ops.events[:3], ['probe:deb', 'stock:' + self.new, 'lock:deb'])
        self.assertFalse((self.root / 'run/akmods').exists())
        self.assertFalse((self.root / 'usr/lib/sysimage/rpm').exists())

    def test_arch_systemd_boot_full_publish_preserves_normal_and_early_loading(self):
        self.setup_profile('systemd-boot')
        self.assert_success(self.new, preserved=self.normal_snapshot())
        self.assertEqual(self.ops.events[:3], ['probe:pacman', 'stock:' + self.new, 'lock:pacman'])
        self.assertFalse((self.root / 'var/lib/pacman/db.lck').exists())

    def test_uki_build_from_type1_recipe_copies_exact_kernel_microcode_and_cmdline(self):
        self.setup_profile('uki')
        self.assert_success(self.new, preserved=self.normal_snapshot())

    def test_uki_build_from_normal_pe_sections_publishes_independent_efi_image(self):
        self.setup_profile('uki', true_uki=True)
        self.assert_success(self.new, preserved=self.normal_snapshot())

    def test_nested_grub_fallback_identity_succeeds_and_rollback_restores_it(self):
        self.setup_profile(nested=True)
        normal = self.config['fallback_entry']
        self.assertTrue(normal.startswith('advanced>'))
        self.ops.fault = 'default'
        with self.assertRaisesRegex(LifecycleError, 'grub wrote then failed'):
            self.worker.reconcile(self.new)
        self.assertEqual(self.ops.environment['saved_entry'], normal)
        journal = json.loads((self.root / STATE.lstrip('/') / 'transaction.json').read_bytes())
        self.assertEqual(journal['phase'], 'rolled-back')
        self.assert_success(self.new)

    def test_nested_grub_depmod_failure_rolls_back_before_image_publication(self):
        self.setup_profile(nested=True)
        normal = self.config['fallback_entry']
        self.ops.fault = 'depmod'
        with self.assertRaisesRegex(LifecycleError, 'depmod failure') as raised:
            self.worker.reconcile(self.new)
        self.assertNotIn('rollback requires review', str(raised.exception))
        self.assertEqual(self.ops.environment['saved_entry'], normal)
        self.assertFalse((self.root / f'usr/lib/modules/{self.new}/updates/vbios-override').exists())
        journal = json.loads((self.root / STATE.lstrip('/') / 'transaction.json').read_bytes())
        self.assertEqual(journal['phase'], 'rolled-back')
        self.assertEqual(journal['boot']['backend'], 'grub')
        status = json.loads((self.root / STATE.lstrip('/') / f'status-{self.new}.json').read_bytes())
        self.assertIsNone(status['rollback_error'])

    def test_image_activation_mismatch_rolls_back_modules_firmware_and_kernel_copy(self):
        self.setup_profile()
        before = self.normal_snapshot()
        self.ops.corrupt_member = initramfs.ACTIVATION_PATH
        with self.assertRaisesRegex(LifecycleError, 'exact activation/module/firmware/early-load'):
            self.worker.reconcile(self.new)
        self.assertEqual(self.ops.environment['saved_entry'], self.config['fallback_entry'])
        self.assertEqual(before, self.normal_snapshot())
        self.assertFalse((self.root / f'usr/lib/modules/{self.new}/updates/vbios-override').exists())
        self.assertFalse(list((self.root / 'boot/nvidia-vbios').rglob('vmlinuz')))
        self.assertFalse(list((self.root / 'usr/lib/firmware').rglob('*.bin')))
        journal = json.loads((self.root / STATE.lstrip('/') / 'transaction.json').read_bytes())
        self.assertEqual(journal['phase'], 'rolled-back')

    def test_arch_image_must_contain_exact_runtime_early_hook_registration(self):
        self.setup_profile('systemd-boot')
        self.ops.corrupt_member = 'config'
        with self.assertRaisesRegex(LifecycleError, 'exact activation/module/firmware/early-load'):
            self.worker.reconcile(self.new)
        self.assertEqual(self.ops.environment['saved_entry'], self.config['fallback_entry'])
        self.assertFalse((self.root / 'var/lib/pacman/db.lck').exists())

    def test_source_mutation_during_module_build_blocks_before_publication(self):
        self.setup_profile()
        self.ops.after_build = lambda: atomic_write(self.root / 'var/lib/nvidia-vbios/sources/p2p/Makefile', b'UNREVIEWED MUTATION')
        with self.assertRaisesRegex(LifecycleError, 'source/build-script tree changed'):
            self.worker.reconcile(self.new)
        self.assertEqual(self.ops.environment['saved_entry'], self.config['fallback_entry'])
        self.assertFalse((self.root / f'usr/lib/modules/{self.new}/updates/vbios-override').exists())

    def test_source_mutation_during_image_build_rolls_back_before_selection(self):
        self.setup_profile('systemd-boot')
        self.ops.after_initramfs = lambda: atomic_write(self.root / 'var/lib/nvidia-vbios/sources/p2p/Makefile', b'UNREVIEWED IMAGE-BUILD MUTATION')
        with self.assertRaisesRegex(LifecycleError, 'source/build-script tree changed'):
            self.worker.reconcile(self.new)
        self.assertEqual(self.ops.environment['saved_entry'], self.config['fallback_entry'])
        self.assertFalse((self.root / f'usr/lib/modules/{self.new}/updates/vbios-override').exists())

    def test_arch_rolling_stock_kernel_overwrite_preserves_old_managed_kernel_and_image(self):
        self.setup_profile('systemd-boot', rolling=True)
        first, generation = self.assert_success(self.old)
        previous = {self.root / item['path'].lstrip('/'): (self.root / item['path'].lstrip('/')).read_bytes() for item in generation['files']}
        self.add_kernel(self.new)
        second, _ = self.assert_success(self.new)
        self.assertNotEqual(first['entry'], second['entry'])
        self.assertEqual({path: path.read_bytes() for path in previous}, previous)
        self.assertIn(first['entry'], self.fleet()['boot_generations'])

    def test_uki_failure_rolls_back_before_default_selection(self):
        self.setup_profile('uki')
        self.ops.fail_uki = True
        with self.assertRaisesRegex(LifecycleError, 'mock UKI build failed'):
            self.worker.reconcile(self.new)
        self.assertEqual(self.ops.environment['saved_entry'], self.config['fallback_entry'])
        self.assertFalse(list((self.root / 'efi/EFI/Linux').glob('vbios-*.efi')))
        self.assertFalse((self.root / f'usr/lib/modules/{self.new}/updates/vbios-override').exists())

    def test_foreign_or_oneshot_boot_selection_blocks_without_a_build(self):
        self.setup_profile('systemd-boot')
        for environment in ({'saved_entry': 'foreign.conf'}, {'saved_entry': self.config['fallback_entry'], 'next_entry': 'other.conf'}):
            self.ops.environment = dict(environment)
            with self.subTest(environment=environment), self.assertRaises(LifecycleError):
                self.worker.reconcile(self.new)
            self.assertEqual(self.ops.environment, environment)
        self.assertEqual(self.ops.builds, 0)

    def test_explicit_default_selection_is_refused_for_portable_boot(self):
        self.setup_profile('systemd-boot')
        environment = dict(self.ops.environment)
        with self.assertRaisesRegex(LifecycleError, 'select-default'):
            self.worker.reconcile(self.new, select_default=True)
        self.assertEqual((self.ops.environment, self.ops.builds), (environment, 0))

    def _assert_unmanaged_artifact_is_preserved(self, backend, artifact):
        self.setup_profile(backend)
        plan = self.worker.plan(self.new)
        target = self.root / getattr(plan['boot_plan'], artifact).lstrip('/')
        atomic_write(target, b'UNMANAGED BOOT ARTIFACT')
        previous = self.ops.environment.copy()
        with self.assertRaisesRegex(LifecycleError, 'unmanaged'):
            self.worker.reconcile(self.new)
        self.assertEqual(target.read_bytes(), b'UNMANAGED BOOT ARTIFACT')
        self.assertEqual(self.ops.environment, previous)

    def test_unmanaged_initramfs_is_not_overwritten(self):
        self._assert_unmanaged_artifact_is_preserved('grub', 'initrd_path')

    def test_unmanaged_grub_entry_is_not_overwritten(self):
        self._assert_unmanaged_artifact_is_preserved('grub', 'entry_path')

    def test_unmanaged_uki_is_not_overwritten(self):
        self._assert_unmanaged_artifact_is_preserved('uki', 'entry_path')

    def test_driver_drift_parks_modules_so_dkms_stock_module_is_selected(self):
        self.setup_profile('grub')
        ready = self.worker.reconcile(self.new)
        managed = self.root / f'usr/lib/modules/{self.new}/updates/vbios-override'
        dkms = self.write(f'/usr/lib/modules/{self.new}/updates/dkms/nvidia.ko', json.dumps({'version': '615.78.08'}).encode())
        # Both live under updates/; depmod's choice between them is not ours to rely on.
        self.ops.selected_module = lambda kernel, name: str(managed / (name + '.ko') if managed.exists() else dkms)
        self.ops.version = '615.78.08'
        result = self.worker.reconcile(self.new)
        self.assertEqual(result['state'], 'driver-drift')
        self.assertFalse(managed.exists())
        self.assertTrue((self.root / result['parked'][0].lstrip('/')).is_dir())
        self.assertEqual(result['stock_module'], str(dkms))
        normal = self.worker.boot.discover(self.new).entry_id
        self.assertEqual(self.ops.environment['saved_entry'], normal)
        self.assertEqual(result['entry'], normal)
        self.assertEqual(result['normal_image'], 'clean')
        for item in self.fleet()['boot_generations'][ready['entry']]['files']:
            self.assertTrue((self.root / item['path'].lstrip('/')).exists())
        self.assertEqual(self.fleet()['drift']['entry'], normal)
        self.assertEqual(self.worker.guard_default(), normal)

    def test_driver_drift_refuses_a_normal_image_with_the_old_nvidia_build(self):
        self.setup_profile('grub')
        ready = self.worker.reconcile(self.new)
        self.write(f'/usr/lib/modules/{self.new}/updates/dkms/nvidia.ko', json.dumps({'version': '615.78.08'}).encode())
        managed = self.root / f'usr/lib/modules/{self.new}/updates/vbios-override'
        dkms = self.root / f'usr/lib/modules/{self.new}/updates/dkms/nvidia.ko'
        self.ops.selected_module = lambda kernel, name: str(managed / (name + '.ko') if managed.exists() else dkms)
        image = self.root / self.worker.boot.discover(self.new).initrd_path.lstrip('/')
        stale = f'usr/lib/modules/{self.new}/updates/dkms/nvidia.ko.zst'
        def normal_image(version):
            atomic_write(image, json.dumps({stale: base64.b64encode(json.dumps({'version': version}).encode()).decode()}).encode())
        normal_image(VERSION)
        self.ops.version = '615.78.08'
        result = self.worker.reconcile(self.new)
        self.assertEqual((result['state'], result['normal_image'], result['boots_normal_driver']), ('driver-drift', 'mismatched', False))
        self.assertEqual(self.ops.environment['saved_entry'], ready['entry'])
        normal_image('615.78.08')
        result = self.worker.reconcile(self.new)
        normal = self.worker.boot.discover(self.new).entry_id
        self.assertEqual((result['normal_image'], result['boots_normal_driver'], self.ops.environment['saved_entry']),
                         ('matching', True, normal))

    def test_dry_run_does_not_create_state_or_boot_publication(self):
        self.setup_profile('systemd-boot')
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*'))
        plan = self.worker.reconcile(self.new, dry_run=True)
        self.assertEqual(plan['version'], VERSION)
        self.assertEqual(before, sorted(str(path.relative_to(self.root)) for path in self.root.rglob('*')))
        self.assertEqual(self.ops.builds, 0)


if __name__ == '__main__':
    unittest.main()
