"""Open payload check: same verdicts as the kernel-side C parser; no GPU, ROM corpus or editor needed."""
import ctypes
import os
from pathlib import Path
import random
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from nvidia_vbios import payload
from nvidia_vbios.driver._payload import PARSER_HEADER
from nvidia_vbios.lifecycle import system
from nvidia_vbios.lifecycle.security import LifecycleError

PRO_6000 = 0x2BB4
RTX_2000_ADA = 0x28B0


def legacy_image(device, *, vendor=0x10DE, blocks=4, code_type=0):
    """A minimal PCI expansion ROM image with a PCIR header and a zero checksum."""
    image = bytearray(blocks * 512)
    image[0:2] = b'\x55\xaa'
    image[0x18:0x1A] = (0x40).to_bytes(2, 'little')
    image[0x40:0x44] = b'PCIR'
    image[0x44:0x48] = (vendor | device << 16).to_bytes(4, 'little')
    image[0x50:0x52] = blocks.to_bytes(2, 'little')
    image[0x54] = code_type
    image[0x55] = 0x80
    image[-1] = -sum(image) & 0xFF
    return bytes(image)


class PayloadCheckTests(unittest.TestCase):
    def test_single_chain_payload_returns_family(self):
        self.assertEqual(payload.check_payload(legacy_image(PRO_6000), 0x10DE, PRO_6000), 'blackwell-gb20x')
        self.assertEqual(payload.check_payload(legacy_image(RTX_2000_ADA), 0x10DE, RTX_2000_ADA), 'ada')
        # A following non-legacy image (e.g. UEFI, code type 3) is allowed, as in the kernel.
        data = legacy_image(PRO_6000) + legacy_image(PRO_6000, code_type=3)
        self.assertEqual(payload.find_legacy(data, 0x10DE, PRO_6000), 0)

    def test_full_rom_with_two_banks_is_refused_with_a_hint(self):
        with self.assertRaisesRegex(payload.PayloadError, 'exactly one.*normalize'):
            payload.check_payload(legacy_image(PRO_6000) * 2, 0x10DE, PRO_6000)

    def test_wrong_identity_checksum_size_and_scope(self):
        image = legacy_image(PRO_6000)
        with self.assertRaisesRegex(payload.PayloadError, 'not 10de:2bb5'):
            payload.check_payload(image, 0x10DE, 0x2BB5)
        broken = bytearray(image)
        broken[0x100] ^= 1
        with self.assertRaisesRegex(payload.PayloadError, 'checksum'):
            payload.check_payload(bytes(broken), 0x10DE, PRO_6000)
        for data in (image[:0x100], image * 4096):
            with self.subTest(size=len(data)), self.assertRaisesRegex(payload.PayloadError, '512 B to 4 MiB'):
                payload.find_legacy(data, 0x10DE, PRO_6000)
        # 0x2501 (RTX 3060 from pci.ids) is recognized by the offline editor only.
        for device in (0xFFFF, 0x2501):
            with self.subTest(device=device), self.assertRaisesRegex(payload.PayloadError, 'outside the supported'):
                payload.check_payload(legacy_image(device), 0x10DE, device)
        with self.assertRaisesRegex(payload.PayloadError, 'only NVIDIA'):
            payload.check_payload(image, 0x1002, PRO_6000)

    def test_system_validation_without_the_editor_extension(self):
        device = {'vendor': 0x10DE, 'device': PRO_6000, 'architecture': 'blackwell-gb20x'}
        with mock.patch.object(payload, 'optional_editor', return_value=None):
            self.assertIsNone(system.SystemOperations.validate_payload(object(), legacy_image(PRO_6000), device))
            with self.assertRaisesRegex(LifecycleError, 'architecture'):
                system.SystemOperations.validate_payload(object(), legacy_image(PRO_6000), dict(device, architecture='ada'))
            with self.assertRaisesRegex(LifecycleError, 'exactly one'):
                system.SystemOperations.validate_payload(object(), legacy_image(PRO_6000) * 2, device)


class ReceiverLimitTests(unittest.TestCase):
    def test_exact_loaded_limit_accepts_prefix_and_rejects_one_extra_byte(self):
        for device in (0x2204, 0x2414, 0x2484, 0x2503, 0x2582, RTX_2000_ADA):
            with self.subTest(device=hex(device)):
                data = bytes(0x9400) + legacy_image(device, blocks=1024)
                self.assertGreater(len(data), payload.GA10X_MAX_SIZE)
                self.assertEqual(payload.gsp_bytes(data, 0x10de, device), 524288)
                family = 'ada' if device == RTX_2000_ADA else 'ampere'
                self.assertEqual(payload.check_loadable_payload(data, 0x10de, device), family)
                # Kernel-side structure is valid; the receiver capacity is a separate check.
                self.assertEqual(payload.check_payload(data + b'\xff', 0x10de, device), family)
                with self.assertRaisesRegex(payload.PayloadError, '512 KiB.*524289 bytes'):
                    payload.check_loadable_payload(data + b'\xff', 0x10de, device)

    def test_turing_has_the_same_512_kib_receiver_capacity(self):
        # Found by static emulation of gsp_tu10x.bin 615.78.08; no Turing board has loaded a payload here.
        for device in (0x1E07, 0x1E84, 0x1F08, 0x1F82, 0x2184):
            with self.subTest(device=hex(device)):
                data = bytes(0x28600) + legacy_image(device, blocks=1024)
                self.assertEqual(payload.check_loadable_payload(data, 0x10de, device), 'turing')
                with self.assertRaises(payload.PayloadError) as refused:
                    payload.check_loadable_payload(data + b'\xff', 0x10de, device)
                self.assertRegex(str(refused.exception), r'Turing TU10x/TU11x GSP accepts at most 512 KiB.*'
                                                         r'524289 bytes.*after its image chain')
                # Plain normalize keeps those bytes, so the hint names the export that drops them.
                self.assertIn('--representation turing-e0-end-v1`', str(refused.exception))
                self.assertNotIn('payload.bin`', str(refused.exception))

    def test_ga100_and_blackwell_do_not_inherit_the_ga10x_capacity(self):
        for device, family in ((0x20b0, 'ampere'), (PRO_6000, 'blackwell-gb20x')):
            with self.subTest(device=hex(device)):
                self.assertEqual(payload.check_loadable_payload(legacy_image(device, blocks=1025), 0x10de, device), family)
        with self.assertRaisesRegex(payload.PayloadError, 'outside the supported'):
            payload.check_loadable_payload(legacy_image(0x2501), 0x10de, 0x2501)

    def test_direct_enrollment_validation_rejects_large_payload_before_optional_parser(self):
        for device, family in ((0x2204, 'ampere'), (RTX_2000_ADA, 'ada')):
            with self.subTest(family=family), mock.patch.object(payload, 'optional_editor',
                    side_effect=AssertionError('oversized payload must be refused before parser lookup')):
                record = {'vendor': 0x10de, 'device': device, 'architecture': family}
                with self.assertRaisesRegex(LifecycleError, '512 KiB'):
                    system.SystemOperations.validate_payload(object(), legacy_image(device, blocks=1025), record)


@unittest.skipUnless(shutil.which('cc'), 'C compiler not available')
class KernelParityTests(unittest.TestCase):
    """Compile the reviewed kernel-side parser and compare verdicts on valid and mutated payloads."""

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        path = Path(cls.directory.name)
        (path / 'nvtypes.h').write_text('typedef unsigned char NvU8;\ntypedef unsigned int NvU32;\n'
                                        'typedef unsigned char NvBool;\n#define NV_TRUE 1\n#define NV_FALSE 0\n')
        (path / 'parser.h').write_text(PARSER_HEADER)
        (path / 'parity.c').write_text('#include "parser.h"\n'
                                       'int find(const NvU8 *d, NvU32 s, NvU32 id, NvU32 *o)'
                                       '{ return kgspVbiosOverrideFindLegacy(d, s, id, o); }\n')
        subprocess.run(['cc', '-shared', '-fPIC', '-std=c11', '-Wall', '-Werror', '-I', str(path),
                        str(path / 'parity.c'), '-o', str(path / 'parity.so')], check=True, capture_output=True)
        cls.library = ctypes.CDLL(str(path / 'parity.so'))
        cls.library.find.argtypes = [ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint32)]

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def kernel(self, data, device):
        offset = ctypes.c_uint32()
        accepted = self.library.find(data, len(data), 0x10DE | device << 16, ctypes.byref(offset))
        return offset.value if accepted else None

    def python(self, data, device):
        try:
            return payload.find_legacy(data, 0x10DE, device)
        except payload.PayloadError:
            return None

    def test_same_verdict_and_offset_on_valid_and_mutated_payloads(self):
        rng = random.Random(1015)
        bases = [legacy_image(PRO_6000), bytes(512) + legacy_image(PRO_6000) + legacy_image(PRO_6000, code_type=3),
                 legacy_image(PRO_6000) * 2, legacy_image(PRO_6000, blocks=1), legacy_image(0x2BB5)]
        cases = 0
        for base in bases:
            self.assertEqual(self.python(base, PRO_6000), self.kernel(base, PRO_6000))
            for _ in range(300):
                data = bytearray(base)
                for _ in range(rng.randint(1, 3)):
                    position = rng.choice([0, 1, 0x18, 0x19, 0x40, 0x44, 0x46, 0x50, 0x51, 0x54,
                                           rng.randrange(len(data))]) + rng.choice([0, 0, 512])
                    if position < len(data):
                        data[position] = rng.randrange(256)
                data = bytes(data[:rng.choice([len(data), len(data) - 1, 0x1FF, len(data)])])
                with self.subTest(case=cases):
                    self.assertEqual(self.python(data, PRO_6000), self.kernel(data, PRO_6000))
                cases += 1


class AkmodsTests(unittest.TestCase):
    def test_reconcile_without_akmods_skips_stock_build_coordination(self):
        operations = system.SystemOperations.__new__(system.SystemOperations)
        with tempfile.TemporaryDirectory() as empty, mock.patch.object(system, 'AKMODS_UNIT_DIRECTORIES', (empty,)), \
                mock.patch.object(system.SystemOperations, '_run') as run:
            self.assertIsNone(operations.coordinate_akmods('6.19.9-200.fc44.x86_64', {}))
            run.assert_not_called()
            Path(empty, 'akmods@.service').write_text('[Unit]\n')
            if os.path.isdir('/run/systemd/system'):
                operations.coordinate_akmods('6.19.9-200.fc44.x86_64', {})
                run.assert_called_once()


if __name__ == '__main__':
    unittest.main()
