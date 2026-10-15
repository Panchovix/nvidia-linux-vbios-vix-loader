"""Open-loader profile preparation from single-chain payloads; synthetic files, no GPU or editor."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from nvidia_vbios import payload
from nvidia_vbios.bootstrap import BootstrapError, BootstrapOperations
from nvidia_vbios.lifecycle.security import digest
from nvidia_vbios.lifecycle.system import SystemOperations
from nvidia_vbios.onboarding import Onboarding

from test_payload import legacy_image

ROOT = Path(__file__).resolve().parents[1]
VERSION = '615.78.08'
KERNEL = '6.19.1-test'
PRO_6000, RTX_2000_ADA = 0x2BB4, 0x28B0


class Operations:
    def __init__(self, device):
        self.gpus = [{'index': 0, 'name': 'Synthetic GPU', 'bdf': '0000:03:00.0',
                      'uuid': 'GPU-00000000-0000-0000-0000-000000000001', 'vendor': 0x10de, 'device': device}]
        self.archive_ops = BootstrapOperations.__new__(BootstrapOperations)
        self.archive_ops.system = SystemOperations.__new__(SystemOperations)

    def gpu_query(self):
        text = '\n'.join(f'{g["index"]}, 0000{g["bdf"]}, {g["uuid"]}, {g["name"]}' for g in self.gpus)
        return subprocess.CompletedProcess([], 0, text.encode(), b'')

    def inventory(self):
        return {g['bdf']: {k: v for k, v in g.items() if k not in ('index', 'name')} for g in self.gpus}

    def current_kernel(self):
        return KERNEL

    def installed_version(self, config):
        return VERSION

    def inspect_source(self, source):
        return {'supported': True, 'version': VERSION, 'reasons': [],
                'source_hashes': {'Makefile': digest((source / 'Makefile').read_bytes())},
                'capabilities': {'already_patched': False}}

    def archive_identity(self, archive, data, device):
        self.archive_ops.archive_identity(archive, data, device)

    def triggers_any_active(self):
        return False


class OpenOnboardingTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.private').mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(dir=ROOT / '.private')
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'Makefile').write_bytes(b'reviewed synthetic source')
        entries = self.root / 'boot/loader/entries'
        entries.mkdir(parents=True)
        (entries / f'normal-{KERNEL}.conf').write_text(
            f'title Fedora\nversion {KERNEL}\nlinux /vmlinuz-{KERNEL}\ninitrd /initramfs-{KERNEL}.img\noptions root=UUID=synthetic\n')
        (self.root / f'boot/vmlinuz-{KERNEL}').write_bytes(b'KERNEL')
        (self.root / f'boot/initramfs-{KERNEL}.img').write_bytes(b'NORMAL')
        self.output = self.root / 'prepared'
        for target in ('nvidia_vbios.onboarding.optional_editor', 'nvidia_vbios.payload.optional_editor'):
            patcher = mock.patch(target, return_value=None)
            patcher.start()
            self.addCleanup(patcher.stop)

    def prepare(self, data, device=PRO_6000, **options):
        file = self.root / 'gpu0.bin'
        file.write_bytes(data)
        worker = Onboarding(self.root, Operations(device))
        return worker.prepare(devices=[('0', file)], driver_source=self.source, output=self.output,
                              userspace='manual', **options)

    def test_single_chain_payload_is_enrolled_as_is(self):
        data = legacy_image(PRO_6000)
        self.prepare(data)
        profile = json.loads((self.output / 'profile.json').read_text())
        device = profile['devices'][0]
        self.assertEqual(device['architecture'], 'blackwell-gb20x')
        self.assertEqual((device['sha256'], device['source_sha256']), (digest(data), digest(data)))
        self.assertEqual(Path(device['payload']).read_bytes(), data)

    def test_full_rom_wrong_gpu_and_large_ada_are_refused_without_output(self):
        cases = [(legacy_image(PRO_6000) * 2, PRO_6000, 'exactly one'),
                 (legacy_image(0x2BB5), PRO_6000, 'not 10de:2bb4'),
                 (legacy_image(RTX_2000_ADA, blocks=1025), RTX_2000_ADA, '512 KiB')]
        for data, device, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(BootstrapError, message):
                self.prepare(data, device)
            self.assertFalse(self.output.exists())
        self.assertEqual(payload.check_payload(legacy_image(RTX_2000_ADA), 0x10de, RTX_2000_ADA), 'ada')

    def test_ada_limit_counts_from_the_legacy_image(self):
        # A relocated Ada payload keeps a prefix before its legacy image; only the part from there is loaded.
        relocated = bytes(0x9400) + legacy_image(RTX_2000_ADA, blocks=1020)
        self.assertGreater(len(relocated), 512 * 1024)
        self.assertEqual(payload.gsp_bytes(relocated, 0x10de, RTX_2000_ADA), 1020 * 512)
        self.prepare(relocated, RTX_2000_ADA)
        self.assertEqual(json.loads((self.output / 'profile.json').read_text())['devices'][0]['architecture'], 'ada')


if __name__ == '__main__':
    unittest.main()
