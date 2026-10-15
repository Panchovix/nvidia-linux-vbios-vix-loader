"""Native kmod parses complete large-fleet configuration without loading a module."""
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest

from nvidia_vbios.lifecycle.engine import modprobe_configuration, typed_parameters
from nvidia_vbios.limits import MAX_GPUS, REGISTRY_STRING_MAX_BYTES


@unittest.skipUnless(shutil.which('modprobe'), 'kmod is not installed')
class NativeKmodConfigurationTests(unittest.TestCase):
    def test_full_32_gpu_configuration_is_preserved(self):
        devices = [dict(bdf=f'0000:{index + 1:02x}:00.0', size=1961983,
                        sha256=f'{index + 1:064x}') for index in range(MAX_GPUS)]
        expected = typed_parameters(devices, '615.78.08')
        self.assertEqual(len(expected['NVreg_RegistryBinaryFilePerDevice']), 3263)
        self.assertTrue(all(len(value.encode()) <= REGISTRY_STRING_MAX_BYTES for value in expected.values()))
        data = modprobe_configuration(devices, '615.78.08')
        self.assertGreater(len(data), 4096)
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'test.conf'
            config.write_bytes(data)
            # --showconfig parses text only: no module insertion, removal or GPU query.
            result = subprocess.run([shutil.which('modprobe'), '--showconfig', '--config', str(config)],
                                    capture_output=True, text=True, check=True)
        lines = [line for line in result.stdout.splitlines() if line.startswith('options nvidia ')]
        self.assertEqual(len(lines), 1)
        observed = dict(word.split('=', 1) for word in shlex.split(lines[0])[2:])
        self.assertEqual(observed, expected)


if __name__ == '__main__':
    unittest.main()
