"""Read-only runtime diagnostics, with sysfs/state entirely in injected roots."""
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
sys.path.insert(0, str(ROOT / 'tests'))
import test_bootstrap
from nvidia_vbios.bootstrap import CONFIG, STATE
from nvidia_vbios.lifecycle.engine import typed_parameters
from nvidia_vbios.lifecycle.security import atomic_write, json_write


class RuntimeStatusTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_bootstrap.BootstrapTests('test_alternate_root_requires_operations')
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.worker = self.fixture.worker
        self.fixture.install = self.worker.install(self.fixture.repository)
        self.fixture.enroll()
        self.prepared = self.fixture.ready()
        self.kernel = self.fixture.ops.current_kernel()
        config = self.fixture.ops.config
        self.parameters = typed_parameters(config['devices'], self.prepared['driver'], config.get('parameters'))
        self.module = self.fixture.root / 'sys/module/nvidia'

    def loaded(self, *, srcversion=None, version=None):
        expected = self.prepared['module_metadata']['nvidia.ko']
        atomic_write(self.module / 'srcversion', (srcversion or expected['srcversion']).encode() + b'\n')
        atomic_write(self.module / 'version', (version or self.prepared['driver']).encode() + b'\n')
        for name, value in self.parameters.items():
            atomic_write(self.module / 'parameters' / name, value.encode() + b'\n')

    def test_exact_loaded_module_and_parameters_match_without_claiming_effects(self):
        self.loaded()
        before = self.fixture.snapshot(); events = list(self.fixture.ops.events)
        report = self.worker.status()
        self.assertTrue(report['ready'])
        self.assertEqual(report['ready_scope'], 'prepared-files-only')
        self.assertEqual(report['running_kernel'], self.kernel)
        runtime = report['runtime']
        self.assertTrue(runtime['activation_matches'])
        self.assertEqual(runtime['scope'], 'loaded-module-and-parameters-only')
        self.assertEqual(runtime['applied'], 'unknown')
        self.assertEqual(runtime['electrical'], 'unknown')
        self.assertTrue(runtime['loaded_module']['srcversion']['matches'])
        self.assertEqual(before, self.fixture.snapshot())
        self.assertEqual(events, self.fixture.ops.events)

    def test_stock_module_and_null_registry_values_do_not_change_prepared_ready(self):
        self.loaded(srcversion='DIFFERENT-STOCK-SRCVERSION')
        for name in self.parameters:
            atomic_write(self.module / 'parameters' / name, b'(null)\n')
        report = self.worker.status()
        self.assertTrue(report['ready'])
        self.assertFalse(report['runtime']['activation_matches'])
        self.assertFalse(report['runtime']['loaded_module']['srcversion']['matches'])
        for observed in report['runtime']['module_parameters'].values():
            self.assertEqual(observed['state'], 'null')
            self.assertEqual(observed['raw'], '(null)')
            self.assertIsNone(observed['observed'])
            self.assertFalse(observed['matches'])

    def test_empty_and_whitespace_are_compared_exactly(self):
        self.loaded()
        name = 'NVreg_RegistryDwords'
        atomic_write(self.module / 'parameters' / name, b'\n')
        field = self.worker.status()['runtime']['module_parameters'][name]
        self.assertEqual(field['state'], 'empty')
        self.assertEqual(field['observed'], '')
        self.assertFalse(field['matches'])
        atomic_write(self.module / 'parameters' / name, b' ' + self.parameters[name].encode() + b'\n')
        self.assertFalse(self.worker.status()['runtime']['module_parameters'][name]['matches'])

    def test_missing_or_unreadable_parameter_is_unknown(self):
        self.loaded()
        missing = self.module / 'parameters/NVreg_RegistryBinaryFilePerDevice'
        missing.unlink()
        report = self.worker.status()
        self.assertIsNone(report['runtime']['activation_matches'])
        self.assertIsNone(report['runtime']['module_parameters'][missing.name]['matches'])
        self.loaded()
        read = Path.read_text
        def denied(path, *args, **kwargs):
            if path == missing:
                raise PermissionError('synthetic sysfs restriction')
            return read(path, *args, **kwargs)
        with patch.object(Path, 'read_text', denied):
            self.assertIsNone(self.worker.status()['runtime']['activation_matches'])

    def test_module_absence_and_expected_metadata_absence_are_unknown(self):
        report = self.worker.status()
        self.assertFalse(report['runtime']['module_present'])
        self.assertIsNone(report['runtime']['activation_matches'])
        self.loaded()
        path = self.fixture.root / STATE.lstrip('/') / f'status-{self.kernel}.json'
        record = json.loads(path.read_bytes()); record['module_metadata'].pop('nvidia.ko')
        json_write(path, record)
        report = self.worker.status()
        self.assertIsNone(report['runtime']['loaded_module']['srcversion']['matches'])
        self.assertIsNone(report['runtime']['activation_matches'])

    def test_sysfs_link_cannot_escape_synthetic_root(self):
        self.loaded()
        path = self.module / 'parameters/NVreg_RegistryDwords'
        path.unlink(); path.symlink_to('/proc/version')
        report = self.worker.status()
        self.assertEqual(report['runtime']['module_parameters'][path.name]['state'], 'unavailable')
        self.assertIsNone(report['runtime']['activation_matches'])

    def test_trusted_prepared_parameter_map_is_preferred_for_matching_profile(self):
        self.loaded()
        path = self.fixture.root / STATE.lstrip('/') / f'status-{self.kernel}.json'
        record = json.loads(path.read_bytes()); record['module_parameters'] = dict(self.parameters)
        json_write(path, record)
        self.assertEqual(self.worker.status()['runtime']['expected_parameters_source'], 'prepared-status')
        config_path = self.fixture.root / CONFIG.lstrip('/')
        config = json.loads(config_path.read_bytes()); config['enabled'] = False
        json_write(config_path, config)
        self.assertEqual(self.worker.status()['runtime']['expected_parameters_source'], 'current-enrollment')


if __name__ == '__main__':
    unittest.main()
