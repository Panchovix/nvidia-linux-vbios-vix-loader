"""Manual source integration in synthetic roots; no host or GPU mutations."""
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_bootstrap as fixtures
from test_lifecycle import OLD
from nvidia_vbios.driver_update import DriverUpdate
from nvidia_vbios.bootstrap import BASE, CONFIG, ENABLED
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write, hash_file


class PostInstallTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.BootstrapTests('test_alternate_root_requires_operations')
        self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.f.worker.install(self.f.repository)
        # Synthetic bytes; existing injected validator deliberately avoids ROM IO.
        self.f.profile['devices'][0].update(architecture='ada', representation='ada-relocated-v1')
        self.f.enroll(); self.previous = self.f.ready(); self.f.worker.enable(OLD)
        self.worker = DriverUpdate(self.f.root, self.f.ops)
        self.before = self.read_config()
        atomic_write(self.f.source / 'Makefile', b'NEW reviewed P2P build input')

    def read_config(self):
        return json.loads(self.f.worker.path(CONFIG).read_text())

    def run_update(self, **kwargs):
        return self.worker.post_install(self.f.source, p2p_preferred=True, **kwargs)

    def test_pre_install_preserves_ready_and_dry_run_writes_nothing(self):
        before=self.f.snapshot(); env=dict(self.f.ops.environment)
        self.assertEqual(self.worker.pre_install(dry_run=True)['state'],'planned')
        self.assertEqual(before,self.f.snapshot())
        report=self.worker.pre_install()
        self.assertEqual(report['state'],'suspended')
        self.assertFalse(self.f.ops.enabled)
        self.assertFalse(self.read_config()['enabled'])
        self.assertEqual(self.f.ops.environment,env)
        self.assertEqual(self.worker.pre_install()['state'],'suspended')
        self.assertEqual(self.run_update()['state'],'complete')
        maintenance=json.loads(self.f.worker.path(BASE+'/driver-maintenance.json').read_text())
        self.assertEqual(maintenance['state'],'complete')
        self.assertTrue(self.f.ops.enabled)

    def test_pre_install_foreign_transition_is_read_only_failure(self):
        self.f.ops.environment['next_entry']='another-test'
        before=self.f.snapshot()
        with self.assertRaises(LifecycleError): self.worker.pre_install()
        self.assertEqual(before,self.f.snapshot())
        self.assertTrue(self.f.ops.enabled)

    def test_dry_run_is_read_only(self):
        before=self.f.snapshot(); builds=self.f.ops.builds
        r=self.run_update(dry_run=True)
        self.assertEqual(r['state'],'planned')
        self.assertEqual(before,self.f.snapshot())
        self.assertEqual(self.f.ops.builds,builds)
        self.assertTrue(self.f.ops.enabled)

    def test_rebuild_preserves_devices_and_boot_recovery_and_restores_triggers(self):
        boot_before={r['path']:hash_file(self.f.worker.path(r['path'])) for r in self.previous['deployment'] if r['path'].startswith('/boot/')}
        previous=self.f.ops.environment['saved_entry']
        def verify_pause():
            self.assertFalse(self.f.ops.enabled)
            self.assertEqual(self.f.ops.environment['saved_entry'],previous)
        self.f.ops.after_build=verify_pause
        result=self.run_update()
        self.assertEqual(result['state'],'complete')
        self.assertTrue(result['triggers_enabled']); self.assertTrue(self.f.ops.enabled)
        self.assertEqual(self.read_config()['devices'],self.before['devices'])
        self.assertEqual(self.read_config()['devices'][0]['representation'],'ada-relocated-v1')
        self.assertEqual(self.f.ops.builds,2)
        self.assertEqual(self.f.ops.environment['saved_entry'],result['entry'])
        self.assertEqual(self.read_config()['sources'][0]['path'],result['snapshot'])
        for name,sha in boot_before.items(): self.assertEqual(hash_file(self.f.worker.path(name)),sha)

    def test_preflight_errors_do_not_suspend_or_write(self):
        cases=('unsupported','headers','version','uuid','transition','foreign','missing-default','busy')
        for case in cases:
            with self.subTest(case=case):
                before=self.f.snapshot(); env=dict(self.f.ops.environment)
                self.f.ops.fault=case if case in ('unsupported','headers') else None
                self.f.ops.version='615.99.01' if case=='version' else '615.71.09'
                self.f.ops.service_active=case=='busy'
                if case=='transition': self.f.ops.environment['next_entry']='foreign-test'
                if case=='foreign': self.f.ops.environment['saved_entry']='another-os'
                if case=='missing-default': self.f.ops.environment.pop('saved_entry',None)
                if case=='uuid':
                    def unavailable():
                        return {d['bdf']:dict(d,uuid=None) for d in self.before['devices']}
                    guard=patch.object(self.f.ops,'inventory',side_effect=unavailable)
                else:
                    from contextlib import nullcontext
                    guard=nullcontext()
                with guard, self.assertRaises(LifecycleError): self.run_update()
                self.assertEqual(before,self.f.snapshot())
                self.assertTrue(self.f.ops.enabled)
                self.f.ops.environment=env
                self.f.ops.fault=None; self.f.ops.version='615.71.09'; self.f.ops.service_active=False

    def test_other_preferred_source_requires_explicit_preference(self):
        before=self.f.snapshot()
        with self.assertRaisesRegex(LifecycleError,'another source is preferred'):
            self.worker.post_install(self.f.source,dry_run=True)
        self.assertEqual(before,self.f.snapshot())

    def test_build_failure_retains_previous_boot_and_supports_explicit_retry(self):
        previous=self.f.ops.environment['saved_entry']; self.f.ops.fault='build'
        with self.assertRaises(LifecycleError): self.run_update()
        self.assertEqual(self.f.ops.environment['saved_entry'],previous)
        self.assertFalse(self.f.ops.enabled)
        self.assertFalse(self.read_config()['enabled'])
        self.assertFalse(self.f.worker.path(ENABLED).exists())
        report=json.loads(self.f.worker.path(BASE+'/post-install.json').read_text())
        self.assertEqual(report['state'],'blocked'); self.assertEqual(report['recovery_errors'],[])
        self.f.ops.fault=None
        self.assertEqual(self.run_update()['state'],'complete')
        self.assertTrue(self.f.ops.enabled)

    def test_source_change_during_snapshot_stops_before_build(self):
        original=self.worker._snapshot
        def changed(*args,**kwargs):
            result=original(*args,**kwargs)
            atomic_write(self.f.source/'Makefile',b'CHANGED DURING SNAPSHOT')
            return result
        before=self.f.ops.builds
        with patch.object(self.worker,'_snapshot',side_effect=changed), self.assertRaisesRegex(LifecycleError,'source changed'):
            self.run_update()
        self.assertEqual(self.f.ops.builds,before)
        self.assertEqual(self.f.ops.environment['saved_entry'],self.previous['entry'])
        self.assertFalse(self.read_config()['enabled'])

    def test_required_p2p_policy_blocks_stock_only_future_version(self):
        from nvidia_vbios.lifecycle.config import load_config, select_source
        from nvidia_vbios.lifecycle.security import json_write
        self.run_update()
        config=self.read_config()
        self.assertTrue(config['require_p2p_source'])
        future=copy.deepcopy(config)
        future['sources']=[dict(config['sources'][0],version='615.99.01',p2p_preferred=False)]
        path=self.f.root/'future-config.json';json_write(path,future)
        loaded=load_config(path,self.f.root)
        with self.assertRaisesRegex(LifecycleError,'no enrolled P2P source'):
            select_source(loaded,'615.99.01',self.f.ops.inspect_source,self.f.root)
        future['require_p2p_source']='yes';json_write(path,future)
        with self.assertRaisesRegex(LifecycleError,'must be boolean'):load_config(path,self.f.root)
        with self.assertRaisesRegex(LifecycleError,'requires a reviewed P2P source'):
            self.worker.post_install(self.f.source,dry_run=True)

    def test_version_switch_registers_exact_new_p2p_source(self):
        self.f.ops.version='615.99.01';atomic_write(self.f.source/'version.mk',b'615.99.01')
        result=self.run_update()
        self.assertEqual(result['version'],'615.99.01')
        self.assertEqual(self.read_config()['sources'][0]['version'],'615.99.01')
        self.assertTrue(self.read_config()['sources'][0]['p2p_preferred'])
        self.assertEqual(self.read_config()['devices'],self.before['devices'])

    def stock(self, version):
        """The distribution's own nvidia.ko (akmods/DKMS)."""
        atomic_write(self.f.root / f'usr/lib/modules/{OLD}/extra/nvidia.ko', json.dumps({'version': version}).encode())

    def drift(self, version='615.99.01'):
        from nvidia_vbios.lifecycle import Reconciler
        self.f.ops.version = version
        self.stock(version)
        result = Reconciler(self.f.root, self.f.ops).reconcile(OLD)
        self.assertEqual(result['state'], 'driver-drift')
        self.assertEqual(self.f.ops.environment['saved_entry'], self.f.normal)
        atomic_write(self.f.source / 'version.mk', version.encode())
        return result

    def test_failed_post_install_for_a_new_driver_falls_back_to_the_normal_entry(self):
        # The old READY entry would load modules built for the old driver against the new userspace.
        self.f.ops.version = '615.99.01'
        self.stock('615.99.01')
        atomic_write(self.f.source / 'version.mk', b'615.99.01')
        self.f.ops.fault = 'build'
        with self.assertRaisesRegex(LifecycleError, 'did not establish READY'):
            self.run_update()
        self.assertEqual(self.f.ops.environment['saved_entry'], self.f.normal)
        report = json.loads(self.f.worker.path(BASE + '/post-install.json').read_text())
        self.assertEqual(report['driver_drift']['entry'], self.f.normal)
        self.assertTrue(all(self.f.worker.path(path).is_dir() for path in report['driver_drift']['parked']))
        self.assertIn(f'the default is {self.f.normal}', report['recovery'])
        self.f.ops.fault = None
        self.assertEqual(self.run_update()['state'], 'complete')

    def test_failed_post_install_without_a_new_distribution_module_keeps_ready(self):
        # .run --no-kernel-modules: the normal entry would load no NVIDIA module at all, and
        # rerunning post-install after a reboot needs one loaded to read the GPU identity.
        self.f.ops.version = '615.99.01'
        atomic_write(self.f.source / 'version.mk', b'615.99.01')
        self.f.ops.fault = 'build'
        with self.assertRaisesRegex(LifecycleError, 'did not establish READY'):
            self.run_update()
        self.assertEqual(self.f.ops.environment['saved_entry'], self.previous['entry'])
        report = json.loads(self.f.worker.path(BASE + '/post-install.json').read_text())
        self.assertIn(f'the default is {self.previous["entry"]}', report['recovery'])
        self.f.ops.fault = None
        self.assertEqual(self.run_update()['state'], 'complete')

    def test_failed_post_install_under_drift_keeps_the_normal_default(self):
        drift = self.drift()
        self.assertEqual(self.f.worker.status()['driver_drift']['entry'], self.f.normal)
        start = len(self.f.ops.events)
        self.f.ops.fault = 'build'
        with self.assertRaisesRegex(LifecycleError, 'did not establish READY: make failed'):
            self.run_update()
        self.assertEqual(self.f.ops.environment['saved_entry'], self.f.normal)
        self.assertFalse(self.f.ops.enabled)
        report = json.loads(self.f.worker.path(BASE + '/post-install.json').read_text())
        self.assertEqual((report['state'], report['recovery_errors']), ('blocked', []))
        self.f.ops.fault = None
        seen = []
        self.f.ops.after_build = lambda: seen.append(self.f.ops.environment['saved_entry'])
        result = self.run_update()
        self.assertEqual(result['state'], 'complete')
        # The old READY image was never reselected while the new modules were built.
        self.assertEqual(seen, [self.f.normal])
        self.assertNotIn('default:' + self.previous['entry'], self.f.ops.events[start:])
        self.assertEqual(self.f.ops.environment['saved_entry'], result['entry'])
        self.assertIsNone(self.f.worker.status()['driver_drift'])
        self.assertFalse(self.f.worker.path(drift['parked'][0]).exists())

    def test_explicit_current_kernel_normal_selection_can_return_to_ready(self):
        self.f.worker.disable()
        self.assertEqual(self.f.ops.environment['saved_entry'],self.f.normal)
        result=self.run_update()
        self.assertEqual(result['state'],'complete')
        self.assertEqual(self.f.ops.environment['saved_entry'],result['entry'])


if __name__=='__main__': unittest.main()
