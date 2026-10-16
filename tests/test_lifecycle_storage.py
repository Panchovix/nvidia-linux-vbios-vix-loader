"""Boot-space and READY preservation regressions; synthetic roots only."""
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import test_lifecycle as fixtures
import test_bootstrap as bootstrap_fixtures
from nvidia_vbios.lifecycle import engine
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.LifecycleTests('test_alternate_root_cannot_accidentally_execute_host_commands')
        self.f.setUp();self.addCleanup(self.f.doCleanups)
        self.worker,self.ops=self.f.worker,self.f.ops

    def attempt(self):
        return json.loads((self.worker.state/f'attempt-{fixtures.NEW}.json').read_text())

    def test_transient_preflight_failures_preserve_ready_and_reuse_without_new_image(self):
        ready=self.worker.reconcile(fixtures.NEW)
        status_path=self.worker.state/f'status-{fixtures.NEW}.json'
        saved=status_path.read_bytes(); images=set((self.f.root/'boot').glob('*vbios*.img'))
        # A changed userspace version with READY is driver drift, not a transient
        # failure: test_lifecycle covers its fail-safe.
        for failure in ('headers','uuid','pending'):
            with self.subTest(failure=failure):
                def inventory():
                    return {d['bdf']:dict(d,uuid=None) for d in self.f.config['devices']}
                from contextlib import nullcontext
                guard=patch.object(self.ops,'inventory',side_effect=inventory) if failure=='uuid' else nullcontext()
                self.ops.fault='headers' if failure=='headers' else None
                if failure=='pending':self.ops.environment['next_entry']='foreign-one-shot'
                with guard,self.assertRaises(LifecycleError):self.worker.reconcile(fixtures.NEW)
                self.assertEqual(status_path.read_bytes(),saved)
                self.assertEqual(self.attempt()['state'],'blocked')
                self.assertTrue(self.attempt()['preserved_ready'])
                self.assertEqual(self.ops.builds,1)
                self.ops.fault=None;self.ops.environment.pop('next_entry',None)
                self.assertEqual(self.worker.reconcile(fixtures.NEW)['entry'],ready['entry'])
                self.assertEqual(self.ops.builds,1)
                self.assertTrue(self.attempt()['reused'])
                self.assertEqual(set((self.f.root/'boot').glob('*vbios*.img')),images)

    def test_changed_deployment_is_not_preserved_as_ready(self):
        self.worker.reconcile(fixtures.NEW)
        file=self.f.root/f'usr/lib/modules/{fixtures.NEW}/updates/vbios-override/nvidia.ko'
        atomic_write(file,b'EXTERNAL CHANGE')
        self.ops.fault='headers'
        with self.assertRaises(LifecycleError):self.worker.reconcile(fixtures.NEW)
        self.assertEqual(self.f.status()['state'],'blocked')
        self.assertFalse(self.attempt()['preserved_ready'])

    def test_build_failure_before_publication_retains_previous_disk_commit(self):
        ready=self.worker.reconcile(fixtures.NEW)
        self.f.config['jobs']=3;self.f.write_config();self.ops.fault='build'
        with self.assertRaises(LifecycleError):self.worker.reconcile(fixtures.NEW)
        self.assertEqual(self.f.status(),ready)
        self.assertTrue(self.attempt()['preserved_ready'])
        # The old disk record does not certify readiness for the changed profile.
        with self.assertRaises(LifecycleError):self.worker.ready_status(fixtures.NEW)

    def test_initramfs_publication_moves_validated_inode_without_copying_it(self):
        original=self.ops.initramfs;observed={}
        def build(kernel,destination,*args,**kwargs):
            original(kernel,destination,*args,**kwargs)
            observed['inode']=destination.stat().st_ino
            observed['path']=destination
            observed['bytes']=destination.read_bytes()
        with patch.object(self.ops,'initramfs',side_effect=build):
            ready=self.worker.reconcile(fixtures.NEW)
        record=next(r for r in ready['deployment'] if r['path'].startswith('/boot/initramfs-'))
        image=self.worker.path(record['path'])
        self.assertEqual(image.stat().st_ino,observed['inode'])
        self.assertEqual(image.read_bytes(),observed['bytes'])
        self.assertEqual(image.stat().st_mode & 0o777,0o600)
        self.assertFalse(observed['path'].exists())

    def test_failed_image_rename_rolls_back_and_cleans_temporary_file(self):
        original=os.replace
        def fail_image(source,destination):
            if Path(destination).name.startswith('initramfs-') and '-vbios-' in Path(destination).name:
                raise OSError('injected publication failure')
            return original(source,destination)
        with patch.object(engine.os,'replace',side_effect=fail_image),self.assertRaises(LifecycleError):
            self.worker.reconcile(fixtures.NEW)
        self.assertEqual(self.ops.environment['saved_entry'],'normal-'+fixtures.OLD)
        self.assertEqual(list((self.f.root/'boot').glob('*-vbios-*.img')),[])
        self.assertEqual(list((self.f.root/'boot').glob('.vbios-initramfs-*.img')),[])
        self.assertIsNone(self.f.status()['rollback_error'])

    def test_wrong_prepared_bytes_are_rejected_before_journaling(self):
        prepared=self.f.root/'boot/prepared.img';target=self.f.root/'boot/target.img'
        atomic_write(prepared,b'WRONG');atomic_write(target,b'ORIGINAL')
        journal={'id':'test-prepared','files':[]}
        with self.assertRaisesRegex(LifecycleError,'verified same-directory'):
            self.worker._stage_write(journal,target,b'EXPECTED',prepared_path=prepared)
        self.assertEqual(journal['files'],[])
        self.assertEqual(target.read_bytes(),b'ORIGINAL')
        self.assertEqual(prepared.read_bytes(),b'WRONG')

    def test_status_remains_readable_when_userspace_executable_is_absent(self):
        f=bootstrap_fixtures.BootstrapTests('test_alternate_root_requires_operations')
        f.setUp();self.addCleanup(f.doCleanups)
        f.worker.install(f.repository);f.enroll();f.ready()
        with patch.object(f.ops,'installed_version',side_effect=FileNotFoundError('nvidia-smi removed')):
            status=f.worker.status()
        self.assertTrue(status['installed'])
        self.assertFalse(status['ready'])
        self.assertIn('last_attempt',status)


if __name__=='__main__':unittest.main()
