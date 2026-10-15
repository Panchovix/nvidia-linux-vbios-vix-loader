"""Retention exercises generated initramfs/BLS pairs in synthetic Fedora roots."""
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import test_lifecycle as fixtures
from nvidia_vbios.lifecycle import retention
from nvidia_vbios.lifecycle.config import load_config
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write, json_write


class RetentionTests(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.LifecycleTests('test_alternate_root_cannot_accidentally_execute_host_commands')
        self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.worker, self.ops = self.f.worker, self.f.ops
        self.normal = self.f.snapshot_normal()

    def build(self, jobs):
        self.f.config['jobs'] = jobs
        self.f.write_config()
        return self.worker.reconcile(fixtures.NEW)

    def live(self, status):
        atomic_write(self.worker.path('/proc/sys/kernel/osrelease'), status['kernel'].encode())
        values = {'version': status['driver'], 'srcversion': status['module_metadata']['nvidia.ko']['srcversion']}
        values.update({'parameters/' + name: value for name, value in status['module_parameters'].items()})
        for name, value in values.items():
            atomic_write(self.worker.path('/sys/module/nvidia/' + name), (value + '\n').encode())

    def history(self):
        return json.loads((self.worker.state / retention.HISTORY).read_text())['generations']

    def images(self):
        return sorted(self.worker.path('/boot').glob('*-vbios-*.img'))

    def older_four(self):
        states = [self.build(jobs) for jobs in range(1, 5)]
        self.assertEqual(len(self.images()), 4)
        self.live(states[-1])
        return states

    def test_repeated_same_kernel_updates_retain_three_and_protect_normal_files(self):
        states = self.older_four()
        result = self.worker.reconcile(fixtures.NEW)
        self.assertEqual(result['retention']['state'], 'complete')
        self.assertEqual(result['retention']['removed'], [states[0]['entry']])
        self.assertEqual(len(self.images()), 3)
        self.assertEqual(self.f.snapshot_normal(), self.normal)
        self.assertEqual(self.ops.environment['saved_entry'], states[-1]['entry'])
        self.assertEqual(self.ops.builds, 4)
        self.assertEqual(len(self.history()), 4)
        # Further reconciles do not republish or resurrect retired boot files.
        again = self.worker.reconcile(fixtures.NEW)
        self.assertEqual(again['retention']['removed'], [])
        self.assertEqual(len(self.images()), 3)

    def test_limit_two(self):
        states = self.older_four()
        result = retention.prune(self.worker, states[-1], keep=2)
        self.assertEqual(len(result['removed']), 2)
        self.assertEqual(len(self.images()), 2)

    def test_pending_boot_retains_all_generations(self):
        states = self.older_four()
        for name in ('next_entry', 'prev_saved_entry'):
            self.ops.environment[name] = states[0]['entry']
            result = retention.prune(self.worker, states[-1])
            self.assertEqual(result['reason'], 'pending-grub-transition')
            self.assertEqual(len(self.images()), 4)
            del self.ops.environment[name]

    def test_waits_for_running_kernel_version_srcversion_and_all_parameters(self):
        states = self.older_four()
        values = ['/proc/sys/kernel/osrelease', '/sys/module/nvidia/version', '/sys/module/nvidia/srcversion']
        values += ['/sys/module/nvidia/parameters/' + key for key in states[-1]['module_parameters']]
        for name in values:
            with self.subTest(name=name):
                file = self.worker.path(name); previous = file.read_bytes()
                atomic_write(file, b'MISMATCH')
                result = retention.prune(self.worker, states[-1])
                self.assertEqual(result['reason'], 'awaiting-matching-running-ready')
                self.assertEqual(len(self.images()), 4)
                atomic_write(file, previous)

    def test_foreign_saved_default_is_preserved(self):
        states = self.older_four()
        self.ops.environment['saved_entry'] = 'foreign'
        self.assertEqual(retention.prune(self.worker, states[-1])['state'], 'deferred')
        self.assertEqual(len(self.images()), 4)

    def test_changed_image_and_unknown_filename_are_never_deleted(self):
        states = self.older_four()
        oldest = self.history()[states[0]['entry']]
        image = self.worker.path(next(name for name in oldest['files'] if '/initramfs-' in name))
        atomic_write(image, b'FOREIGN CHANGE')
        unknown = self.worker.path('/boot/initramfs-test-vbios-unowned.img')
        atomic_write(unknown, b'NOT OWNED')
        result = retention.prune(self.worker, states[-1])
        self.assertEqual(result['removed'], [])
        self.assertTrue(result['warnings'])
        self.assertEqual(image.read_bytes(), b'FOREIGN CHANGE')
        self.assertEqual(unknown.read_bytes(), b'NOT OWNED')

    def test_shared_image_foreign_bls_or_grub_variable_prevents_deletion(self):
        states = self.older_four()
        image = next(name for name in self.history()[states[0]['entry']]['files'] if '/initramfs-' in name)
        foreign = self.worker.path('/boot/loader/entries/foreign.conf')
        for text in ('initrd /' + Path(image).name, 'initrd ${extra_image}', '\tinitrd\t/' + Path(image).name):
            atomic_write(foreign, (text + '\n').encode())
            self.ops.environment['extra_image'] = '/' + Path(image).name
            result = retention.prune(self.worker, states[-1])
            self.assertEqual(result['removed'], [])
            self.assertIn('referenced', result['warnings'][0])

    def test_symlink_is_not_followed_or_unlinked(self):
        states = self.older_four()
        image = self.worker.path(next(name for name in self.history()[states[0]['entry']]['files'] if '/initramfs-' in name))
        image.unlink(); image.symlink_to(self.worker.path(f'/boot/initramfs-{fixtures.NEW}.img'))
        result = retention.prune(self.worker, states[-1])
        self.assertTrue(result['warnings'])
        self.assertTrue(image.is_symlink())
        self.assertEqual(self.f.snapshot_normal(), self.normal)

    def test_interrupted_retirement_retries_after_bls_removed(self):
        states = self.older_four()
        image = self.worker.path(next(name for name in self.history()[states[0]['entry']]['files'] if '/initramfs-' in name))
        original = Path.unlink
        def fail(path, *args, **kwargs):
            if path == image:
                raise OSError('interrupted after removing BLS')
            return original(path, *args, **kwargs)
        with patch.object(Path, 'unlink', fail):
            first = retention.prune(self.worker, states[-1])
        self.assertTrue(first['warnings'])
        self.assertEqual(self.history()[states[0]['entry']]['state'], 'retiring')
        self.assertFalse(self.worker.path('/boot/loader/entries/' + states[0]['entry'] + '.conf').exists())
        again = retention.prune(self.worker, states[-1])
        self.assertEqual(again['removed'], [states[0]['entry']])
        self.assertFalse(image.exists())

    def test_grub_race_prevents_unlink(self):
        states = self.older_four()
        original = dict(self.ops.environment)
        with patch.object(self.ops, 'grub_environment', side_effect=[original, dict(original, next_entry='foreign')]):
            result = retention.prune(self.worker, states[-1])
        self.assertTrue(result['warnings'])
        self.assertEqual(len(self.images()), 4)

    def test_bad_history_does_not_degrade_ready(self):
        status = self.build(2)
        atomic_write(self.worker.state / retention.HISTORY, b'{"schema_version":99}')
        again = self.worker.reconcile(fixtures.NEW)
        self.assertEqual(again['state'], 'ready')
        self.assertEqual(again['entry'], status['entry'])
        self.assertTrue(again['retention']['warnings'])
        self.assertEqual(self.ops.builds, 1)

    def test_absent_archived_pairs_stop_counting_without_resurrection(self):
        states = self.older_four()
        for name in self.history()[states[0]['entry']]['files']:
            self.worker.path(name).unlink()
        result = retention.prune(self.worker, states[-1])
        self.assertEqual(result['retained'], 3)
        self.assertEqual(result['removed'], [])

    def test_retention_record_cannot_authorize_normal_image_or_wrong_entry(self):
        states = self.older_four()
        path = self.worker.state / retention.HISTORY
        original = path.read_bytes()
        for invalid in ('wrong_image', 'wrong_entry', 'not_object'):
            data = json.loads(original)
            entry = states[0]['entry']
            if invalid == 'wrong_image':
                record = data['generations'][entry]
                image = next(name for name in record['files'] if '/initramfs-' in name)
                record['files'][f'/boot/initramfs-{fixtures.NEW}.img'] = record['files'].pop(image)
            elif invalid == 'wrong_entry':
                data['generations']['vbios-unowned'] = data['generations'].pop(entry)
            else:
                data['generations'][entry] = []
            json_write(path, data)
            with self.assertRaises(LifecycleError): retention.prune(self.worker, states[-1])
            self.assertEqual(self.f.snapshot_normal(), self.normal)
            self.assertEqual(len(self.images()), 4)
        atomic_write(path, original)

    def test_configuration_accepts_only_two_or_three(self):
        for value in (0, 1, 4, True, '3', None):
            with self.subTest(value=value):
                self.f.config['retain_boot_generations'] = value; self.f.write_config()
                with self.assertRaises(LifecycleError): load_config(self.worker.config_path, self.f.root)
        for value in (2, 3):
            self.f.config['retain_boot_generations'] = value; self.f.write_config()
            self.assertEqual(load_config(self.worker.config_path, self.f.root).raw['retain_boot_generations'], value)


if __name__ == '__main__':
    unittest.main()
