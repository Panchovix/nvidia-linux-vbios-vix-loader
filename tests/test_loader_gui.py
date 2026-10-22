"""The Linux loader window without GTK: probe on a fake root, pkexec runner, controller state, argv and texts."""
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import string
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from nvidia_vbios.loader_gui import controller as gui_controller, probe, runner
from nvidia_vbios.loader_gui.controller import STRINGS, Controller, check_file, find_checkout, language_from_env
from nvidia_vbios.payload import PayloadError, optional_editor
from nvidia_vbios.loader_gui.runner import Outcome, classify, sudo_text
from test_payload import PRO_6000, RTX_2000_ADA, legacy_image

KERNEL = '7.1.4-200.fc43.x86_64'
NEWER = '7.1.10-200.fc43.x86_64'
VERSION = '615.78.08'
PKEXEC = ['/usr/bin/pkexec', '--disable-internal-agent']
GPU0 = probe.Gpu('0000:03:00.0', 0x10de, PRO_6000, 0, 'RTX PRO 6000', 'SN0001', '98.02.6a.00.03', None)
GPU1 = probe.Gpu('0000:13:00.0', 0x10de, RTX_2000_ADA, 1, 'RTX 2000 Ada', 'SN0002', '95.07.47.00.19', None)


def system(**changes):
    values = dict(kernel=KERNEL, newest_kernel=KERNEL, headers=True, distribution='fedora', family='fedora',
                  secure_boot=False, grub_saved=True, open_modules=True, loaded_version=VERSION,
                  installed_version=VERSION, userspace='manual', plugin=True, release=None, release_has_setup=False,
                  release_internal=None, clone_matches=None, triggers=False, service_active=False, running=(),
                  images=(), old_images=False, boot_free=900 * 2 ** 20, boot_needed=600 * 2 ** 20,
                  saved_source=False, distro_source=False, smi=True)
    values.update(changes)
    return probe.System(**values)


def snapshot(gpus=(GPU0, GPU1), problems=(), **changes):
    return probe.Snapshot(system(**changes), tuple(gpus), tuple(problems))


def make_checkout(directory, internal=False):
    root = Path(directory) / 'clone'
    (root / 'src/nvidia_vbios').mkdir(parents=True)
    (root / 'nvbios').write_text('#!/usr/bin/env python3\n')
    (root / 'src/nvidia_vbios/system_setup.py').write_text('"""setup"""\n')
    if internal:
        (root / 'src/nvidia_vbios/gui').mkdir(parents=True, exist_ok=True)
        (root / 'src/nvidia_vbios/gui/__init__.py').write_text('"""editor window"""\n')
    return root


def write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    (path.write_bytes if isinstance(data, bytes) else path.write_text)(data)
    return path


SMI = (f'0, 00000000:03:00.0, NVIDIA RTX PRO 6000 Blackwell, 1650000000001\n'
       f'1, 00000000:13:00.0, NVIDIA RTX 2000 Ada Generation, [N/A]\n')


class FakeRun:
    def __init__(self, **answers):
        self.calls = []
        self.answers = {('/usr/bin/nvidia-smi', '--query-gpu=index,pci.bus_id,name,serial', '--format=csv,noheader'):
                        (0, SMI),
                        ('/usr/bin/rpm', '--nosignature', '-q', 'libdnf5-plugin-actions'): (0, 'libdnf5\n'),
                        ('/usr/bin/systemctl', 'is-enabled', 'nvidia-vbios-reconcile.path'): (0, 'enabled\n'),
                        ('/usr/bin/systemctl', 'is-enabled', 'nvidia-vbios-reconcile.timer'): (0, 'enabled\n'),
                        ('/usr/bin/systemctl', 'show', '--property=ActiveState', '--value',
                         'nvidia-vbios-reconcile.service'): (0, 'inactive\n')}
        self.answers.update(answers)

    def __call__(self, argv):
        self.calls.append(list(argv))
        return self.answers.get(tuple(argv), (1, ''))


class ProbeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = root = Path(directory.name) / 'root'
        devices = root / 'sys/bus/pci/devices'
        for name, vendor, pci_class, device in (('0000:03:00.0', '0x10de', '0x030000', '0x2bb4'),
                                                ('0000:03:00.1', '0x10de', '0x040300', '0x22e8'),
                                                ('0000:13:00.0', '0x10de', '0x030200', '0x28b0'),
                                                ('0000:00:1f.3', '0x8086', '0x040300', '0x7ad0')):
            for key, value in (('vendor', vendor), ('class', pci_class), ('device', device)):
                write(devices / name / key, value + '\n')
        write(root / 'proc/driver/nvidia/gpus/0000:03:00.0/information',
              'Model: \t\t NVIDIA RTX PRO 6000 Blackwell\nGPU UUID: \t GPU-00000000-0000-0000-0000-000000000000\n'
              'Video BIOS: \t 98.02.6a.00.03\nBus Location: \t 0000:03:00.0\n')
        write(root / 'proc/driver/nvidia/version',
              f'NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  {VERSION}  Release Build\n')
        write(root / 'sys/module/nvidia/version', VERSION + '\n')
        parameters = root / 'sys/module/nvidia/parameters'
        write(parameters / 'NVreg_RegistryDwordsPerDevice',
              'pci=0000:03:00.0;RmLinuxVbiosOverride=2;RmLinuxVbiosOverrideSize=2048;'
              'pci=0000:13:00.0;RmLinuxVbiosOverrideSize=2048\n')
        write(parameters / 'NVreg_RegistryBinaryFilePerDevice',
              f'pci=0000:03:00.0;RmLinuxVbiosOverrideImage={VERSION}/vbios-override/0000:03:00.0-0123456789abcdef.bin;'
              f'pci=0000:13:00.0;RmLinuxVbiosOverrideImage={VERSION}/vbios-override/'
              '0000:13:00.0-fedcba9876543210.bin\n')
        write(root / 'etc/os-release', 'NAME="Fedora Linux"\nID=fedora\nVERSION_ID=43\n')
        write(root / f'usr/lib/modules/{KERNEL}/build/Makefile', '')
        (root / f'usr/lib/modules/{NEWER}').mkdir(parents=True)        # no /boot/vmlinuz: not a boot kernel
        write(root / f'boot/vmlinuz-{KERNEL}', b'k')
        write(root / f'boot/initramfs-{KERNEL}.img', b'i' * 1000)
        write(root / f'boot/initramfs-{KERNEL}-vbios-0123456789abcdef0123.img', b'o')
        write(root / probe.SECURE_BOOT, bytes([6, 0, 0, 0, 0]))
        write(root / 'etc/default/grub', 'GRUB_TIMEOUT=5\nGRUB_DEFAULT=saved\nGRUB_ENABLE_BLSCFG=true\n')
        write(root / f'usr/lib64/libnvidia-ml.so.{VERSION}', b'elf')
        (root / 'usr/lib64/libnvidia-ml.so.1').symlink_to(f'libnvidia-ml.so.{VERSION}')
        write(root / 'usr/bin/nvidia-smi', b'')
        write(root / 'usr/bin/dnf5', b'')
        (root / f'{probe.SOURCES}/{VERSION}-{"ab" * 32}').mkdir(parents=True)
        write(root / 'proc/4242/cmdline', b'/usr/bin/python3\0-I\0/usr/local/bin/nvbios\0system\0reconcile\0'
                                          b'--kernel\0' + KERNEL.encode() + b'\0')
        write(root / 'proc/4243/cmdline', b'bash\0-c\0echo system enable\0')
        self.clone = make_checkout(directory.name)
        files = {f'nvidia_vbios/{path.relative_to(self.clone / "src/nvidia_vbios")}':
                 {'sha256': hashlib.sha256(path.read_bytes()).hexdigest(), 'mode': 0o644}
                 for path in (self.clone / 'src/nvidia_vbios').rglob('*.py')}
        write(root / probe.CURRENT, json.dumps({'schema_version': 1, 'release': 'ab' * 32, 'files': files}))

    def snapshot(self, run=None, **kwargs):
        return probe.snapshot(self.root, run or FakeRun(), kernel=KERNEL, checkout=self.clone, **kwargs)

    def test_gpus_come_from_sysfs_with_index_name_and_serial_from_nvidia_smi(self):
        result = self.snapshot()
        self.assertEqual([gpu.bdf for gpu in result.gpus], ['0000:03:00.0', '0000:13:00.0'])
        first, second = result.gpus
        self.assertEqual((first.index, first.name, first.serial, first.vbios, first.device),
                         (0, 'NVIDIA RTX PRO 6000 Blackwell', '1650000000001', '98.02.6a.00.03', PRO_6000))
        self.assertEqual((second.index, second.serial, second.vbios), (1, None, None))
        # Only GPU 0 has both the override flag and its image name: "requested at boot", not proof of loading.
        self.assertEqual((first.requested, second.requested), ('0123456789abcdef', None))
        self.assertEqual(result.problems, ())

    def test_gpu_nvidia_smi_leaves_out_stays_listed_without_an_index(self):
        # The driver did not initialize 13:00.0: sysfs still has it, nvidia-smi lists only 03:00.0.
        run = FakeRun()
        run.answers[('/usr/bin/nvidia-smi', '--query-gpu=index,pci.bus_id,name,serial', '--format=csv,noheader')] = \
            (0, SMI.splitlines()[0] + '\n')
        result = self.snapshot(run)
        self.assertTrue(result.system.smi)
        self.assertEqual([(gpu.bdf, gpu.index, gpu.name) for gpu in result.gpus],
                         [('0000:03:00.0', 0, 'NVIDIA RTX PRO 6000 Blackwell'), ('0000:13:00.0', None, '10de:28b0')])

    def test_no_devices_found_is_an_nvidia_smi_answer(self):
        # Exit 6 ("No devices were found"): the driver initialized no GPU, every GPU stays listed without an index.
        run = FakeRun()
        query = ('/usr/bin/nvidia-smi', '--query-gpu=index,pci.bus_id,name,serial', '--format=csv,noheader')
        run.answers[query] = (6, 'No devices were found\n')
        result = self.snapshot(run)
        self.assertTrue(result.system.smi)
        self.assertEqual([(gpu.bdf, gpu.index) for gpu in result.gpus],
                         [('0000:03:00.0', None), ('0000:13:00.0', None)])
        run.answers[query] = (9, '')                     # any other failure is not an answer
        self.assertFalse(self.snapshot(run).system.smi)

    def test_system_state(self):
        run = FakeRun()
        s = self.snapshot(run).system
        self.assertEqual((s.kernel, s.newest_kernel, s.headers), (KERNEL, KERNEL, True))
        self.assertEqual((s.distribution, s.family, s.secure_boot, s.grub_saved), ('fedora', 'fedora', False, True))
        self.assertEqual((s.open_modules, s.loaded_version, s.installed_version), (True, VERSION, VERSION))
        self.assertEqual((s.userspace, s.plugin), ('manual', True))      # rpm -qf failed: a .run install
        self.assertEqual((s.release, s.release_has_setup, s.release_internal, s.clone_matches),
                         ('ab' * 32, True, False, True))
        self.assertEqual((s.triggers, s.service_active, s.running), (True, False, ('reconcile',)))
        self.assertEqual(s.images, (f'initramfs-{KERNEL}-vbios-0123456789abcdef0123.img',))
        self.assertTrue(s.old_images and s.saved_source and s.smi)
        self.assertFalse(s.distro_source)
        self.assertEqual(s.boot_needed, 2000)
        self.assertIn(['/usr/bin/rpm', '-qf', '/usr/bin/nvidia-smi'], run.calls)

    def test_changed_clone_secure_boot_newer_kernel_and_package_owner(self):
        write(self.clone / 'src/nvidia_vbios/system_setup.py', '"""changed"""\n')
        write(self.root / probe.SECURE_BOOT, bytes([6, 0, 0, 0, 1]))
        write(self.root / f'boot/vmlinuz-{NEWER}', b'k')
        write(self.root / f'usr/share/nvidia-kmod-{VERSION}/nvidia-kmod-{VERSION}-x86_64.tar.xz', b'')
        run = FakeRun()
        run.answers[('/usr/bin/rpm', '-qf', '/usr/bin/nvidia-smi')] = (0, 'nvidia-driver\n')
        s = self.snapshot(run).system
        self.assertEqual((s.clone_matches, s.secure_boot, s.newest_kernel), (False, True, NEWER))
        self.assertEqual((s.userspace, s.distro_source), ('rpm', True))

    def test_missing_pieces(self):
        for path in (probe.SECURE_BOOT, probe.CURRENT, 'proc/driver/nvidia/version', 'etc/default/grub'):
            (self.root / path).unlink()
        write(self.root / 'etc/os-release', 'ID="ubuntu-like"\n')
        run = FakeRun()
        del run.answers[('/usr/bin/nvidia-smi', '--query-gpu=index,pci.bus_id,name,serial', '--format=csv,noheader')]
        result = self.snapshot(run)
        s = result.system
        self.assertEqual((s.secure_boot, s.release, s.release_has_setup, s.clone_matches), (False, None, False, None))
        self.assertEqual((s.open_modules, s.grub_saved, s.family, s.userspace, s.plugin, s.smi),
                         (None, None, None, None, None, False))
        self.assertEqual([gpu.index for gpu in result.gpus], [None, None])
        self.assertEqual(result.gpus[0].name, 'NVIDIA RTX PRO 6000 Blackwell')     # procfs Model
        self.assertEqual(result.gpus[1].name, '10de:28b0')
        self.assertEqual(result.problems, ('nvidia-smi: exit code 1',))

    def test_requested_parsing_tolerates_other_settings(self):
        self.assertEqual(probe.requested('(null)', ''), {})
        dwords = 'pci=0000:0A:00.0;RmLinuxVbiosOverride=2;pci=bogus;RmLinuxVbiosOverride=2'
        binary = (f'pci=0000:0a:00.0;RmLinuxVbiosOverrideImage={VERSION}/vbios-override/'
                  '0000:0a:00.0-00ff00ff00ff00ff.bin')
        self.assertEqual(probe.requested(dwords, binary), {'0000:0a:00.0': '00ff00ff00ff00ff'})
        other = binary.replace('0000:0a:00.0-', '0000:0b:00.0-')      # an image named for another GPU
        self.assertEqual(probe.requested(dwords, other), {})


class RunnerTests(unittest.TestCase):
    def test_classify(self):
        cases = [(0, '', ('ok', '')), (126, 'Error executing command as another user: Request dismissed\n',
                                         ('cancelled', '')),
                 (127, 'Error executing command as another user: No authentication agent found.\n', ('no-agent', '')),
                 (127, 'Error executing command as another user: Not authorized\n', ('not-authorized', '')),
                 (127, 'pkexec: something else\n', ('pkexec-error', 'pkexec: something else')),
                 (2, 'usage: nvbios setup\nnvbios setup: error: bad\n',
                  ('usage', 'usage: nvbios setup\nnvbios setup: error: bad')),
                 (1, 'Traceback (most recent call last):\n  File "x"\nKeyError: \'a\'\n',
                  ('crash', 'Traceback (most recent call last):\n  File "x"\nKeyError: \'a\'')),
                 (-9, '', ('crash', ''))]
        for prefix in ('SETUP', 'PREPARE', 'BOOTSTRAP', 'VBIOS', 'PRE_INSTALL', 'POST_INSTALL'):
            cases.append((1, f'noise\n{prefix}_BLOCKED: it failed\n', ('blocked', 'it failed')))
        for code, stderr, expected in cases:
            with self.subTest(code=code, stderr=stderr):
                self.assertEqual(classify(Outcome(code, (), stderr)), expected)

    def test_sudo_text_has_no_pkexec_and_no_progress(self):
        argv = [*PKEXEC, '/usr/local/bin/nvbios', 'system', 'setup', '--progress', '--device', '0000:03:00.0',
                '/srv/my files/gpu0.bin', 'ab' * 32]
        self.assertEqual(sudo_text(argv), "sudo /usr/local/bin/nvbios system setup --device 0000:03:00.0 "
                                          f"'/srv/my files/gpu0.bin' {'ab' * 32}")

    def test_stream_drains_both_pipes_and_runs_in_root_directory(self):
        code = ('import os, sys\nprint(os.getcwd(), flush=True)\nsys.stderr.write("e" * 2000000)\n'
                'print("{\\"event\\": \\"done\\"}")\nsys.exit(3)')
        lines = []
        outcome = runner.stream([sys.executable, '-c', code], lines.append)
        self.assertEqual((outcome.returncode, outcome.stdout), (3, ('/', '{"event": "done"}')))
        self.assertEqual(lines, ['/', '{"event": "done"}'])
        self.assertEqual(len(outcome.stderr), 2000000)

    def test_missing_program_is_a_pkexec_error(self):
        outcome = runner.stream(['/nonexistent/pkexec'], lambda line: None)
        self.assertEqual(outcome.returncode, 127)
        self.assertEqual(classify(outcome)[0], 'pkexec-error')


class ControllerTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(os.path.realpath(directory.name))
        self.clone = make_checkout(self.directory)
        self.gpu0 = write(self.directory / 'gpu0-loader.bin', legacy_image(PRO_6000))
        self.sha0 = hashlib.sha256(self.gpu0.read_bytes()).hexdigest()
        self.inspected = []

    def inspect(self, path):
        self.inspected.append(path)
        return {'version': VERSION, 'supported': True, 'reasons': [], 'capabilities': {}}

    def controller(self, snap=None, language='en', **kwargs):
        # The public loader's file check; internal builds are covered by test_internal_builds_check_*.
        kwargs.setdefault('check', lambda data, vendor, device: check_file(data, vendor, device, editor=lambda: None))
        c = Controller(language, checkout=kwargs.pop('checkout', self.clone), inspect=self.inspect, **kwargs)
        self.assertEqual(c.apply_snapshot(snap or snapshot()), [])
        return c

    def ready(self, snap=None, **kwargs):
        """A controller where Load is possible: a new file for GPU 0, GPU 1 stays on its own VBIOS."""
        c = self.controller(snap, **kwargs)
        c.choose_file('0000:03:00.0', str(self.gpu0))
        return c

    def test_exact_argv_before_install(self):
        c = self.ready()
        self.assertEqual(c.load_blockers(), [])
        self.assertEqual(c.load_argv(), [
            *PKEXEC, str(self.clone / 'nvbios'), 'system', 'setup', '--progress', '--repository', str(self.clone),
            '--kernel', KERNEL, '--userspace', 'manual', '--device', '0000:03:00.0', str(self.gpu0), self.sha0,
            '--download-source', VERSION])

    def test_exact_argv_after_install_with_kept_files_and_source(self):
        snap = snapshot(gpus=(GPU0, replace(GPU1, requested='fedcba9876543210')), release='cd' * 32,
                        release_has_setup=True, release_internal=False, saved_source=True, triggers=True,
                        userspace='rpm')
        c = self.ready(snap)
        self.assertEqual(c.choices['0000:13:00.0'].mode, 'keep')     # an override was requested at boot
        self.assertEqual(c.source.mode, 'keep')
        self.assertEqual(c.load_argv(), [
            *PKEXEC, '/usr/local/bin/nvbios', 'system', 'setup', '--progress', '--kernel', KERNEL,
            '--userspace', 'rpm', '--device', '0000:03:00.0', str(self.gpu0), self.sha0, '--keep', '0000:13:00.0',
            '--keep-source'])
        self.assertEqual(c.remove_argv(), [*PKEXEC, '/usr/local/bin/nvbios', 'system', 'disable'])
        self.assertEqual(c.details_argv(), [*PKEXEC, '/usr/local/bin/nvbios', 'system', 'status'])
        self.assertEqual(c.reboot_argv(), ['/usr/bin/systemctl', 'reboot'])

    def test_reopened_before_the_reboot_keeps_the_prepared_gpus(self):
        # Load for GPU 0, reopen before the reboot, choose a new file for GPU 1. GPU 0 is
        # enrolled but not requested at boot yet; it must stay, or be removed only on purpose.
        snap = snapshot(gpus=(replace(GPU0, enrolled='0123456789abcdef'), GPU1), release='cd' * 32,
                        release_has_setup=True, release_internal=False, saved_source=True, triggers=True)
        c = self.controller(snap)
        self.assertEqual((c.choices['0000:03:00.0'].mode, c.choices['0000:13:00.0'].mode), ('keep', 'own'))
        self.assertEqual(c.gpu_view(c.gpu('0000:03:00.0'))['now'], 'Now: prepared (0123456789abcdef), reboot to load it')
        gpu1 = write(self.directory / 'gpu1-loader.bin', legacy_image(RTX_2000_ADA))
        c.choose_file('0000:13:00.0', str(gpu1))
        argv = c.load_argv()
        self.assertIn('--keep', argv)
        self.assertEqual(argv[argv.index('--keep') + 1], '0000:03:00.0')
        self.assertNotIn('--remove', argv)
        c.set_mode('0000:03:00.0', 'own')
        argv = c.load_argv()
        self.assertEqual(argv[argv.index('--remove') + 1], '0000:03:00.0')
        self.assertIn('GPU 0 RTX PRO 6000 (0000:03:00.0): goes back to its own VBIOS', c.confirm_load())

    def test_an_enrolled_gpu_that_is_gone_is_removed_on_purpose(self):
        snap = replace(snapshot(release='cd' * 32, release_has_setup=True, release_internal=False, saved_source=True),
                       enrolled_absent=('0000:41:00.0',))
        c = self.ready(snap)
        argv = c.load_argv()
        self.assertEqual(argv[argv.index('--remove') + 1], '0000:41:00.0')
        self.assertIn('GPU 0000:41:00.0 (not in this machine now): its enrolled override is removed', c.confirm_load())

    @unittest.skipUnless(optional_editor(), 'internal build only')
    def test_internal_builds_check_ada_files_against_the_full_rom(self):
        self.assertEqual(check_file(legacy_image(PRO_6000), 0x10de, PRO_6000), 'blackwell-gb20x')
        with self.assertRaisesRegex(PayloadError, 'choose the .rom the editor saved'):
            check_file(legacy_image(RTX_2000_ADA), 0x10de, RTX_2000_ADA)      # an already relocated payload
        with self.assertRaises(PayloadError):
            check_file(b'not a ROM' * 100, 0x10de, RTX_2000_ADA)              # the full-ROM check refuses it
        self.assertEqual(check_file(legacy_image(RTX_2000_ADA), 0x10de, RTX_2000_ADA, editor=lambda: None), 'ada')

    def test_folder_source_with_p2p_uses_the_real_path(self):
        tree = self.directory / 'open-gpu-kernel-modules'
        tree.mkdir()
        link = self.directory / 'source-link'
        link.symlink_to(tree)
        c = self.ready()
        c.choose_source('folder', str(link))
        c.set_p2p(True)
        self.assertEqual(self.inspected, [str(tree)])
        self.assertEqual(c.load_argv()[-3:], ['--driver-source', str(tree), '--p2p-preferred'])
        self.assertEqual(c.source_view()['check'], ('ok', f'OK: {VERSION}, supported, not patched'))

    def test_folder_source_refusals(self):
        c = self.ready()
        reports = [{'version': '615.71.09', 'supported': True, 'capabilities': {}},
                   {'version': VERSION, 'supported': True, 'capabilities': {'already_patched': True}},
                   {'version': None, 'supported': False, 'reasons': ['version.mk missing'], 'capabilities': {}}]
        texts = ['the folder has 615.71.09, the installed driver is 615.78.08',
                 'the folder is already patched; use an unpatched copy', 'unsupported source: version.mk missing']
        for report, text in zip(reports, texts):
            c.inspect = lambda path, report=report: report
            c.choose_source('folder', str(self.directory))
            self.assertEqual(c.load_blockers(), [f'Driver source: {text}'])
        c.choose_source('folder', str(self.gpu0))
        self.assertEqual(c.load_blockers(), [f'Driver source: {self.gpu0} is not a folder'])
        c.choose_source('folder', '')
        self.assertEqual(c.load_blockers(), ['Driver source: Choose the folder.'])
        c.choose_source('download')
        self.assertEqual(c.load_blockers(), [])

    def test_paths_are_absolute_and_real(self):
        link = self.directory / 'link.bin'
        link.symlink_to(self.gpu0)
        c = self.controller()
        with mock.patch.dict(os.environ, HOME=str(self.directory)):
            c.choose_file('0000:03:00.0', '~/link.bin')
        self.assertEqual(c.choices['0000:03:00.0'].path, str(self.gpu0))
        for value in c.load_argv():
            self.assertFalse(value.startswith('~') or value.startswith('.'), value)
            if '/' in value:
                self.assertTrue(os.path.isabs(value) and value == os.path.realpath(value), value)

    def test_file_checks(self):
        c = self.controller()
        bdf = '0000:03:00.0'
        view = c.gpu_view(GPU0)
        self.assertEqual((view['title'], view['subtitle'], view['now']),
                         ('#0 RTX PRO 6000', '0000:03:00.0 · VBIOS 98.02.6a.00.03', 'Now: own VBIOS'))
        self.assertEqual(view['check'], ('idle', 'No override: this GPU starts with its own VBIOS.'))
        c.set_mode(bdf, 'new')
        self.assertEqual(c.gpu_view(GPU0)['check'], ('warn', 'Choose a payload file.'))
        c.choose_file(bdf, str(self.gpu0))
        self.assertEqual(c.gpu_view(GPU0)['check'],
                         ('ok', f'OK: blackwell-gb20x, 2048 bytes, sha256 {self.sha0[:16]}…'))
        wrong = write(self.directory / 'ada.bin', legacy_image(RTX_2000_ADA))
        c.choose_file(bdf, str(wrong))
        self.assertEqual(c.gpu_view(GPU0)['check'][0], 'error')
        self.assertIn('Refused: legacy image at 0x0 is for PCI ID 10de:28b0, not 10de:2bb4', c.load_blockers()[0])
        c.choose_file(bdf, str(write(self.directory / 'big.bin', b'\0' * (4 * 2 ** 20 + 1))))
        self.assertEqual(c.gpu_view(GPU0)['check'][1],
                         'Refused: the file is larger than 4 MiB; the loader accepts 512 B to 4 MiB')
        c.choose_file(bdf, str(self.directory / 'missing.bin'))
        self.assertIn('cannot read', c.gpu_view(GPU0)['check'][1])
        c.choose_file(bdf, '/run/user/1000/doc/1a2b3c4d/gpu0.bin')     # a document portal path root cannot read
        self.assertEqual(c.load_blockers(), ['GPU 0: Refused: /run/user/1000/doc/1a2b3c4d/gpu0.bin exists only for '
                                             'this session (a file portal path); choose it from its real folder'])
        other = write(self.directory / 'serial.bin', legacy_image(PRO_6000)[:-16] + b'SN0002' + bytes(10))
        c.check = lambda data, vendor, device: 'blackwell-gb20x'
        c.choose_file(bdf, str(other))
        level, text = c.gpu_view(GPU0)['check']
        self.assertEqual(level, 'warn')
        self.assertTrue(text.endswith('The file holds the serial number of GPU 1: make sure it is meant for this '
                                      'card.'))
        self.assertEqual(c.load_blockers(), [])

    def test_each_blocker(self):
        two_part = snapshot(installed_version='575.64', loaded_version='575.64')
        cases = [
            (dict(running=('reconcile',)), 'A loader command is running (reconcile); wait until it finishes.'),
            (dict(service_active=True), 'An automatic rebuild is running; wait until it finishes.'),
            (dict(family=None, distribution='ubuntu'), 'Load from this window works on Fedora and the RHEL family '
                                                       'only (this system: ubuntu); use the command line (README).'),
            (dict(secure_boot=True), 'Secure Boot is on: Load from this window is not supported. Use the command '
                                     'line with your module signing key (README).'),
            (dict(newest_kernel=NEWER), f'The running kernel {KERNEL} is not the newest installed one ({NEWER}): '
                                        f'start {NEWER} first.'),
            (dict(headers=False), f'The kernel headers for {KERNEL} are missing: install kernel-devel.'),
            (dict(open_modules=False), 'The proprietary NVIDIA kernel modules are loaded; the override needs the '
                                       'open modules.'),
            (dict(open_modules=None), 'No NVIDIA kernel module is loaded.'),
            (dict(smi=False), 'nvidia-smi does not answer, so the GPUs cannot be matched.'),
            (dict(userspace=None), 'The installed NVIDIA userspace (version or install type) is unknown.'),
            (dict(plugin=False), 'The package hook plugin that automatic rebuilds need is missing '
                                 '(libdnf5-plugin-actions).'),
            (dict(grub_saved=False), 'Set GRUB_DEFAULT=saved and GRUB_ENABLE_BLSCFG=true in /etc/default/grub.'),
            (dict(release='cd' * 32, release_internal=True), 'The installed loader is a different build (internal '
                                                             'or public) than this clone: update it from the command '
                                                             'line (README, "Updating").'),
        ]
        for changes, text in cases:
            with self.subTest(changes=changes):
                self.assertEqual(self.ready(snapshot(**changes)).load_blockers(), [text])
        self.assertEqual(self.ready(checkout=None).load_blockers(), [
            'The loader is not installed and this window does not run from a clone with the setup helper: start '
            './vbios-loader-gui from the clone.'])
        self.assertEqual(self.controller(snapshot(gpus=())).load_blockers(), ['No NVIDIA GPU found.'])
        self.assertEqual(self.controller().load_blockers(), [
            'Choose a file (or keep the current one) for at least one GPU. To go back to the normal VBIOS on every '
            'GPU, use Remove override.'])
        c = self.ready(two_part)               # no download for two-part versions and nothing saved: a folder
        self.assertEqual((c.source.mode, c.load_blockers()), ('folder', ['Driver source: Choose the folder.']))
        c = self.ready(snapshot(installed_version=None))
        self.assertEqual(c.load_blockers(), ['The installed NVIDIA userspace (version or install type) is unknown.',
                                             'Driver source: The installed driver version is unknown.'])
        c = self.ready()
        c.busy = 'details'
        self.assertEqual(c.load_blockers(), ['Wait until the current task finishes.'])
        self.assertFalse(c.can_load() or c.can_remove() or c.can_details() or c.can_reboot())

    def test_summary_states(self):
        asked = replace(GPU0, requested='0123456789abcdef')
        installed = dict(release='cd' * 32, release_has_setup=True)
        cases = [
            (snapshot(running=('setup',)), ('warn', 'A loader command is still running (setup).')),
            (snapshot(service_active=True), ('warn', 'Automatic rebuild running (kernel or driver update). Wait '
                                                     'until it finishes.')),
            (snapshot(gpus=()), ('error', 'No NVIDIA GPU found.')),
            (snapshot(), ('warn', 'Not installed. Choose a file per GPU and press Load.')),
            (snapshot(gpus=(asked, GPU1), triggers=True, **installed), ('ok', 'Override requested at boot on GPU 0.')),
            (snapshot(gpus=(asked, GPU1), **installed), ('warn', 'Removed. Reboot to return to the normal VBIOS.')),
            (snapshot(triggers=True, images=('x',), **installed),
             ('warn', 'Prepared for this kernel. Reboot to load it (or you started the normal entry).')),
            (snapshot(triggers=True, **installed),
             ('warn', f'Automatic rebuilds are on, but nothing is built for kernel {KERNEL} yet. Use Details.')),
            (snapshot(old_images=True, **installed),
             ('ok', 'No override; automatic rebuilds off; older override entries stay in the boot menu.')),
            (snapshot(**installed), ('ok', 'No override.'))]
        for snap, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(self.controller(snap).summary(), expected)

    def test_gpu_the_driver_did_not_initialize(self):
        # On the PCI bus, but nvidia-smi lists only the other GPU: setup's prepare would refuse it.
        missing = replace(GPU1, index=None, name='NVIDIA RTX 2000 Ada Generation', requested='fedcba9876543210')
        snap = snapshot(gpus=(GPU0, missing), release='cd' * 32, release_has_setup=True, triggers=True)
        c = self.ready(snap)
        self.assertEqual(c.summary(), ('error', 'The NVIDIA driver did not initialize GPU 0000:13:00.0 (missing from '
                                                'nvidia-smi).'))
        self.assertEqual(c.load_blockers(), [
            'The NVIDIA driver did not initialize GPU 0000:13:00.0, usually because of a VBIOS override it cannot '
            'use. Reboot and choose the normal entry in the boot menu, the one without "VBIOS override" in its name '
            '(press Esc or hold Shift while the computer starts). Then choose another file or Own VBIOS for that GPU '
            'and Load again. Remove override and a reboot also work.'])
        self.assertFalse(c.can_load())
        self.assertTrue(c.can_remove())                  # disable never needs the GPU list
        self.assertEqual(c.gpu_view(missing)['title'], '#? NVIDIA RTX 2000 Ada Generation')
        self.assertTrue(c.set_language('es'))
        self.assertEqual(c.summary()[1], 'El driver NVIDIA no inicializó la GPU 0000:13:00.0 (no aparece en '
                                         'nvidia-smi).')
        self.assertEqual(c.load_blockers(), [
            'El driver NVIDIA no inicializó la GPU 0000:13:00.0, normalmente por un override de VBIOS que no puede '
            'usar. Reinicia y elige la entrada normal en el menú de arranque, la que no lleva "VBIOS override" en el '
            'nombre (pulsa Esc o mantén Shift mientras el equipo arranca). Luego elige otro archivo o VBIOS propia '
            'para esa GPU y vuelve a Cargar. También sirve pulsar Quitar override y reiniciar.'])
        # After Remove (triggers off) the summary keeps asking for the reboot; Load stays blocked until then.
        c = self.ready(replace(snap, system=replace(snap.system, triggers=False)))
        self.assertEqual(c.summary(), ('warn', 'Removed. Reboot to return to the normal VBIOS.'))
        self.assertTrue(c.load_blockers()[0].startswith('The NVIDIA driver did not initialize GPU 0000:13:00.0, '
                                                        'usually because of a VBIOS override'))
        # No override asked at this boot (a first use, or vfio-pci): nothing blames an override.
        c = self.ready(snapshot(gpus=(GPU0, replace(missing, requested=None))))
        self.assertEqual(c.summary(), ('error', 'The NVIDIA driver did not initialize GPU 0000:13:00.0 (missing from '
                                                'nvidia-smi).'))
        self.assertEqual(c.load_blockers(), [
            'The NVIDIA driver did not initialize GPU 0000:13:00.0, so it cannot be matched. Check the kernel log '
            '(sudo dmesg | grep NVRM) and whether another driver, such as vfio-pci, uses that GPU.'])
        self.assertTrue(c.set_language('es'))
        self.assertEqual(c.load_blockers(), [
            'El driver NVIDIA no inicializó la GPU 0000:13:00.0, así que no se puede identificar. Revisa el log del '
            'kernel (sudo dmesg | grep NVRM) y si otro driver, como vfio-pci, usa esa GPU.'])
        # nvidia-smi found no GPU at all (exit 6, a one-GPU system): every GPU is named.
        c = self.ready(snapshot(gpus=(replace(GPU0, index=None, requested='0123456789abcdef'), missing),
                                release='cd' * 32, release_has_setup=True, triggers=True))
        self.assertEqual(c.summary(), ('error', 'The NVIDIA driver did not initialize GPU 0000:03:00.0, 0000:13:00.0 '
                                                '(missing from nvidia-smi).'))
        self.assertTrue(c.load_blockers()[0].startswith('The NVIDIA driver did not initialize GPU 0000:03:00.0, '
                                                        '0000:13:00.0, usually because of a VBIOS override'))
        # Without any nvidia-smi answer every index is unknown: that is the nvidia-smi blocker, not this one.
        c = self.ready(snapshot(gpus=(replace(GPU0, index=None), missing), smi=False))
        self.assertEqual(c.load_blockers(), ['nvidia-smi does not answer, so the GPUs cannot be matched.'])
        self.assertEqual(c.summary(), ('warn', 'Not installed. Choose a file per GPU and press Load.'))

    def test_setup_refusal_for_an_uninitialized_gpu_gets_the_window_hint(self):
        message = ('PREPARE_BLOCKED: the NVIDIA driver did not initialize GPU 0000:13:00.0 [10de:28b0], so '
                   'nvidia-smi does not list it (look for NVRM in dmesg). If you booted a VBIOS override, the driver '
                   'most likely cannot use it. Reboot, choose the normal boot entry (without "VBIOS override" in its '
                   'name), then try again with another file for that GPU or without an override.')
        failed = {'event': 'failed', 'step': 'prepare', 'message': message,
                  'cleanup': {'ran': False, 'ok': None, 'message': None}}
        result = self.finish_load(self.ready(), 1, f'SETUP_BLOCKED: prepare: {message}\n', failed)
        self.assertEqual(result.lines, [f'Load failed at "Checking the files and the system": {message} To see the '
                                        'boot menu, press Esc or hold Shift while the computer starts. Remove '
                                        'override and a reboot also work.', 'Nothing was changed.'])
        c = self.ready(language='es')
        lines = self.finish_load(c, 1, f'SETUP_BLOCKED: prepare: {message}\n', failed).lines
        self.assertTrue(lines[0].endswith(f'{message} El driver NVIDIA no inicializó esa GPU. Si arrancaste con un '
                                          'override de VBIOS, lo más probable es que no pueda usarlo. Reinicia y '
                                          'elige la entrada normal en el menú de arranque, la que no lleva "VBIOS '
                                          'override" en el nombre (pulsa Esc o mantén Shift mientras el equipo '
                                          'arranca). Luego elige otro archivo o VBIOS propia para esa GPU y vuelve a '
                                          'Cargar. También sirve pulsar Quitar override y reiniciar.'), lines[0])

    def test_system_rows(self):
        rows = self.controller(snapshot(loaded_version='615.71.09', newest_kernel=NEWER, boot_free=200 * 2 ** 20,
                                        release='cd' * 32, clone_matches=False, triggers=True)).system_rows()
        self.assertEqual(rows, [
            ('Loader', 'Installed (release cdcdcdcd…), automatic rebuilds on; installed release differs from this '
                       'clone', 'warn'),
            ('NVIDIA driver', 'installed 615.78.08, running 615.71.09: reboot pending or post-install needed', 'error'),
            ('Kernel', f'{KERNEL}; the newest installed kernel is {NEWER}', 'error'),
            ('Secure Boot', 'off', 'ok'),
            ('Boot', 'GRUB saved default with BLS, /boot free 200 MB (about 600 MB needed)', 'warn'),
            ('Package hook', 'plugin installed', 'ok')])
        self.assertEqual(self.controller().system_rows()[1],
                         ('NVIDIA driver', f'{VERSION}, open kernel modules, installed with the .run installer '
                                           '(manual)', 'ok'))

    def events(self, c, *events):
        lines = []
        for event in events:
            lines += c.on_line(json.dumps(event))
        return lines

    def test_progress_from_events(self):
        clock = iter(range(1000, 2000, 65)).__next__
        c = self.ready(clock=clock)
        argv, lines = c.begin('load')
        self.assertEqual(lines, ['$ ' + ' '.join(argv)])
        self.assertEqual(c.progress_text(), 'Waiting for the password… 1:05')
        steps = ['prepare', 'preflight', 'install', 'enroll', 'reconcile', 'enable']
        self.assertEqual(self.events(c, {'event': 'start', 'protocol': 1, 'kernel': KERNEL, 'steps': steps},
                                     {'event': 'step', 'step': 'prepare', 'index': 0, 'total': 6}),
                         ['Step 1/6 · Checking the files and the system'])
        self.assertEqual(self.events(c, {'event': 'result', 'step': 'prepare', 'result': {'state': 'prepared'}},
                                     {'event': 'step', 'step': 'reconcile', 'index': 5, 'total': 6},
                                     {'event': 'phase', 'step': 'reconcile', 'phase': 'build'}),
                         ['Checking the files and the system: done', f'Step 5/6 · Building for kernel {KERNEL}',
                          '  building the NVIDIA modules (a few minutes)'])
        self.assertEqual(c.progress_text(), f'Step 5/6 · Building for kernel {KERNEL}: building the NVIDIA modules '
                                            '(a few minutes) · 2:10')
        self.assertEqual(c.progress_fraction(), 4 / 6)
        self.assertEqual(self.events(c, {'event': 'phase', 'step': 'reconcile', 'phase': 'source'}),
                         ['  copying and patching the driver source'])
        self.assertEqual(c.on_line('not json'), ['not json'])
        self.assertEqual(c.on_line(''), [])

    def finish_load(self, c, code, stderr='', *events):
        c.begin('load')
        self.events(c, *events)
        lines = tuple(json.dumps(event) for event in events)
        return c.finish(Outcome(code, lines, stderr))

    def test_load_success_and_reboot_text(self):
        done = {'event': 'done', 'ok': True, 'kernel': KERNEL, 'entry': f'vbios-{KERNEL}-0123', 'default': 'selected',
                'default_reason': None, 'devices': [
                    {'bdf': '0000:03:00.0', 'sha256': self.sha0, 'architecture': 'blackwell-gb20x', 'kept': False},
                    {'bdf': '0000:13:00.0', 'sha256': 'ef' * 32, 'architecture': 'ada', 'kept': True}]}
        result = self.finish_load(self.ready(), 0, '', done)
        self.assertTrue(result.ok and result.offer_reboot)
        self.assertEqual(result.lines, [
            f'Load finished for kernel {KERNEL}.',
            f'GPU 0000:03:00.0: new file, blackwell-gb20x, sha256 {self.sha0[:16]}…',
            f'GPU 0000:13:00.0: current file kept, ada, sha256 {"ef" * 8}…',
            f'The override entry vbios-{KERNEL}-0123 is the default boot entry now.'])
        self.assertIn('Your normal boot entry stays in the boot menu', result.reboot_text)
        result = self.finish_load(self.ready(), 0, '', dict(done, default='preserved',
                                                            default_reason='foreign default'))
        self.assertFalse(result.ok or result.offer_reboot)        # a respected foreign default is not a Load
        self.assertEqual(result.lines[-1], 'The default boot entry was not changed (foreign default): pick the '
                                           'override entry in the boot menu.')
        result = self.finish_load(self.ready(), 0, '')
        self.assertEqual((result.ok, result.lines), (False, ['The command ended without a result.',
                                                             'The state is unknown: press Refresh, then Details.']))

    def test_load_failures_name_the_state(self):
        failed = {'event': 'failed', 'step': 'reconcile', 'message': 'VBIOS_BLOCKED: foreign or unrelated GRUB '
                  'default preserved; explicit selection required', 'cleanup': {'ran': False, 'ok': None,
                                                                                  'message': None}}
        result = self.finish_load(self.ready(), 1, 'SETUP_BLOCKED: reconcile: x\n', failed)
        self.assertFalse(result.ok or result.offer_reboot)
        self.assertEqual(result.lines, [
            f'Load failed at "Building for kernel {KERNEL}": VBIOS_BLOCKED: foreign or unrelated GRUB default '
            'preserved; explicit selection required The default boot entry is not the normal entry of this kernel: '
            'start the normal entry of the newest kernel, then Load again.',
            'The step undid its own changes; automatic rebuilds are off and the normal entry stays the default.'])
        enable = dict(failed, step='enable', message='BOOTSTRAP_BLOCKED: plugin prerequisites are unavailable',
                      cleanup={'ran': True, 'ok': True, 'message': None})
        result = self.finish_load(self.ready(), 1, '', enable)
        self.assertEqual(result.lines[1], 'Remove ran after the failure: the normal entry is the default and '
                                          'automatic rebuilds are off.')
        self.assertTrue(result.lines[0].endswith('Install libdnf5-plugin-actions.'))
        enable['cleanup'] = {'ran': True, 'ok': False, 'message': 'lock busy'}
        result = self.finish_load(self.ready(), 1, '', enable)
        self.assertTrue(result.lines[1].startswith('The cleanup after the failure failed as well (lock busy): the '
                                                   'system may still start the override by default.'))
        result = self.finish_load(self.ready(), 1, 'SETUP_BLOCKED: prepare: PREPARE_BLOCKED: output already exists\n')
        self.assertEqual(result.lines, ['Load failed at "Checking the files and the system": PREPARE_BLOCKED: '
                                        'output already exists Internal error; try again.', 'Nothing was changed.'])
        result = self.finish_load(self.ready(), 1, 'SETUP_BLOCKED: kernel mismatch\n')
        self.assertEqual(result.lines, ['Load failed: kernel mismatch',
                                        'The state is unknown: press Refresh, then Details.'])
        unknown = 'The state is unknown: press Refresh, then Details.'
        disable = dict(failed, step='disable', message='BOOTSTRAP_BLOCKED: update/build lock busy')
        self.assertEqual(self.finish_load(self.ready(), 1, '', disable).lines[-1], unknown)   # disable may not have run
        stuck = dict(failed, message='VBIOS_BLOCKED: the interrupted transaction could not be rolled back')
        self.assertEqual(self.finish_load(self.ready(), 1, '', stuck).lines[-1], unknown)
        result = self.finish_load(self.ready(), 1, 'Traceback (most recent call last):\nKeyError: \'x\'\n')
        self.assertEqual(result.lines, ['Unexpected error (exit code 1): Traceback (most recent call last):\n'
                                        'KeyError: \'x\'', 'The state is unknown: press Refresh, then Details.'])

    def test_pkexec_outcomes(self):
        c = self.ready()
        argv, _ = c.begin('load')
        self.assertEqual(c.finish(Outcome(126, (), 'Request dismissed\n')).lines,
                         ['The password dialog was closed; nothing was changed.'])
        c.begin('load')
        lines = c.finish(Outcome(127, (), 'Error executing command as another user: No authentication agent '
                                          'found.\n')).lines
        self.assertEqual(lines, ['No password dialog is available (no polkit agent). Run this in a terminal instead:',
                                 'sudo ' + ' '.join(value for value in argv[2:] if value != '--progress')])
        c.begin('remove')
        self.assertEqual(c.finish(Outcome(127, (), 'Not authorized\n')).lines,
                         ['Not authorized. Run this in a terminal as an administrator instead:',
                          'sudo /usr/local/bin/nvbios system disable'])
        c.begin('load')
        self.assertEqual(c.finish(Outcome(2, (), 'nvbios: error: unrecognized arguments: --keep\n')).lines,
                         ['The command was rejected (a bug in this window): nvbios: error: unrecognized arguments: '
                          '--keep'])
        self.assertIsNone(c.busy)

    def test_remove_details_and_reboot_results(self):
        c = self.ready(snapshot(release='cd' * 32, release_has_setup=True))
        for restoration, line in (({'state': 'normal', 'entry': 'n'}, 'Removed: automatic rebuilds are off and the '
                                                                        'normal entry is the default again.'),
                                  ({'state': 'preserved', 'reason': 'foreign default'},
                                   'Removed: automatic rebuilds are off; the default boot entry was not changed '
                                   '(foreign default).'),
                                  (None, 'Automatic rebuilds are off; nothing was enrolled.')):
            c.begin('remove')
            self.assertEqual(c.on_line('{'), [])                       # an indented document, not events
            stdout = tuple(json.dumps({'state': 'disabled', 'default_restoration': restoration}, indent=2).splitlines())
            result = c.finish(Outcome(0, stdout, ''))
            self.assertEqual((result.lines, result.offer_reboot, result.reboot_text),
                             ([line], True, 'Reboot to return to the stock VBIOS.'))
        c.begin('remove')
        busy = Outcome(1, (), 'BOOTSTRAP_BLOCKED: update/build lock busy: /x; timer will retry\n')
        self.assertEqual(c.finish(busy).lines, ['Remove failed: update/build lock busy: /x; timer will retry Another '
                                                'loader task or an automatic rebuild is running; try again in a few '
                                                'minutes.'])
        status = {'installed': True, 'enrolled': True, 'ready': False, 'triggers_enabled': True,
                  'last_attempt': {'state': 'blocked', 'finished': 0, 'error': 'matching kernel-devel missing for K'},
                  'driver_drift': {'resume': 'nvbios system post-install --source PATH --p2p-preferred'},
                  'source_fetch': {'state': 'off'}, 'runtime': {'activation_matches': None}}
        c.begin('details')
        result = c.finish(Outcome(0, tuple(json.dumps(status, indent=2).splitlines()), ''))
        self.assertTrue(result.ok)
        self.assertFalse(result.offer_reboot)
        self.assertEqual(result.lines[:4], ['Installed: yes', 'Enrolled: yes', 'Ready for the running kernel: no',
                                            'Automatic rebuilds: yes'])
        self.assertTrue(result.lines[4].startswith('Last build: blocked, 19'))
        self.assertEqual(result.lines[5:], [
            'Last build error: matching kernel-devel missing for K Install kernel-devel for the running kernel.',
            'The driver changed; register its source with: sudo nvbios system post-install --source PATH '
            '--p2p-preferred', 'Source download: off', 'Loaded module parameters match the enrollment: unknown'])
        c.begin('details')
        self.assertEqual(c.finish(Outcome(0, ('not json',), '')).lines,
                         ['Details failed: Unexpected error (exit code 0): The command ended without a result.'])
        c.begin('reboot')
        self.assertEqual(c.finish(Outcome(0, (), '')).lines, [])
        c.begin('reboot')
        self.assertEqual(c.finish(Outcome(1, (), 'Operation inhibited by "nvidia-vbios"\n')).lines,
                         ['The reboot was refused (exit code 1): Operation inhibited by "nvidia-vbios"'])

    def test_confirmations(self):
        asked = replace(GPU1, requested='fedcba9876543210')
        c = self.ready(snapshot(gpus=(GPU0, asked)))
        c.set_mode('0000:13:00.0', 'own')
        question = c.confirm_load()
        self.assertIn(f'GPU 0 RTX PRO 6000 (0000:03:00.0): {self.gpu0}, blackwell-gb20x, 2048 bytes\n'
                      'GPU 1 RTX 2000 Ada (0000:13:00.0): goes back to its own VBIOS', question)
        self.assertIn('Driver source: download 615.78.08 from GitHub (no distribution copy to compare with: '
                      "trusted on GitHub's HTTPS).", question)
        self.assertIn('the system, install the loader, build', question)
        self.assertTrue(question.endswith('then press Remove override here.'))
        self.gpu0.write_bytes(legacy_image(PRO_6000, blocks=8))   # changed after the check: read again
        c.confirm_load()
        self.assertEqual(c.load_argv()[c.load_argv().index('--device') + 3],
                         hashlib.sha256(self.gpu0.read_bytes()).hexdigest())
        self.gpu0.write_bytes(b'')
        self.assertIsNone(c.confirm_load())
        self.assertIn('There is no uninstall.', c.confirm_remove())

    def test_language(self):
        c = self.controller(language='es')
        c.choose_file('0000:03:00.0', '/run/user/1000/doc/x.bin')
        self.assertEqual(c.gpu_view(GPU0)['check'][1], 'Rechazado: /run/user/1000/doc/x.bin solo existe en esta '
                         'sesión (una ruta del portal de archivos); elígelo desde su carpeta real')
        c.busy = 'load'
        self.assertFalse(c.set_language('en'))
        c.busy = None
        self.assertTrue(c.set_language('en'))
        self.assertTrue(c.gpu_view(GPU0)['check'][1].startswith('Refused: /run/user/1000/doc/x.bin exists only'))
        for environ, expected in (({'LC_ALL': 'es_CL.UTF-8', 'LANG': 'en_US.UTF-8'}, 'es'),
                                  ({'LC_ALL': '', 'LC_MESSAGES': 'en_GB.UTF-8', 'LANG': 'es_ES.UTF-8'}, 'en'),
                                  ({'LANG': 'es_MX.UTF-8'}, 'es'), ({}, 'en')):
            self.assertEqual(language_from_env(environ), expected)

    def test_spanish_has_every_key_with_the_same_placeholders(self):
        def fields(text):
            return {name for _, name, _, _ in string.Formatter().parse(text) if name}
        self.assertEqual(set(STRINGS['es']), set(STRINGS['en']))
        for name, text in STRINGS['en'].items():
            self.assertEqual(fields(STRINGS['es'][name]), fields(text), name)
        used = {key for _, key in gui_controller.HINTS} | set(gui_controller.FAILED_STATE.values())
        self.assertLessEqual(used, set(STRINGS['en']))


class LaunchTests(unittest.TestCase):
    def test_window_needs_nothing_newer_than_its_minimum_gtk(self):
        source = (Path(gui_controller.__file__).parent / 'gui.py').read_text()
        self.assertFalse('.remove_all(' in source)    # Gtk.ListBox.remove_all is GTK 4.12; the minimum is 4.10

    def test_probe_runner_and_controller_never_import_gi(self):
        code = ('import sys\nimport nvidia_vbios.loader_gui, nvidia_vbios.loader_gui.probe\n'
                'import nvidia_vbios.loader_gui.runner, nvidia_vbios.loader_gui.controller\n'
                'assert "gi" not in sys.modules')
        subprocess.run([sys.executable, '-c', code], check=True)

    def test_refuses_root_and_missing_gtk(self):
        from nvidia_vbios.loader_gui import main
        with mock.patch('os.geteuid', return_value=0), mock.patch('sys.stderr'):
            self.assertEqual(main([]), 1)
        code = ('import importlib.abc, os, sys\n'
                'class Block(importlib.abc.MetaPathFinder):\n'
                '    def find_spec(self, name, path, target=None):\n'
                '        if name == "gi":\n'
                '            raise ImportError("no gi here")\n'
                'sys.meta_path.insert(0, Block())\nos.geteuid = lambda: 1000\n'
                'from nvidia_vbios.loader_gui import main\nassert main([]) == 2')
        result = subprocess.run([sys.executable, '-c', code], check=True, capture_output=True, text=True)
        self.assertIn('needs GTK 4 and PyGObject', result.stderr)
        self.assertNotIn('Traceback', result.stderr)

    def test_checkout_and_launcher(self):
        with tempfile.TemporaryDirectory() as directory:
            clone = make_checkout(directory)
            module = clone / 'src/nvidia_vbios/__init__.py'
            module.write_text('')
            self.assertEqual(find_checkout(module), clone.resolve())
            (clone / 'src/nvidia_vbios/system_setup.py').unlink()
            self.assertIsNone(find_checkout(module))
        launcher = Path(__file__).resolve().parents[1] / 'vbios-loader-gui'
        self.assertTrue(os.access(launcher, os.X_OK))
        self.assertIn('from nvidia_vbios.loader_gui import main', launcher.read_text())


if __name__ == '__main__':
    unittest.main()
