"""Upstream tag download, extraction and package cross-check with local tarballs; no network."""
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch
import urllib.error

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / 'src'))
sys.path.insert(0, str(REPO / 'tests'))
import test_bootstrap as bootstrap_fixtures
import test_onboarding_open as onboarding_fixtures
from test_payload import legacy_image
from nvidia_vbios.bootstrap import BASE, CONFIG, ENABLED, STATE
from nvidia_vbios.driver_update import DriverUpdate, FETCH_RECORD
from nvidia_vbios.lifecycle import Reconciler, source_fetch
from nvidia_vbios.lifecycle.__main__ import after_drift
from nvidia_vbios.lifecycle.config import load_config
from nvidia_vbios.lifecycle.security import LifecycleError, LockBusy, digest, json_write
from nvidia_vbios.onboarding import Onboarding, main as onboarding_main

VERSION = '615.78.08'
TOP = f'open-gpu-kernel-modules-{VERSION}'
URL = source_fetch.URL.format(version=VERSION)
COMMIT = '1a82fbfda8f321b056eb3568850f9316c5e465c5'
KERNEL_OPEN = {'Kbuild': b'obj-m += nvidia/\n', 'Makefile': b'all:\n\t$(MAKE) modules\n',
               'conftest.sh': b'#!/bin/sh\necho conftest\n', 'nvidia/nv.c': b'int nv_init(void) { return 0; }\n',
               'nvidia-uvm/uvm.c': b'int uvm_init(void) { return 0; }\n'}


UTILS_MK = b'CC ?= cc\nDATE                  ?= date\nECHO ?= echo\n'


def tag_files(version=VERSION):
    files = {'version.mk': f'NVIDIA_VERSION = {version}\n'.encode(), 'kernel-open/.gitignore': b'*.o\n',
             'kernel-open/dkms.conf': b'PACKAGE_NAME="nvidia"\n', 'src/nvidia/rm.c': b'int rm(void);\n',
             'Makefile': b'modules:\n\t$(MAKE) -C src/nvidia\n\t$(MAKE) -C kernel-open modules\n',
             'utils.mk': UTILS_MK, 'nv-compiler.sh': b'#!/bin/sh\necho cc\n',
             '.github/ISSUE_TEMPLATE/bug.yml': b'name: bug\n'}
    files.update({'kernel-open/' + name: data for name, data in KERNEL_OPEN.items()})
    return files


def add(tar, name, data=None, kind=tarfile.REGTYPE, mode=0o644, linkname=''):
    info = tarfile.TarInfo(name)
    info.type, info.mode, info.linkname = kind, mode, linkname
    if kind == tarfile.DIRTYPE:
        info.mode = 0o755
    info.size = len(data) if data is not None else 0
    tar.addfile(info, io.BytesIO(data) if data is not None else None)


def write_tag(path, files, *, top=TOP, extra=(), commit=COMMIT):
    """git-archive shaped tarball: pax comment, directories before their files."""
    with tarfile.open(path, 'w:gz', format=tarfile.PAX_FORMAT, pax_headers={'comment': commit}) as tar:
        made = set()
        for name in sorted(files):
            parts = (top, *name.split('/'))
            for depth in range(1, len(parts)):
                directory = '/'.join(parts[:depth])
                if directory not in made:
                    add(tar, directory, kind=tarfile.DIRTYPE)
                    made.add(directory)
            add(tar, '/'.join(parts), files[name], mode=0o755 if name.endswith('.sh') else 0o644)
        for item in extra:
            add(tar, *item)
    return path


class Response(io.BytesIO):
    def __init__(self, data, status=200, url=URL, fail_after=None):
        super().__init__(data)
        self.status, self.url, self.fail_after, self.reads = status, url, fail_after, 0

    def geturl(self):
        return self.url

    def read(self, size=-1):
        self.reads += 1
        if self.fail_after is not None and self.reads > self.fail_after:
            raise TimeoutError('timed out')
        return super().read(min(size, 1024) if size and size > 0 else size)

    read1 = read


class Trickle(Response):
    """One byte per socket receive, one second each: read() waits for the whole size, read1() for one receive."""
    def __init__(self, data):
        super().__init__(data)
        self.now = 0

    def receive(self):
        self.now += 1
        return io.BytesIO.read(self, 1)

    def read(self, size=-1):
        data = b''
        while len(data) < size and (byte := self.receive()):
            data += byte
        return data

    def read1(self, size=-1):
        return self.receive()


class SourceFetchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='source-fetch-')
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def tarball(self, files=None, **kwargs):
        return write_tag(self.dir / f'tag-{len(list(self.dir.iterdir()))}.tar.gz', tag_files() if files is None else files, **kwargs)

    def extract(self, archive, top=TOP):
        destination = Path(tempfile.mkdtemp(dir=self.dir))
        return source_fetch.extract(archive, destination, top)

    def test_extract_accepts_a_git_archive_and_normalizes_modes(self):
        tree, commit = self.extract(self.tarball())
        self.assertEqual((tree.name, commit), (TOP, COMMIT))
        self.assertEqual((tree / 'kernel-open/nvidia/nv.c').read_bytes(), KERNEL_OPEN['nvidia/nv.c'])
        self.assertEqual(stat.S_IMODE((tree / 'kernel-open/conftest.sh').stat().st_mode), 0o755)
        self.assertEqual(stat.S_IMODE((tree / 'version.mk').stat().st_mode), 0o644)
        self.assertEqual(stat.S_IMODE((tree / 'kernel-open').stat().st_mode), 0o755)
        _, missing = self.extract(self.tarball(commit='not a commit'))
        self.assertIsNone(missing)

    def test_extract_rejects_unsafe_or_unexpected_entries(self):
        unsafe, special = 'unsafe, duplicate', 'not a plain file'
        cases = {
            'traversal': ([(f'{TOP}/../evil', b'x')], unsafe),
            'absolute': ([('/etc/evil', b'x')], unsafe),
            'charset': ([(f'{TOP}/bad name.c', b'x')], unsafe),
            'symlink': ([(f'{TOP}/link', None, tarfile.SYMTYPE, 0o777, '/etc/passwd')], special),
            'hardlink': ([(f'{TOP}/hard', None, tarfile.LNKTYPE, 0o644, f'{TOP}/version.mk')], special),
            'device': ([(f'{TOP}/dev', None, tarfile.CHRTYPE)], special),
            'fifo': ([(f'{TOP}/fifo', None, tarfile.FIFOTYPE)], special),
            'duplicate': ([(f'{TOP}/version.mk', b'second copy')], unsafe),
            'second top': ([('other', None, tarfile.DIRTYPE), ('other/file', b'x')], 'outside'),
            'before directory': ([(f'{TOP}/later/file.c', b'x')], 'before its directory'),
        }
        for label, (extra, reason) in cases.items():
            with self.subTest(label=label), self.assertRaisesRegex(source_fetch.Rejected, reason):
                self.extract(self.tarball(extra=extra))
        with self.subTest(label='wrong top'), self.assertRaisesRegex(source_fetch.Rejected, 'outside'):
            self.extract(self.tarball(top='open-gpu-kernel-modules-615.78.07'))

    def test_extract_enforces_entry_file_and_total_caps(self):
        archive = self.tarball()
        for name, value, reason in (('MAX_ENTRIES', 5, 'excess'), ('MAX_FILE', 16, 'size limit'), ('MAX_TOTAL', 64, 'size limit')):
            with self.subTest(cap=name), patch.object(source_fetch, name, value), self.assertRaisesRegex(source_fetch.Rejected, reason):
                self.extract(archive)
        self.extract(archive)

    def download(self, response, **kwargs):
        calls = []
        def opener(request, timeout):
            calls.append((request.full_url, timeout))
            if isinstance(response, Exception):
                raise response
            return response
        target = self.dir / f'download-{len(list(self.dir.iterdir()))}.tar.gz'
        try:
            return source_fetch.download(VERSION, target, open_url=opener, **kwargs), target, calls
        finally:
            self.assertTrue(all(call == (URL, source_fetch.READ_TIMEOUT) for call in calls))

    def test_download_hashes_while_streaming_into_a_new_private_file(self):
        data = self.tarball().read_bytes()
        result, target, calls = self.download(Response(data))
        self.assertEqual(result, {'url': URL, 'archive_sha256': hashlib.sha256(data).hexdigest(), 'size': len(data)})
        self.assertEqual(target.read_bytes(), data)
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        self.assertEqual(len(calls), 1)
        with self.assertRaises(source_fetch.FetchFailed):
            source_fetch.download(VERSION, target, open_url=lambda request, timeout: Response(data))

    def test_http_errors_redirects_and_timeouts_fail_for_a_retry(self):
        not_found = urllib.error.HTTPError(URL, 404, 'Not Found', {}, None)
        redirect = urllib.error.HTTPError(URL, 302, 'Found', {'Location': 'https://example.invalid/x'}, None)
        ticks = iter(range(0, 10000, 200))
        for label, response, kwargs in (('404', not_found, {}), ('redirect', redirect, {}),
                                        ('moved url', Response(b'data', url='https://example.invalid/x'), {}),
                                        ('status', Response(b'data', status=206), {}),
                                        ('socket timeout', Response(b'x' * 4096, fail_after=1), {}),
                                        ('total timeout', Response(b'x' * 4096), {'clock': lambda: next(ticks)}),
                                        ('tls', urllib.error.URLError('certificate verify failed'), {})):
            with self.subTest(label=label), self.assertRaises(source_fetch.FetchFailed):
                self.download(response, **kwargs)
        self.assertIsNone(source_fetch._NoRedirect().redirect_request(None, None, 302, 'Found', {}, 'https://example.invalid/'))

    def test_total_timeout_holds_against_a_trickling_server(self):
        response = Trickle(b'x' * 4096)
        with self.assertRaisesRegex(source_fetch.FetchFailed, 'longer than'):
            self.download(response, clock=lambda: response.now)
        self.assertLessEqual(response.now, source_fetch.TOTAL_TIMEOUT + source_fetch.READ_TIMEOUT)

    def test_oversized_download_is_rejected_and_bad_versions_never_connect(self):
        with patch.object(source_fetch, 'MAX_ARCHIVE', 100), self.assertRaises(source_fetch.Rejected):
            self.download(Response(b'x' * 4096))
        for version in ('615.78', '615.78.08; rm', '../615.78.08'):
            with self.subTest(version=version), self.assertRaises(LifecycleError):
                source_fetch.download(version, self.dir / 'never', open_url=lambda *args: self.fail('network used'))

    def root_with(self, layout, files=None, version=VERSION):
        root = Path(tempfile.mkdtemp(dir=self.dir))
        files = dict(KERNEL_OPEN if files is None else files)
        if layout == 'rpmfusion':
            share = root / f'usr/share/nvidia-kmod-{version}'
            share.mkdir(parents=True)
            with tarfile.open(share / f'nvidia-kmod-{version}-{os.uname().machine}.tar.xz', 'w:xz') as tar:
                add(tar, 'kernel', kind=tarfile.DIRTYPE)
                add(tar, 'kernel/nvidia/closed.c', b'proprietary tree is ignored')
                add(tar, 'kernel-open', kind=tarfile.DIRTYPE)
                for name, data in files.items():
                    add(tar, 'kernel-open/' + name, data)
                add(tar, 'kernel-open/nvidia/nv-kernel.o_binary', b'\x7fELF prebuilt')
                add(tar, 'supported-gpus/supported-gpus.json', b'{}')
            return root
        base = root / f'usr/src/nvidia-{version}'
        if layout == 'full':
            (base / 'kernel').mkdir(parents=True)
            base = base / 'kernel-open'
        files.update({'dkms.conf': b'PACKAGE_VERSION=x\n', 'patches/0001-distro.patch': b'--- a\n',
                      'nvidia-modeset/nv-modeset-kernel.o_binary': b'\x7fELF'})
        for name, data in files.items():
            path = base / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return root

    def tree_root(self, changes=None):
        """NVIDIA's CUDA repositories and Arch install the whole release as /usr/src/nvidia-VERSION."""
        root = Path(tempfile.mkdtemp(dir=self.dir))
        files = {name: data for name, data in tag_files().items() if not name.startswith('.github/')
                 and not name.endswith('.gitignore')}
        files.update({'dkms.conf': b'PACKAGE_VERSION=615.78.08\n', 'nv-compiler.sh': b'#!/usr/bin/sh\necho cc\n'})
        for name, data in (changes or {}).items():
            if data is None:
                files.pop(name)
            else:
                files[name] = data
        for name, data in files.items():
            path = root / f'usr/src/nvidia-{VERSION}' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        return root

    def test_a_packaged_whole_tree_is_compared_whole(self):
        tree, _ = self.extract(self.tarball())
        def verify(root):
            return source_fetch.verify(tree, source_fetch.packaged_source(VERSION, root))
        self.assertEqual(verify(self.tree_root()), 'matched')
        # Arch: dkms.conf moved out of kernel-open, and the exact reproducible-build edit of utils.mk.
        arch = UTILS_MK.replace(b'DATE                  ?= date', b'DATE = date -r version.mk')
        arch_root = self.tree_root({'kernel-open/dkms.conf': None, 'utils.mk': arch})
        self.assertEqual(verify(arch_root), 'matched')
        # Only the upstream DATE line takes that edit; the build runs DATE in a shell.
        for line in (b'DATE ?= date; id > /tmp/owned', b'DATE ?= $(shell id > /tmp/owned) date'):
            tampered = dict(tag_files(), **{'utils.mk': UTILS_MK.replace(b'DATE                  ?= date', line)})
            with self.subTest(line=line), self.assertRaisesRegex(source_fetch.Rejected, 'utils.mk'):
                source_fetch.verify(self.extract(self.tarball(tampered))[0], source_fetch.packaged_source(VERSION, arch_root))
        # Interpreter lines are normalized, not dropped, and only the tag's own .gitignore files and
        # kernel-open/dkms.conf go uncompared (they are still snapshotted with the tree).
        for name, data in (('nv-compiler.sh', b'#!/bin/sh .gitignore\necho cc\n'),
                           ('Makefile', b'#!/bin/sh x\n' + tag_files()['Makefile']),
                           ('src/nvidia/.gitignore', b'id > /tmp/owned\n'), ('src/nvidia/dkms.conf', b'x\n')):
            tampered = dict(tag_files(), **{name: data})
            with self.subTest(name=name), self.assertRaisesRegex(source_fetch.Rejected, name):
                source_fetch.verify(self.extract(self.tarball(tampered))[0], source_fetch.packaged_source(VERSION, self.tree_root()))
        # Fedora also turns `#!/usr/bin/env python3` into `#!/usr/bin/python3`.
        script = dict(tag_files(), **{'nouveau/extract.py': b'#!/usr/bin/env python3\nprint()\n'})
        packaged = source_fetch.packaged_source(VERSION, self.tree_root({'nouveau/extract.py': b'#!/usr/bin/python3\nprint()\n'}))
        self.assertEqual(source_fetch.verify(self.extract(self.tarball(script))[0], packaged), 'matched')
        # What the build runs as root outside kernel-open: top-level Makefiles, scripts and src/.
        for name, data in (('Makefile', b'modules:\n\tid > /tmp/owned\n'), ('src/nvidia/rm.c', b'int rm(void) { return 1; }\n'),
                           ('utils.mk', UTILS_MK.replace(b'?= date', b'= date; id')), ('src/nvidia/extra.c', b'added\n'),
                           ('nv-compiler.sh', None)):
            with self.subTest(name=name, data=data), self.assertRaisesRegex(source_fetch.Rejected, name):
                verify(self.tree_root({name: data}))

    def test_cross_check_accepts_each_packaged_layout_and_rejects_differences(self):
        tree, _ = self.extract(self.tarball())
        for layout in ('rpmfusion', 'full', 'flattened'):
            with self.subTest(layout=layout):
                # Only kernel-open is packaged: the top-level Makefiles and src/ rest on GitHub's TLS.
                self.assertEqual(source_fetch.verify(tree, source_fetch.packaged_source(VERSION, self.root_with(layout))),
                                 'kernel-open-only')
                changed = dict(KERNEL_OPEN, **{'nvidia/nv.c': b'int nv_init(void) { return 1; }\n'})
                with self.assertRaisesRegex(source_fetch.Rejected, 'nvidia/nv.c'):
                    source_fetch.cross_check(tree, source_fetch.packaged_source(VERSION, self.root_with(layout, changed)))
                extra = dict(KERNEL_OPEN, **{'nvidia/extra.c': b'added by a distribution\n'})
                with self.assertRaisesRegex(source_fetch.Rejected, 'extra.c'):
                    source_fetch.cross_check(tree, source_fetch.packaged_source(VERSION, self.root_with(layout, extra)))
                missing = {name: data for name, data in KERNEL_OPEN.items() if name != 'nvidia-uvm/uvm.c'}
                with self.assertRaisesRegex(source_fetch.Rejected, 'uvm.c'):
                    source_fetch.cross_check(tree, source_fetch.packaged_source(VERSION, self.root_with(layout, missing)))

    def test_rewritten_interpreter_line_is_ignored_but_script_body_is_not(self):
        tree, _ = self.extract(self.tarball())
        rewritten = dict(KERNEL_OPEN, **{'conftest.sh': b'#!/usr/bin/sh\necho conftest\n'})
        source_fetch.cross_check(tree, source_fetch.packaged_source(VERSION, self.root_with('full', rewritten)))
        changed = dict(KERNEL_OPEN, **{'conftest.sh': b'#!/bin/sh\necho something else\n'})
        with self.assertRaises(source_fetch.Rejected):
            source_fetch.cross_check(tree, source_fetch.packaged_source(VERSION, self.root_with('full', changed)))
        # Only a plain interpreter path is ignored; a tag cannot hide a command in that line.
        packaged = source_fetch.packaged_source(VERSION, self.root_with('full', rewritten))
        for line in (b'#!/usr/bin/env -S sh -c "id > /tmp/owned; exec /bin/sh $0"', b'#!/tmp/x/sh', b'#!anything'):
            tampered = dict(tag_files(), **{'kernel-open/conftest.sh': line + b'\necho conftest\n'})
            with self.subTest(line=line), self.assertRaises(source_fetch.Rejected):
                source_fetch.cross_check(self.extract(self.tarball(tampered))[0], packaged)

    def test_no_packaged_tree_means_the_cross_check_is_unavailable(self):
        root = Path(tempfile.mkdtemp(dir=self.dir))
        (root / f'usr/src/nvidia-{VERSION}').mkdir(parents=True)  # an unrelated, empty directory
        self.assertIsNone(source_fetch.packaged_source(VERSION, root))
        self.assertIsNone(source_fetch.packaged_source('615.71.09', self.root_with('full')))

    def test_fetch_reports_origin_and_verify_reports_the_cross_check(self):
        data = self.tarball().read_bytes()
        work = Path(tempfile.mkdtemp(dir=self.dir))
        tree, origin = source_fetch.fetch(VERSION, work, open_url=lambda request, timeout: Response(data))
        self.assertEqual(tree, work / 'tree' / TOP)
        self.assertEqual(origin, {'kind': 'github-tag', 'url': URL, 'commit': COMMIT, 'size': len(data),
                                  'archive_sha256': hashlib.sha256(data).hexdigest()})
        def verify(root):
            return source_fetch.verify(tree, source_fetch.packaged_source(VERSION, root))
        self.assertEqual(verify(Path(tempfile.mkdtemp(dir=self.dir))), 'unavailable')
        self.assertEqual(verify(self.root_with('rpmfusion')), 'kernel-open-only')
        changed = dict(KERNEL_OPEN, **{'Kbuild': b'obj-m += other/\n'})
        with self.assertRaises(source_fetch.Rejected):
            verify(self.root_with('flattened', changed))
        work = Path(tempfile.mkdtemp(dir=self.dir))
        with self.assertRaises(source_fetch.FetchFailed):
            source_fetch.fetch(VERSION, work, open_url=lambda request, timeout: Response(data[:len(data) // 2]))


class AutoSourceTests(unittest.TestCase):
    """The reconcile service registers the exact upstream tag after a package driver upgrade."""
    def setUp(self):
        self.f = bootstrap_fixtures.BootstrapTests('test_alternate_root_requires_operations')
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.profile['driver_sources'][0]['p2p_preferred'] = False
        self.f.profile['auto_source'] = True
        self.f.worker.install(self.f.repository)
        self.f.enroll()
        self.previous = self.f.ready()
        self.f.worker.enable(bootstrap_fixtures.OLD)
        self.worker = DriverUpdate(self.f.root, self.f.ops)
        self.calls = []
        self.archive = self.tag(VERSION)

    def tag(self, version_mk):
        # The injected source inspector reads a bare version from version.mk.
        files = dict(tag_files(), **{'version.mk': version_mk.encode()})
        return write_tag(self.f.root / f'tag-{len(self.calls)}-{version_mk}.tar.gz', files).read_bytes()

    def opener(self, request, timeout):
        self.calls.append(request.full_url)
        if isinstance(self.archive, Exception):
            raise self.archive
        return Response(self.archive)

    def config(self):
        return json.loads(self.f.worker.path(CONFIG).read_text())

    def write_config(self, **changes):
        json_write(self.f.worker.path(CONFIG), dict(self.config(), **changes))

    def drift(self):
        self.f.ops.version = VERSION
        result = Reconciler(self.f.root, self.f.ops).reconcile(bootstrap_fixtures.OLD)
        self.assertEqual(result['state'], 'driver-drift')
        return result

    def auto(self):
        return self.worker.auto_source(VERSION, open_url=self.opener)

    def test_package_upgrade_registers_the_tag_and_the_next_reconcile_is_ready(self):
        drift = self.drift()
        fetched = self.auto()
        self.assertEqual(self.calls, [URL])
        self.assertEqual((fetched['state'], fetched['cross_check'], fetched['commit']), ('registered', 'unavailable', COMMIT))
        config = self.config()
        source = config['sources'][0]
        self.assertEqual((source['version'], source['p2p_preferred']), (VERSION, False))
        self.assertEqual(source['origin'], {'kind': 'github-tag', 'url': URL, 'commit': COMMIT, 'cross_check': 'unavailable',
                                            'archive_sha256': fetched['archive_sha256'], 'size': fetched['size']})
        self.assertEqual(source['path'], fetched['snapshot'])
        self.assertNotIn('require_p2p_source', config)
        data = self.f.worker.path(CONFIG).read_bytes()
        self.assertEqual(json.loads(self.f.worker.path(BASE + '/enrolled.json').read_text())['configuration_sha256'], digest(data))
        self.assertEqual(json.loads(self.f.worker.path(ENABLED).read_text())['configuration_sha256'], digest(data))
        self.assertEqual(list(self.f.worker.path(STATE + '/fetch').iterdir()), [])
        self.assertEqual(self.f.worker.status()['source_fetch']['state'], 'registered')
        ready = Reconciler(self.f.root, self.f.ops).reconcile(bootstrap_fixtures.OLD)
        self.assertEqual((ready['state'], ready['driver']), ('ready', VERSION))
        self.assertEqual(self.f.ops.environment['saved_entry'], ready['entry'])
        self.assertIsNone(self.f.worker.status()['driver_drift'])
        self.assertFalse(self.f.worker.path(drift['parked'][0]).exists())
        self.assertEqual(self.auto()['state'], 'present')
        self.assertEqual(len(self.calls), 1)

    def test_service_reconciles_once_more_after_registration(self):
        drift = self.drift()
        worker = Reconciler(self.f.root, self.f.ops)
        with patch.object(source_fetch, '_open_url', self.opener):
            result = after_drift(worker, bootstrap_fixtures.OLD, drift)
        self.assertEqual((result['state'], result['source_fetch']['state']), ('ready', 'registered'))
        self.assertEqual(self.f.ops.environment['saved_entry'], result['entry'])
        self.archive = urllib.error.HTTPError(URL, 404, 'Not Found', {}, None)
        self.f.ops.version = '615.78.09'
        again = worker.reconcile(bootstrap_fixtures.OLD)
        with patch.object(source_fetch, '_open_url', self.opener):
            result = after_drift(worker, bootstrap_fixtures.OLD, again)
        self.assertEqual((result['state'], result['source_fetch']['state']), ('driver-drift', 'failed'))
        self.assertEqual(self.f.ops.builds, 2)

    def test_disabled_manual_p2p_registered_rejected_or_two_part_versions_skip_the_network(self):
        self.drift()
        self.archive = AssertionError('no network expected')
        original = self.config()
        cases = (({'auto_source': False}, VERSION, 'off'), ({'enabled': False}, VERSION, 'off'),
                 ({'userspace': {'provider': 'manual', 'nvidia_smi': '/usr/bin/nvidia-smi',
                                 'libraries': ['/usr/lib64/libnvidia-ml.so.1', '/usr/lib64/libcuda.so.1']}}, VERSION, 'off'),
                 ({'require_p2p_source': True}, VERSION, 'p2p-required'),
                 ({'sources': [dict(original['sources'][0], p2p_preferred=True)]}, VERSION, 'p2p-required'),
                 ({}, bootstrap_fixtures.VERSION, 'present'), ({}, '615.80', 'unsupported-version'))
        for changes, version, state in cases:
            with self.subTest(changes=changes, version=version):
                json_write(self.f.worker.path(CONFIG), dict(original, **changes))
                self.assertEqual(self.worker.auto_source(version, open_url=self.opener)['state'], state)
        json_write(self.f.worker.path(CONFIG), original)
        json_write(self.f.worker.path(FETCH_RECORD), {'version': VERSION, 'state': 'rejected', 'error': 'earlier'})
        self.assertEqual(self.auto()['error'], 'earlier')
        self.f.ops.assert_transaction_idle = Mock(side_effect=LockBusy('update/build lock busy: rpm'))
        json_write(self.f.worker.path(FETCH_RECORD), {})
        self.assertEqual(self.auto()['state'], 'failed')
        self.f.ops.assert_transaction_idle.assert_called_once_with(self.f.root)
        self.assertEqual(self.calls, [])

    def test_network_failure_retries_and_verification_failure_does_not(self):
        self.drift()
        self.archive = urllib.error.HTTPError(URL, 404, 'Not Found', {}, None)
        self.assertEqual(self.auto()['state'], 'failed')
        self.assertEqual(self.auto()['state'], 'failed')
        self.assertEqual(len(self.calls), 2)
        self.archive = self.tag('615.78.07')
        rejected = self.auto()
        self.assertEqual(rejected['state'], 'rejected')
        self.assertIn('not a supported unpatched', rejected['error'])
        self.assertEqual(self.auto(), rejected)
        self.assertEqual(len(self.calls), 3)
        self.assertNotIn(VERSION, [source['version'] for source in self.config()['sources']])
        self.assertEqual(list(self.f.worker.path(STATE + '/fetch').iterdir()), [])

    def test_a_fetch_directory_left_by_a_killed_service_is_removed(self):
        self.drift()
        leftover = self.f.worker.path(STATE + '/fetch/.fetch-killed')
        leftover.mkdir(parents=True)
        (leftover / 'tag.tar.gz').write_bytes(b'partial')
        self.assertEqual(self.auto()['state'], 'registered')
        self.assertEqual(list(self.f.worker.path(STATE + '/fetch').iterdir()), [])

    def test_packaged_source_mismatch_is_rejected(self):
        self.drift()
        packaged = self.f.root / f'usr/src/nvidia-{VERSION}/kernel-open'
        for name, data in dict(KERNEL_OPEN, **{'nvidia/nv.c': b'patched by someone else\n'}).items():
            (packaged / name).parent.mkdir(parents=True, exist_ok=True)
            (packaged / name).write_bytes(data)
        result = self.auto()
        self.assertEqual((result['state'], result['url']), ('rejected', URL))
        self.assertIn('nvidia/nv.c', result['error'])
        (packaged / 'nvidia/nv.c').write_bytes(KERNEL_OPEN['nvidia/nv.c'])
        json_write(self.f.worker.path(FETCH_RECORD), {})
        self.assertEqual((self.auto()['state'], self.config()['sources'][0]['origin']['cross_check']),
                         ('registered', 'kernel-open-only'))

    def test_unreadable_packaged_reference_fails_before_any_download(self):
        self.drift()
        share = self.f.root / f'usr/share/nvidia-kmod-{VERSION}'
        share.mkdir(parents=True)
        archive = share / f'nvidia-kmod-{VERSION}-{os.uname().machine}.tar.xz'
        with tarfile.open(archive, 'w:xz') as tar:
            add(tar, 'kernel-open/Kbuild', KERNEL_OPEN['Kbuild'] * 4096)
        archive.write_bytes(archive.read_bytes()[:-100])  # a damaged or partial package file
        for _ in range(2):
            result = self.auto()
            self.assertEqual(result['state'], 'failed')
            self.assertIn('unreadable packaged source', result['error'])
        self.assertEqual(self.calls, [])

    def test_auto_source_registration_can_be_rolled_back_and_stays_rolled_back(self):
        self.drift()
        before = self.f.worker.path(CONFIG).read_bytes()
        fetched = self.auto()
        self.f.worker.rollback(fetched['transaction_id'])
        self.assertEqual(self.f.worker.path(CONFIG).read_bytes(), before)
        self.assertEqual(self.auto()['state'], 'rolled-back')
        self.assertEqual(self.auto()['state'], 'rolled-back')
        self.assertEqual(len(self.calls), 1)

    def test_auto_source_is_validated_enrolled_and_prepared_per_provider(self):
        self.assertIs(self.config()['auto_source'], True)
        path = self.f.root / 'check.json'
        json_write(path, dict(self.config(), auto_source='yes'))
        with self.assertRaisesRegex(LifecycleError, 'auto_source must be boolean'):
            load_config(path, self.f.root)
        o = onboarding_fixtures.OpenOnboardingTests('test_single_chain_payload_is_enrolled_as_is')
        o.setUp()
        self.addCleanup(o.doCleanups)
        rom = o.root / 'gpu0.bin'
        rom.write_bytes(legacy_image(onboarding_fixtures.PRO_6000))
        operations = onboarding_fixtures.Operations(onboarding_fixtures.PRO_6000)
        for index, (options, expected) in enumerate(((dict(userspace='rpm'), True), (dict(userspace='manual'), False),
                                                     (dict(userspace='rpm', p2p_preferred=True), False),
                                                     (dict(userspace='rpm', no_auto_source=True), False))):
            with self.subTest(options=options):
                output = o.root / f'prepared-{index}'
                Onboarding(o.root, operations).prepare(devices=[('0', rom)], driver_source=o.source, output=output, **options)
                self.assertIs(json.loads((output / 'profile.json').read_text())['auto_source'], expected)
        output = o.root / 'prepared-cli'
        with patch('sys.stdout', io.StringIO()):
            self.assertEqual(onboarding_main(['prepare', '--device', '0', str(rom), '--driver-source', str(o.source),
                                              '--output', str(output), '--userspace', 'rpm', '--no-auto-source'],
                                             root=o.root, operations=operations), 0)
        self.assertIs(json.loads((output / 'profile.json').read_text())['auto_source'], False)


if __name__ == '__main__':
    unittest.main()
