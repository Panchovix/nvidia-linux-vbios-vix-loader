"""`nvbios system setup`: one root action for the loader window.

It runs the existing `nvbios system` verbs as child processes, in order: download
(optional) → prepare → preflight → disable → install (optional) → enroll →
reconcile → enable. Every verb keeps its own checks and rollback; this module
orders them, checks what must hold before the first change, carries the enrolled
policy over and reports progress. It never repeats the logic of a step.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

from .bootstrap import BootstrapError, CONFIG, RUNTIME, STATE, _platform
from .lifecycle import source_fetch
from .lifecycle.config import ARCHIVE_VERIFIED, load_config, select_source
from .lifecycle.engine import activation
from .lifecycle.security import LifecycleError, LockBusy, atomic_write, checked_path, locked
from .onboarding import canonical_bdf
from .families import GA100_DEVICE_IDS, architecture
from .payload import PayloadError, check_loadable_payload, optional_editor

SETUP = '/var/lib/nvidia-vbios/setup'
INSTALLED = '/usr/local/bin/nvbios'
# Present only in the internal build; setup never installs one flavor over the other.
# Internal builds relocate a new Ada or Ampere file from its full edited ROM (verified against it).
RELOCATIONS = {'ada': 'ada-relocated-v2', 'ampere': 'ampere-relocated-v1'}
# A release with the editor window is an internal build; the public loader export has no gui/.
EDITOR_MARKER = 'nvidia_vbios/gui/__init__.py'
# World-readable summary of the enrolled GPUs (BDF, payload sha256, architecture), written after each enroll so
# the window, which cannot read /etc/nvidia-vbios, knows what a Load would keep or remove before the reboot.
ENROLLED = '/var/lib/nvidia-vbios/enrolled-devices.json'
# Enrolled policy that prepare cannot write; devices, sources and fingerprints never carry over.
CARRIED = ('parameters', 'retain_build_tree', 'retain_boot_generations', 'stock_builder')
ENVIRONMENT = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'HOME': '/root', 'LANG': 'C.UTF-8',
               'PYTHONDONTWRITEBYTECODE': '1'}
NO_CLEANUP = {'ran': False, 'ok': None, 'message': None}


class Blocked(Exception):
    """A check refused or a step failed; `step` names where, `cleanup` what the disable after a failed enable did."""
    def __init__(self, step, message, cleanup=NO_CLEANUP):
        super().__init__(' '.join(str(message).split()))
        self.step, self.cleanup = step, cleanup


def default_launcher(module=None):
    """An installed release runs /usr/local/bin/nvbios, a checkout its own ./nvbios (never sys.argv[0])."""
    here = Path(module or __file__).resolve()
    return INSTALLED if here.is_relative_to(RUNTIME + '/releases') else str(here.parents[2] / 'nvbios')


def run_child(argv, poll=None):
    """Run one step with both pipes drained together, so no pipe fills up; `poll` runs about twice a second."""
    process = subprocess.Popen(argv, cwd='/', env=ENVIRONMENT, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    while True:
        try:
            stdout, stderr = process.communicate(timeout=0.5)
        except subprocess.TimeoutExpired:
            if poll:
                poll()
            continue
        return process.returncode, stdout.decode('utf-8', 'replace'), stderr.decode('utf-8', 'replace')


def last_error(stderr, code):
    """The child's `<PREFIX>_BLOCKED: ...` line, else its last line (a traceback ends with the exception)."""
    lines = [line.strip() for line in stderr.splitlines() if line.strip()]
    marked = [line for line in lines if re.match(r'[A-Z_]+_BLOCKED: ', line)]
    return (marked or lines or [f'exit status {code}'])[-1]


def reconcile_phase(state, kernel, since):
    """Coarse phase of the reconcile transaction started after `since` (ns), from its root-only state files."""
    runs = []
    for path in (state / 'transactions').glob(kernel + '-*'):
        stamp = path.name[len(kernel) + 1:]
        if stamp.isdigit() and int(stamp) >= since:
            runs.append((int(stamp), path))
    if not runs:
        return None  # akmods coordination or the reuse of an existing build
    run = max(runs)[1]
    try:
        journal = json.loads((state / 'transaction.json').read_bytes())
    except (OSError, ValueError):
        journal = {}
    if journal.get('id') == run.name:
        return {'installing': 'initramfs', 'selecting': 'boot-entry'}.get(journal.get('phase'))
    return 'build' if (run / 'build.log').exists() else 'source'


def _private_directory(path, root):
    """Create `path` root-only; missing parents get 0755, as bootstrap leaves /var/lib/nvidia-vbios.

    The window reads /var/lib/nvidia-vbios/sources unprivileged to offer the saved source.
    """
    checked_path(path, root, missing=True)
    missing = []
    while not path.exists():
        missing.append(path)
        path = path.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700 if directory == missing[0] else 0o755)


def _accept(key, value, what):
    return lambda result: None if result.get(key) == value else f'{what} ended in state {result.get("state")!r}'


def _ready(result):
    if result.get('state') == 'ready' and result.get('marker') == 'VBIOS_READY':
        return None
    return f'reconcile ended in state {result.get("state")!r}: {result.get("error") or "no override was built"}'


def _enabled(result):
    selection = result.get('default_selection') or {}
    if result.get('ready') is not True or result.get('triggers_enabled') is not True:
        return 'enable did not confirm the boot selection and automatic rebuilds'
    if selection.get('state') == 'preserved':
        return (f'enable kept the existing default boot entry ({selection.get("reason") or "no reason given"}); '
                'the override entry was not selected')
    if selection.get('state') not in ('selected', 'ready'):
        return f'enable ended with boot selection {selection.get("state")!r}'
    return None


class Setup:
    def __init__(self, args, *, root=Path('/'), operations=None, euid=None, run=run_child,
                 fetch=source_fetch.fetch, launcher=None, cpu_count=os.cpu_count):
        self.args, self.root, self.ops = args, Path(root), operations
        self.euid = os.geteuid() if euid is None else euid
        self.run, self.fetch, self.cpu_count = run, fetch, cpu_count
        self.launcher = launcher or default_launcher()
        self.state = self.path(STATE)
        self.step, self.index, self.steps, self.phase = 'preflight', 0, [], None

    def path(self, value):
        return self.root / str(value).lstrip('/')

    def emit(self, **event):
        if not self.args.progress:
            return
        try:
            print(json.dumps(event, separators=(',', ':')), flush=True)
        except (OSError, ValueError):
            pass  # the window went away: the steps go on

    def begin(self, step):
        self.step = step
        self.index += 1
        self.emit(event='step', step=step, index=self.index, total=len(self.steps))

    def child(self, step, argv, accept, poll=None):
        self.begin(step)
        code, stdout, stderr = self.run([self.launcher, 'system', *argv], poll)
        if code:
            raise Blocked(step, last_error(stderr, code))
        try:
            result = json.loads(stdout)
        except ValueError:
            raise Blocked(step, f'nvbios system {argv[0]} printed no JSON result') from None
        problem = accept(result)
        if problem:
            raise Blocked(step, problem)
        self.emit(event='result', step=step, result=result)
        return result

    def main(self):
        try:
            done = self.execute()
        except Blocked as exc:
            return self.fail(exc)
        except (LifecycleError, OSError, ValueError, KeyError, TypeError) as exc:
            return self.fail(Blocked(self.step, exc))
        if self.args.progress:
            self.emit(**done)
        else:
            print(json.dumps(done, indent=2, sort_keys=True))
        return 0

    def fail(self, exc):
        self.emit(event='failed', step=exc.step, message=str(exc), cleanup=exc.cleanup)
        text = f'SETUP_BLOCKED: {exc.step}: {exc}'
        if exc.cleanup['ran']:
            text += ('; disable ran: automatic rebuilds are off and the normal entry is the default' if exc.cleanup['ok']
                     else f'; disable also failed, the default may still be the override: {exc.cleanup["message"]}')
        try:
            print(text, file=sys.stderr, flush=True)
        except (OSError, ValueError):
            pass
        return 1

    def execute(self):
        if self.euid != 0:
            raise Blocked('preflight', 'setup requires root; run it through pkexec or sudo')
        if self.ops is None:
            from .bootstrap import BootstrapOperations
            self.ops = BootstrapOperations()
        directory = self.path(SETUP)
        _private_directory(directory, self.root)
        with ExitStack() as stack:
            try:
                stack.enter_context(locked(directory / 'setup.lock', self.root))
            except LockBusy:
                raise Blocked('preflight', 'another setup is running') from None
            for leftover in directory.iterdir():
                if leftover.is_dir():
                    shutil.rmtree(checked_path(leftover, self.root))  # from a run that was killed
            self.work = directory / str(time.time_ns())
            self.work.mkdir(mode=0o700)
            stack.callback(shutil.rmtree, self.work, ignore_errors=True)
            self.check()
            return self.sequence()

    def check(self):
        """Read-only checks before the first step; a refusal here changes nothing."""
        args, ops = self.args, self.ops
        if _platform(ops).family not in ('fedora', 'rhel'):
            raise Blocked('preflight', 'setup supports the Fedora/RHEL family; use the CLI steps on this distribution')
        if args.kernel != ops.current_kernel():
            raise Blocked('preflight', f'--kernel {args.kernel} is not the running kernel {ops.current_kernel()}')
        if ops.reconcile_active():
            raise Blocked('preflight', 'reconciliation service is active; wait until the automatic rebuild finishes')
        configuration = self.path(CONFIG)
        # The enrolled policy, read before disable or enroll can replace it.
        self.old = load_config(configuration, self.root, require_enabled=False) if configuration.exists() else None
        enrolled = {device['bdf']: device for device in (self.old.devices if self.old else ())}
        self.kept = {}
        for bdf in args.keep:
            device = enrolled.get(bdf)
            if device is None:
                raise Blocked('preflight', f'{bdf} has no enrolled payload to keep; choose its file')
            if device.get('representation') and optional_editor() is None:
                raise Blocked('preflight', f'{bdf}: the enrolled payload uses the {device["representation"]} representation, '
                                           'which this build cannot verify; choose its file again')
            checked_path(self.path(device['payload_path']), self.root)
            if device.get('representation') in ARCHIVE_VERIFIED:
                # prepare relocates the kept GPU again from its archived full ROM; the result must be the same bytes.
                if not device.get('archive_path') or not self.path(device['archive_path']).is_file():
                    raise Blocked('preflight', f'{bdf}: its full ROM was not kept at enrollment; choose its file again')
                checked_path(self.path(device['archive_path']), self.root)
            self.kept[bdf] = device
        self.relocations = self.relocation_plan() if optional_editor() is not None else {}
        named = {bdf for bdf, _, _ in args.device} | set(args.keep) | set(args.remove)
        unnamed = sorted(set(enrolled) - named)
        if unnamed:
            # Never drop an enrolled GPU silently, e.g. one prepared by a Load that has not been booted yet.
            raise Blocked('preflight', f'enrolled GPU(s) {", ".join(unnamed)} not named: choose keep, a new file or '
                                       'own VBIOS for each (press Refresh)')
        fleet = self.state / 'fleet.json'
        committed = (json.loads(checked_path(fleet, self.root).read_bytes()) if fleet.exists() else {}).get('last_ready')
        if self.old and (self.old.raw.get('seed_previous_ready') or self.old.raw.get('adopt_existing')) and not committed:
            raise Blocked('preflight', 'this enrollment still depends on a migration (seed_previous_ready/adopt_existing) '
                                       'without a committed build; finish it with the CLI first')
        if args.keep_source:
            if self.old is None:
                raise Blocked('preflight', 'no enrolled driver source to keep; choose a folder or download it')
            source, _ = select_source(self.old, ops.installed_version(self.old.raw), ops.inspect_source, self.root)
            self.source, self.p2p = str(self.path(source['path'])), bool(source.get('p2p_preferred'))
        else:
            self.source, self.p2p = args.driver_source, args.p2p_preferred
            if self.old and self.old.raw.get('require_p2p_source') and not self.p2p:
                raise Blocked('preflight', 'this enrollment requires a P2P source (require_p2p_source); '
                                           'choose the P2P source folder and mark it as P2P')
        selector = self.path(RUNTIME + '/current.json')
        if not selector.exists() and not args.repository:
            raise Blocked('preflight', 'the loader is not installed; run setup from a clone with --repository')
        if args.repository and selector.exists():
            installed = EDITOR_MARKER in json.loads(checked_path(selector, self.root).read_bytes()).get('files', {})
            if installed != (Path(args.repository) / 'src' / EDITOR_MARKER).is_file():
                raise Blocked('preflight', 'installed release differs from this clone: one is the internal build, '
                                           'the other the public loader; setup does not switch between them')
        # Keep the enrolled value (it drives every later rebuild); a first install uses up to 8.
        self.jobs = args.jobs or (self.old.raw.get('jobs', 1) if self.old else min(max(self.cpu_count() or 1, 1), 8))
        # disable is idempotent; enroll and install refuse while any trigger is enabled or active.
        self.disable = self.old is not None or ops.triggers_any_active()
        self.steps = [*(['download'] if args.download_source else []), 'prepare', 'preflight',
                      *(['disable'] if self.disable else []), *(['install'] if args.repository else []),
                      'enroll', 'reconcile', 'enable']

    def relocation_plan(self):
        """{bdf: representation} for new Ada/Ampere files; the internal prepare relocates them from the full ROM."""
        plan = {}
        for bdf, rom, _ in self.args.device:
            try:
                device = int(self.path(f'/sys/bus/pci/devices/{bdf}/device').read_text(), 16)
            except (OSError, ValueError):
                continue
            representation = RELOCATIONS.get(architecture(device)['family'])
            if representation is None or device in GA100_DEVICE_IDS:
                continue
            try:
                check_loadable_payload(Path(rom).read_bytes(), 0x10de, device)
            except PayloadError:
                plan[bdf] = representation          # a full ROM: prepare relocates and verifies it
            except OSError:
                continue                            # prepare reports the unreadable file
            else:
                raise Blocked('preflight', f'{bdf}: this build checks Ada and Ampere files against the edited full ROM: '
                                           'choose the .rom the editor saved, not its -loader.bin')
        return plan

    def sequence(self):
        args, kernel = self.args, self.args.kernel
        self.emit(event='start', protocol=1, kernel=kernel, steps=self.steps)
        if args.download_source:
            self.source = self.download(args.download_source)
        roms = {bdf: rom for bdf, rom, _ in args.device}
        for bdf, device in self.kept.items():
            archived = device.get('representation') in ARCHIVE_VERIFIED
            roms[bdf] = str(self.path(device['archive_path' if archived else 'payload_path']))
            if archived:
                self.relocations[bdf] = device['representation']
        argv = ['prepare']
        for bdf in sorted(roms):  # in BDF order, so an unchanged Load enrolls identical bytes and reuses its build
            argv += ['--device', bdf, roms[bdf]]
        for bdf in sorted(self.relocations):
            argv += ['--representation', bdf, self.relocations[bdf]]
        argv += ['--driver-source', self.source, '--userspace', args.userspace,
                 '--output', str(self.work / 'profile'), '--jobs', str(self.jobs), *(['--p2p-preferred'] if self.p2p else [])]
        self.child('prepare', argv, self.prepared)
        self.preflight()
        # Nothing on the system has changed up to here.
        if self.disable:
            self.child('disable', ['disable'], _accept('state', 'disabled', 'disable'))
        if args.repository:
            self.child('install', ['install', '--repository', args.repository],
                       lambda result: None if result.get('release') else 'install reported no release')
            self.launcher = INSTALLED
        self.child('enroll', ['enroll', '--profile', str(self.work / 'profile/profile.json')],
                   _accept('state', 'enrolled', 'enroll'))
        devices = [{'bdf': device['bdf'], 'sha256': device['sha256'], 'architecture': device['architecture']}
                   for device in self.profile['devices']]
        try:   # informative only: setup itself checks every enrolled GPU as root on the next Load
            atomic_write(self.path(ENROLLED), (json.dumps({'schema_version': 1, 'devices': devices}, indent=2,
                                                          sort_keys=True) + '\n').encode(), 0o644)
        except (OSError, LifecycleError):
            pass
        shutil.rmtree(self.work / 'fetch', ignore_errors=True)  # enroll snapshotted the download
        since = time.time_ns()
        ready = self.child('reconcile', ['reconcile', '--kernel', kernel, '--select-default'], _ready,
                           poll=lambda: self.report_phase(kernel, since))
        try:
            enabled = self.child('enable', ['enable', '--kernel', kernel], _enabled)
        except Exception as exc:
            # reconcile already selected the new entry: never leave it without automatic rebuilds.
            failure = exc if isinstance(exc, Blocked) else Blocked('enable', exc)
            raise Blocked('enable', failure, self.cleanup()) from None
        selection = enabled['default_selection']
        return {'event': 'done', 'ok': True, 'kernel': kernel, 'entry': ready['entry'],
                'default': selection['state'], 'default_reason': selection.get('reason'),
                'devices': [{'bdf': device['bdf'], 'sha256': device['sha256'], 'architecture': device['architecture'],
                             'kept': device['bdf'] in self.kept} for device in self.profile['devices']]}

    def download(self, version):
        """Fetch the exact tag as root and check it the way auto_source does; returns the tree."""
        self.begin('download')
        work = self.work / 'fetch'
        work.mkdir(mode=0o700)
        packaged = source_fetch.packaged_source(version, self.root)
        tree, origin = self.fetch(version, work)
        origin['cross_check'] = source_fetch.verify(tree, packaged)
        info = self.ops.inspect_source(tree)
        if info.get('version') != version or not info.get('supported') or info.get('capabilities', {}).get('already_patched'):
            raise Blocked('download', f'tag is not a supported unpatched {version} source: {info.get("reasons", [])}')
        self.emit(event='result', step='download', result=dict(origin, version=version))
        return str(tree)

    def prepared(self, result):
        """Before any change: prepare used the files the caller checked and the kept payloads; the policy carries over."""
        if result.get('state') != 'prepared':
            return f'prepare ended in state {result.get("state")!r}'
        path = checked_path(self.work / 'profile/profile.json', self.root)
        profile = json.loads(path.read_bytes())
        devices = {device['bdf']: device for device in profile['devices']}
        for bdf, _, sha256 in self.args.device:
            if devices[bdf]['source_sha256'] != sha256:
                return f'{bdf}: the file changed after it was checked; choose it again'
        for bdf, enrolled in self.kept.items():
            record = devices[bdf]
            if any(record.get(key) != enrolled.get(key) for key in ('uuid', 'vendor', 'device', 'architecture', 'sha256', 'size')):
                return f'{bdf}: the GPU or its kept payload differs from the enrollment; choose its file'
            representation = enrolled.get('representation')
            if representation:
                # Only the internal build gets here (checked before prepare); enroll validates it again.
                try:
                    optional_editor().validate_strict(Path(record['payload']).read_bytes(), dict(record, representation=representation))
                except (LifecycleError, ValueError) as exc:
                    return f'{bdf}: the kept payload is not a valid {representation} payload: {exc}'
                record['representation'] = representation
        if self.old:
            raw = self.old.raw
            profile.update({name: raw[name] for name in CARRIED if name in raw})
            # prepare turns auto_source on for packaged installs; an enrollment that had it off stays off.
            profile['auto_source'] = raw.get('auto_source', False)
            if self.args.keep_source:
                # The kept snapshot decides nothing: the enrolled requirement carries over as it was.
                profile.pop('require_p2p_source', None)
                if raw.get('require_p2p_source'):
                    profile['require_p2p_source'] = True
            elif raw.get('require_p2p_source'):
                profile['require_p2p_source'] = True
            try:
                activation(profile['devices'], result['version'], profile.get('parameters'))
            except LifecycleError as exc:
                return f'the enrolled registry parameters cannot be kept with these GPUs: {exc}'
        atomic_write(path, (json.dumps(profile, indent=2, sort_keys=True, allow_nan=False) + '\n').encode(), 0o600)
        self.profile = profile
        return None

    def preflight(self):
        """What reconcile and enable need, checked as root before the first change."""
        self.begin('preflight')
        ops, kernel, normal = self.ops, self.args.kernel, self.profile['fallback_entry']
        ops.prerequisites(kernel, self.profile)
        environment = ops.grub_environment()
        if environment.get('next_entry') or environment.get('prev_saved_entry'):
            raise Blocked('preflight', 'another GRUB transition is pending (next_entry or prev_saved_entry); boot once first')
        fleet = self.state / 'fleet.json'
        last = (json.loads(checked_path(fleet, self.root).read_bytes()) if fleet.exists() else {}).get('last_ready') or {}
        # disable puts the normal entry of the last build back, so its override entry counts only for this kernel.
        allowed = {normal, *([last['entry']] if last.get('kernel') == kernel else [])}
        saved = environment.get('saved_entry')
        if saved not in allowed:
            raise Blocked('preflight', f'foreign or unrelated GRUB default {saved!r}; make {normal} the default first')
        provider = _platform(ops).hook_provider
        if not ops.plugin_available(provider):
            raise Blocked('preflight', f'native package callback/plugin prerequisites are unavailable ({provider})')
        if ops.reconcile_active():
            raise Blocked('preflight', 'reconciliation service is active; wait until the automatic rebuild finishes')
        self.emit(event='result', step='preflight', result={'saved_entry': saved, 'normal_entry': normal, 'hook_provider': provider})

    def report_phase(self, kernel, since):
        try:
            phase = reconcile_phase(self.state, kernel, since)
        except (OSError, ValueError):
            return  # phases are informative; the running reconcile must never look failed
        if phase and phase != self.phase:
            self.phase = phase
            self.emit(event='phase', step='reconcile', phase=phase)

    def cleanup(self):
        """After a failed enable, disable turns rebuilds off and puts the normal entry back."""
        try:
            code, stdout, stderr = self.run([self.launcher, 'system', 'disable'], None)
            if code:
                return {'ran': True, 'ok': False, 'message': last_error(stderr, code)}
            restoration = json.loads(stdout).get('default_restoration') or {}
        except (OSError, ValueError, AttributeError) as exc:
            return {'ran': True, 'ok': False, 'message': str(exc)}
        if restoration.get('state') != 'normal':
            return {'ran': True, 'ok': False, 'message': f'default kept: {restoration.get("reason", "no enrollment")}'}
        return {'ran': True, 'ok': True, 'message': None}


def _arguments(argv):
    parser = argparse.ArgumentParser(prog='nvbios system setup', description=__doc__.splitlines()[0])
    parser.add_argument('--progress', action='store_true', help='JSON Lines progress events on stdout')
    parser.add_argument('--repository', help='install the runtime from this checkout first')
    parser.add_argument('--kernel', required=True, help='the running kernel')
    parser.add_argument('--userspace', required=True, choices=('rpm', 'deb', 'pacman', 'manual'))
    parser.add_argument('--device', action='append', nargs=3, default=[], metavar=('BDF', 'ROM', 'SHA256'),
                        help='new payload file for this GPU and the SHA-256 the caller checked')
    parser.add_argument('--keep', action='append', default=[], metavar='BDF', help='keep the enrolled payload of this GPU')
    parser.add_argument('--remove', action='append', default=[], metavar='BDF',
                        help='this enrolled GPU goes back to its own VBIOS (every enrolled GPU must be named)')
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--driver-source')
    source.add_argument('--download-source', metavar='VERSION')
    source.add_argument('--keep-source', action='store_true', help='reuse the enrolled source of the installed driver')
    parser.add_argument('--p2p-preferred', action='store_true')
    parser.add_argument('--jobs', type=int)
    args = parser.parse_args(argv)
    try:
        args.device = [(canonical_bdf(bdf), rom, sha256) for bdf, rom, sha256 in args.device]
        args.keep = [canonical_bdf(bdf) for bdf in args.keep]
        args.remove = [canonical_bdf(bdf) for bdf in args.remove]
    except BootstrapError as exc:
        parser.error(str(exc))
    selected = [bdf for bdf, _, _ in args.device] + args.keep
    if not selected:
        parser.error('name at least one GPU with --device or --keep')
    if len(set(selected + args.remove)) != len(selected + args.remove):
        parser.error('each GPU may be named once')
    if any(not re.fullmatch(r'[0-9a-f]{64}', sha256) for _, _, sha256 in args.device):
        parser.error('SHA256 must be 64 lowercase hexadecimal digits')
    paths = [rom for _, rom, _ in args.device] + [path for path in (args.repository, args.driver_source) if path]
    if any(not os.path.isabs(path) for path in paths):
        parser.error('paths must be absolute: setup runs its steps from /')
    if args.p2p_preferred and not args.driver_source:
        parser.error('--p2p-preferred needs --driver-source')
    if args.download_source and not source_fetch.VERSION.fullmatch(args.download_source):
        parser.error('--download-source needs a three-part version such as 615.78.08')
    if args.jobs is not None and not 1 <= args.jobs <= 256:
        parser.error('--jobs must be between 1 and 256')
    return args


def main(argv=None, **injected):
    args = _arguments(argv)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)  # a closed terminal must not stop the sequence between steps
    return Setup(args, **injected).main()


if __name__ == '__main__':
    raise SystemExit(main())
