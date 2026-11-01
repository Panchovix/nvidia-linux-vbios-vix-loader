"""Root-owned runtime installation and explicit lifecycle enrollment.

Installation, enrollment, current-kernel reconciliation, and trigger activation
are separate operations. Alternate filesystem roots require injected operations.
"""
from __future__ import annotations
from .limits import MAX_GPUS

import argparse
import contextlib
import csv
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
import time

from .lifecycle.security import (LifecycleError, atomic_write, checked_path, digest,
                                 hash_file, json_write, locked, resolve_trusted_file,
                                 source_tree_hash, token)
from .lifecycle.config import ARCHIVE_VERIFIED, load_config
from .lifecycle import hook_templates
from .lifecycle.engine import CONFIG, STATE, Reconciler, parse_bls

BASE = '/var/lib/nvidia-vbios/bootstrap'
RUNTIME = '/usr/local/lib/nvidia-vbios-tools'
OWNER = BASE + '/owned.json'
ENABLED = BASE + '/enabled.json'
ACTION_TARGETS = {'dnf5': '/etc/dnf/libdnf5-plugins/actions.d/nvidia-vbios.actions',
                  'dnf4': '/etc/dnf/plugins/post-transaction-actions.d/nvidia-vbios.action',
                  'apt': '/etc/apt/apt.conf.d/99-nvidia-vbios',
                  'pacman': '/etc/pacman.d/hooks/99-nvidia-vbios.hook'}
UNITS = ('nvidia-vbios-reconcile.path', 'nvidia-vbios-reconcile.timer')
TEMPLATES = {
    'kernel-install/99-nvidia-vbios.install': '/usr/lib/kernel/install.d/99-nvidia-vbios.install',
    **{'systemd/' + name: '/etc/systemd/system/' + name for name in (*UNITS, 'nvidia-vbios-reconcile.service')},
}


def _platform(ops):
    from .lifecycle.platform import PlatformSpec, FEDORA_PLATFORM
    value = getattr(ops, 'platform', None)
    return value if isinstance(value, PlatformSpec) else FEDORA_PLATFORM


class BootstrapError(LifecycleError):
    """Installation/enrollment/activation prerequisite or ownership failure."""


def _json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()


def _input_path(path):
    path = Path(os.path.abspath(Path(path).expanduser()))
    for part in [*reversed(path.parents), path]:
        if part.is_symlink():
            raise BootstrapError(f'enrollment input has a symlink: {part}')
    return path


def _external(path):
    """Read mutable enrollment inputs without following links or executing them."""
    path = _input_path(path)
    if not path.is_file():
        raise BootstrapError(f'enrollment input is not a regular file: {path}')
    return path.read_bytes()


def _input(value):
    if isinstance(value, dict):
        return json.loads(json.dumps(value, allow_nan=False))
    try:
        result = json.loads(_external(value))
    except (ValueError, TypeError) as exc:
        raise BootstrapError('profile must be a JSON object') from exc
    if not isinstance(result, dict):
        raise BootstrapError('profile must be a JSON object')
    return result


def _fingerprint(records):
    return digest(_json_bytes(records))


def _source_records(path):
    from .driver import _source_files
    return {str(file.relative_to(path)): {'sha256': hash_file(file),
            'mode': 0o755 if file.stat().st_mode & 0o111 else 0o644}
            for file in _source_files(path)}


def _launcher(entry, interpreter="/usr/bin/python3"):
    # This launcher has no dependency on checkout, cwd, PYTHONPATH or site-packages.
    return f'''#!{interpreter} -I
import json, os, re, stat, sys
from pathlib import Path
base = Path({RUNTIME!r})
def trusted(path):
    for part in [*reversed(path.parents), path]:
        value = part.lstat()
        if stat.S_ISLNK(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
            raise SystemExit("untrusted nvidia-vbios runtime")
    return path
selected = json.loads(trusted(base / "current.json").read_text())
release = selected.get("release", "")
if not re.fullmatch(r"[0-9a-f]{{64}}", release):
    raise SystemExit("invalid nvidia-vbios release")
package = trusted(base / "releases" / release)
trusted(package / "nvidia_vbios" / "__init__.py")
sys.path.insert(0, str(package))
{entry}
'''.encode()


def _runtime_python(root):
    """Prefer the stable system command, use a trusted newer Python on older OSes."""
    if root != Path('/'):
        return '/usr/bin/python3'  # synthetic installs never inspect host tools
    import subprocess
    standard = Path('/usr/bin/python3')
    resolve_trusted_file(standard)
    probe = subprocess.run([str(standard), '-I', '-c', 'import sys; print(sys.version_info.major, sys.version_info.minor)'],
                           check=True, capture_output=True, text=True, timeout=10)
    version = tuple(int(part) for part in probe.stdout.split())
    if version >= (3, 11):
        return str(standard)
    selected = resolve_trusted_file(Path(sys.executable))
    if sys.version_info < (3, 11) or not re.fullmatch(r'/[A-Za-z0-9_./+-]+', str(selected)):
        raise BootstrapError('trusted Python 3.11 or newer is required for the installed runtime')
    return str(selected)


class BootstrapOperations:
    """Fixed production system operations; no shell, package install, or GPU writes."""
    def __init__(self):
        from .lifecycle.system import SystemOperations
        self.system = SystemOperations()

    def __getattr__(self, name):
        return getattr(self.system, name)

    def inventory(self):
        inventory = self.system.inventory()
        response = self.system._run(['nvidia-smi', '--query-gpu=pci.bus_id,uuid,serial,vbios_version', '--format=csv,noheader'], allow_failure=True)
        if response.returncode:
            return inventory
        for row in csv.reader(response.stdout.decode().splitlines()):
            if len(row) != 4:
                raise BootstrapError('unexpected physical GPU enrollment query format')
            bdf, uuid, serial, version = (item.strip() for item in row)
            domain, bus, slot = bdf.lower().split(':')
            bdf = f'{int(domain, 16):04x}:{bus}:{slot}'
            if bdf in inventory:
                if inventory[bdf]['uuid'] != uuid:
                    raise BootstrapError('procfs and NVML physical GPU identities disagree')
                inventory[bdf].update(serial=serial, vbios_version=version)
        return inventory

    def current_kernel(self):
        return os.uname().release

    def triggers(self, enabled):
        self.system._run(['systemctl', 'daemon-reload'])
        self.system._run(['systemctl', 'enable' if enabled else 'disable', '--now', *UNITS])

    def retire_triggers(self):
        """Uninstall: stop the path, the timer and a service run they started since the check, which can only wait for
        the locks uninstall holds; disable the path and timer. A missing or masked unit is no error. Without a running
        systemd (a chroot without /run) nothing runs: uninstall unlinks the enable links itself."""
        if Path('/run/systemd/system').is_dir():
            self.system._run(['systemctl', 'stop', *UNITS, 'nvidia-vbios-reconcile.service'], allow_failure=True)
            self.system._run(['systemctl', 'disable', *UNITS], allow_failure=True)

    def daemon_reload(self):
        if Path('/run/systemd/system').is_dir():
            self.system._run(['systemctl', 'daemon-reload'], allow_failure=True)

    def triggers_enabled(self):
        return all(self.system._run(['systemctl', 'is-enabled', name], allow_failure=True).returncode == 0 for name in UNITS)

    def reconcile_active(self):
        response = self.system._run(['systemctl', 'show', '--property=ActiveState', '--value',
                                     'nvidia-vbios-reconcile.service'], allow_failure=True)
        return response.stdout.decode().strip() not in ('', 'inactive', 'failed')

    def triggers_any_active(self):
        for name in UNITS:
            if self.system._run(['systemctl', 'is-enabled', name], allow_failure=True).returncode == 0:
                return True
            state = self.system._run(['systemctl', 'show', '--property=ActiveState', '--value', name], allow_failure=True)
            if state.stdout.decode().strip() not in ('', 'inactive', 'failed'):
                return True
        return self.reconcile_active()

    def plugin_available(self, provider):
        if provider in ('apt', 'pacman'):
            from .lifecycle.portable_hooks import provider_available
            return provider_available(self.system, provider)
        package = 'libdnf5-plugin-actions' if provider == 'dnf5' else 'python3-dnf-plugin-post-transaction-actions'
        return self.system._run(['rpm', '--nosignature', '-q', package], allow_failure=True).returncode == 0

    def archive_identity(self, archive, payload, device):
        from .payload import optional_editor
        serial = device.get('serial')
        # Validate the full container before selecting an Ada primary bank.
        if serial and str(serial).encode('ascii') not in archive:
            raise BootstrapError('full archival ROM lacks the enrolled board serial')
        # A payload that verifies only from its full ROM must always be reproduced from a real archive.
        if archive != payload or device.get('representation') in ARCHIVE_VERIFIED:
            editor = optional_editor()
            if editor is None:
                raise BootstrapError('archive differs from its payload; the open loader enrolls the single-chain payload itself')
            editor.archive_reproduces(archive, payload, device)
        self.system.validate_payload(payload, device)


class Bootstrap:
    def __init__(self, root=Path('/'), operations=None):
        self.root = Path(os.path.abspath(root))
        if self.root.is_symlink():
            raise BootstrapError('filesystem root cannot be a symlink')
        if operations is None:
            if self.root != Path('/'):
                raise BootstrapError('alternate root requires explicitly injected operations')
            if os.geteuid() != 0:
                raise BootstrapError('production bootstrap requires root')
            operations = BootstrapOperations()
        self.ops = operations
        checked_path(self.root, self.root)
        self._boot_operations()

    def _boot_operations(self):
        configuration = self._read(CONFIG)
        if configuration.get('boot'):
            from .lifecycle.portable import operations_for
            self.ops = operations_for(self.ops, self.root, configuration)

    def path(self, value):
        value = str(value)
        if not value.startswith('/') or '..' in Path(value).parts:
            raise BootstrapError('managed path must be absolute and confined to its root')
        return self.root / value.lstrip('/')

    def _read(self, value, default=None):
        path = self.path(value)
        if not path.exists():
            return {} if default is None else default
        checked_path(path, self.root)
        try:
            return json.loads(path.read_bytes())
        except ValueError as exc:
            raise BootstrapError(f'invalid managed JSON: {value}') from exc

    def _mkdir(self, path, mode):
        checked_path(path, self.root, missing=True)
        missing = []
        parent = path
        while parent != self.root and not parent.exists():
            missing.append(parent)
            parent = parent.parent
        for directory in reversed(missing):
            directory.mkdir(mode=mode)
            directory.chmod(mode)

    def _trusted_bytes(self, value):
        path = self.path(value)
        checked_path(path, self.root)
        return path.read_bytes()

    def _owners(self):
        value = self._read(OWNER, {'schema_version': 1, 'files': {}})
        if not isinstance(value, dict) or value.get('schema_version') != 1 or not isinstance(value.get('files'), dict):
            raise BootstrapError('invalid bootstrap ownership registry')
        return value

    def _publish(self, writes, kind, *, dry_run=False, replacements=None):
        """Validate every target, back up hashes, then replace with a durable journal."""
        replacements = replacements or {}
        owners = self._owners()
        records = []
        for name, (data, mode) in writes.items():
            path = self.path(name)
            checked_path(path, self.root, missing=True)
            before = path.read_bytes() if path.exists() else None
            current = digest(before) if before is not None else None
            owned = owners['files'].get(name)
            after = digest(data) if data is not None else None
            if current is not None and current != after and current not in (owned, replacements.get(name)):
                raise BootstrapError(f'foreign or changed managed file: {name}')
            if owned is not None and current not in (None, owned, after):
                raise BootstrapError(f'previously managed file changed: {name}')
            records.append({'path': name, 'before_sha256': current, 'after_sha256': after,
                            'before_mode': path.stat().st_mode & 0o777 if before is not None else None,
                            'mode': mode, 'backup': None})
        identifier = f'{kind}-{time.time_ns()}'
        report = {'schema_version': 1, 'transaction_id': identifier, 'kind': kind,
                  'state': 'planned' if dry_run else 'publishing', 'files': records}
        if dry_run:
            return report
        transaction = self.path(BASE + '/transactions/' + identifier)
        checked_path(transaction, self.root, missing=True)
        transaction.mkdir(parents=True, mode=0o700)
        json_write(transaction / 'owners-before.json', owners)
        for index, record in enumerate(records):
            target = self.path(record['path'])
            if record['before_sha256'] is not None:
                backup = transaction / f'{index}.backup'
                atomic_write(backup, target.read_bytes())
                if hash_file(backup) != record['before_sha256']:
                    raise BootstrapError('target changed while backing up')
                record['backup'] = backup.name
        json_write(transaction / 'journal.json', report)
        written = []
        try:
            for record in records:
                target = self.path(record['path'])
                current = hash_file(target) if target.exists() else None
                if current != record['before_sha256']:
                    raise BootstrapError(f'target changed during publication: {record["path"]}')
                written.append(record)
                if record['after_sha256'] is None:
                    target.unlink(missing_ok=True)
                else:
                    public = record['path'].startswith(('/usr/local/', '/usr/libexec/', '/usr/lib/kernel/', '/etc/systemd/'))
                    self._mkdir(target.parent, 0o755 if public else 0o700)
                    atomic_write(target, writes[record['path']][0], record['mode'])
            updated_files = dict(owners['files'])
            for record in records:
                if record['after_sha256'] is None:
                    updated_files.pop(record['path'], None)
                else:
                    updated_files[record['path']] = record['after_sha256']
            updated = dict(owners, files=updated_files)
            json_write(self.path(OWNER), updated)
            report['state'] = 'published'
            json_write(transaction / 'journal.json', report)
            return report
        except BaseException:
            for record in reversed(written):
                target = self.path(record['path'])
                if record['backup'] is None:
                    target.unlink(missing_ok=True)
                else:
                    atomic_write(target, (transaction / record['backup']).read_bytes(), record['before_mode'])
            json_write(self.path(OWNER), owners)
            report['state'] = 'rolled-back'
            json_write(transaction / 'journal.json', report)
            raise

    def rollback(self, transaction_id, *, dry_run=False):
        token(transaction_id, 'bootstrap transaction')
        journal = self._read(BASE + '/transactions/' + transaction_id + '/journal.json')
        if journal.get('kind') == 'enable' and not dry_run:
            if self.ops.reconcile_active():
                raise BootstrapError('reconciliation service is active; wait before activation rollback')
            with locked(self.path(STATE + '/reconcile.lock'), self.root):
                if self.ops.reconcile_active():
                    raise BootstrapError('reconciliation service became active; retry rollback after completion')
                result = self._rollback_locked(transaction_id)
                if self.path(CONFIG).exists():
                    config = load_config(self.path(CONFIG), self.root, require_enabled=False).raw
                    self._publish({CONFIG: (_json_bytes(dict(config, enabled=False)), 0o600)}, 'rollback-disable')
                    result['default_restoration'] = Reconciler(self.root, self.ops)._restore_normal_default_locked()
                return result
        return self._rollback_locked(transaction_id, dry_run=dry_run)

    def _rollback_locked(self, transaction_id, *, dry_run=False):
        token(transaction_id, 'bootstrap transaction')
        transaction = self.path(BASE + '/transactions/' + transaction_id)
        checked_path(transaction, self.root)
        journal = self._read(BASE + '/transactions/' + transaction_id + '/journal.json')
        if journal.get('state') != 'published':
            raise BootstrapError('only a published bootstrap transaction can be rolled back')
        for record in journal['files']:
            target = self.path(record['path'])
            checked_path(target, self.root, missing=record['after_sha256'] is None)
            current = hash_file(target) if target.exists() else None
            if current != record['after_sha256']:
                raise BootstrapError(f'rollback refuses a foreign edit: {record["path"]}')
            if record['backup']:
                backup = transaction / record['backup']
                checked_path(backup, self.root)
                if hash_file(backup) != record['before_sha256']:
                    raise BootstrapError('rollback backup changed')
        if not dry_run:
            if journal.get('kind') == 'enable':
                self.ops.triggers(False)
            for record in reversed(journal['files']):
                target = self.path(record['path'])
                if record['backup']:
                    atomic_write(target, (transaction / record['backup']).read_bytes(), record['before_mode'])
                else:
                    target.unlink(missing_ok=True)
            previous = self._read(BASE + '/transactions/' + transaction_id + '/owners-before.json')
            current = self._owners()
            for record in journal['files']:
                name = record['path']
                if name in previous['files']:
                    current['files'][name] = previous['files'][name]
                else:
                    current['files'].pop(name, None)
            json_write(self.path(OWNER), current)
            journal['state'] = 'rolled-back'
            json_write(transaction / 'journal.json', journal)
        return dict(journal, dry_run=dry_run)

    def _snapshot(self, records, files, destination, *, dry_run=False):
        path = self.path(destination)
        checked_path(path, self.root, missing=True)
        if path.exists():
            actual = {}
            for file in path.rglob('*'):
                checked_path(file, self.root)
                if file.is_file():
                    actual[str(file.relative_to(path))] = {'sha256': hash_file(file), 'mode': file.stat().st_mode & 0o777}
            if actual != records:
                raise BootstrapError('immutable snapshot changed or contains foreign files')
            return path
        if dry_run:
            return path
        self._mkdir(path.parent, 0o755)
        stage = Path(tempfile.mkdtemp(prefix='.snapshot-', dir=path.parent))
        try:
            stage.chmod(0o755)
            for name, record in records.items():
                data = files(name)
                if digest(data) != record['sha256']:
                    raise BootstrapError(f'input changed during snapshot: {name}')
                target = stage / name
                self._mkdir(target.parent, 0o755)
                target.write_bytes(data)
                target.chmod(record['mode'])
            os.rename(stage, path)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        return path

    def install(self, repository=None, *, dry_run=False, replace_hashes=None):
        if self.ops.triggers_any_active():
            raise BootstrapError('disable every enabled/active trigger and wait for reconciliation before replacing the installed runtime')
        package = Path(__file__).parent if repository is None else _input_path(repository) / 'src/nvidia_vbios'
        package = _input_path(package)
        records, code = {}, {}
        for file in sorted(package.rglob('*')):
            if not file.is_file() or file.suffix not in ('.py', '.json', '.patch', '.c', '.h'):
                continue
            data = _external(file)
            if file.suffix == '.py':
                ast.parse(data, filename=str(file))
            elif file.suffix == '.json':
                json.loads(data)
            name = 'nvidia_vbios/' + str(file.relative_to(package))
            records[name] = {'sha256': digest(data), 'mode': 0o644}
            code[name] = data
        # A graphical editor and its launcher are installed only when the runtime includes one.
        editor_gui = 'nvidia_vbios/gui/__init__.py' in code
        required = ('__init__.py', 'cli.py', 'bootstrap.py', 'lifecycle/__main__.py', *(('gui/__init__.py',) if editor_gui else ()))
        if any('nvidia_vbios/' + name not in code for name in required):
            raise BootstrapError('runtime lacks a required public/internal entrypoint')
        release = _fingerprint(records)
        destination = RUNTIME + '/releases/' + release
        writes = {}
        bundle = code.get('nvidia_vbios/lifecycle/hook_templates.json')
        if bundle is None:
            raise BootstrapError('runtime lacks package-local lifecycle hook resources')
        # Decode reviewed candidate data with the installed codec, never candidate code.
        templates = hook_templates(resource_bytes=bundle)
        platform = _platform(self.ops)
        boot = self._read(CONFIG).get('boot')
        if platform.family != 'fedora' or boot:
            from .lifecycle.portable_hooks import hook_templates_for
            templates = hook_templates_for(platform, boot)
        expected = {Path(name).name for name in TEMPLATES}
        expected_actions = {provider for provider, target in ACTION_TARGETS.items() if target in templates}
        staged_actions = set()
        installed_templates = set()
        for target, value in templates.items():
            data, mode = value['data'], value['mode']
            basename = Path(target).name
            if target in ACTION_TARGETS.values():
                provider = next(name for name, path in ACTION_TARGETS.items() if path == target)
                if b'/usr/libexec/nvidia-vbios lifecycle' not in data:
                    raise BootstrapError('DNF callback does not use trusted runtime')
                writes[BASE + '/actions/' + provider] = (data, 0o600)
                staged_actions.add(provider)
                continue
            native_kernel_hook = target in ('/etc/kernel/postinst.d/zz-nvidia-vbios', '/etc/kernel/postrm.d/zz-nvidia-vbios')
            allowed = (target == '/usr/lib/kernel/install.d/99-nvidia-vbios.install' or native_kernel_hook or
                       target in {prefix + name for prefix in ('/etc/systemd/system/', '/usr/lib/systemd/system/')
                                  for name in (*UNITS, 'nvidia-vbios-reconcile.service')})
            if not allowed or (not native_kernel_hook and basename in installed_templates) or not isinstance(mode, int) or isinstance(mode, bool) or mode not in (0o644, 0o755):
                raise BootstrapError('unsupported/duplicate lifecycle template destination or mode')
            if basename.endswith(('.path', '.timer')):
                if b'Unit=nvidia-vbios-reconcile.service' not in data:
                    raise BootstrapError('trigger template does not target the installed reconcile unit')
            elif b'/usr/libexec/nvidia-vbios lifecycle' not in data:
                raise BootstrapError('executable template does not use the trusted runner')
            if basename == '99-nvidia-vbios.install' or native_kernel_hook:
                first, _, body = data.partition(b'\n')
                data = first + f'\n[ -f {ENABLED} ] || exit 0\n'.encode() + body
            writes[target] = (data, mode)
            if not native_kernel_hook:
                installed_templates.add(basename)
        if installed_templates != expected or staged_actions != expected_actions:
            raise BootstrapError('incomplete package-local lifecycle template bundle')
        interpreter = _runtime_python(self.root)
        writes.update({
            '/usr/local/bin/nvbios': (_launcher('from nvidia_vbios.cli import main\nraise SystemExit(main())', interpreter), 0o755),
            **({'/usr/local/bin/nvbios-editor': (_launcher('from nvidia_vbios.gui import main\nraise SystemExit(main())', interpreter), 0o755)}
               if editor_gui else {}),
            '/usr/libexec/nvidia-vbios': (_launcher('if len(sys.argv) < 2 or sys.argv[1] != "lifecycle":\n    raise SystemExit("expected lifecycle command")\nfrom nvidia_vbios.lifecycle.__main__ import main\nraise SystemExit(main(sys.argv[2:]))', interpreter), 0o755),
            RUNTIME + '/current.json': (_json_bytes({'schema_version': 1, 'release': release, 'files': records}), 0o644),
            BASE + '/installed.json': (_json_bytes({'schema_version': 1, 'release': release, 'runtime': destination}), 0o600),
        })
        # Validate targets before publishing immutable files or selector.
        self._publish(writes, 'install', dry_run=True, replacements=replace_hashes)
        self._snapshot(records, code.__getitem__, destination, dry_run=dry_run)
        report = self._publish(writes, 'install', dry_run=dry_run, replacements=replace_hashes)
        return dict(report, release=release, runtime=destination, triggers_enabled=False)

    def _archive_device(self, device, actual):
        required = ('uuid', 'bdf', 'vendor', 'device', 'architecture', 'archive', 'source_sha256', 'source_size', 'payload', 'sha256', 'size')
        if any(name not in device for name in required):
            raise BootstrapError('device requires physical identity and archive/payload provenance')
        observed = actual.get(device['bdf'])
        if observed is None or any(observed.get(name) != device[name] for name in ('uuid', 'vendor', 'device')):
            raise BootstrapError('selected UUID/BDF/PCI identity does not match physical GPU')
        archive, payload = _external(device['archive']), _external(device['payload'])
        if len(archive) != device['source_size'] or digest(archive) != device['source_sha256']:
            raise BootstrapError('full archival image changed before normalization')
        if len(payload) != device['size'] or digest(payload) != device['sha256']:
            raise BootstrapError('reviewed payload changed')
        self.ops.archive_identity(archive, payload, device)
        # Firmware identity is checked when enrollment provides reviewed values.
        for name in ('serial', 'vbios_version'):
            if device.get(name) and observed.get(name) != device[name]:
                raise BootstrapError(f'physical GPU {name} unavailable or changed during enrollment')
        evidence = device.get('evidence', {'boot': 'unverified', 'application': 'unverified', 'fields': {}})
        output = {name: device[name] for name in ('uuid', 'bdf', 'vendor', 'device', 'architecture', 'source_sha256', 'sha256', 'size')}
        if device.get('representation') is not None:
            output['representation'] = device['representation']
        output.update(structurally_validated=True, evidence=evidence,
                      payload_path=f'/var/lib/nvidia-vbios/roms/{device["sha256"]}.bin')
        if output.get('representation') in ARCHIVE_VERIFIED:
            # The payload re-verifies only from its full ROM: keep the ROM for later Loads that keep this GPU.
            output['archive_path'] = f'/var/lib/nvidia-vbios/roms/{device["source_sha256"]}.rom'
            return output, payload, archive
        return output, payload, None

    def enroll(self, profile, *, dry_run=False):
        profile = _input(profile)
        if self.ops.triggers_any_active():
            raise BootstrapError('disable every enabled/active trigger and wait for reconciliation before replacing enrollment')
        if not isinstance(profile.get('devices'), list) or not 1 <= len(profile['devices']) <= MAX_GPUS:
            raise BootstrapError(f'explicit profile requires one through {MAX_GPUS} GPUs')
        if any(not isinstance(device, dict) for device in profile['devices']):
            raise BootstrapError('each selected device must be a JSON object')
        if not isinstance(profile.get('driver_sources'), list) or any(not isinstance(source, dict) or not isinstance(source.get('path'), str) for source in profile['driver_sources']):
            raise BootstrapError('driver_sources must contain explicit source path objects')
        actual = self.ops.inventory()
        devices, payloads = [], {}
        for device in profile['devices']:
            selected, data, archive = self._archive_device(device, actual)
            devices.append(selected)
            payloads[selected['payload_path']] = data
            if archive is not None:
                payloads[selected['archive_path']] = archive
        normal_boot = None
        if profile.get('boot'):
            from .lifecycle.boot import BootAdapter, entry_identity
            adapter = BootAdapter(self.root, profile)
            fallback = entry_identity(profile['fallback_entry'], adapter.backend)
            baseline = adapter.discover(self.ops.current_kernel(), fallback)
            normal_boot = adapter.fallback_record(baseline)
            entry = baseline.descriptor
            fallback_files = normal_boot['boot_files']
        else:
            fallback = token(profile['fallback_entry'], 'normal fallback entry')
            entry_name = f'/boot/loader/entries/{fallback}.conf'
            entry = self._trusted_bytes(entry_name)
            kernel, _ = parse_bls(entry, **profile.get('bls', {}))
            fallback_files = {name: digest(self._trusted_bytes(name)) for name in
                              (f'/boot/vmlinuz-{kernel}', f'/boot/initramfs-{kernel}.img')}
        sources, snapshots = [], []
        from .driver import inspect_source
        for supplied in profile.get('driver_sources', []):
            original = _input_path(supplied['path'])
            info = inspect_source(original)
            if not info['supported'] or info['capabilities'].get('already_patched'):
                raise BootstrapError(f'unsupported or patched enrollment source: {info["reasons"]}')
            records = _source_records(original)
            destination = f'/var/lib/nvidia-vbios/sources/{info["version"]}-{_fingerprint(records)}'
            sources.append({'version': info['version'], 'path': destination, 'source_hashes': info['source_hashes'],
                            'tree_sha256': '0' * 64, 'p2p_preferred': supplied.get('p2p_preferred', False)})
            snapshots.append((original, records, destination, info))
        if not sources:
            raise BootstrapError('at least one structurally supported driver source required')
        configuration = {'schema_version': 1, 'enabled': True, 'devices': devices, 'sources': sources,
                         'userspace': profile.get('userspace', {'provider': _platform(self.ops).package_provider}),
                         'fallback_entry': fallback, 'fallback_sha256': digest(entry), 'fallback_files': fallback_files,
                         'jobs': profile.get('jobs', 1), 'bls': profile.get('bls', {})}
        if normal_boot is not None:
            configuration.update(boot=profile['boot'], normal_boot=normal_boot)
        for name in ('seed_previous_ready', 'adopt_existing', 'parameters', 'signing', 'retain_build_tree', 'require_p2p_source',
                     'stock_builder', 'retain_boot_generations', 'auto_source'):
            if name in profile:
                configuration[name] = profile[name]
        # Validate the complete config grammar in disposable scratch, before any publication.
        with tempfile.TemporaryDirectory() as temporary:
            boundary = Path(temporary)
            file = boundary / 'config.json'
            file.write_bytes(_json_bytes(configuration)); file.chmod(0o600)
            load_config(file, boundary)
        version = self.ops.installed_version(configuration)
        if not any(source['version'] == version for source in sources):
            raise BootstrapError('no enrolled source matches exact installed userspace version')
        migration = profile.get('migration')
        if migration:
            for record in configuration.get('seed_previous_ready', {}).get('boot_files', []):
                if digest(self._trusted_bytes(record['path'])) != record['sha256']:
                    raise BootstrapError('legacy working boot artifact changed before enrollment')
        report = {'schema_version': 1, 'state': 'planned' if dry_run else 'enrolled',
                  'version': version, 'device_count': len(devices), 'sources': sources,
                  'configuration': CONFIG, 'triggers_enabled': False}
        if dry_run:
            return report
        for original, records, destination, info in snapshots:
            copied = self._snapshot(records, lambda name, root=original: _external(root / name), destination)
            if _source_records(original) != records or inspect_source(original)['source_hashes'] != info['source_hashes']:
                raise BootstrapError('original source changed during snapshot')
            inspected = inspect_source(copied)
            if not inspected['supported'] or inspected['source_hashes'] != info['source_hashes']:
                raise BootstrapError('source snapshot does not retain the inspected source interface')
            next(source for source in sources if source['path'] == destination)['tree_sha256'] = source_tree_hash(copied, self.root)
        writes = {path: (data, 0o600) for path, data in payloads.items()}
        writes[CONFIG] = (_json_bytes(configuration), 0o600)
        writes[BASE + '/enrolled.json'] = (_json_bytes({'schema_version': 1, 'configuration_sha256': digest(_json_bytes(configuration)),
                                                      'version': version, 'migration': migration}), 0o600)
        report.update(self._publish(writes, 'enroll'))
        return dict(report, state='enrolled', device_count=len(devices), sources=sources)

    def _legacy_target(self, name):
        for alias, canonical in (('/lib', '/usr/lib'), ('/lib64', '/usr/lib64')):
            if name == alias or name.startswith(alias + '/'):
                path = self.path(alias)
                info = path.lstat()
                if not stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid():
                    raise BootstrapError('legacy usr-merge alias is not a trusted link')
                target = Path(os.readlink(path))
                resolved = self.path(str(target)) if target.is_absolute() else path.parent / target
                if Path(os.path.abspath(resolved)) != self.path(canonical):
                    raise BootstrapError('legacy usr-merge alias has an unexpected target')
                name = canonical + name[len(alias):]
                break
        return resolve_trusted_file(self.path(name), self.root)

    def migrate_legacy(self, state_path, driver_sources, *, userspace, evidence=None, jobs=1, dry_run=False):
        state_path = Path(state_path).absolute()
        checked_path(state_path, self.root)
        state_data = state_path.read_bytes(); state = json.loads(state_data)
        if state.get('phase') not in ('persistent-enabled', 'persistent-default-selected'):
            raise BootstrapError('legacy migration requires a reviewed persistent working deployment')
        bundle = Path(state['bundle'])
        manifest_data = _external(bundle / 'manifest.json'); manifest = json.loads(manifest_data)
        test = state['test_boot']
        if test.get('manifest_sha256') and digest(manifest_data) != test['manifest_sha256']:
            raise BootstrapError('legacy bundle manifest differs from recorded reviewed manifest')
        devices = []
        actual = self.ops.inventory()
        for device in manifest['devices']:
            item = dict(device, archive=device['source_image'], payload=str(bundle / device['bundle_image']))
            if hasattr(self.ops, 'archive_architecture'):
                item['architecture'] = self.ops.archive_architecture(item)
            else:
                from .payload import optional_editor
                editor = optional_editor()
                if editor is None:
                    raise BootstrapError('legacy bundle migration is not part of the open loader')
                item['architecture'] = editor.archive_family(_external(item['archive']))
            item['evidence'] = (evidence or {}).get(item['uuid'], {'boot': 'verified' if manifest.get('runtime_tested') is True else 'unverified', 'application': 'unverified', 'fields': {}})
            self._archive_device(item, actual)
            devices.append(item)
        adoption = {}
        retire_files = {}
        for record in state['files']:
            target = Path(record['target'])
            physical = self.path(str(target))
            # /lib is commonly a trusted usr-merge alias; store canonical paths.
            canonical = self._legacy_target(str(target))
            if hash_file(canonical) != record['after_sha256']:
                raise BootstrapError('legacy deployment file changed before adoption')
            name = '/' + str(canonical.relative_to(self.root))
            if name.startswith(('/usr/lib/modules/', '/usr/lib/firmware/nvidia/')):
                adoption[name] = record['after_sha256']
            if name == '/etc/dracut.conf.d/99-vbios-override.conf':
                retire_files[name] = record['after_sha256']
        legacy_kernel = token(state['kernel'])
        entry = token(test['entry_id'], 'legacy boot entry')
        boot_paths = [f'/boot/loader/entries/{entry}.conf', str(test['initramfs']), f'/boot/vmlinuz-{legacy_kernel}']
        seed = {'entry': entry, 'kernel': legacy_kernel, 'version': manifest['driver'],
                'boot_files': [{'path': name, 'sha256': digest(self._trusted_bytes(name))} for name in boot_paths]}
        fallback = test.get('saved_entry') or test.get('base_entry')
        if fallback and str(fallback).endswith('.conf'):
            fallback = Path(fallback).stem
        environment = self.ops.grub_environment()
        if environment.get('saved_entry') != entry:
            raise BootstrapError('legacy working entry is no longer the selected persistent default')
        profile = {'devices': devices, 'driver_sources': driver_sources, 'userspace': userspace,
                   'fallback_entry': fallback, 'seed_previous_ready': seed, 'adopt_existing': adoption,
                   'jobs': jobs, 'migration': {'legacy_state': '/' + str(state_path.relative_to(self.root)),
                                              'legacy_state_sha256': digest(state_data), 'legacy_entry': entry, 'retire_files': retire_files}}
        return self.enroll(profile, dry_run=dry_run)

    def _ready(self, kernel, configuration_path=CONFIG):
        if kernel != self.ops.current_kernel():
            raise BootstrapError('activation requires successful reconciliation for the running kernel')
        configuration = load_config(self.path(configuration_path), self.root)
        enrolled = self._read(BASE + '/enrolled.json')
        status = Reconciler(self.root, self.ops, config_path=configuration_path).ready_status(token(kernel))
        fleet = self._read(STATE + '/fleet.json')
        if (status.get('state') != 'ready' or status.get('marker') != 'VBIOS_READY' or
            status.get('kernel') != kernel or status.get('configuration_sha256') != configuration.fingerprint or
            enrolled.get('configuration_sha256') != configuration.fingerprint or
            fleet.get('last_ready', {}).get('entry') != status.get('entry') or
            fleet.get('last_ready', {}).get('kernel') != kernel or
            not status.get('activation_config_sha256') or not status.get('force_driver_sha256')):
            raise BootstrapError('current-kernel lifecycle readiness/configuration commit is missing or stale')
        for record in fleet['last_ready']['boot_files']:
            if digest(self._trusted_bytes(record['path'])) != record['sha256']:
                raise BootstrapError('ready boot artifact changed before trigger activation')
        for record in status.get('deployment', []):
            name = record.get('path') or record.get('target')
            expected = record.get('after_sha256')
            if not name or not expected or digest(self._trusted_bytes(name)) != expected:
                raise BootstrapError('ready deployment changed before trigger activation')
        if not status.get('deployment'):
            raise BootstrapError('ready status has no validated deployment records')
        return configuration, status, enrolled

    def _ready_default_plan(self, configuration, status):
        """Plan explicit activation without treating normal as an update event."""
        worker = Reconciler(self.root, self.ops)
        fleet = self._read(STATE + '/fleet.json')
        if configuration.raw.get('boot'):
            environment = worker.ops.grub_environment()
            current, target = environment.get('saved_entry'), status['entry']
            result = {'state': 'preserved', 'entry': current, 'target': target, 'environment': environment,
                      'boot_files': fleet['last_ready']['boot_files'], 'portable': True}
            if environment.get('next_entry') or environment.get('prev_saved_entry'):
                return dict(result, reason='pending boot transition')
            if current == target:
                return dict(result, state='ready')
            normal = fleet.get('normal_fallback', configuration.raw['normal_boot'])
            if current != normal['entry']:
                return dict(result, reason='foreign or unrelated boot default')
            worker._validate_normal(configuration, normal)
            return dict(result, state='planned', normal_boot=normal,
                        normal_files=[{'path':name,'sha256':sha} for name,sha in normal['boot_files'].items()])
        normal = fleet.get('normal_fallback', {'entry': configuration.fallback_entry,
            'sha256': configuration.raw['fallback_sha256'], 'boot_files': configuration.raw['fallback_files']})
        environment = self.ops.grub_environment()
        worker._check_option_variables(configuration, environment)
        current, target = environment.get('saved_entry'), status['entry']
        result = {'state': 'preserved', 'entry': current, 'target': target,
                  'environment': environment, 'boot_files': fleet['last_ready']['boot_files']}
        if environment.get('next_entry') or environment.get('prev_saved_entry'):
            return dict(result, reason='pending GRUB transition')
        if current == target:
            return dict(result, state='ready')
        if current != normal['entry']:
            return dict(result, reason='foreign or unrelated GRUB default')
        entry_name = f'/boot/loader/entries/{token(normal["entry"], "normal entry")}.conf'
        entry = self._trusted_bytes(entry_name)
        if digest(entry) != normal['sha256']:
            raise BootstrapError('normal recovery BLS changed before explicit reenable')
        kernel, _ = parse_bls(entry, **worker._bls_options(configuration))
        if set(normal['boot_files']) != {f'/boot/vmlinuz-{kernel}', f'/boot/initramfs-{kernel}.img'}:
            raise BootstrapError('normal recovery artifacts do not match the enrolled BLS')
        normal_records = [{'path': entry_name, 'sha256': normal['sha256']},
                          *({'path': name, 'sha256': sha} for name, sha in normal['boot_files'].items())]
        for record in normal_records:
            if digest(self._trusted_bytes(record['path'])) != record['sha256']:
                raise BootstrapError('normal recovery artifact changed before explicit reenable')
        return dict(result, state='planned', normal_files=normal_records)

    def _select_ready_default_locked(self, plan):
        """Caller holds reconcile.lock; change only the hash-verified normal choice."""
        public = {key: value for key, value in plan.items() if key not in ('environment', 'boot_files', 'normal_files')}
        if plan['state'] != 'planned':
            return public
        operations = self.ops
        if plan.get('portable'):
            worker = Reconciler(self.root, self.ops)
            operations = worker.ops
            worker._validate_normal(load_config(self.path(CONFIG), self.root, require_enabled=False), plan['normal_boot'])
        for record in (*plan['boot_files'], *plan['normal_files']):
            if digest(self._trusted_bytes(record['path'])) != record['sha256']:
                raise BootstrapError('boot artifact changed during explicit reenable')
        if operations.grub_environment() != plan['environment']:
            raise BootstrapError('GRUB selection changed during explicit reenable')
        try:
            operations.set_default(plan['target'])
            after = operations.grub_environment()
            if after != dict(plan['environment'], saved_entry=plan['target']):
                raise BootstrapError('READY default selection did not persist unchanged GRUB choices')
        except BaseException:
            current = operations.grub_environment()
            if current == dict(plan['environment'], saved_entry=plan['target']):
                # A command can change saved_entry and then fail. Restore only
                # our exact transition, never another actor's new boot choice.
                for record in plan['normal_files']:
                    if digest(self._trusted_bytes(record['path'])) != record['sha256']:
                        raise BootstrapError('normal recovery changed; default rollback needs review')
                operations.set_default(plan['entry'])
            raise
        return dict(public, state='selected', entry=plan['target'], previous_entry=plan['entry'])

    def enable(self, kernel, *, dry_run=False, provider=None):
        provider = provider or _platform(self.ops).hook_provider
        if dry_run:
            return self._enable_locked(kernel, dry_run=True, provider=provider)
        if self.ops.reconcile_active():
            raise BootstrapError('reconciliation service is active; wait before enabling triggers')
        with locked(self.path(STATE + '/reconcile.lock'), self.root):
            if self.ops.reconcile_active():
                raise BootstrapError('reconciliation service became active; retry enable after completion')
            report = self._enable_locked(kernel, provider=provider)
        if report.get('state') == 'already-enabled':
            return report
        # An expired OnBootSec timer may launch immediately: never start it
        # while holding the lock that its service must acquire.
        try:
            self.ops.triggers(True)
            if not self.ops.triggers_enabled():
                raise BootstrapError('path/timer enable verification failed')
        except BaseException as exc:
            self.ops.triggers(False)
            try:
                self.rollback(report['transaction_id'])
            except LifecycleError as rollback_error:
                raise BootstrapError(f'trigger startup failed; rollback deferred for {report["transaction_id"]}: {rollback_error}') from exc
            raise
        return dict(report, triggers_enabled=True)

    def _enable_locked(self, kernel, *, dry_run=False, provider='dnf5'):
        self.status(require_installed=True)
        raw = load_config(self.path(CONFIG), self.root, require_enabled=False).raw
        if raw['enabled']:
            return self._enable(kernel, dry_run=dry_run, provider=provider)
        if self.ops.triggers_any_active():
            raise BootstrapError('disabled profile still has active triggers or reconciliation')
        candidate = dict(raw, enabled=True)
        data = _json_bytes(candidate)
        if digest(data) != self._read(BASE + '/enrolled.json').get('configuration_sha256'):
            raise BootstrapError('disabled enrollment differs from the previously reconciled profile')
        directory = self.path(BASE)
        checked_path(directory, self.root)
        with tempfile.TemporaryDirectory(prefix='.enable-check-', dir=directory) as temporary:
            file = Path(temporary) / 'config.json'
            atomic_write(file, data)
            name = '/' + str(file.relative_to(self.root))
            return self._enable(kernel, dry_run=dry_run, provider=provider,
                                configuration_path=name, resume_data=data)

    def _enable(self, kernel, *, dry_run=False, provider='dnf5', configuration_path=CONFIG, resume_data=None):
        configuration, status, enrolled = self._ready(token(kernel), configuration_path)
        if provider not in ACTION_TARGETS or not self.ops.plugin_available(provider):
            raise BootstrapError('native package callback/plugin prerequisites are unavailable')
        action = self._trusted_bytes(BASE + '/actions/' + provider)
        selection = self._ready_default_plan(configuration, status)
        prior = self._read(ENABLED)
        if self.ops.triggers_enabled():
            if prior.get('provider') == provider and prior.get('configuration_sha256') == configuration.fingerprint:
                chosen = ({key: value for key, value in selection.items() if key not in ('environment', 'boot_files', 'normal_files')}
                          if dry_run else self._select_ready_default_locked(selection))
                if not dry_run and (prior.get('kernel'), prior.get('entry')) != (kernel, status['entry']):
                    # A reconcile after a parameter change moved the ready entry: same provider/profile.
                    self._publish({ENABLED: (_json_bytes(dict(prior, kernel=kernel, entry=status['entry'])), 0o600)}, 'enable')
                return {'state': 'already-enabled', 'ready': True, 'triggers_enabled': True, 'kernel': kernel, 'default_selection': chosen}
            raise BootstrapError('disable existing triggers before changing activation provider/profile')
        enabled = {'schema_version': 1, 'kernel': kernel, 'entry': status['entry'],
                   'configuration_sha256': configuration.fingerprint, 'provider': provider}
        writes = {ACTION_TARGETS[provider]: (action, 0o644), ENABLED: (_json_bytes(enabled), 0o600)}
        if _platform(self.ops).family != 'fedora' or configuration.raw.get('boot'):
            from .lifecycle.portable_hooks import hook_templates_for
            for name, record in hook_templates_for(_platform(self.ops), configuration.raw.get('boot')).items():
                if name.endswith('/nvidia-vbios-reconcile.service'):
                    writes[name] = (record['data'], record['mode'])
        if resume_data is not None:
            writes[CONFIG] = (resume_data, 0o600)
        migration = enrolled.get('migration')
        replacements = {}
        migrated = self._read(BASE + '/migration.json')
        if migration and not migrated:
            original = self.path(migration['legacy_state']); checked_path(original, self.root)
            if hash_file(original) != migration['legacy_state_sha256']:
                raise BootstrapError('legacy state changed; stale manager cannot be retired safely')
            retired_name = str(Path(migration['legacy_state']).with_name('state.migrated.json'))
            retired = self.path(retired_name)
            checked_path(retired, self.root, missing=True)
            if retired.exists():
                raise BootstrapError('legacy state archive already exists')
            writes[retired_name] = (original.read_bytes(), 0o600)
            writes[migration['legacy_state']] = (None, 0o600)
            replacements[migration['legacy_state']] = migration['legacy_state_sha256']
            for name, expected in migration.get('retire_files', {}).items():
                checked_path(self.path(name), self.root)
                if hash_file(self.path(name)) != expected:
                    raise BootstrapError('legacy dracut file changed before retirement')
                writes[name] = (None, 0o600)
                replacements[name] = expected
            record = dict(migration, archived_state=retired_name,
                          current_manager='nvidia-vbios.lifecycle')
            writes[BASE + '/migration.json'] = (_json_bytes(record), 0o600)
        elif migration:
            if (self.path(migration['legacy_state']).exists() or
                migrated.get('legacy_state_sha256') != migration['legacy_state_sha256'] or
                digest(self._trusted_bytes(migrated['archived_state'])) != migration['legacy_state_sha256']):
                raise BootstrapError('retired legacy state changed or stale manager state reappeared')
        report = self._publish(writes, 'enable', dry_run=True, replacements=replacements)
        if dry_run:
            public = {key: value for key, value in selection.items() if key not in ('environment', 'boot_files', 'normal_files')}
            return dict(report, ready=True, triggers_enabled=False, default_selection=public)
        report = self._publish(writes, 'enable', replacements=replacements)
        try:
            chosen = self._select_ready_default_locked(selection)
        except BaseException:
            self._rollback_locked(report['transaction_id'])
            raise
        return dict(report, ready=True, triggers_enabled=False, default_selection=chosen)

    def disable(self, *, dry_run=False):
        if self.ops.reconcile_active():
            raise BootstrapError('reconciliation service is active; wait for completion before disabling')
        if dry_run:
            return self._disable_locked(dry_run=True)
        # Do not stop a build or mutate triggers if another reconciler holds the lock.
        with locked(self.path(STATE + '/reconcile.lock'), self.root):
            if self.ops.reconcile_active():
                raise BootstrapError('reconciliation service became active; retry after completion')
            return self._disable_locked()

    def _disable_locked(self, *, dry_run=False, preserve_default=False):
        owners = self._owners()
        targets = [name for name in (*ACTION_TARGETS.values(), ENABLED) if self.path(name).exists()]
        for name in targets:
            checked_path(self.path(name), self.root)
            if hash_file(self.path(name)) != owners['files'].get(name):
                raise BootstrapError('refusing to remove foreign trigger file')
        writes = {name: (None, 0o600) for name in targets}
        if self.path(CONFIG).exists():
            config = load_config(self.path(CONFIG), self.root, require_enabled=False).raw
            writes[CONFIG] = (_json_bytes(dict(config, enabled=False)), 0o600)
        if dry_run:
            return dict(self._publish(writes, 'disable', dry_run=True), remove=targets,
                        triggers_enabled=self.ops.triggers_enabled())
        self.ops.triggers(False)
        report = self._publish(writes, 'disable')
        restoration = (Reconciler(self.root, self.ops)._restore_normal_default_locked()
                       if self.path(CONFIG).exists() and not preserve_default else None)
        return dict(report, state='disabled', triggers_enabled=False, default_restoration=restoration)

    def update_parameters(self, change, *, dry_run=False):
        """Replace the optional registry `parameters` with change(current) in one ownership transaction.

        Enrollment and enabled bookkeeping follow the new profile; the path unit then reconciles it."""
        if dry_run:
            return self._update_parameters_locked(change, dry_run=True)
        if self.ops.reconcile_active():
            raise BootstrapError('reconciliation service is active; wait before changing registry parameters')
        with locked(self.path(STATE + '/reconcile.lock'), self.root):
            if self.ops.reconcile_active():
                raise BootstrapError('reconciliation service became active; retry after completion')
            return self._update_parameters_locked(change)

    def _update_parameters_locked(self, change, *, dry_run=False):
        from .lifecycle.engine import activation
        raw = load_config(self.path(CONFIG), self.root, require_enabled=False).raw
        if not raw['enabled']:
            # A disabled profile is never reconciled, so a changed one could not be re-enabled.
            raise BootstrapError('enable the profile before changing registry parameters')
        enrolled = self._read(BASE + '/enrolled.json')
        if enrolled.get('configuration_sha256') != digest(_json_bytes(dict(raw, enabled=True))):
            raise BootstrapError('enrollment record does not match the current profile')
        before = raw.get('parameters') or {}
        after = change(before)
        if after == before:
            return {'schema_version': 1, 'state': 'unchanged', 'parameters': after}
        configuration = {key: value for key, value in raw.items() if key != 'parameters'}
        if after:
            configuration['parameters'] = after
        data = _json_bytes(configuration)
        with tempfile.TemporaryDirectory() as temporary:
            file = Path(temporary) / 'config.json'
            file.write_bytes(data); file.chmod(0o600)
            activation(load_config(file, Path(temporary), require_enabled=False).devices, '0', after)
        writes = {CONFIG: (data, 0o600),
                  BASE + '/enrolled.json': (_json_bytes(dict(enrolled, configuration_sha256=digest(
                      _json_bytes(dict(configuration, enabled=True))))), 0o600)}
        enabled = self._read(ENABLED)
        if enabled:
            writes[ENABLED] = (_json_bytes(dict(enabled, configuration_sha256=digest(data))), 0o600)
        return dict(self._publish(writes, 'parameters', dry_run=dry_run), parameters=after)

    def _runtime_value(self, name):
        """Read one sysfs observation without escaping an injected root."""
        path = self.path(name)
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(self.root):
                raise OSError('sysfs observation escapes its filesystem root')
            raw = path.read_text(encoding='utf-8').removesuffix('\n')
        except (OSError, UnicodeError):
            return {'sysfs_path': name, 'available': False, 'state': 'unavailable',
                    'raw': None, 'observed': None}
        state = 'null' if raw == '(null)' else 'empty' if raw == '' else 'value'
        return {'sysfs_path': name, 'available': True, 'state': state, 'raw': raw,
                'observed': None if state == 'null' else raw}

    @staticmethod
    def _runtime_comparison(observation, expected):
        return dict(observation, expected=expected,
                    matches=observation['observed'] == expected
                    if observation['available'] and isinstance(expected, str) else None)

    def _runtime_status(self, running_kernel):
        """Loaded identity/parameter evidence never establishes firmware effects."""
        names = ('NVreg_RegistryDwords', 'NVreg_RegistryDwordsPerDevice',
                 'NVreg_RegistryBinaryFilePerDevice')
        diagnostics, prepared, configuration, expected_parameters = [], {}, None, {}
        try:
            prepared = self._read(STATE + f'/status-{token(running_kernel)}.json')
            if not isinstance(prepared, dict):
                prepared = {}
                diagnostics.append('prepared-status-unavailable')
        except (LifecycleError, OSError):
            diagnostics.append('prepared-status-unavailable')
        metadata = prepared.get('module_metadata', {})
        primary = metadata.get('nvidia.ko', {}) if isinstance(metadata, dict) else {}
        if not isinstance(primary, dict):
            primary = {}
        version = prepared.get('driver') or primary.get('version')
        if not isinstance(version, str):
            version = None
        expected_source = 'unavailable'
        try:
            configuration = load_config(self.path(CONFIG), self.root, require_enabled=False)
            stored = prepared.get('module_parameters')
            if (prepared.get('configuration_sha256') == configuration.fingerprint and
                    isinstance(stored, dict) and all(isinstance(stored.get(name), str) for name in names)):
                expected_parameters = {name: stored[name] for name in names}
                expected_source = 'prepared-status'
            elif version:
                from .lifecycle.engine import typed_parameters
                expected_parameters = typed_parameters(configuration.devices, version, configuration.raw.get('parameters'))
                expected_source = 'current-enrollment'
        except (LifecycleError, OSError, TypeError, ValueError):
            diagnostics.append('expected-parameters-unavailable')
        observations = {name: self._runtime_comparison(
            self._runtime_value('/sys/module/nvidia/parameters/' + name), expected_parameters.get(name))
            for name in names}
        identity = {
            'srcversion': self._runtime_comparison(self._runtime_value('/sys/module/nvidia/srcversion'),
                                                 primary.get('srcversion')),
            'version': self._runtime_comparison(self._runtime_value('/sys/module/nvidia/version'), version)}
        comparisons = [value['matches'] for value in (*identity.values(), *observations.values())]
        activation_matches = None if any(value is None for value in comparisons) else all(comparisons)
        module = self.path('/sys/module/nvidia')
        try:
            present = module.is_dir() if not module.is_symlink() and module.resolve().is_relative_to(self.root) else None
        except OSError:
            present = None
        return {'running_kernel': running_kernel, 'scope': 'loaded-module-and-parameters-only',
                'module_present': present, 'loaded_module': identity,
                'expected_parameters_source': expected_source, 'expected_parameters_version': version,
                'module_parameters': observations, 'activation_matches': activation_matches,
                'applied': 'unknown', 'electrical': 'unknown', 'diagnostics': diagnostics}

    def _distribution_patches(self, kernel):
        """The distribution DKMS build fixes in the prepared build for `kernel`, by name; None without any."""
        from .lifecycle.distribution_patches import summary
        try:
            prepared = self._read(STATE + f'/status-{token(kernel)}.json')
        except (LifecycleError, OSError):
            return None
        return summary(prepared.get('distribution_patches')) if isinstance(prepared, dict) else None

    def status(self, *, require_installed=False):
        installed = self._read(BASE + '/installed.json')
        valid = bool(installed)
        if valid:
            selector = self._read(RUNTIME + '/current.json')
            files = selector.get('files')
            valid = (selector.get('release') == installed.get('release') and
                     isinstance(files, dict) and bool(files) and _fingerprint(files) == selector['release'])
            if valid:
                for name, record in files.items():
                    target = self.path(RUNTIME + '/releases/' + selector['release']) / name
                    try:
                        checked_path(target, self.root)
                        if hash_file(target) != record['sha256'] or target.stat().st_mode & 0o777 != record['mode']:
                            valid = False
                    except (LifecycleError, OSError):
                        valid = False
        if require_installed and not valid:
            raise BootstrapError('trusted installed runtime is missing or changed')
        enrolled = self.path(CONFIG).exists()
        running_kernel = self.ops.current_kernel()
        ready = False
        if enrolled:
            try:
                self._ready(running_kernel); ready = True
            except (LifecycleError, OSError):
                pass
        return {'schema_version': 1, 'installed': valid, 'enrolled': enrolled, 'ready': ready,
                'ready_scope': 'prepared-files-only', 'running_kernel': running_kernel,
                'last_attempt': self._read(STATE + f'/attempt-{token(running_kernel)}.json'),
                'driver_drift': self._read(STATE + '/fleet.json').get('drift'),
                'source_fetch': self._read(STATE + '/source-fetch.json'),
                'distribution_patches': self._distribution_patches(running_kernel),
                'runtime': self._runtime_status(running_kernel),
                'triggers_enabled': self.path(ENABLED).exists() and self.ops.triggers_enabled(),
                'release': installed.get('release'), 'migration': self._read(BASE + '/migration.json'),
                'platform': {'id': _platform(self.ops).id, 'family': _platform(self.ops).family,
                             'package_provider': _platform(self.ops).package_provider,
                             'hook_provider': self._read(ENABLED).get('provider', _platform(self.ops).hook_provider),
                             'boot_backend': self._read(CONFIG).get('boot', {}).get('backend', 'fedora-bls')}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    install = commands.add_parser('install'); install.add_argument('--repository', type=Path)
    install.add_argument('--replace-hashes', type=Path)
    enroll = commands.add_parser('enroll'); enroll.add_argument('--profile', type=Path, required=True)
    migrate = commands.add_parser('migrate'); migrate.add_argument('--state', type=Path, required=True)
    migrate.add_argument('--profile', type=Path, required=True, help='driver_sources/userspace/evidence/jobs JSON')
    enable = commands.add_parser('enable'); enable.add_argument('--kernel', required=True)
    enable.add_argument('--provider', choices=tuple(ACTION_TARGETS))
    commands.add_parser('status'); commands.add_parser('disable')
    rollback = commands.add_parser('rollback'); rollback.add_argument('transaction_id')
    for command in (install, enroll, migrate, enable, rollback):
        command.add_argument('--dry-run', action='store_true')
    commands.choices['disable'].add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        worker = Bootstrap()
        guard = contextlib.nullcontext() if args.action == 'status' or getattr(args, 'dry_run', False) else locked(worker.path(BASE + '/bootstrap.lock'), worker.root)
        with guard:
            if args.action == 'install':
                result = worker.install(args.repository, dry_run=args.dry_run,
                                        replace_hashes=_input(args.replace_hashes) if args.replace_hashes else None)
            elif args.action == 'enroll': result = worker.enroll(args.profile, dry_run=args.dry_run)
            elif args.action == 'migrate':
                options = _input(args.profile)
                result = worker.migrate_legacy(args.state, options['driver_sources'], userspace=options['userspace'],
                                               evidence=options.get('evidence'), jobs=options.get('jobs', 1), dry_run=args.dry_run)
            elif args.action == 'enable': result = worker.enable(args.kernel, dry_run=args.dry_run, provider=args.provider)
            elif args.action == 'disable': result = worker.disable(dry_run=args.dry_run)
            elif args.action == 'rollback': result = worker.rollback(args.transaction_id, dry_run=args.dry_run)
            else: result = worker.status()
        print(json.dumps(result, indent=2, sort_keys=True)); return 0
    except (LifecycleError, OSError, ValueError, KeyError) as exc:
        print(f'BOOTSTRAP_BLOCKED: {exc}', file=sys.stderr); return 1


if __name__ == '__main__':
    raise SystemExit(main())
