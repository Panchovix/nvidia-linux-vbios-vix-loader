"""Fingerprint-owned portable boot retention; call under reconciliation locks.

Only generation-specific boot copies and descriptors may be removed. GRUB's
shared include changes use a durable before/after intent so an interrupted
write or unlink can be retried without adopting arbitrary on-disk bytes.
"""
from __future__ import annotations

import base64
from pathlib import Path, PurePosixPath
import re

from .boot import BootAdapter, entry_identity
from .retention import running_matches, _sync_parent
from .security import LifecycleError, atomic_write, digest, hash_file, json_write, token

_HASH = re.compile(r'[0-9a-f]{64}')


def _records(worker, fleet):
    records = fleet.get('boot_generations', {})
    if not isinstance(records, dict):
        raise LifecycleError('invalid portable boot generation history')
    paths = set()
    for entry, record in records.items():
        if not isinstance(record, dict):
            raise LifecycleError('invalid portable retention record')
        try:
            kernel, managed = token(record['kernel']), token(record['managed_id'], 'managed generation')
            if not re.fullmatch(re.escape(f'vbios-{kernel}-') + r'[0-9a-f]{20}(?:-[0-9a-f]{12})?', managed):
                raise LifecycleError('portable retention generation is outside managed namespace')
            adapter = BootAdapter(worker.root, {'boot': record['boot']})
            if adapter.backend != record['backend'] or adapter.backend != worker.boot.backend:
                raise LifecycleError('portable retention backend differs from enrolled boot adapter')
            # A changed layout must be reviewed before it can grant deletion
            # authority over an old ESP/GRUB directory.
            for field in ('boot_root', 'esp', 'xbootldr', 'grub_config'):
                if adapter.config.get(field) != worker.boot.config.get(field):
                    raise LifecycleError('portable retention boot layout changed')
            expected_entry = managed + {'grub': '', 'systemd-boot': '.conf', 'uki': '.efi'}[adapter.backend]
            if entry_identity(entry, adapter.backend) != expected_entry:
                raise LifecycleError('portable retention identity does not match generation')
            files, roles = record['files'], record['roles']
            if not isinstance(files, list) or not isinstance(roles, dict) or len(files) < 3:
                raise LifecycleError('portable retention requires copied kernel/initramfs and descriptor')
            owned = {}
            for item in files:
                if not isinstance(item, dict) or set(item) != {'path', 'sha256'}:
                    raise LifecycleError('invalid portable retention fingerprint')
                name, sha = item['path'], item['sha256']
                if not isinstance(name, str) or not isinstance(sha, str) or not _HASH.fullmatch(sha) or name in owned:
                    raise LifecycleError('invalid or duplicate portable retention file')
                owned[name] = sha
            if set(roles) != set(owned):
                raise LifecycleError('portable retention roles differ from owned files')
            roots = {'/boot'} if adapter.backend == 'grub' else {
                adapter.boot_root, *[adapter.config[key] for key in ('esp', 'xbootldr', 'boot_root') if key in adapter.config]}
            base = next((f'{root}/nvidia-vbios/{managed}' for root in roots
                         if f'{root}/nvidia-vbios/{managed}/vmlinuz' in owned), None)
            if base is None:
                raise LifecycleError('portable retention kernel is outside reviewed generation root')
            boot_root = base.split('/nvidia-vbios/', 1)[0]
            descriptor = (f'{adapter.grub_root}/nvidia-vbios-entries/{managed}.cfg' if adapter.backend == 'grub'
                          else f'{boot_root}/loader/entries/{managed}.conf' if adapter.backend == 'systemd-boot'
                          else f'{boot_root}/EFI/Linux/{managed}.efi')
            required = {base + '/vmlinuz': 'kernel', base + '/initramfs.img': 'initramfs',
                        descriptor: 'uki' if adapter.backend == 'uki' else 'entry'}
            if any(roles.get(name) != role for name, role in required.items()):
                raise LifecycleError('portable retention boot artifact roles do not match plan')
            for name, role in roles.items():
                if name in required:
                    continue
                leaf = name.removeprefix(base + '/')
                if (role != 'supplemental-initrd' or not name.startswith(base + '/') or '/' in leaf
                        or not re.fullmatch(r'microcode-(?:embedded\.cpio|[0-9]+-[A-Za-z0-9_.+-]+)', leaf)):
                    raise LifecycleError('portable retention artifact is outside plan conventions')
            if type(record.get('created_ns')) is not int or record['created_ns'] < 0 or record.get('state') not in ('active', 'retiring', 'removed'):
                raise LifecycleError('invalid portable retention state or timestamp')
            for name in owned:
                if name in paths:
                    raise LifecycleError('portable generations share a supposedly owned boot artifact')
                paths.add(name)
            record['_validated'] = {'owned': owned, 'descriptor': descriptor, 'base': base, 'boot_root': boot_root}
        except (KeyError, TypeError, ValueError) as exc:
            raise LifecycleError(f'malformed portable retention record: {exc}') from exc
    return records


def _save(worker, fleet):
    # Validation annotations are ephemeral and never grant future authority.
    value = dict(fleet)
    value['boot_generations'] = {entry: {key: item for key, item in record.items() if key != '_validated'}
                                 for entry, record in fleet.get('boot_generations', {}).items()}
    json_write(worker.state / 'fleet.json', value)


def _check_owned(worker, record):
    for name, sha in record['_validated']['owned'].items():
        path = worker.path(name)
        worker.trusted(path, missing=True)
        if path.exists():
            if not path.is_file() or hash_file(path) != sha:
                raise LifecycleError('managed portable boot artifact changed externally')
        elif record['state'] != 'retiring':
            raise LifecycleError('managed portable boot artifact missing outside retirement')


def _references(worker, record):
    """Read foreign/normal/managed descriptors; never evaluate GRUB text."""
    info = record['_validated']
    roots = {'/boot', worker.boot.boot_root, *[worker.boot.config[key] for key in ('esp', 'xbootldr', 'boot_root') if key in worker.boot.config]}
    directories = [(root + '/loader/entries', '*.conf') for root in roots]
    directories += [(root + '/EFI/Linux', '*.efi') for root in roots]
    if worker.boot.backend == 'grub':
        directories.append((worker.boot.grub_root, '*.cfg'))
    needles = {name.encode() for name in info['owned']}
    needles.update(name.removeprefix(info['boot_root']).encode() for name in info['owned'] if name.startswith(info['boot_root'] + '/'))
    # The descriptor basename is unique and also catches $prefix-relative or
    # quoted source/chainloader references without interpreting shell variables.
    needles.add(PurePosixPath(info['descriptor']).name.encode())
    visited = set()
    aggregate = worker.boot.grub_root + '/nvidia-vbios.cfg' if worker.boot.backend == 'grub' else None
    for name, pattern in directories:
        directory = worker.path(name)
        worker.trusted(directory, missing=True)
        if not directory.exists():
            continue
        for path in directory.rglob(pattern):
            logical = '/' + str(path.relative_to(worker.root))
            if path in visited or logical in (info['descriptor'], aggregate):
                continue
            visited.add(path)
            worker.trusted(path)
            data = path.read_bytes()
            if any(needle and needle in data for needle in needles):
                raise LifecycleError('generation artifact still referenced by another boot entry')


def _shared_before(worker, fleet, after):
    authority = fleet.get('shared_boot_files', {})
    if not isinstance(authority, dict):
        raise LifecycleError('invalid shared portable boot ownership')
    before = {}
    for name in after:
        sha = authority.get(name)
        if not isinstance(sha, str) or not _HASH.fullmatch(sha):
            raise LifecycleError('GRUB retention lacks shared include ownership')
        path = worker.path(name)
        worker.trusted(path)
        if not path.is_file() or hash_file(path) != sha:
            raise LifecycleError('shared GRUB include changed externally')
        before[name] = sha
    return before


def _finish_visibility(worker, fleet, records, environment):
    pending = fleet.get('retention_pending')
    if not pending:
        return
    if not isinstance(pending, dict) or set(pending) != {'entry', 'remaining_ids', 'shared'}:
        raise LifecycleError('invalid portable retirement intent')
    record = records.get(pending['entry'])
    if not record or record['state'] != 'retiring' or worker.boot.backend != 'grub':
        raise LifecycleError('portable retirement intent has no matching GRUB generation')
    remaining = sorted(record['managed_id'] for record in records.values() if record['state'] == 'active')
    if pending['remaining_ids'] != remaining:
        raise LifecycleError('portable generation set changed during interrupted GRUB retirement')
    after = worker.boot.visibility_files(remaining)
    if not isinstance(pending['shared'], dict) or set(pending['shared']) != set(after):
        raise LifecycleError('portable retirement intent has invalid shared paths')
    updates = []
    for name, data in after.items():
        intent = pending['shared'][name]
        if not isinstance(intent, dict) or set(intent) != {'before', 'after', 'data'}:
            raise LifecycleError('malformed portable shared retirement intent')
        if (not isinstance(intent['before'], str) or not _HASH.fullmatch(intent['before'])
                or intent['after'] != digest(data) or intent['data'] != base64.b64encode(data).decode()):
            raise LifecycleError('portable retirement shared bytes differ from rendered intent')
        path = worker.path(name)
        worker.trusted(path)
        if hash_file(path) not in (intent['before'], intent['after']):
            raise LifecycleError('shared GRUB include changed during retirement')
        if fleet.get('shared_boot_files', {}).get(name) not in (intent['before'], intent['after']):
            raise LifecycleError('shared GRUB ownership differs from retirement intent')
        updates.append((name, path, data, intent['after']))
    if worker.ops.grub_environment() != environment:
        raise LifecycleError('boot selection changed during retention')
    for name, path, data, sha in updates:
        if hash_file(path) != sha:
            atomic_write(path, data, 0o755 if name.startswith('/etc/grub.d/') else 0o644)
        fleet.setdefault('shared_boot_files', {})[name] = sha
    fleet.pop('retention_pending')
    try:
        _save(worker, fleet)
    except OSError:
        # Disk still owns the durable intent. Keep it in the working copy too
        # so a subsequent candidate cannot accidentally erase recovery state.
        fleet['retention_pending'] = pending
        raise


def prune(worker, status, keep=3):
    """Bound history after matching running READY, preserving selected entries."""
    if type(keep) is not int or keep not in (2, 3):
        raise LifecycleError('retain_boot_generations must be 2 or 3')
    fleet = worker._json(worker.state / 'fleet.json')
    if not isinstance(fleet, dict):
        raise LifecycleError('invalid portable boot generation history')
    pending = fleet.get('retention_pending')
    if pending is not None and (not isinstance(pending, dict) or set(pending) != {'entry', 'remaining_ids', 'shared'}):
        raise LifecycleError('invalid portable retirement intent')
    records = _records(worker, fleet)
    result = {'keep': keep, 'removed': [], 'state': 'deferred', 'warnings': [],
              'retained': sum(record['state'] != 'removed' for record in records.values())}
    environment = worker.ops.grub_environment()
    journal = worker._json(worker.state / 'transaction.json')
    if journal.get('phase') not in (None, 'ready', 'rolled-back'):
        result['reason'] = 'transaction-not-complete'
        return result
    if environment.get('next_entry') or environment.get('prev_saved_entry'):
        result['reason'] = 'pending-boot-transition'
        return result
    current = fleet.get('last_ready', {}).get('entry')
    if (status.get('state') != 'ready' or status.get('entry') != current
            or environment.get('saved_entry') != current or not running_matches(worker, status)):
        result['reason'] = 'awaiting-matching-running-ready'
        return result
    if current not in records or records[current]['state'] == 'removed':
        result['reason'] = 'current-ready-generation-not-owned'
        return result
    protected = {current, fleet.get('normal_fallback', {}).get('entry')}
    protected.update(environment.get(key) for key in ('saved_entry', 'next_entry', 'prev_saved_entry'))
    pending = fleet.get('retention_pending')
    if pending and pending.get('entry') in protected:
        result['reason'] = 'selected-retirement-protected'
        return result
    active = sorted((entry for entry, record in records.items() if record['state'] != 'removed'),
                    key=lambda entry: (records[entry]['created_ns'], entry), reverse=True)
    retained = protected.intersection(active)
    for entry in active:
        if len(retained) >= keep:
            break
        if records[entry]['state'] != 'retiring':
            retained.add(entry)
    candidates = [entry for entry in reversed(active) if entry not in retained or records[entry]['state'] == 'retiring']
    if pending:
        entry = pending.get('entry')
        if entry not in candidates:
            result['warnings'].append('interrupted retirement is not an eligible generation')
            return result
        candidates.remove(entry)
        candidates.insert(0, entry)
    for entry in candidates:
        if entry in protected:
            continue
        record = records[entry]
        try:
            _check_owned(worker, record)
            _references(worker, record)
            if worker.ops.grub_environment() != environment:
                raise LifecycleError('boot selection changed during retention')
            if fleet.get('retention_pending'):
                if fleet['retention_pending']['entry'] != entry:
                    raise LifecycleError('another GRUB retirement is incomplete')
                _finish_visibility(worker, fleet, records, environment)
            elif worker.boot.backend == 'grub':
                ids = sorted(value['managed_id'] for identity, value in records.items()
                             if identity != entry and value['state'] == 'active')
                after = worker.boot.visibility_files(ids)
                before = _shared_before(worker, fleet, after)
                record['state'] = 'retiring'
                fleet['retention_pending'] = {'entry': entry, 'remaining_ids': ids,
                    'shared': {name: {'before': before[name], 'after': digest(data),
                                      'data': base64.b64encode(data).decode()} for name, data in after.items()}}
                _save(worker, fleet)
                _finish_visibility(worker, fleet, records, environment)
            else:
                record['state'] = 'retiring'
                _save(worker, fleet)
            # Remove the descriptor before its dependency files. A restarted
            # cleanup can accept missing bytes only after committed retirement.
            names = [record['_validated']['descriptor'], *sorted(name for name in record['_validated']['owned']
                                                                  if name != record['_validated']['descriptor'])]
            for name in names:
                if worker.ops.grub_environment() != environment:
                    raise LifecycleError('boot selection changed during retention')
                path = worker.path(name)
                worker.trusted(path, missing=True)
                if path.exists() and hash_file(path) != record['_validated']['owned'][name]:
                    raise LifecycleError('managed portable boot bytes changed before unlink')
                path.unlink(missing_ok=True)
                if path.parent.exists():
                    _sync_parent(path)
            record['state'] = 'removed'
            _save(worker, fleet)
            result['removed'].append(entry)
        except (LifecycleError, OSError) as exc:
            result['warnings'].append(f'{entry}: {exc}')
            # Preserve a single durable shared-file transaction; do not replace
            # its recovery evidence with an unrelated candidate's intent.
            if fleet.get('retention_pending'):
                break
    result['retained'] = sum(record['state'] != 'removed' for record in records.values())
    result['state'] = 'complete' if not result['warnings'] else 'deferred'
    return result
