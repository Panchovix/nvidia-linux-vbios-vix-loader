"""Bounded retention of committed boot generations, independent of RPM kernels.

Call only while holding reconcile, akmods and RPM locks. Ownership comes from
committed deployment fingerprints, never from a filename glob. Firmware, modules,
normal/rescue images and GRUB selections are outside this module's write scope.
"""
from __future__ import annotations
import os
from pathlib import Path
import re
from .security import LifecycleError, hash_file, json_write, token

HISTORY = 'boot-history.json'


def _history(worker):
    value = worker._json(worker.state / HISTORY, {'schema_version': 1, 'generations': {}})
    if not isinstance(value, dict) or value.get('schema_version') != 1 or not isinstance(value.get('generations'), dict):
        raise LifecycleError('invalid boot retention history')
    for entry, record in value['generations'].items():
        if not isinstance(record, dict):
            raise LifecycleError('invalid boot retention record')
        token(entry, 'retained entry'); kernel = token(record['kernel'])
        if not re.fullmatch(re.escape(f'vbios-{kernel}-') + r'[0-9a-f]{20}(?:-[0-9a-f]{12})?', entry):
            raise LifecycleError('boot retention entry is outside managed namespace')
        files = record['files']
        bls = f'/boot/loader/entries/{entry}.conf'
        image = f'/boot/initramfs-{kernel}-vbios-' + entry.removeprefix(f'vbios-{kernel}-') + '.img'
        if not isinstance(files, dict) or set(files) != {bls, image}:
            raise LifecycleError('boot retention must own exactly one BLS and initramfs')
        for name, digest in files.items():
            if '..' in Path(name).parts or not re.fullmatch('[0-9a-f]{64}', digest):
                raise LifecycleError('invalid boot retention path or fingerprint')
        if (type(record.get('created_ns')) is not int or record['created_ns'] < 0 or
                record.get('state') not in ('active', 'retiring', 'removed')):
            raise LifecycleError('invalid boot retention record')
    return value


def remember(worker):
    """Capture the old commit before same-kernel fleet metadata is replaced."""
    history = _history(worker)
    fleet = worker._json(worker.state / 'fleet.json')
    changed = False
    for record in history['generations'].values():
        if record['state'] != 'removed' and all(not worker.path(name).exists() and not worker.path(name).is_symlink() for name in record['files']):
            record['state'] = 'removed'
            changed = True
    for kernel, deployment in fleet.get('kernels', {}).items():
        token(kernel); entry = token(deployment['entry'], 'entry')
        files = {item['path']: item['after_sha256'] for item in deployment['deployment']
                 if item['path'] == f'/boot/loader/entries/{entry}.conf' or
                 item['path'].startswith(f'/boot/initramfs-{kernel}-vbios-')}
        if len(files) != 2:
            continue
        previous = history['generations'].get(entry)
        if previous and previous['files'] == files:
            continue
        # A manually retired or absent artifact cannot grant deletion authority.
        if not all(worker.path(name).exists() for name in files):
            continue
        for name, digest in files.items():
            worker.trusted(worker.path(name))
            if hash_file(worker.path(name)) != digest:
                raise LifecycleError('committed boot bytes changed before retention registration')
        if previous and previous['state'] != 'removed':
            raise LifecycleError('retained generation has conflicting fingerprints')
        history['generations'][entry] = {
            'kernel': kernel, 'driver': deployment['driver'], 'files': files,
            'created_ns': worker.path(f'/boot/loader/entries/{entry}.conf').stat().st_mtime_ns,
            'state': 'active'}
        changed = True
    if changed:
        json_write(worker.state / HISTORY, history)
    return history


def running_matches(worker, status):
    """Read-only loaded-module evidence; no NVML, SET, reset, or module commands."""
    expected = {'version': status.get('driver'),
                'srcversion': status.get('module_metadata', {}).get('nvidia.ko', {}).get('srcversion')}
    params = status.get('module_parameters', {})
    names = ('NVreg_RegistryDwords', 'NVreg_RegistryDwordsPerDevice', 'NVreg_RegistryBinaryFilePerDevice')
    if any(not isinstance(params.get(name), str) for name in names):
        return False
    expected.update({'parameters/' + name: params[name] for name in names})
    try:
        if worker.path('/proc/sys/kernel/osrelease').read_text().strip() != status['kernel']:
            return False
        for suffix, value in expected.items():
            if not isinstance(value, str) or not value:
                return False
            if worker.path('/sys/module/nvidia/' + suffix).read_text().strip() != value:
                return False
    except (OSError, UnicodeError):
        return False
    return True


def _sync_parent(path):
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def prune(worker, status, keep=3):
    """Persist retirement intent first; a failed/interrupted unlink is retryable.

    The maximum is a convergence target after the new loaded module and requests
    match READY. Pending boots and changed/shared/unowned files defer deletion.
    """
    if type(keep) is not int or keep not in (2, 3):
        raise LifecycleError('retain_boot_generations must be 2 or 3')
    history = remember(worker)
    result = {'keep': keep, 'removed': [], 'state': 'deferred', 'warnings': []}
    fleet = worker._json(worker.state / 'fleet.json')
    environment = worker.ops.grub_environment()
    journal = worker._json(worker.state / 'transaction.json')
    if journal.get('phase') not in (None, 'ready', 'rolled-back'):
        result['reason'] = 'transaction-not-complete'
        return result
    if environment.get('next_entry') or environment.get('prev_saved_entry'):
        result['reason'] = 'pending-grub-transition'
        return result
    current = fleet.get('last_ready', {}).get('entry')
    if (status.get('state') != 'ready' or status.get('entry') != current or
            environment.get('saved_entry') != current or not running_matches(worker, status)):
        result['reason'] = 'awaiting-matching-running-ready'
        return result
    protected = {current, fleet.get('normal_fallback', {}).get('entry')}
    protected.update(environment.get(name) for name in ('saved_entry', 'next_entry', 'prev_saved_entry'))
    records = history['generations']
    active = sorted((entry for entry, record in records.items() if record['state'] != 'removed'),
                    key=lambda entry: (records[entry]['created_ns'], entry), reverse=True)
    retained = protected.intersection(active)
    for entry in active:
        if len(retained) >= keep:
            break
        retained.add(entry)
    candidates = [entry for entry in reversed(active) if entry not in retained or records[entry]['state'] == 'retiring']
    for entry in candidates:
        record = records[entry]
        if entry in protected:
            continue
        try:
            bls = worker.path(f'/boot/loader/entries/{entry}.conf')
            image = worker.path(next(name for name in record['files'] if '/loader/entries/' not in name))
            for name, digest in record['files'].items():
                path = worker.path(name)
                worker.trusted(path, missing=True)
                if path.exists():
                    if hash_file(path) != digest:
                        raise LifecycleError('managed boot artifact changed externally')
                elif record['state'] != 'retiring':
                    raise LifecycleError('managed boot artifact missing outside retirement')
            # Includes normal/rescue/foreign BLS and supplementary initrds.
            for other in worker.path('/boot/loader/entries').glob('*.conf'):
                if other == bls:
                    continue
                worker.trusted(other)
                data = other.read_text()
                for key, value in environment.items():
                    data = data.replace('${' + key + '}', value).replace('$' + key, value)
                for line in data.splitlines():
                    fields = line.split()
                    if fields and fields[0] == 'initrd' and any(Path(name).name == image.name for name in fields[1:]):
                        raise LifecycleError('initramfs still referenced by another BLS entry')
            if worker.ops.grub_environment() != environment:
                raise LifecycleError('GRUB selection changed during retention')
            record['state'] = 'retiring'
            json_write(worker.state / HISTORY, history)
            bls.unlink(missing_ok=True); _sync_parent(bls)
            image.unlink(missing_ok=True); _sync_parent(image)
            record['state'] = 'removed'
            json_write(worker.state / HISTORY, history)
            result['removed'].append(entry)
        except (LifecycleError, OSError) as exc:
            result['warnings'].append(f'{entry}: {exc}')
    result['state'] = 'complete' if not result['warnings'] else 'deferred'
    result['retained'] = sum(record['state'] != 'removed' for record in records.values())
    return result
