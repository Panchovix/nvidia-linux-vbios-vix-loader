"""Runtime VFE layout store: /var/lib/nvidia-vbios/vfe-layouts/<payload SHA-256>.json.

Runtime voltage-offset tools trust the hook slots of a GB20x override only through the layout document the VBIOS
editor builds from the exact payload (`nvbios vfe-layout`). The store mirrors /var/lib/nvidia-vbios/roms: one
document per stored payload that has runtime voltage-offset hooks, named by the payload's SHA-256. Between a setup
and the reboot the configured payload is not the loaded one, so every stored payload keeps its document, and a tool
picks the one whose slots match the live GPU. The directory is 0755 and the files regular, 0644 and owned by the
caller (root); at most MAX_FILES files of at most MAX_BYTES each.

sync() never raises: a problem is a warning in its report, named by the logical path it is about, and enrollment and
reconcile go on; one entry that fails does not stop the others. Without the editor extension (the open loader) it
does nothing. Links are never followed, and only file names of the store's own form are written or removed. A
document is removed only when its payload is gone or has no hooks: a payload stored after this sync listed the
payloads (an enrollment running alongside) keeps its document until the next sync.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import stat
from .security import LifecycleError, atomic_write, checked_path, digest

ROMS = '/var/lib/nvidia-vbios/roms'
STORE = '/var/lib/nvidia-vbios/vfe-layouts'
NAME = re.compile(r'[0-9a-f]{64}\.json')
MAX_FILES = 256
MAX_BYTES = 64 * 1024


def _read(path):
    """Bytes of a regular file, never through a link."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', 0))
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise LifecycleError('not a regular file')
        return stream.read()


def _current(target, data):
    """True when target already is the document: a regular 0644 file of ours with these bytes."""
    try:
        info = target.lstat()
    except FileNotFoundError:
        return False
    return (stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o644 and info.st_uid == os.geteuid()
            and _read(target) == data)


def _documents(payloads, layout, warnings):
    """{store file name: document bytes} of the listed payloads [(path, lstat)] with hooks, newest first, at most
    MAX_FILES. The file name and the document's image_sha256 are both the SHA-256 of the payload bytes."""
    found = {}
    for path, info in sorted(payloads, key=lambda item: item[1].st_mtime_ns, reverse=True):
        try:
            if not stat.S_ISREG(info.st_mode):
                raise LifecycleError('not a regular file')
            data = _read(path)
            document = layout(data)
            if document is None:
                continue
            sha = digest(data)
            if json.loads(document)['image_sha256'] != sha:
                raise LifecycleError("the layout document's image_sha256 is not the payload's SHA-256")
        except Exception as exc:
            warnings.append(f'{ROMS}/{path.name}: {exc}')
            continue
        name = sha + '.json'
        if len(document) > MAX_BYTES:
            warnings.append(f'{ROMS}/{path.name}: layout document larger than {MAX_BYTES} bytes')
        elif name not in found and len(found) == MAX_FILES:
            warnings.append(f'{ROMS}: more than {MAX_FILES} stored payloads have hooks: older ones get no layout '
                            'document')
            break
        else:
            found[name] = document
    return found


def sync(root=Path('/')):
    """Make the store mirror the stored payloads; returns {written, removed, warnings} (logical paths)."""
    report = {'written': [], 'removed': [], 'warnings': []}
    warn = report['warnings'].append
    where = STORE
    try:
        from ..payload import optional_editor
        layout = getattr(optional_editor(), 'vfe_layout', None)
        if layout is None:
            return report
        root = Path(os.path.abspath(root))
        roms, store = root / ROMS.lstrip('/'), root / STORE.lstrip('/')
        wanted, listed = {}, set()
        if roms.is_symlink() or roms.exists():
            where = ROMS
            checked_path(roms, root)
            if not roms.is_dir():
                raise LifecycleError('not a directory')
            payloads = [(path, path.lstat()) for path in roms.iterdir() if path.suffix == '.bin']
            listed = {path.name for path, _ in payloads}
            wanted = _documents(payloads, layout, report['warnings'])
            where = STORE
        if store.is_symlink() or store.exists():
            # A link, a foreign owner or a group/other-writable mode is refused, never repaired.
            checked_path(store, root)
            if not store.is_dir():
                raise LifecycleError('not a directory')
        elif not wanted:
            return report
        else:
            checked_path(store, root, missing=True)
            store.mkdir(mode=0o755)
        if stat.S_IMODE(store.lstat().st_mode) != 0o755:
            store.chmod(0o755)
        for name, data in sorted(wanted.items()):
            try:
                if not _current(store / name, data):
                    atomic_write(store / name, data, 0o644)
                    report['written'].append(f'{STORE}/{name}')
            except Exception as exc:
                warn(f'{STORE}/{name}: {exc}')
        entries = sorted(store.iterdir())
    except Exception as exc:
        warn(f'{where}: {exc}')
        return report
    for entry in entries:
        payload = entry.name[:-len('.json')] + '.bin'
        if (not NAME.fullmatch(entry.name) or entry.name in wanted or
                (payload not in listed and os.path.lexists(roms / payload))):
            continue
        try:
            if stat.S_ISREG(entry.lstat().st_mode) or entry.is_symlink():
                entry.unlink()
                report['removed'].append(f'{STORE}/{entry.name}')
        except Exception as exc:
            warn(f'{STORE}/{entry.name}: {exc}')
    return report
