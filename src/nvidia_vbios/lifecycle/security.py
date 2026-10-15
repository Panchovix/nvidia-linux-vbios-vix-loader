"""Small filesystem primitives shared by the lifecycle executor."""
from __future__ import annotations
import contextlib
import fcntl
import hashlib
import grp
import json
import os
from pathlib import Path
import re
import stat
import tempfile


class LifecycleError(RuntimeError):
    """A prerequisite or transaction failed; no ready boot was selected."""


def token(value: str, label: str = "kernel") -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.+-]+", value) or value in (".", ".."):
        raise LifecycleError(f"invalid {label}")
    return value


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_file(path: Path) -> str:
    return digest(path.read_bytes())


def checked_path(path: Path, boundary: Path = Path("/"), *, missing: bool = False) -> Path:
    """Reject links and writable/non-owned ancestors, including the leaf.

    A synthetic root is an explicit testing boundary. Production calls use /.
    """
    path = Path(os.path.abspath(path))
    boundary = Path(os.path.abspath(boundary))
    if not path.is_relative_to(boundary):
        raise LifecycleError(f"path outside root: {path}")
    for part in [boundary, *list(reversed(path.parents))[len(boundary.parts)-1:], path]:
        if not part.is_relative_to(boundary):
            continue
        try:
            info = part.lstat()
        except FileNotFoundError:
            if missing:
                continue
            raise LifecycleError(f"missing trusted path: {part}") from None
        if stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise LifecycleError(f"untrusted ownership, permissions or symlink: {part}")
        if part == path and not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
            raise LifecycleError(f"unsupported file type: {part}")
    return path


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".vbios-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def json_write(path: Path, value: dict) -> None:
    atomic_write(path, (json.dumps(value, indent=2, sort_keys=True) + "\n").encode())


def _akmods_lock_path(path: Path, boundary: Path) -> Path:
    """Narrow exception for Fedora's root:akmods 0770 coordination directory.

    This never grants an exception to executable source, runtime, boot files or
    any other path. The dedicated daemon group is a trusted coordination peer;
    it must have no unrelated supplementary members. The lock leaf stays strict.
    """
    path, boundary = Path(os.path.abspath(path)), Path(os.path.abspath(boundary))
    if path != boundary / "run/akmods/akmods.lock":
        raise LifecycleError("akmods permission exception is limited to its fixed lock path")
    checked_path(path.parent.parent, boundary, missing=True)
    if not path.parent.exists():
        checked_path(path, boundary, missing=True)
        return path
    info = path.parent.lstat()
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o002:
        raise LifecycleError("untrusted akmods coordination directory")
    if info.st_mode & 0o020:
        try:
            group = grp.getgrnam("akmods")
        except KeyError:
            raise LifecycleError("dedicated akmods coordination group is missing") from None
        if info.st_gid != group.gr_gid or any(member != "akmods" for member in group.gr_mem):
            raise LifecycleError("akmods coordination directory has an untrusted shared group")
    if path.exists() or path.is_symlink():
        leaf = path.lstat()
        if not stat.S_ISREG(leaf.st_mode) or leaf.st_uid != os.geteuid() or leaf.st_mode & 0o022 or leaf.st_nlink != 1:
            raise LifecycleError("untrusted akmods lock leaf")
    return path


@contextlib.contextmanager
def locked(path: Path, boundary: Path, *, rpm: bool = False, akmods: bool = False):
    if akmods:
        path = _akmods_lock_path(path, boundary)
    else:
        checked_path(path, boundary, missing=True)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        opened = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid() or opened.st_mode & 0o022
                or opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)):
            raise LifecycleError("opened coordination lock is untrusted or its inode was replaced")
        function = fcntl.lockf if rpm else fcntl.flock
        try:
            function(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise LifecycleError(f"update/build lock busy: {path}; timer will retry") from None
        named = os.stat(path, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            raise LifecycleError("coordination lock inode changed before acquisition")
        yield
    finally:
        os.close(fd)


def source_tree_hash(path: Path, boundary: Path = Path("/")) -> str:
    """Pin every source/build-script input, not only the adapter's patch anchors."""
    checked_path(path, boundary)
    result = hashlib.sha256()
    for directory, directories, names in os.walk(path, followlinks=False):
        directories[:] = sorted(name for name in directories if name != ".git")
        for name in directories:
            checked_path(Path(directory) / name, boundary)
        for name in sorted(names):
            file = Path(directory) / name
            checked_path(file, boundary)
            if not file.is_file():
                raise LifecycleError(f"source tree contains non-file: {file}")
            result.update(str(file.relative_to(path)).encode() + b"\0")
            info = file.stat()
            result.update(str(info.st_mode & 0o777).encode() + b"\0")
            result.update(str(info.st_size).encode() + b"\0")
            with file.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    result.update(chunk)
            result.update(b"\0")
    return result.hexdigest()


def exchange_directory(stage: Path, destination: Path) -> None:
    """Publish a complete module set with one Linux rename operation.

    Existing directory replacement uses renameat2(RENAME_EXCHANGE). Unsupported
    filesystems/platforms fail before replacing the old set; no rename-away gap.
    After an exchange, stage contains the old directory for validated cleanup.
    """
    if destination.exists():
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise LifecycleError("atomic directory exchange unavailable on this platform")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 2):
            error = ctypes.get_errno()
            raise LifecycleError(f"atomic module directory exchange failed: {os.strerror(error)}")
    else:
        os.replace(stage, destination)
    fd = os.open(destination.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def resolve_trusted_file(path: Path, boundary: Path = Path("/")) -> Path:
    """Resolve a reviewed library alias without trusting writable symlink owners.

    Only the leaf may be a link. Every parent and final regular file must be
    root-owned in production, and the entire chain remains inside the boundary.
    """
    path = Path(os.path.abspath(path))
    boundary = Path(os.path.abspath(boundary))
    visited = set()
    for _ in range(16):
        if not path.is_relative_to(boundary):
            raise LifecycleError("userspace library alias escapes the trusted root")
        checked_path(path.parent, boundary)
        info = path.lstat()
        if not stat.S_ISLNK(info.st_mode):
            checked_path(path, boundary)
            if not path.is_file():
                raise LifecycleError("userspace provider requires regular files")
            return path
        if info.st_uid != os.geteuid() or path in visited:
            raise LifecycleError("untrusted or cyclic userspace library alias")
        visited.add(path)
        target = Path(os.readlink(path))
        if target.is_absolute():
            path = boundary / str(target).lstrip("/")
        else:
            path = path.parent / target
        path = Path(os.path.abspath(path))
    raise LifecycleError("userspace library alias chain is too deep")
