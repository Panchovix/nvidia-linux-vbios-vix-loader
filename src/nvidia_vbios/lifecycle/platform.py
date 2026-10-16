"""Explicit distribution identities and native package transaction protocols.

No ID_LIKE guessing: a compatible derivative must be reviewed explicitly.
"""
from __future__ import annotations
from contextlib import contextmanager, ExitStack
from dataclasses import dataclass, replace
import os
from pathlib import Path
import shlex
import stat
from .security import LifecycleError, LockBusy, checked_path, locked


@dataclass(frozen=True)
class PlatformSpec:
    id: str
    family: str
    package_provider: str
    hook_provider: str
    library_paths: tuple[str, ...]
    module_root: str = "/usr/lib/modules"


FEDORA_PLATFORM = PlatformSpec("fedora", "fedora", "rpm", "dnf5", ("/usr/lib64", "/usr/lib"))
RHEL_PLATFORM = PlatformSpec("rhel", "rhel", "rpm", "dnf4", ("/usr/lib64", "/usr/lib"))
DEBIAN_PLATFORM = PlatformSpec("debian", "debian", "deb", "apt",
                               ("/usr/lib/x86_64-linux-gnu", "/usr/lib/aarch64-linux-gnu", "/usr/lib"))
ARCH_PLATFORM = PlatformSpec("arch", "arch", "pacman", "pacman", ("/usr/lib", "/usr/lib32"))
_SUPPORTED = {"fedora": FEDORA_PLATFORM,
              **{name: replace(RHEL_PLATFORM, id=name) for name in ("rhel", "rocky", "almalinux", "centos")},
              **{name: replace(DEBIAN_PLATFORM, id=name) for name in ("debian", "ubuntu")},
              **{name: replace(ARCH_PLATFORM, id=name) for name in ("arch", "cachyos", "endeavouros")}}


def detect_platform(root: Path = Path("/")) -> PlatformSpec:
    root = Path(root)
    if (root / "run/ostree-booted").exists():
        raise LifecycleError("rpm-ostree deployments require a different lifecycle adapter")
    release = root / "etc/os-release"
    # /etc/os-release is commonly a distribution-owned symlink to /usr/lib.
    try:
        from .security import resolve_trusted_file
        values = {}
        for line in resolve_trusted_file(release, root).read_text().splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, separator, raw = line.partition("=")
            if not separator or key in values:
                raise LifecycleError("invalid or duplicate os-release field")
            parsed = shlex.split(raw, comments=True)
            if len(parsed) != 1:
                raise LifecycleError("invalid os-release field")
            values[key] = parsed[0]
    except (OSError, ValueError) as exc:
        raise LifecycleError(f"cannot read distribution identity: {exc}") from exc
    identity = values.get("ID")
    if identity not in _SUPPORTED:
        raise LifecycleError(f"unsupported distribution ID: {identity!r}; ID_LIKE is not an adapter")
    result = _SUPPORTED[identity]
    if result.family == "fedora":
        result = replace(result, hook_provider="dnf5" if (root / "usr/bin/dnf5").exists() else "dnf4")
    return result


def rpm_lock_path(root: Path) -> Path:
    # Fedora migrated its RPM DB; RHEL 8/9 still use /var/lib/rpm.
    current = root / "usr/lib/sysimage/rpm"
    return current / ".rpm.lock" if current.is_dir() else root / "var/lib/rpm/.rpm.lock"


@contextmanager
def pacman_locked(root: Path):
    """Use libalpm's exclusive lockfile protocol; never delete an existing lock.

    See https://man.archlinux.org/man/pacman.8.en and
    https://wiki.archlinux.org/title/Pacman#Database_locking.
    """
    path = root / "var/lib/pacman/db.lck"
    checked_path(path, root, missing=True)
    checked_path(path.parent, root)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        raise LockBusy(f"update/build lock busy: {path}; timer will retry") from None
    opened = os.fstat(fd)
    try:
        os.write(fd, (str(os.getpid()) + "\n").encode())
        os.fsync(fd)
        yield
    finally:
        try:
            named = path.lstat()
            if (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino) and stat.S_ISREG(named.st_mode):
                path.unlink()
        except FileNotFoundError:
            pass
        os.close(fd)


@contextmanager
def package_transaction_lock(platform: PlatformSpec, root: Path = Path("/")):
    root = Path(root)
    if platform.package_provider == "rpm":
        with locked(rpm_lock_path(root), root, rpm=True):
            yield
    elif platform.package_provider == "deb":
        # dpkg and APT use POSIX record locks, not flock. Frontend first
        # matches apt/dpkg ordering. Do not unlink their persistent lockfiles.
        with ExitStack() as stack:
            for leaf in ("lock-frontend", "lock"):
                stack.enter_context(locked(root / "var/lib/dpkg" / leaf, root, rpm=True))
            yield
    elif platform.package_provider == "pacman":
        with pacman_locked(root):
            yield
    else:
        raise LifecycleError("unsupported package transaction protocol")
