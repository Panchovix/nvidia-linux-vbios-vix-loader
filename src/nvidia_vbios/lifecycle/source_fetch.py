"""Download the exact NVIDIA open-gpu-kernel-modules release tag and check it.

Standard library only. The download is HTTPS with the default TLS context, no
redirects, bounded in time and size, and hashed while streaming. Extraction
accepts one top directory of plain directories and regular files with safe
names. When the distribution installed its own copy of the source, the tag
must match it file for file: the whole tree when the package carries the
whole release, else kernel-open only (the rest then rests on GitHub's TLS).
"""
from __future__ import annotations
import hashlib
import http.client
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import tarfile
import time
import urllib.error
import urllib.request
import zlib

from .security import LifecycleError

URL = "https://codeload.github.com/NVIDIA/open-gpu-kernel-modules/tar.gz/refs/tags/{version}"
READ_TIMEOUT = 30
TOTAL_TIMEOUT = 300
MAX_ARCHIVE = 64 << 20
MAX_ENTRIES = 20000
MAX_FILE = 32 << 20
MAX_TOTAL = 512 << 20
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_SAFE = re.compile(r"[A-Za-z0-9._+-]+")
_CHUNK = 1 << 20


class FetchFailed(LifecycleError):
    """Network or disk problem; the next timer run tries again."""


class Rejected(LifecycleError):
    """The downloaded tag failed verification; not retried for this version."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # urllib then raises HTTPError for the 3xx response


def _open_url(request, timeout):
    opener = urllib.request.build_opener(_NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    return opener.open(request, timeout=timeout)


def download(version, destination, *, open_url=None, clock=time.monotonic):
    """Stream the tag tarball into the new file `destination`; return url, sha256 and size."""
    if not VERSION.fullmatch(version):
        raise LifecycleError(f"no upstream tag download for version {version}")
    url = URL.format(version=version)
    request = urllib.request.Request(url, headers={"User-Agent": "nvidia-vbios-loader"})
    deadline = clock() + TOTAL_TIMEOUT
    digest, size = hashlib.sha256(), 0
    try:
        with (open_url or _open_url)(request, READ_TIMEOUT) as response:
            if getattr(response, "status", None) != 200 or response.geturl() != url:
                raise FetchFailed(f"unexpected response for {url}")
            fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as output:
                # read1: one socket receive per call, so a trickling peer cannot hold
                # a 1 MiB read past the deadline (READ_TIMEOUT bounds each receive).
                while chunk := response.read1(_CHUNK):
                    size += len(chunk)
                    if size > MAX_ARCHIVE:
                        raise Rejected(f"tag archive is larger than {MAX_ARCHIVE} bytes")
                    if clock() > deadline:
                        raise FetchFailed(f"download took longer than {TOTAL_TIMEOUT} s")
                    digest.update(chunk)
                    output.write(chunk)
    except (urllib.error.URLError, http.client.HTTPException, OSError, ValueError) as exc:
        # HTTPError (404, refused redirects), TLS errors and socket timeouts.
        if isinstance(exc, urllib.error.HTTPError):
            exc.close()
        raise FetchFailed(f"download of {url} failed: {exc}") from None
    return {"url": url, "archive_sha256": digest.hexdigest(), "size": size}


def extract(archive, destination, top):
    """Unpack into the empty directory `destination`; return (tree, commit or None)."""
    entries = total = 0
    seen, directories = set(), {destination}
    with tarfile.open(archive, "r|gz") as tar:
        for member in tar:
            entries += 1
            parts = PurePosixPath(member.name).parts
            if (entries > MAX_ENTRIES or not parts or member.name.startswith("/") or member.name in seen
                    or any(part in (".", "..") or not _SAFE.fullmatch(part) for part in parts)):
                raise Rejected(f"unsafe, duplicate or excess archive entry: {member.name!r}")
            if parts[0] != top:
                raise Rejected(f"archive entry outside {top}/: {member.name!r}")
            seen.add(member.name)
            target = destination.joinpath(*parts)
            if target.parent not in directories:
                raise Rejected(f"archive entry before its directory: {member.name!r}")
            if member.type == tarfile.DIRTYPE:
                os.mkdir(target, 0o700)
                os.chmod(target, 0o755)
                directories.add(target)
            elif member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
                total += member.size
                if member.size > MAX_FILE or total > MAX_TOTAL:
                    raise Rejected(f"archive exceeds the file or total size limit at {member.name!r}")
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as output:
                    os.fchmod(output.fileno(), 0o755 if member.mode & 0o111 else 0o644)
                    output.write(tar.extractfile(member).read())
            else:
                raise Rejected(f"archive entry is not a plain file or directory: {member.name!r}")
        commit = tar.pax_headers.get("comment", "")
    if top not in seen:
        raise Rejected(f"archive lacks its {top}/ directory")
    return destination / top, commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None


# Arch's nvidia-utils prepare() rewrites utils.mk's DATE line (its HOSTNAME and WHOAMI
# edits match nothing upstream). Only the exact upstream line: the build runs DATE in a shell.
_ARCH_UTILS_MK = ((rb"(?m)^DATE[ \t]+\?= date$", b"DATE = date -r version.mk"),)


def _comparable(data):
    # Fedora's packaging rewrites interpreter lines (#!/bin/sh -> #!/usr/bin/sh,
    # #!/usr/bin/env python3 -> #!/usr/bin/python3): normalize only those spellings.
    for prefix in (b"#!/bin/", b"#!/usr/bin/env "):
        if data.startswith(prefix):
            data = b"#!/usr/bin/" + data[len(prefix):]
    return data


def _sha(data):
    return hashlib.sha256(_comparable(data)).hexdigest()


def _packaged_skip(relative):
    name = PurePosixPath(relative).name
    return name in ("dkms.conf", ".gitignore") or name.endswith(".o_binary") or relative.startswith("patches/")


def _tag_skip(relative):
    """Upstream files no package ships, by exact path from the top of the tag."""
    return relative in (".gitignore", "kernel-open/.gitignore", "kernel-open/dkms.conf") or relative.startswith(".github/")


def _tree_hashes(base, skip):
    """{relative path: sha256} of a directory; links and special files never match a tag file."""
    result = {}
    for directory, directories, names in os.walk(base, followlinks=False):
        for name in [*names, *(entry for entry in directories if (Path(directory) / entry).is_symlink())]:
            path = Path(directory) / name
            relative = path.relative_to(base).as_posix()
            if not skip(relative):
                result[relative] = (_sha(path.read_bytes()) if path.is_file() and not path.is_symlink()
                                    else "not-a-regular-file")
    return result


def _archive_hashes(path):
    """Hashes of the one kernel-open tree in a packaged .tar.xz, read in a single pass."""
    result, prefix = {}, None
    try:
        with tarfile.open(path, "r|xz") as tar:
            for member in tar:
                parts = PurePosixPath(member.name).parts
                if "kernel-open" not in parts:
                    continue
                here = parts[:parts.index("kernel-open") + 1]
                if prefix not in (None, here):
                    raise Rejected(f"packaged source archive has more than one kernel-open tree: {path}")
                prefix = here
                relative = PurePosixPath(*parts[len(here):]).as_posix() if len(parts) > len(here) else ""
                if member.isdir() or not relative or _packaged_skip(relative):
                    continue
                result[relative] = _sha(tar.extractfile(member).read()) if member.isreg() else "not-a-regular-file"
    except (tarfile.TarError, lzma.LZMAError, EOFError) as exc:
        # A damaged local package, not a bad tag: retried, without a download, until it is reinstalled.
        raise LifecycleError(f"unreadable packaged source archive {path}: {exc}") from None
    if prefix is None:
        raise Rejected(f"packaged source archive has no kernel-open tree: {path}")
    return result


def packaged_source(version, root=Path("/")):
    """(scope, hashes) of the distribution's own source for `version`, or None when none is installed.

    "tree": the whole release in /usr/src/nvidia-VERSION (NVIDIA's CUDA
    repositories, Arch). "kernel-open": only that directory, from RPM Fusion's
    /usr/share/nvidia-kmod-VERSION/*.tar.xz (built with the .run's prebuilt
    objects), a /usr/src/nvidia-VERSION/kernel-open without the rest, or its
    contents at the top of /usr/src/nvidia-VERSION (Ubuntu).
    """
    root = Path(root)
    archives = sorted((root / f"usr/share/nvidia-kmod-{version}").glob("*.tar.xz"))
    if archives:
        native = [path for path in archives if path.name.endswith(f"-{os.uname().machine}.tar.xz")]
        if len(native or archives) != 1:
            raise Rejected("ambiguous packaged NVIDIA source archives")
        return "kernel-open", _archive_hashes((native or archives)[0])
    tree = root / f"usr/src/nvidia-{version}"
    if (tree / "kernel-open").is_dir():
        if (tree / "Makefile").is_file() and (tree / "version.mk").is_file() and (tree / "src").is_dir():
            return "tree", _tree_hashes(tree, _packaged_skip)
        return "kernel-open", _tree_hashes(tree / "kernel-open", _packaged_skip)
    if (tree / "Kbuild").is_file() and (tree / "nvidia").is_dir():
        return "kernel-open", _tree_hashes(tree, _packaged_skip)
    return None


def cross_check(tree, packaged):
    """The tag must equal the packaged (scope, hashes) byte for byte; return the verdict for that scope."""
    scope, hashes = packaged
    prefix = "" if scope == "tree" else "kernel-open/"
    base = tree / prefix
    expected = _tree_hashes(base, lambda relative: _tag_skip(prefix + relative))
    if scope == "tree" and "utils.mk" in expected:
        data = (base / "utils.mk").read_bytes()
        for pattern, replacement in _ARCH_UTILS_MK:
            data = re.sub(pattern, replacement, data)
        if hashes.get("utils.mk") == _sha(data):
            expected["utils.mk"] = hashes["utils.mk"]
    differing = sorted(set(expected) ^ set(hashes)) + sorted(
        name for name in set(expected) & set(hashes) if expected[name] != hashes[name])
    if differing:
        raise Rejected(f"tag differs from the packaged source ({scope}) in {len(differing)} files, "
                       f"first {differing[0]}")
    return "matched" if scope == "tree" else "kernel-open-only"


def fetch(version, work, *, open_url=None, clock=time.monotonic):
    """Download and unpack the tag inside the private directory `work`; return (tree, origin)."""
    archive = work / "tag.tar.gz"
    origin = dict(download(version, archive, open_url=open_url, clock=clock), kind="github-tag")
    unpacked = work / "tree"
    os.mkdir(unpacked, 0o700)
    try:
        tree, origin["commit"] = extract(archive, unpacked, f"open-gpu-kernel-modules-{version}")
    except (tarfile.TarError, EOFError, zlib.error) as exc:
        # Broken framing is more likely a damaged transfer than a bad tag.
        raise FetchFailed(f"unreadable tag archive: {exc}") from None
    return tree, origin


def verify(tree, packaged):
    """For packaged_source()'s result: 'matched' (whole tree), 'kernel-open-only', or
    'unavailable' without a packaged copy; Rejected on any difference."""
    return "unavailable" if packaged is None else cross_check(tree, packaged)
