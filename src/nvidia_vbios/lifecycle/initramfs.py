"""Private portable initramfs/UKI builds and exact embedded-byte evidence.

Command contracts: Debian mkinitramfs(8)/initramfs-tools(7), Arch
mkinitcpio(8)/mkinitcpio.conf(5)/lsinitcpio(1), and systemd ukify(1).
No host boot configuration is written, no presets/post hooks are invoked,
and signed raw modules are copied without a strip/re-sign operation.
"""
from __future__ import annotations

import base64
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import struct
import tempfile
import uuid

from .security import LifecycleError, atomic_write, checked_path, digest, resolve_trusted_file, token

ACTIVATION_PATH = "etc/modprobe.d/zz-vbios-override-test.conf"
FORCE_PATH = "etc/cmdline.d/20-force_drivers.conf"
LOAD_PATH = "etc/modules-load.d/vbios-override.conf"
DEBIAN_LOAD_PATH = "scripts/init-top/vbios_override"
ARCH_LOAD_PATH = "hooks/vbios_override"
LOAD_BYTES = b"nvidia\n"
INIT_PATH = "init"
SYSTEMD_INIT_PATH = "usr/lib/systemd/systemd"
SYSTEMD_UNIT_PATH = "usr/lib/systemd/system/systemd-modules-load.service"
SYSTEMD_WANT_PATH = "usr/lib/systemd/system/sysinit.target.wants/systemd-modules-load.service"
SYSTEMD_LOAD_BINARY = "usr/lib/systemd/systemd-modules-load"
_FILE_PROOF = b"@regular-file\0"
_LINK_PROOF = b"@symlink\0"
DEBIAN_LOAD_BYTES = (b'#!/bin/sh\nPREREQ=""\n'
                     b'case "$1" in prereqs) echo "$PREREQ"; exit 0;; esac\n'
                     b'modprobe nvidia\n')
ARCH_LOAD_BYTES = b"run_earlyhook() {\n    modprobe nvidia\n}\n"


def _root(ops):
    return Path(getattr(ops, "filesystem_root", "/"))


def _physical(root, name):
    path = Path(name)
    if not path.is_absolute() or ".." in path.parts:
        raise LifecycleError("portable builder input requires an absolute trusted path")
    return root / str(path).lstrip("/")


def backend(config):
    name = config.get("boot", {}).get("initramfs")
    if name not in ("initramfs-tools", "mkinitcpio", "dracut"):
        raise LifecycleError("portable initramfs backend must be explicitly configured")
    return name


def _command(ops, name):
    # Resolve only the approved command names; SystemOperations also checks the
    # final executable and its ancestors before running it.
    candidates = {
        "dracut": ("/usr/bin/dracut",),
        "lsinitrd": ("/usr/bin/lsinitrd",),
        "mkinitramfs": ("/usr/sbin/mkinitramfs", "/usr/bin/mkinitramfs"),
        "unmkinitramfs": ("/usr/bin/unmkinitramfs", "/usr/sbin/unmkinitramfs"),
        "lsinitramfs": ("/usr/bin/lsinitramfs", "/usr/sbin/lsinitramfs"),
        "mkinitcpio": ("/usr/bin/mkinitcpio",),
        "lsinitcpio": ("/usr/bin/lsinitcpio",),
        "ukify": ("/usr/lib/systemd/ukify", "/usr/bin/ukify"),
        "openssl": ("/usr/bin/openssl",),
        "mokutil": ("/usr/bin/mokutil",),
        "efi-readvar": ("/usr/bin/efi-readvar", "/usr/sbin/efi-readvar"),
        "sbverify": ("/usr/bin/sbverify",),
    }[name]
    for candidate in candidates:
        if _physical(_root(ops), candidate).exists():
            return candidate
    return candidates[0]


def _trusted_file(path, root):
    checked_path(Path(path), root)
    if not Path(path).is_file():
        raise LifecycleError("portable builder expected a trusted regular file")
    return Path(path)


def _copy_tree(source, destination, root):
    """Copy trusted configuration, retaining valid distribution hook aliases."""
    checked_path(source, root)
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for child in sorted(source.iterdir()):
        target = destination / child.name
        if child.is_symlink():
            source_file = resolve_trusted_file(child, root)
            shutil.copy2(source_file, target)
        elif child.is_dir():
            _copy_tree(child, target, root)
        else:
            shutil.copy2(_trusted_file(child, root), target)


def _member(name):
    if (not isinstance(name, str) or not name or "\0" in name or "\n" in name
            or name.startswith("/") or "\\" in name or "//" in name):
        raise LifecycleError("invalid initramfs member path")
    path = PurePosixPath(name)
    if any(part in (".", "..") for part in name.split("/")) or str(path) != name:
        raise LifecycleError("invalid initramfs member path")
    return name


def _targets(targets, root, kernel):
    result = []
    for value in targets:
        path = _trusted_file(value, root)
        relative = str(path.relative_to(root))
        _member(relative)
        if not (relative.startswith(f"usr/lib/modules/{kernel}/updates/vbios-override/")
                and path.suffix == ".ko" or relative.startswith("usr/lib/firmware/nvidia/")):
            raise LifecycleError("portable build target is outside managed modules/firmware")
        if any(character in str(path) for character in ("\n", "\r")):
            raise LifecycleError("portable target contains unsupported control characters")
        result.append((path, relative))
    if not result or not any(path.name == "nvidia.ko" for path, _ in result):
        raise LifecycleError("portable build requires the managed raw NVIDIA module")
    return result


def build(ops, kernel, destination, targets, *, activation_config, force_config, config):
    """Build a separate image and return members requiring exact verification.

    The caller must extract/compare every returned member and every target
    before publication. Return evidence identifies real boot-time force loading;
    the legacy dracut command-line marker is retained only for compatibility.
    """
    kernel = token(kernel)
    root = _root(ops)
    destination = checked_path(Path(destination), root, missing=True)
    activation = _trusted_file(activation_config, root)
    force = _trusted_file(force_config, root)
    selected = _targets(targets, root, kernel)
    if destination in {activation, force, *(path for path, _ in selected)}:
        raise LifecycleError("initramfs output aliases a build input")
    evidence = {ACTIVATION_PATH: activation.read_bytes(), FORCE_PATH: force.read_bytes(), LOAD_PATH: LOAD_BYTES}
    name = backend(config)
    with tempfile.TemporaryDirectory(prefix=".vbios-build-", dir=destination.parent) as temporary:
        work = Path(temporary)
        includes = [(activation, ACTIVATION_PATH, 0o644), (force, FORCE_PATH, 0o644)]
        load = work / "load.conf"
        atomic_write(load, LOAD_BYTES)
        includes.append((load, LOAD_PATH, 0o644))
        if name == "dracut":
            command = [_command(ops, "dracut"), "--force", "--no-uefi", "--nostrip", "--kver", kernel,
                       "--force-drivers", "nvidia", "--add-drivers", "nvidia-modeset nvidia-drm nvidia-uvm"]
            # Separate include arguments preserve BDF colons and whitespace;
            # never flatten source paths into dracut's --install word list.
            for path, relative, mode in [*((p, r, 0o644) for p, r in selected), *includes]:
                command += ["--include", path, "/" + relative]
            ops._run([*command, destination], timeout=1200)
        elif name == "initramfs-tools":
            private = work / "initramfs-tools"
            _copy_tree(_physical(root, "/etc/initramfs-tools"), private, root)
            early = private / DEBIAN_LOAD_PATH
            # A copied configuration must not overwrite our managed hook later.
            atomic_write(early, DEBIAN_LOAD_BYTES, 0o755)
            evidence[DEBIAN_LOAD_PATH] = DEBIAN_LOAD_BYTES
            lines = ['#!/bin/sh', 'set -e', 'PREREQ=""',
                     'case "$1" in prereqs) echo "$PREREQ"; exit 0;; esac',
                     '. /usr/share/initramfs-tools/hook-functions',
                     'force_load nvidia', 'manual_add_modules nvidia_modeset nvidia_drm nvidia_uvm']
            # Copy raw bytes after dependency inclusion. These commands do not
            # pass module files through copy_exec/strip or alter signatures.
            for source, member, mode in [*( (p, r, 0o644) for p, r in selected), *includes]:
                parent = str(PurePosixPath(member).parent)
                lines += [f'mkdir -p -- "${{DESTDIR}}"/{shlex.quote(parent)}',
                          f'cp -- {shlex.quote(str(source))} "${{DESTDIR}}"/{shlex.quote(member)}',
                          f'chmod {mode:o} "${{DESTDIR}}"/{shlex.quote(member)}']
            atomic_write(private / "hooks/zzzz_vbios_override", ("\n".join(lines) + "\n").encode(), 0o755)
            ops._run([_command(ops, "mkinitramfs"), "-d", private, "-o", destination, kernel], timeout=1200)
        else:
            source = _physical(root, "/etc/mkinitcpio.conf")
            texts = [_trusted_file(source, root).read_bytes()]
            dropins = _physical(root, "/etc/mkinitcpio.conf.d")
            if dropins.exists():
                checked_path(dropins, root)
                texts.extend(_trusted_file(path, root).read_bytes() for path in sorted(dropins.glob("*.conf")))
            private = work / "mkinitcpio.conf"
            additions = ("\nMODULES+=(nvidia nvidia_modeset nvidia_drm nvidia_uvm)\n"
                         "MODULES_DECOMPRESS=no\nFILES+=(" +
                         " ".join(shlex.quote(str(path)) for path, _ in selected) + ")\n")
            atomic_write(private, b"\n".join(texts) + additions.encode())
            hooks = work / "initcpio"
            hooks.mkdir(mode=0o700)
            # -D replaces hook search directories. Copy standard and local
            # hooks, with local precedence, instead of dropping root/crypt hooks.
            for prefix in ("/usr/lib/initcpio", "/etc/initcpio"):
                for kind in ("install", "hooks"):
                    source_hooks = _physical(root, prefix + "/" + kind)
                    if source_hooks.exists():
                        _copy_tree(source_hooks, hooks / kind, root)
            atomic_write(hooks / "hooks/vbios_override", ARCH_LOAD_BYTES, 0o755)
            # add_file takes distinct quoted source/destination arguments. In
            # contrast, -I uses colon/comma delimiters and cannot represent our
            # real PCI-BDF firmware filenames (0000:03:00.0-<hash>.bin).
            install = ["build() {", "    add_runscript"]
            for path, relative, mode in [*((p, r, 0o644) for p, r in selected), *includes]:
                install.append(f"    add_file {shlex.quote(str(path))} {shlex.quote('/' + relative)} {mode:o}")
            install += ["}", "help() {", "    echo 'Force early NVIDIA loading for the separate override image.'", "}"]
            atomic_write(hooks / "install/vbios_override", ("\n".join(install) + "\n").encode(), 0o755)
            evidence[ARCH_LOAD_PATH] = ARCH_LOAD_BYTES
            command = [_command(ops, "mkinitcpio"), "-c", private, "-k", kernel,
                       "-g", destination, "-D", hooks, "-A", "vbios_override", "--nopost"]
            ops._run(command, timeout=1200)
    _trusted_file(destination, root)
    if not destination.stat().st_size:
        raise LifecycleError("portable initramfs build produced an empty image")
    if name == "mkinitcpio":
        # Detect the actual /init rather than infer its implementation from a
        # shell config. systemd ignores mkinitcpio's busybox runtime hooks.
        init = extract(ops, destination, [INIT_PATH], config=config)[INIT_PATH]
        evidence[INIT_PATH] = init
        if init is not None and init.startswith(_LINK_PROOF):
            if init[len(_LINK_PROOF):] not in (b"usr/lib/systemd/systemd", b"/usr/lib/systemd/systemd"):
                raise LifecycleError("mkinitcpio image has an unsupported init symlink")
            evidence.pop(ARCH_LOAD_PATH)
            members = [SYSTEMD_INIT_PATH, SYSTEMD_UNIT_PATH, SYSTEMD_WANT_PATH, SYSTEMD_LOAD_BINARY, LOAD_PATH]
            generated = extract(ops, destination, members, config=config)
            _verify_systemd_registration(generated)
            # Native binaries/unit bytes remain unchanged; the enabled link and
            # exact modules-load.d request prove this service can actually run.
            for member in (SYSTEMD_INIT_PATH, SYSTEMD_UNIT_PATH, SYSTEMD_LOAD_BINARY):
                source = _trusted_file(_physical(root, "/" + member), root)
                if generated[member] != source.read_bytes():
                    raise LifecycleError("mkinitcpio systemd loader differs from trusted native bytes")
            evidence.update(generated)
        else:
            native_init = _trusted_file(_physical(root, "/usr/lib/initcpio/init"), root).read_bytes()
            if init != _FILE_PROOF + native_init:
                raise LifecycleError("mkinitcpio image does not use the trusted busybox init")
            generated = extract(ops, destination, ["config"], config=config)["config"]
            _verify_arch_registration(generated)
            evidence["config"] = generated
    return evidence


def _verify_arch_registration(data):
    if data is None:
        raise LifecycleError("mkinitcpio image lacks runtime module/hook registration")
    values = {}
    try:
        for line in data.decode("ascii").splitlines():
            match = re.fullmatch(r'([A-Z][A-Z_]*)="([A-Za-z0-9_.+ -]*)"', line)
            if not match or match[1] in values or match[1] not in {
                    "MODULES", "EARLYHOOKS", "HOOKS", "LATEHOOKS", "CLEANUPHOOKS", "EMERGENCYHOOKS"}:
                raise LifecycleError("mkinitcpio runtime registration has unsupported shell text")
            values[match[1]] = match[2].split()
    except UnicodeError as exc:
        raise LifecycleError("mkinitcpio runtime registration is not ASCII") from exc
    if "nvidia" not in values.get("MODULES", ()) or "vbios_override" not in values.get("EARLYHOOKS", ()):
        raise LifecycleError("mkinitcpio image does not register early NVIDIA module loading")


def _verify_systemd_registration(members):
    if members.get(LOAD_PATH) != LOAD_BYTES:
        raise LifecycleError("systemd initrd lacks the exact NVIDIA modules-load request")
    link = members.get(SYSTEMD_WANT_PATH)
    if link not in (_LINK_PROOF + b"../systemd-modules-load.service",
                    _LINK_PROOF + b"/usr/lib/systemd/system/systemd-modules-load.service",
                    _LINK_PROOF + b"/lib/systemd/system/systemd-modules-load.service"):
        raise LifecycleError("systemd initrd modules-load service is not enabled in sysinit.target.wants")
    unit, binary = members.get(SYSTEMD_UNIT_PATH), members.get(SYSTEMD_LOAD_BINARY)
    if not isinstance(unit, bytes) or not isinstance(binary, bytes) or not binary.startswith(b"\x7fELF"):
        raise LifecycleError("systemd initrd lacks its native modules-load unit/executable")
    try:
        text = unit.decode()
    except UnicodeError as exc:
        raise LifecycleError("systemd modules-load unit is not valid text") from exc
    if (len(re.findall(r"(?m)^ExecStart=", text)) != 1
            or not re.search(r"(?m)^ExecStart=/(?:usr/)?lib/systemd/systemd-modules-load\s*$", text)
            or not re.search(r"(?m)^Before=[^\n]*\bsysinit\.target\b", text)):
        raise LifecycleError("systemd modules-load unit has unsupported execution/ordering")


def _aliases(member):
    result = [member]
    if member.startswith("usr/lib/"):
        result.append(member.removeprefix("usr/"))
    elif member.startswith("lib/"):
        result.append("usr/" + member)
    return result


def _read_extracted(tree, member):
    """Accept only internal usrmerge aliases, never archive-defined escapes."""
    path = tree
    parts = PurePosixPath(member).parts
    for index, part in enumerate(parts):
        path /= part
        if path.is_symlink():
            relative = str(path.relative_to(tree))
            target = os.readlink(path)
            if index == len(parts) - 1 and member in (INIT_PATH, SYSTEMD_WANT_PATH,
                    SYSTEMD_WANT_PATH.removeprefix("usr/")):
                # These fixed proof members expose link metadata as typed bytes,
                # never follow it. Every other requested leaf remains regular.
                return _LINK_PROOF + target.encode()
            aliases = {"lib": {"usr/lib", "/usr/lib"}, "lib64": {"usr/lib64", "/usr/lib64"},
                       "bin": {"usr/bin", "/usr/bin"}, "sbin": {"usr/sbin", "/usr/sbin"}}
            if target not in aliases.get(relative, set()):
                raise LifecycleError("unsupported or escaping initramfs member symlink")
            path = tree / target.lstrip("/")
            if path.is_symlink():
                raise LifecycleError("nested initramfs alias is unsupported")
        if not path.exists():
            return None
    if not path.is_file() or path.is_symlink():
        raise LifecycleError("initramfs member is not a regular file")
    data = path.read_bytes()
    if member == INIT_PATH:
        return _FILE_PROOF + data
    if member in (SYSTEMD_WANT_PATH, SYSTEMD_WANT_PATH.removeprefix("usr/")):
        raise LifecycleError("systemd initrd wants registration must be a symlink")
    return data


_LISTED_MODE = re.compile(r"[-dlcbps][-rwxsStT]{9}[.+@]?")


def parse_lsinitrd(text):
    """Member names of every archive in an `lsinitrd IMAGE` listing (cpio -tv lines)."""
    names = []
    for line in text.splitlines():
        fields = line.split(None, 8)
        if len(fields) == 9 and _LISTED_MODE.fullmatch(fields[0]):
            name = fields[8].split(" -> ", 1)[0].removeprefix("./")
            if name not in (".", ""):
                names.append(name)
    if not names:
        raise LifecycleError("initramfs listing has no members")
    return names


def _archive_names(ops, image, name):
    listing = ops._run([_command(ops, "lsinitramfs" if name == "initramfs-tools" else "lsinitcpio"), image], timeout=120)
    archive_names = []
    try:
        for line in listing.stdout.decode("utf-8", "strict").splitlines():
            if line in (".", "./"):
                continue
            archive_names.append(_member(line.removeprefix("./").rstrip("/")))
    except UnicodeError as exc:
        raise LifecycleError("initramfs listing is not valid UTF-8") from exc
    return archive_names


def list_members(ops, image, *, config=None):
    """Every member name of a portable initramfs, for presence checks."""
    image = _trusted_file(image, _root(ops))
    name = backend(config or getattr(ops, "lifecycle_config", {}))
    if name == "dracut":
        response = ops._run([_command(ops, "lsinitrd"), image], timeout=120)
        try:
            return parse_lsinitrd(response.stdout.decode("utf-8", "strict"))
        except UnicodeError as exc:
            raise LifecycleError("initramfs listing is not valid UTF-8") from exc
    return _archive_names(ops, image, name)


def extract(ops, image, members, destination=None, *, config=None):
    """Extract once and return exact requested members, allowing usrmerge aliases.

    Extraction destinations are private children of the caller's trusted scratch
    directory, and archive names are checked before invoking the extractor.
    """
    root = _root(ops)
    image = _trusted_file(image, root)
    names = [_member(name) for name in members]
    if len(set(names)) != len(names):
        raise LifecycleError("duplicate requested initramfs member")
    name = backend(config or getattr(ops, "lifecycle_config", {}))
    if name == "dracut":
        result = {}
        for member in names:
            observed = []
            for alias in _aliases(member):
                response = ops._run([_command(ops, "lsinitrd"), "--file", alias, image],
                                    timeout=120, allow_failure=True)
                if response.returncode == 0:
                    observed.append(response.stdout)
            if observed and any(value != observed[0] for value in observed[1:]):
                raise LifecycleError("conflicting initramfs member bytes across aliases/archives")
            result[member] = observed[0] if observed else None
        return result
    parent = checked_path(Path(destination) if destination is not None else image.parent, root)
    archive_names = _archive_names(ops, image, name)
    if SYSTEMD_WANT_PATH in names:
        # A lower-precedence native unit and its wants link do not establish
        # effective enablement when an override masks/replaces that unit or a
        # drop-in changes ExecStart/conditions. Such customizations need a
        # separate reviewed implementation; never silently accept them here.
        for member in archive_names:
            if member in ("etc/systemd/system/systemd-modules-load.service",
                          "run/systemd/system/systemd-modules-load.service") or any(
                    member.startswith(prefix + "/systemd-modules-load.service.d/")
                    for prefix in ("etc/systemd/system", "run/systemd/system", "usr/lib/systemd/system", "lib/systemd/system")):
                raise LifecycleError("systemd initrd modules-load unit override/drop-in is unsupported")
    with tempfile.TemporaryDirectory(prefix=".vbios-extract-", dir=parent) as temporary:
        work = Path(temporary)
        if name == "initramfs-tools":
            unpacked = work / "unpacked"
            ops._run([_command(ops, "unmkinitramfs"), image, unpacked], timeout=120)
            trees = [unpacked / "main", *sorted(unpacked.glob("early*"))]
            if not (unpacked / "main").is_dir():
                trees = [unpacked]
        else:
            ops._run([_command(ops, "lsinitcpio"), "--extract", image], cwd=work, timeout=120)
            trees = [work]
        result = {}
        for member in names:
            observed = [value for tree in trees for alias in _aliases(member)
                        if (value := _read_extracted(tree, alias)) is not None]
            if observed and any(value != observed[0] for value in observed[1:]):
                raise LifecycleError("conflicting initramfs member bytes across aliases/archives")
            result[member] = observed[0] if observed else None
        return result


def extract_uki_sections(image, members=(".linux", ".initrd", ".cmdline")):
    """Read EFI PE section VirtualSize bytes, excluding file-alignment padding."""
    data = Path(image).read_bytes() if not isinstance(image, bytes) else image
    try:
        if len(data) < 64 or data[:2] != b"MZ":
            raise ValueError("missing DOS header")
        offset = struct.unpack_from("<I", data, 60)[0]
        if data[offset:offset + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        count, optional_size = struct.unpack_from("<H12xH", data, offset + 6)
        optional = offset + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        if magic not in (0x10b, 0x20b) or optional_size < 70 or struct.unpack_from("<H", data, optional + 68)[0] != 10:
            raise ValueError("not an EFI application")
        table = optional + optional_size
        if not 1 <= count <= 96 or table + count * 40 > len(data):
            raise ValueError("invalid section table")
        sections, ranges = {}, []
        for number in range(count):
            entry = table + number * 40
            name = data[entry:entry + 8].rstrip(b"\0").decode("ascii")
            size, address, raw_size, raw_offset = struct.unpack_from("<IIII", data, entry + 8)
            if name in sections or (size > raw_size and raw_size) or raw_offset + raw_size > len(data):
                raise ValueError("duplicate, truncated, or unsupported PE section")
            if raw_size:
                if raw_offset < table + count * 40 or any(raw_offset < end and raw_offset + raw_size > start for start, end in ranges):
                    raise ValueError("overlapping PE sections")
                ranges.append((raw_offset, raw_offset + raw_size))
            if name in members and size > raw_size:
                raise ValueError("required UKI section has no complete file data")
            sections[name] = data[raw_offset:raw_offset + min(size, raw_size)]
        if any(name not in sections for name in members):
            raise ValueError("missing required UKI section")
        return {name: sections[name] for name in members}
    except (ValueError, struct.error, UnicodeError) as exc:
        raise LifecycleError(f"invalid UKI PE image: {exc}") from exc


def _certificate_der(data):
    if data.startswith(b"-----BEGIN CERTIFICATE-----"):
        match = re.fullmatch(rb"-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*", data)
        if not match:
            raise LifecycleError("UKI signing requires one PEM/DER certificate")
        try:
            data = base64.b64decode(re.sub(rb"\s", b"", match[1]), validate=True)
        except ValueError as exc:
            raise LifecycleError("invalid UKI certificate PEM") from exc
    if len(data) < 4 or data[0] != 0x30:
        raise LifecycleError("invalid UKI certificate DER")
    return data


def _db_has_certificate(data, certificate):
    # EFI_SIGNATURE_LIST header followed by EFI_SIGNATURE_DATA owner GUID + DER.
    x509_guid = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072").bytes_le
    offset, found = 0, False
    while offset < len(data):
        if len(data) - offset < 28:
            raise LifecycleError("malformed firmware Secure Boot certificate database")
        kind = data[offset:offset + 16]
        length, header, entry = struct.unpack_from("<III", data, offset + 16)
        start = offset + 28 + header
        end = offset + length
        if length < 28 + header or end > len(data) or entry < 16 or (end - start) % entry:
            raise LifecycleError("malformed firmware Secure Boot signature list")
        for position in range(start, end, entry):
            if kind == x509_guid and data[position + 16:position + entry] == certificate:
                found = True
        offset = end
    return found


def build_uki(ops, kernel_image, initrd, destination, *, cmdline, config):
    """Build and verify a UKI around immutable kernel/concatenated initrd inputs.

    A firmware-db signing certificate is required when Secure Boot is enabled.
    Module signing configuration is intentionally independent. A MOK-only key
    cannot prove direct firmware or systemd-boot acceptance and is rejected.
    """
    root = _root(ops)
    kernel = _trusted_file(kernel_image, root)
    initrd = _trusted_file(initrd, root)
    destination = checked_path(Path(destination), root, missing=True)
    if destination in (kernel, initrd):
        raise LifecycleError("UKI output aliases an immutable input")
    if isinstance(cmdline, Path):
        text = _trusted_file(cmdline, root).read_text().strip()
    elif isinstance(cmdline, str):
        text = cmdline.strip()
    else:
        raise LifecycleError("UKI cmdline must be explicit text or a trusted file")
    if not text or any(character in text for character in ("\0", "\n", "\r")):
        raise LifecycleError("UKI requires one explicit kernel command line")
    state = ops._run([_command(ops, "mokutil"), "--sb-state"]).stdout.decode().strip().lower()
    if state in ("secureboot enabled", "secure boot enabled"):
        secure = True
    elif state in ("secureboot disabled", "secure boot disabled"):
        secure = False
    else:
        raise LifecycleError("cannot determine Secure Boot state for UKI build")
    expected = {".linux": kernel.read_bytes(), ".initrd": initrd.read_bytes(), ".cmdline": text.encode()}
    signing = config.get("boot", {}).get("uki", {}).get("signing")
    if secure and not signing:
        raise LifecycleError("Secure Boot UKI requires explicit PE signing key/certificate")
    with tempfile.TemporaryDirectory(prefix=".vbios-uki-", dir=destination.parent) as temporary:
        work = Path(temporary)
        private = work / "ukify.conf"
        atomic_write(private, b"[UKI]\n")
        cmdline_file = work / "cmdline"
        atomic_write(cmdline_file, expected[".cmdline"])
        command = [_command(ops, "ukify"), "build", "--config", private,
                   "--linux", kernel, "--initrd", initrd, "--cmdline", "@" + str(cmdline_file),
                   "--no-sign-kernel", "--output", destination]
        certificate_der, pem = None, None
        if signing:
            if signing.get("trust", "firmware-db") != "firmware-db":
                raise LifecycleError("UKI signing requires proven firmware-db trust; MOK alone is insufficient")
            key = _trusted_file(_physical(root, signing["key"]), root)
            certificate = _trusted_file(_physical(root, signing["certificate"]), root)
            if key.stat().st_mode & 0o077:
                raise LifecycleError("UKI private key must have root-only permissions")
            certificate_der = _certificate_der(certificate.read_bytes())
            der, pem = work / "certificate.der", work / "certificate.pem"
            atomic_write(der, certificate_der)
            ops._run([_command(ops, "openssl"), "x509", "-inform", "DER", "-in", der, "-out", pem])
            _trusted_file(pem, root)
            if secure:
                database = work / "db.esl"
                ops._run([_command(ops, "efi-readvar"), "-v", "db", "-o", database])
                if not _db_has_certificate(_trusted_file(database, root).read_bytes(), certificate_der):
                    raise LifecycleError("UKI PE signing certificate is not enrolled in firmware db")
            command += ["--secureboot-private-key", key, "--secureboot-certificate", pem]
        ops._run(command, timeout=1200)
        _trusted_file(destination, root)
        sections = extract_uki_sections(destination)
        if sections != expected:
            raise LifecycleError("UKI embedded kernel/initrd/cmdline bytes differ from immutable inputs")
        if signing:
            ops._run([_command(ops, "sbverify"), "--cert", pem, destination])
        # A concurrent mutation of an input must not produce valid stale evidence.
        if kernel.read_bytes() != expected[".linux"] or initrd.read_bytes() != expected[".initrd"]:
            raise LifecycleError("UKI immutable build inputs changed during construction")
    return {"sha256": digest(destination.read_bytes()), "sections": {name: digest(data) for name, data in expected.items()},
            "secure_boot": secure, "signed": bool(signing),
            "signing_certificate_sha256": digest(certificate_der) if certificate_der else None,
            "signing_trust": "firmware-db" if secure else None}
