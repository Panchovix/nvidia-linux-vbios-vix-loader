"""Read-only portable boot discovery and generation publication plans.

No GRUB text is evaluated. Only conservative, single-line generated Linux
commands are recognized; the trusted setup body is copied verbatim. All paths
are logical absolute paths beneath ``root``. Callers journal and publish plans.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
from pathlib import Path, PurePosixPath
import re
import shlex
import struct

from .security import LifecycleError, checked_path, token

_BACKENDS = {"grub", "systemd-boot", "uki"}
_BUILDERS = {"dracut", "initramfs-tools", "mkinitcpio"}
_COMPONENT = re.compile(r"[A-Za-z0-9_.+-]{1,240}")
_PATH = re.compile(r"/[A-Za-z0-9_./+-]+")


def entry_identity(value: str, backend: str = "grub") -> str:
    """Validate menu selectors separately from filesystem/artifact tokens."""
    if not isinstance(value, str) or backend not in _BACKENDS:
        raise LifecycleError("invalid boot entry identity")
    parts = value.split(">") if backend == "grub" else [value]
    if not parts or any(not _COMPONENT.fullmatch(part) or part in (".", "..") for part in parts):
        raise LifecycleError("unsafe boot entry identity")
    if backend != "grub" and ">" in value:
        raise LifecycleError("submenu selector requires GRUB")
    return value


def _absolute(value: str, label: str = "boot path") -> str:
    if not isinstance(value, str) or not _PATH.fullmatch(value) or ".." in PurePosixPath(value).parts or "//" in value:
        raise LifecycleError(f"unsafe {label}")
    return str(PurePosixPath(value))


def validate_config(config: dict) -> dict:
    raw = getattr(config, "raw", config)
    boot = raw.get("boot", {})
    if not isinstance(boot, dict) or boot.get("backend") not in _BACKENDS:
        raise LifecycleError("portable boot requires an explicit supported backend")
    if boot.get("initramfs") not in _BUILDERS:
        raise LifecycleError("portable boot requires an explicit initramfs builder")
    for key in ("esp", "boot_root", "xbootldr", "grub_config"):
        if key in boot:
            _absolute(boot[key], key)
    if "kernel_package" in boot:
        token(boot["kernel_package"], "kernel package base")
    variables = boot.get("option_variables", {})
    if not isinstance(variables, dict):
        raise LifecycleError("boot.option_variables must be a reviewed literal mapping")
    for name, value in variables.items():
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise LifecycleError("invalid reviewed boot option variable")
        _options(value)
    normal = boot.get("normal")
    if normal is not None:
        if not isinstance(normal, dict):
            raise LifecycleError("boot.normal must be a reviewed mapping")
        for key in ("kernel_path", "initrd_path"):
            if key in normal:
                _absolute(normal[key], key)
        if "entry_id" in normal:
            entry_identity(normal["entry_id"], boot["backend"])
        if "options" in normal:
            _options(normal["options"])
    return dict(boot)


def _options(value: str) -> str:
    if not isinstance(value, str) or any(char in value for char in ("\n", "\r", "\0", "$", "`", ";", "{", "}")):
        raise LifecycleError("unresolved variables or shell syntax in kernel options")
    try:
        shlex.split(value)
    except ValueError as exc:
        raise LifecycleError("malformed kernel options") from exc
    return value


@dataclass(frozen=True)
class BootEntry:
    entry_id: str
    kernel: str
    title: str
    descriptor_path: str
    descriptor: bytes
    kernel_path: str
    initrd_path: str
    supplemental_paths: tuple[str, ...]
    options: str
    backend: str
    metadata: dict = field(default_factory=dict, compare=False)

    @property
    def id(self) -> str:
        return self.entry_id

    def fingerprints(self) -> dict[str, str]:
        """Stored discovery hashes, with descriptor hash representing its stanza."""
        values = dict(self.metadata.get("fingerprints", {}))
        values[self.descriptor_path] = hashlib.sha256(self.descriptor).hexdigest()
        return values


@dataclass(frozen=True)
class ManagedBootPlan:
    entry_id: str
    entry_path: str
    kernel_path: str
    initrd_path: str
    supplemental_paths: tuple[str, ...]
    copy_files: dict[str, bytes]
    files: dict[str, bytes]
    roles: dict[str, str]
    loader_kernel: str = ""
    loader_initrd: str = ""
    loader_supplements: tuple[str, ...] = ()
    title: str = ""


@dataclass(frozen=True)
class _GrubStanza:
    entry_id: str
    title: str
    data: bytes


def _braces(line: str) -> int:
    """Structural braces only: ignore quotes, comments and ${expansions}."""
    quote = None
    escape = False
    depth = 0
    variable = 0
    for index, char in enumerate(line):
        if escape:
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if quote:
            if char == quote:
                quote = None
            continue
        if char in "'\"":
            quote = char
        elif char == "#":
            break
        elif char == "{" and index and line[index - 1] == "$":
            variable += 1
        elif char == "}" and variable:
            variable -= 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
    return depth


def _header(line: str) -> tuple[str, str]:
    try:
        words = shlex.split(line.rstrip().removesuffix("{").rstrip(), comments=True)
    except ValueError as exc:
        raise LifecycleError("unsupported GRUB entry header") from exc
    if len(words) < 2:
        raise LifecycleError("missing GRUB title")
    identity = None
    for index, word in enumerate(words[2:], 2):
        if word.startswith("--id="):
            if identity is not None:
                raise LifecycleError("duplicate GRUB entry identity")
            identity = word[5:]
        elif word in ("--id", "$menuentry_id_option", "${menuentry_id_option}"):
            if identity is not None or index + 1 >= len(words):
                raise LifecycleError("missing/duplicate GRUB entry identity")
            identity = words[index + 1]
    if identity is None:
        raise LifecycleError("GRUB Linux entry requires a stable explicit ID")
    entry_identity(identity)
    # menuentry_id_option is the sole reviewed generated-header variable.
    rest = line.replace("${menuentry_id_option}", "").replace("$menuentry_id_option", "")
    if "$" in rest or "`" in rest:
        raise LifecycleError("unresolved GRUB entry header variable")
    return words[1], identity


def _grub_stanzas(data: bytes) -> list[_GrubStanza]:
    try:
        lines = data.decode("utf-8").splitlines(keepends=True)
    except UnicodeError as exc:
        raise LifecycleError("GRUB configuration is not UTF-8") from exc
    depth = 0
    submenus: list[tuple[int, str]] = []
    active = None
    result = []
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if re.match(r"(?:submenu|menuentry)\s", stripped):
            if active is not None or not stripped.rstrip().endswith("{") or _braces(line) != 1:
                raise LifecycleError("unsupported nested/multiline GRUB entry")
            title, identity = _header(stripped)
            if stripped.startswith("submenu"):
                submenus.append((depth, identity))
            else:
                full_id = ">".join([item[1] for item in submenus] + [identity])
                active = (index, depth, full_id, title)
        depth += _braces(line)
        if depth < 0:
            raise LifecycleError("unbalanced GRUB configuration")
        if active and depth == active[1]:
            start, _, identity, title = active
            result.append(_GrubStanza(identity, title, "".join(lines[start:index + 1]).encode()))
            active = None
        while submenus and depth == submenus[-1][0]:
            submenus.pop()
    if active or depth:
        raise LifecycleError("unbalanced GRUB entry braces")
    return result


def _linux_commands(data: bytes, option_variables: dict | None = None) -> tuple[int, list[str], int, list[str]]:
    linux, initrd = [], []
    for index, line in enumerate(data.decode().splitlines()):
        if not re.match(r"\s*(linux(?:efi)?|initrd(?:efi)?)\s", line):
            continue
        if any(char in line for char in ("`", ";", "\\", "\0")):
            raise LifecycleError("unresolved or unsupported GRUB Linux command syntax")
        try:
            words = shlex.split(line, comments=True)
        except ValueError as exc:
            raise LifecycleError("malformed GRUB Linux command") from exc
        if words[0] in ("linux", "linuxefi"):
            if len(words) < 2 or "$" in words[1]:
                raise LifecycleError("unresolved GRUB kernel path variable")
            resolved = words[:2]
            for word in words[2:]:
                if "$" not in word:
                    resolved.append(word)
                    continue
                variable = re.fullmatch(r"\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})", word)
                name = (variable.group(1) or variable.group(2)) if variable else None
                if name is None or name not in (option_variables or {}):
                    raise LifecycleError("unreviewed or embedded GRUB kernel option variable")
                resolved.extend(shlex.split(_options(option_variables[name])))
            linux.append((index, resolved))
        else:
            if any("$" in word for word in words):
                raise LifecycleError("unresolved GRUB initrd variable")
            initrd.append((index, words))
    if len(linux) != 1 or len(initrd) != 1 or len(linux[0][1]) < 2 or len(initrd[0][1]) < 2:
        raise LifecycleError("GRUB normal entry needs exactly one Linux and initrd command")
    return (*linux[0], *initrd[0])


def _pe_sections(data: bytes) -> dict[str, bytes]:
    """Read bounded EFI-app PE sections without executing/extracting the image."""
    try:
        if data[:2] != b"MZ" or len(data) < 64:
            raise ValueError("missing DOS header")
        offset = struct.unpack_from("<I", data, 0x3c)[0]
        if offset < 64 or data[offset:offset + 4] != b"PE\0\0":
            raise ValueError("missing PE signature")
        count = struct.unpack_from("<H", data, offset + 6)[0]
        optional_size = struct.unpack_from("<H", data, offset + 20)[0]
        optional = offset + 24
        if optional_size < 70 or optional + optional_size > len(data):
            raise ValueError("truncated EFI optional header")
        magic = struct.unpack_from("<H", data, optional)[0]
        subsystem = struct.unpack_from("<H", data, optional + 68)[0]
        if magic not in (0x10b, 0x20b) or subsystem != 10:
            raise ValueError("not an EFI application")
        table = optional + optional_size
        end_table = table + count * 40
        if not 1 <= count <= 96 or end_table > len(data):
            raise ValueError("invalid section table")
        sections, ranges = {}, []
        resources = {".linux", ".initrd", ".cmdline", ".uname", ".ucode", ".osrel", ".sbat"}
        for index in range(count):
            start = table + index * 40
            name = data[start:start + 8].split(b"\0", 1)[0].decode("ascii")
            virtual_size, _, size, position = struct.unpack_from("<IIII", data, start + 8)
            if not name or name in sections or position + size > len(data):
                raise ValueError("invalid/duplicate PE section")
            if size:
                if virtual_size > size or position < end_table or any(position < end and position + size > begin for begin, end in ranges):
                    raise ValueError("truncated or overlapping PE section")
                ranges.append((position, position + size))
            if name in resources and (not virtual_size or virtual_size > size):
                raise ValueError("UKI resource section has no complete file data")
            # A regular executable .bss may be backed only by zeroed memory.
            # Resource sections require all VirtualSize bytes in the file.
            sections[name] = data[position:position + min(size, virtual_size)]
        return sections
    except (ValueError, UnicodeError, struct.error) as exc:
        raise LifecycleError(f"invalid UKI PE image: {exc}") from exc


class BootAdapter:
    def __init__(self, root: Path, config: dict):
        self.root = Path(root)
        self.config = validate_config(config)
        self.backend = self.config["backend"]
        self.boot_root = self.config.get("xbootldr", self.config.get("boot_root", self.config.get("esp", "/boot")))
        self.grub_config = self.config.get("grub_config", "/boot/grub/grub.cfg")
        self.grub_root = str(PurePosixPath(self.grub_config).parent)
        if self.backend == "grub" and not self.grub_root.startswith("/boot/"):
            raise LifecycleError("GRUB configuration must be in a reviewed /boot directory")

    def path(self, name: str, *, missing: bool = False) -> Path:
        name = _absolute(name)
        path = Path(name) if self.root == Path("/") else self.root / name.lstrip("/")
        return checked_path(path, self.root, missing=missing)

    def _read(self, name: str) -> bytes:
        path = self.path(name)
        if not path.is_file():
            raise LifecycleError(f"boot input is not a regular file: {name}")
        return path.read_bytes()

    def _hashes(self, paths) -> dict[str, str]:
        return {name: hashlib.sha256(self._read(name)).hexdigest() for name in paths}

    def installed_kernels(self) -> list[str]:
        found = set()
        for prefix in self._module_roots():
            base = self.path(prefix, missing=True)
            if not base.exists():
                continue
            for path in base.iterdir():
                if path.is_dir() and not path.is_symlink() and _COMPONENT.fullmatch(path.name):
                    checked_path(path, self.root)
                    if self._matches_package(path.name):
                        found.add(path.name)
        return sorted(found)

    def _matches_package(self, kernel: str) -> bool:
        expected = self.config.get("kernel_package")
        if expected is None:
            return True
        for prefix in self._module_roots():
            path = self.path(f"{prefix}/{kernel}/pkgbase", missing=True)
            if path.exists():
                return token(path.read_text().strip(), "kernel package base") == expected
        return False

    def _module_roots(self) -> tuple[str, ...]:
        # A merged /usr installation has /lib -> usr/lib. Prefer its canonical
        # module directory without granting general symlink permission.
        if self.path("/usr/lib/modules", missing=True).exists():
            return ("/usr/lib/modules",)
        return ("/lib/modules",)

    def _matches_kernel(self, kernel_path: str, kernel: str, version: str = "") -> bool:
        if version and version != kernel:
            return False
        name = PurePosixPath(kernel_path).name
        if name in (f"vmlinuz-{kernel}", f"linux-{kernel}") or kernel_path.endswith(f"/{kernel}/linux"):
            return True
        for modules in self._module_roots():
            pkgbase = self.path(f"{modules}/{kernel}/pkgbase", missing=True)
            if pkgbase.exists():
                value = pkgbase.read_text().strip()
                token(value, "kernel package base")
                if name == f"vmlinuz-{value}":
                    # A pkgbase is not proof that a rolling /boot image still
                    # matches this module version. Require the installed copy.
                    source = self.path(f"{modules}/{kernel}/vmlinuz", missing=True)
                    if not source.exists() or source.read_bytes() != self._read(kernel_path):
                        raise LifecycleError("rolling kernel image does not match the requested installed kernel")
                    return True
        return bool(version)

    def _grub_path(self, loader_path: str) -> str:
        loader_path = _absolute(loader_path, "GRUB image path")
        names = [loader_path] if loader_path.startswith("/boot/") else ["/boot" + loader_path, loader_path]
        candidates = [name for name in names if self.path(name, missing=True).is_file()]
        if len(candidates) != 1:
            raise LifecycleError(f"missing or ambiguous GRUB image path: {loader_path}")
        return candidates[0]

    def _grub_entries(self, kernel: str) -> list[BootEntry]:
        result = []
        data = self._read(self.grub_config)
        # Ubuntu uses this only for graphical terminal handoff. Empty omits
        # handoff if generated conditionals provide different platform values.
        # A sole literal assignment is safe to derive; no expression is run.
        handoffs = []
        for line in data.decode("utf-8").splitlines():
            match = re.fullmatch(r"\s*set\s+vt_handoff=(.*)\s*", line)
            if match:
                try:
                    values = shlex.split(match.group(1), comments=True)
                except ValueError:
                    continue
                if len(values) <= 1 and not any(char in match.group(1) for char in "$`;\\"):
                    handoffs.append(values[0] if values else "")
        variables = {"vt_handoff": handoffs[0] if handoffs and len(set(handoffs)) == 1 else ""}
        variables.update(self.config.get("option_variables", {}))
        for stanza in _grub_stanzas(data):
            if "vbios-" in stanza.entry_id or re.search(r"recovery|fallback initramfs", stanza.title, re.I):
                continue
            if not re.search(rb"(?m)^\s*linux(?:efi)?\s", stanza.data):
                continue
            _, linux, _, initrd = _linux_commands(stanza.data, variables)
            kernel_path = self._grub_path(linux[1])
            if not self._matches_kernel(kernel_path, kernel):
                continue
            images = tuple(self._grub_path(name) for name in initrd[1:])
            options = _options(" ".join(shlex.quote(value) for value in linux[2:]))
            hashes = self._hashes((kernel_path, *images))
            result.append(BootEntry(stanza.entry_id, kernel, stanza.title, self.grub_config,
                                    stanza.data, kernel_path, images[-1], images[:-1], options,
                                    self.backend, {"loader_kernel": linux[1], "fingerprints": hashes, "option_variables": variables}))
        return result

    def _type1_entries(self, kernel: str) -> list[BootEntry]:
        result = []
        roots = list(dict.fromkeys((self.boot_root, self.config.get("esp", self.boot_root))))
        for boot_root in roots:
            directory = self.path(boot_root + "/loader/entries", missing=True)
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.conf")):
                if "vbios-" in path.name:
                    continue
                logical = boot_root + "/loader/entries/" + path.name
                data = self._read(logical)
                try:
                    text = data.decode("utf-8")
                except UnicodeError as exc:
                    raise LifecycleError("boot entry is not UTF-8") from exc
                fields: dict[str, list[str]] = {}
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    pair = line.split(None, 1)
                    if len(pair) != 2:
                        raise LifecycleError("malformed Type #1 boot entry")
                    fields.setdefault(pair[0], []).append(pair[1])
                if "linux" not in fields:
                    continue
                if len(fields["linux"]) != 1 or "efi" in fields or not fields.get("initrd"):
                    raise LifecycleError("ambiguous Type #1 Linux entry")
                if any(len(fields.get(key, [])) > 1 for key in ("version", "title", "machine-id", "architecture")):
                    raise LifecycleError("duplicate Type #1 identity field")
                kernel_path = boot_root + _absolute(fields["linux"][0], "Type #1 kernel")
                if not self._matches_kernel(kernel_path, kernel, fields.get("version", [""])[0]):
                    continue
                images = tuple(boot_root + _absolute(name, "Type #1 initrd") for name in fields["initrd"])
                options = _options(" ".join(fields.get("options", [])))
                entry_identity(path.name, "systemd-boot")
                hashes = self._hashes((kernel_path, *images))
                result.append(BootEntry(path.name, kernel, fields.get("title", [path.stem])[0], logical,
                                        data, kernel_path, images[-1], images[:-1], options, self.backend,
                                        {"boot_root": boot_root, "fingerprints": hashes, "fields": fields}))
        return result

    def _uki_entries(self, kernel: str) -> list[BootEntry]:
        result = []
        roots = list(dict.fromkeys((self.boot_root, self.config.get("esp", self.boot_root))))
        normal = self.config.get("normal", {})
        for boot_root in roots:
            directory = self.path(boot_root + "/EFI/Linux", missing=True)
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.efi")):
                if "vbios-" in path.name:
                    continue
                logical = boot_root + "/EFI/Linux/" + path.name
                data = self._read(logical)
                sections = _pe_sections(data)
                # .sbat is standard systemd-stub revocation metadata. The
                # builder invokes ukify, which regenerates SBAT by merging the
                # current installed stub and extracted kernel metadata (plus
                # its default UKI record). Copying the old outer UKI's .sbat
                # would attach stale stub metadata to the new executable.
                # https://github.com/systemd/systemd/blob/main/man/ukify.xml
                unsupported = {".pcrsig", ".pcrpkey", ".dtb", ".dtbauto", ".hwids", ".efifw", ".profile", ".splash"} & sections.keys()
                if unsupported:
                    raise LifecycleError("normal UKI needs unsupported rebuild metadata: " + ", ".join(sorted(unsupported)))
                # Stub-local addons and credentials also change the effective
                # initrd/cmdline. Their semantics require a dedicated adapter.
                for addons in (logical + ".extra.d", boot_root + "/loader/addons"):
                    directory = self.path(addons, missing=True)
                    if directory.exists() and any(directory.iterdir()):
                        raise LifecycleError("normal UKI has unsupported runtime addons")
                try:
                    version = sections.get(".uname", b"").rstrip(b"\0").decode("utf-8")
                    options = sections.get(".cmdline", b"").rstrip(b"\0").decode("utf-8")
                except UnicodeError as exc:
                    raise LifecycleError("invalid UKI text section") from exc
                if not version:
                    version = normal.get("kernel", "") if normal.get("entry_id") == path.name else ""
                if version != kernel:
                    continue
                if not sections.get(".linux") or not sections.get(".initrd"):
                    raise LifecycleError("normal UKI requires embedded kernel and initrd")
                if not options:
                    options = normal.get("options", "") if normal.get("entry_id") == path.name else ""
                if not options:
                    raise LifecycleError("normal UKI requires embedded or explicitly reviewed kernel options")
                entry_identity(path.name, "uki")
                result.append(BootEntry(path.name, kernel, path.stem, logical, data, logical, logical, (),
                                        _options(options), "uki", {"boot_root": boot_root, "uki_sections": sections,
                                        "fingerprints": {logical: hashlib.sha256(data).hexdigest()}}))
        return result

    def discover(self, kernel: str, entry_id: str | None = None) -> BootEntry:
        token(kernel, "kernel version")
        if not self._matches_package(kernel):
            raise LifecycleError("kernel does not belong to the enrolled kernel package")
        if entry_id is not None:
            entry_identity(entry_id, self.backend)
        candidates = self._grub_entries(kernel) if self.backend == "grub" else self._type1_entries(kernel)
        if self.backend == "uki":
            candidates += self._uki_entries(kernel)
        if entry_id is not None:
            candidates = [entry for entry in candidates if entry.entry_id == entry_id]
        elif self.config.get("normal", {}).get("entry_id"):
            candidates = [entry for entry in candidates if entry.entry_id == self.config["normal"]["entry_id"]]
        # Generated GRUB commonly repeats the same recipe inside Advanced.
        if len(candidates) > 1 and self.backend == "grub" and entry_id is None:
            recipes = {(entry.kernel_path, entry.initrd_path, entry.supplemental_paths, entry.options) for entry in candidates}
            if len(recipes) == 1:
                depth = min(entry.entry_id.count(">") for entry in candidates)
                candidates = [entry for entry in candidates if entry.entry_id.count(">") == depth]
        if len(candidates) != 1:
            raise LifecycleError(f"normal boot discovery requires one unambiguous entry for {kernel}; found {len(candidates)}")
        return candidates[0]

    def fallback_record(self, entry: BootEntry) -> dict:
        return {"entry": entry.entry_id, "kernel": entry.kernel, "sha256": hashlib.sha256(entry.descriptor).hexdigest(),
                "descriptor_path": entry.descriptor_path, "boot_files": dict(entry.metadata["fingerprints"]), "backend": self.backend, "options": entry.options}

    def fallback_records(self, entry: BootEntry) -> list[dict]:
        roles = {entry.kernel_path: "kernel", entry.initrd_path: "initramfs"}
        if entry.metadata.get("uki_sections"):
            roles[entry.descriptor_path] = "uki"
        roles.update({name: "supplemental-initrd" for name in entry.supplemental_paths})
        result = [{"path": name, "sha256": sha, "role": roles.get(name, "uki")} for name, sha in entry.metadata["fingerprints"].items()]
        if entry.descriptor_path not in entry.metadata["fingerprints"]:
            result.append({"path": entry.descriptor_path, "sha256": hashlib.sha256(entry.descriptor).hexdigest(), "role": "entry"})
        return result

    def plan(self, entry: BootEntry, managed_id: str, title: str | None = None) -> ManagedBootPlan:
        token(managed_id, "managed boot artifact")
        if not managed_id.startswith("vbios-"):
            raise LifecycleError("managed boot artifact must use the vbios- namespace")
        title = title or f"{entry.title} (NVIDIA VBIOS override)"
        if any(char in title for char in ("\n", "\r", "\0")):
            raise LifecycleError("invalid managed boot title")
        boot_root = "/boot" if self.backend == "grub" else entry.metadata.get("boot_root", self.boot_root)
        base = f"{boot_root}/nvidia-vbios/{managed_id}"
        kernel_path, initrd_path = base + "/vmlinuz", base + "/initramfs.img"
        copies = {}
        sections = entry.metadata.get("uki_sections")
        copies[kernel_path] = sections[".linux"] if sections else self._read(entry.kernel_path)
        supplements = tuple(f"{base}/microcode-{index}-{PurePosixPath(name).name}" for index, name in enumerate(entry.supplemental_paths))
        if sections and sections.get(".ucode"):
            supplements = (base + "/microcode-embedded.cpio",)
            copies[supplements[0]] = sections[".ucode"]
        for source, destination in zip(entry.supplemental_paths, supplements):
            copies[destination] = self._read(source)
        if sections:
            # This extraction input is staged, never published as the managed
            # initrd; the initramfs builder produces the override initrd.
            copies[base + "/normal-initramfs.img"] = sections[".initrd"]
        roles = {kernel_path: "kernel", initrd_path: "initramfs", **{name: "supplemental-initrd" for name in supplements}}
        if self.backend == "grub":
            entry_path, identity = f"{self.grub_root}/nvidia-vbios-entries/{managed_id}.cfg", managed_id
            # Preserve whether the original GRUB root is /boot or /.
            prefix = "" if entry.metadata["loader_kernel"].startswith("/boot/") else "/boot"
            loader = lambda name: name[len(prefix):] if prefix else name
        else:
            loader = lambda name: name[len(boot_root):]
            if self.backend == "uki":
                entry_path, identity = f"{boot_root}/EFI/Linux/{managed_id}.efi", managed_id + ".efi"
            else:
                entry_path, identity = f"{boot_root}/loader/entries/{managed_id}.conf", managed_id + ".conf"
        roles[entry_path] = "uki" if self.backend == "uki" else "entry"
        plan = ManagedBootPlan(identity, entry_path, kernel_path, initrd_path, supplements, copies, {}, roles,
                               loader(kernel_path), loader(initrd_path), tuple(loader(name) for name in supplements), title)
        if self.backend != "uki":
            plan.files[entry_path] = self.render(entry, plan)
        return plan

    def render(self, entry: BootEntry, plan: ManagedBootPlan, *, options: str | None = None) -> bytes:
        options = _options(entry.options if options is None else options)
        if self.backend == "uki":
            raise LifecycleError("UKI publication requires the initramfs/PE builder")
        if self.backend == "grub":
            lines = entry.descriptor.decode().splitlines(keepends=True)
            linux_index, linux, initrd_index, initrd = _linux_commands(entry.descriptor, entry.metadata.get("option_variables", {}))
            # Retain header switches, replacing title and ID without evaluating
            # menuentry_id_option or exposing a submenu identity on the clone.
            header = shlex.split(lines[0].strip().removesuffix("{").rstrip())
            rebuilt = ["menuentry", shlex.quote(plan.title)]
            index = 2
            while index < len(header):
                word = header[index]
                if word.startswith("--id="):
                    index += 1
                    continue
                if word in ("--id", "$menuentry_id_option", "${menuentry_id_option}"):
                    index += 2
                    continue
                rebuilt.append(shlex.quote(word))
                index += 1
            rebuilt += ["--id", shlex.quote(plan.entry_id)]
            lines[0] = " ".join(rebuilt) + " {\n"
            indent = lambda line: line[:len(line) - len(line.lstrip())]
            lines[linux_index] = f"{indent(lines[linux_index])}{linux[0]} {plan.loader_kernel} {options}\n"
            lines[initrd_index] = f"{indent(lines[initrd_index])}{initrd[0]} " + " ".join((*plan.loader_supplements, plan.loader_initrd)) + "\n"
            return "".join(lines).encode()
        fields = entry.metadata.get("fields", {})
        lines = [f"title {plan.title}", f"version {entry.kernel}"]
        for key in ("machine-id", "sort-key", "architecture"):
            if key in fields:
                lines.append(f"{key} {fields[key][0]}")
        lines.append(f"linux {plan.loader_kernel}")
        lines.extend(f"initrd {name}" for name in (*plan.loader_supplements, plan.loader_initrd))
        lines.append(f"options {options}")
        return ("\n".join(lines) + "\n").encode()

    def visibility_files(self, entry_ids: list[str] | tuple[str, ...] = ()) -> dict[str, bytes]:
        """Own fixed GRUB include and generator; caller must regenerate grub.cfg."""
        if self.backend != "grub":
            return {}
        identifiers = sorted(set(entry_ids))
        for identity in identifiers:
            token(identity, "managed GRUB entry")
            if not identity.startswith("vbios-"):
                raise LifecycleError("unowned GRUB include identity")
        include = "# Managed by nvidia-vbios lifecycle.\n" + "".join(
            f"source $prefix/nvidia-vbios-entries/{identity}.cfg\n" for identity in identifiers)
        hook = b'#!/bin/sh\n# Managed by nvidia-vbios lifecycle.\ncat <<\'NVIDIA_VBIOS_GRUB\'\nif [ -f $prefix/nvidia-vbios.cfg ]; then\n  source $prefix/nvidia-vbios.cfg\nfi\nNVIDIA_VBIOS_GRUB\n'
        return {self.grub_root + "/nvidia-vbios.cfg": include.encode(), "/etc/grub.d/41_nvidia_vbios": hook}

    def validate_visibility(self) -> None:
        if self.backend != "grub":
            return
        data = self._read(self.grub_config).decode()
        if not re.search(r"(?m)^\s*source\s+(?:\$prefix|\$\{prefix\})/nvidia-vbios\.cfg\s*$", data):
            raise LifecycleError("managed GRUB include is not visible in generated grub.cfg")
