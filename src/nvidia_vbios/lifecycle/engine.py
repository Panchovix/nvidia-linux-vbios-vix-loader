"""Transactional Fedora per-kernel reconciliation; no module load/unload actions."""
from __future__ import annotations
from contextlib import ExitStack
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
import time
from .config import load_config, select_source
from .security import LifecycleError, atomic_write, checked_path, digest, hash_file, json_write, locked, token, exchange_directory

STATE = "/var/lib/nvidia-vbios/lifecycle"
CONFIG = "/etc/nvidia-vbios/lifecycle.json"
MODULES = ("nvidia.ko", "nvidia-modeset.ko", "nvidia-drm.ko", "nvidia-uvm.ko")
ACTIVATION_PATH = "etc/modprobe.d/zz-vbios-override-test.conf"
FORCE_PATH = "etc/cmdline.d/20-force_drivers.conf"
FORCE_BYTES = b"rd.driver.pre=nvidia\n"
MODULE_STRING_MAX_BYTES = 1024
ACTIVATION_GENERATION = 3


def firmware_filename(device):
    """Compact request_firmware name; integrity always uses the full SHA256."""
    return f"{device['bdf']}-{device['sha256'][:16]}.bin"


def _validate_parameter_lengths(parameters):
    # Linux param_set_charp() accepts 1024 bytes, excluding the terminating NUL,
    # and rejects 1025. Check decoded values, not kmod quoting or option names.
    for name, value in parameters.items():
        size = len(value.encode("utf-8"))
        if size > MODULE_STRING_MAX_BYTES:
            raise LifecycleError(f"{name} is {size} bytes; Linux string parameter limit is {MODULE_STRING_MAX_BYTES} bytes")


def activation(devices, version, current=None):
    """Preserve reviewed unrelated registry settings, replace all override scopes."""
    current = current or {}
    allowed = {"NVreg_RegistryDwords", "NVreg_RegistryDwordsPerDevice", "NVreg_RegistryBinaryFilePerDevice"}
    if not isinstance(current, dict) or set(current) - allowed:
        raise LifecycleError("unsupported preserved registry parameters")
    def parse(value, scoped=False):
        if not isinstance(value, str) or (value and not re.fullmatch(r"[A-Za-z0-9_=;:./,+-]+", value)):
            raise LifecycleError("registry parameters contain unsafe syntax")
        result, scope = {}, None
        for field in value.split(";"):
            if not field:
                continue
            if field.count("=") != 1:
                raise LifecycleError("malformed registry parameter")
            key, data = field.split("=", 1)
            if not key or not data:
                raise LifecycleError("empty registry key/value")
            if scoped and key == "pci":
                from .config import BDF
                if not BDF.fullmatch(data):
                    raise LifecycleError("preserved registry BDF must be canonical")
                scope = data
                result.setdefault(scope, {})
            elif scoped:
                if scope is None:
                    raise LifecycleError("registry key has no PCI scope")
                result[scope][key] = data
            else:
                result[key] = data
        return result
    global_keys = parse(current.get("NVreg_RegistryDwords", ""))
    dwords = parse(current.get("NVreg_RegistryDwordsPerDevice", ""), True)
    binary = parse(current.get("NVreg_RegistryBinaryFilePerDevice", ""), True)
    for key in ("RmLinuxVbiosOverride", "RmLinuxVbiosOverrideSize", "RmLinuxVbiosOverrideImage"):
        global_keys.pop(key, None)
        for scope in dwords.values():
            scope.pop(key, None)
        for scope in binary.values():
            scope.pop(key, None)
    global_keys["RmLinuxVbiosOverrideDisable"] = "0"
    for device in devices:
        bdf = device["bdf"]
        filename = firmware_filename(device)
        dwords.setdefault(bdf, {}).update(RmLinuxVbiosOverride="2", RmLinuxVbiosOverrideSize=str(device["size"]))
        binary.setdefault(bdf, {})["RmLinuxVbiosOverrideImage"] = f"{version}/vbios-override/{filename}"
    def serialize(scopes):
        return ";".join(part for bdf, values in scopes.items() if values
                        for part in ["pci=" + bdf, *[f"{key}={value}" for key, value in values.items()]])
    parameters = {"NVreg_RegistryDwords": ";".join(f"{key}={value}" for key, value in global_keys.items()),
                  "NVreg_RegistryDwordsPerDevice": serialize(dwords),
                  "NVreg_RegistryBinaryFilePerDevice": serialize(binary)}
    _validate_parameter_lengths(parameters)
    return [f"nvidia.{name}={value}" for name, value in parameters.items()]


def device_evidence(device):
    """runtime_tested is a legacy boot-only assertion for this payload/GPU.

    It never verifies requested field effects. Explicit evidence takes priority;
    missing assertions remain unverified and never gate structural enrollment.
    """
    evidence = device.get("evidence", {})
    return {"boot": evidence.get("boot", "verified" if device.get("runtime_tested") is True else "unverified"),
            "application": evidence.get("application", "unverified"), "fields": evidence.get("fields", {})}

def typed_parameters(devices, version, current=None):
    return {name.removeprefix("nvidia."): value for argument in activation(devices, version, current)
            for name, value in [argument.split("=", 1)]}


def modprobe_configuration(devices, version, current=None):
    parameters = typed_parameters(devices, version, current)
    # Values have already passed the strict registry grammar. Quoting is kmod
    # syntax, not shell syntax; typed strings/size/mode are preserved exactly.
    return ("# NVIDIA VBIOS override: included only in the separate initramfs.\n"
            "options nvidia " + " ".join(f'{name}="{value}"' for name, value in parameters.items()) + "\n").encode()


def parse_bls(data: bytes, kernel: str | None = None, *, supplemental_initrd=("$tuned_initrd",),
              option_variables=("tuned_params", "kernelopts")):
    try:
        text = data.decode()
        if any(character in text for character in ("\x00", "\r")):
            raise LifecycleError("BLS contains invalid control bytes")
        lines = text.splitlines()
    except UnicodeError as exc:
        raise LifecycleError("BLS entry is not UTF-8") from exc
    values = {}
    for line in lines:
        parts = line.split(None, 1)
        if not parts or parts[0].startswith("#"):
            continue
        if parts[0] in ("title", "version", "linux", "initrd", "options"):
            if len(parts) != 2 or parts[0] in values:
                raise LifecycleError("unsupported duplicate/empty BLS fields")
            values[parts[0]] = parts[1]
    if not all(name in values for name in ("title", "linux", "initrd", "options")):
        raise LifecycleError("incomplete Fedora BLS entry")
    if kernel is None:
        kernel = values["linux"].removeprefix("/vmlinuz-")
    token(kernel)
    primary = f"/initramfs-{kernel}.img"
    images = values["initrd"].split()
    if values["linux"] != f"/vmlinuz-{kernel}" or images.count(primary) != 1:
        raise LifecycleError("expected one conventional Fedora primary kernel/initrd; UKI needs an adapter")
    for image in images:
        if image == primary:
            continue
        if image not in supplemental_initrd:
            raise LifecycleError("unreviewed supplemental initrd token")
        if image != "$tuned_initrd" and (not re.fullmatch(r"/[A-Za-z0-9_./+-]+", image) or ".." in Path(image).parts or "//" in image):
            raise LifecycleError("unsafe supplemental initrd token")
    options = values["options"]
    if "nvidia.NVreg_Registry" in options or any(character in options for character in ("`", ";", "\x00", "\r", "\n")) or "$(" in options:
        raise LifecycleError("normal fallback contains NVIDIA activation or unsafe options")
    pattern = r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
    for variable in re.finditer(pattern, options):
        if (variable[1] or variable[2]) not in option_variables:
            raise LifecycleError("unreviewed BLS option variable")
    if "$" in re.sub(pattern, "", options):
        raise LifecycleError("invalid BLS option variable syntax")
    return kernel, values


def managed_bls(base: bytes, kernel: str, image: str, *, supplemental_initrd=("$tuned_initrd",),
                option_variables=("tuned_params", "kernelopts")):
    _, values = parse_bls(base, kernel, supplemental_initrd=supplemental_initrd, option_variables=option_variables)
    token(image, "managed initramfs filename")
    primary = f"/initramfs-{kernel}.img"
    values.update(title=values["title"] + " (VBIOS override)",
                  initrd=" ".join("/" + image if word == primary else word for word in values["initrd"].split()))
    # Preserve all normal options and supplemental tokens; activation is inside
    # the image. No NVreg options are appended to the kernel command line.
    return ("# Managed by nvidia-vbios lifecycle; normal entry retained.\n" + "\n".join(
        f"{line.split(None, 1)[0]} {values[line.split(None, 1)[0]]}"
        if line.split() and line.split(None, 1)[0] in values else line
        for line in base.decode().splitlines()) + "\n").encode()


class Reconciler:
    """Inject operations and root for tests; default operations never act on an alternate root.

    Operations implement installed_version, inspect_source, prepare_source,
    prerequisites, inventory, build, modinfo, sign, depmod, selected_module,
    initramfs, extract, grub_environment and set_default. None uses a shell.
    """
    def __new__(cls, root=Path("/"), operations=None, config_path=CONFIG):
        # Existing schema-1 Fedora profiles retain the original implementation.
        if cls is Reconciler:
            boundary = Path(root).absolute()
            path = boundary / str(config_path).lstrip("/")
            if path.exists():
                checked_path(path, boundary)
                try:
                    raw = json.loads(path.read_bytes())
                except (ValueError, OSError):
                    raw = {}
                if isinstance(raw, dict) and isinstance(raw.get("boot"), dict) and raw["boot"].get("backend") in ("grub", "systemd-boot", "uki"):
                    from .portable import PortableReconciler
                    return object.__new__(PortableReconciler)
        return object.__new__(cls)

    def __init__(self, root=Path("/"), operations=None, config_path=CONFIG):
        self.root = Path(root).absolute()
        if operations is None:
            if self.root != Path("/"):
                raise LifecycleError("synthetic root requires explicitly injected operations")
            from .system import SystemOperations
            operations = SystemOperations()
        self.ops = operations
        self.config_path = self.path(config_path)
        self.state = self.path(STATE)

    def path(self, value):
        return self.root / str(value).lstrip("/")

    def trusted(self, path, missing=False):
        return checked_path(path, self.root, missing=missing)

    def _json(self, path, default=None):
        if not path.exists():
            return {} if default is None else default
        self.trusted(path)
        try:
            return json.loads(path.read_text())
        except (ValueError, OSError) as exc:
            raise LifecycleError(f"invalid state {path}: {exc}") from exc

    def _effective_fleet(self, config):
        fleet = self._json(self.state / "fleet.json")
        if not fleet.get("last_ready") and config.raw.get("seed_previous_ready"):
            fleet = dict(fleet, last_ready=config.raw["seed_previous_ready"])
        return fleet

    def _bls_options(self, config):
        layout = config.raw.get("bls", {})
        return {"supplemental_initrd": layout.get("supplemental_initrd", ["$tuned_initrd"]),
                "option_variables": layout.get("option_variables", ["tuned_params", "kernelopts"])}

    def _fallback(self, config, fleet):
        fallback = fleet.get("normal_fallback", {"entry": config.fallback_entry,
                                                "sha256": config.raw["fallback_sha256"], "boot_files": config.raw["fallback_files"]})
        path = self.path(f"/boot/loader/entries/{token(fallback['entry'], 'entry')}.conf")
        self.trusted(path)
        last = fleet.get("last_ready")
        if last:
            # Stock akmods/dracut may legitimately rebuild the normal image
            # during a driver-only update. The separate immutable ready image
            # is the protected fallback once the lifecycle has a commit.
            for record in last["boot_files"]:
                protected = self.path(record["path"])
                self.trusted(protected)
                if hash_file(protected) != record["sha256"]:
                    raise LifecycleError("last ready boot artifact changed; cannot use it as fallback")
        elif hash_file(path) != fallback["sha256"]:
            raise LifecycleError("enrolled normal fallback BLS changed or missing")
        kernel, _ = parse_bls(path.read_bytes(), **self._bls_options(config))
        names = (f"/boot/vmlinuz-{kernel}", f"/boot/initramfs-{kernel}.img")
        if set(fallback.get("boot_files", {})) != set(names):
            raise LifecycleError("fallback does not record exact kernel/initramfs fingerprints")
        for name in names:
            self.trusted(self.path(name))
            if not last and hash_file(self.path(name)) != fallback["boot_files"][name]:
                raise LifecycleError("normal fallback kernel/initramfs bytes changed")
        return fallback

    def _check_option_variables(self, config, environment):
        variables = self._bls_options(config)["option_variables"]
        pattern = r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"
        for name in variables:
            value = environment.get(name, "")
            if (not isinstance(value, str) or any(ord(character) < 32 or ord(character) > 126 for character in value)
                    or any(character in value for character in (";", "`", "\\")) or "$(" in value):
                raise LifecycleError(f"unsafe GRUB option variable {name}")
            if "nvidia.NVreg_Registry" in value or "RmLinuxVbiosOverride" in value:
                raise LifecycleError(f"GRUB option variable {name} contains foreign VBIOS activation")
            for match in re.finditer(pattern, value):
                if (match[1] or match[2]) not in variables:
                    raise LifecycleError(f"GRUB option variable {name} expands an unreviewed variable")
            if "$" in re.sub(pattern, "", value):
                raise LifecycleError(f"invalid GRUB option variable syntax in {name}")

    def _guard_default(self, config, fleet):
        last = fleet.get("last_ready")
        if last:
            for record in last["boot_files"]:
                path = self.path(record["path"])
                self.trusted(path)
                if hash_file(path) != record["sha256"]:
                    raise LifecycleError("last ready boot artifact changed; cannot use it as fallback")
            target = token(last["entry"], "last ready entry")
        else:
            target = self._fallback(config, fleet)["entry"]
        env = self.ops.grub_environment()
        if env.get("next_entry") or env.get("prev_saved_entry"):
            raise LifecycleError("another GRUB transition is pending; refusing to change boot selection")
        self._check_option_variables(config, env)
        saved = env.get("saved_entry")
        if saved == target:
            return target
        # Recognize an actual normal entry on this installation as an update
        # candidate. A different OS, legacy entry not explicitly seeded, older
        # managed entry, or deliberate same-kernel normal choice is preserved.
        candidate = None
        if isinstance(saved, str):
            try:
                token(saved, "saved entry")
                path = self.path(f"/boot/loader/entries/{saved}.conf")
                self.trusted(path)
                candidate, _ = parse_bls(path.read_bytes(), **self._bls_options(config))
                if path != self._base_entry(candidate, config):
                    candidate = None
            except (LifecycleError, OSError):
                candidate = None
        eligible = not last and saved == config.fallback_entry
        if last and candidate:
            from .__main__ import kernel_key
            queued = self._json(self.state / "pending" / (candidate + ".json"))
            eligible = kernel_key(candidate) > kernel_key(last["kernel"]) or (
                candidate == last["kernel"] and queued.get("action") == "add" and queued.get("kernel") == candidate)
        if not eligible:
            raise LifecycleError("foreign or unrelated GRUB default preserved; explicit selection required")
        self.ops.set_default(target)
        if self.ops.grub_environment().get("saved_entry") != target:
            raise LifecycleError("could not retain the last ready boot default")
        return target

    def _normal_entry_id(self, kernel, config):
        explicit = config.raw.get("bls", {}).get("entry_prefix")
        if explicit is not None:
            return token(explicit + kernel, "normal BLS entry")
        original = next(name.removeprefix("/boot/vmlinuz-") for name in config.raw["fallback_files"]
                        if name.startswith("/boot/vmlinuz-"))
        if not config.fallback_entry.endswith("-" + original):
            if kernel == original:
                return config.fallback_entry
            raise LifecycleError("nonstandard normal BLS ID requires an explicit reviewed entry_prefix")
        return config.fallback_entry[:-len(original)] + kernel

    def _base_entry(self, kernel, config=None):
        entries = self.path("/boot/loader/entries")
        self.trusted(entries)
        matches = []
        expected_id = self._normal_entry_id(kernel, config) if config else None
        for path in entries.glob("*.conf"):
            if path.name.startswith("vbios-") or (expected_id and path.stem != expected_id):
                continue
            self.trusted(path)
            try:
                parse_bls(path.read_bytes(), kernel, **(self._bls_options(config) if config else {}))
            except LifecycleError:
                continue
            matches.append(path)
        if len(matches) != 1:
            raise LifecycleError(f"expected exactly one conventional normal BLS entry for {kernel}")
        return matches[0]

    def guard_default(self):
        """Hook-time safeguard: no RPM queries/builds while the transaction is active."""
        self.trusted(self.state, missing=True)
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        with locked(self.state / "reconcile.lock", self.root):
            self.ops.set_log(self.state / "queue-commands.log")
            config = load_config(self.config_path, self.root)
            return self._guard_default(config, self._effective_fleet(config))

    def restore_normal_default(self):
        """Explicit disable/recovery action: restore only our owned saved default.

        No file removal, module action, foreign default, or one-time transition
        is touched. A changed normal recovery artifact fails before selection.
        """
        self.trusted(self.state, missing=True)
        with locked(self.state / "reconcile.lock", self.root):
            return self._restore_normal_default_locked()

    def _restore_normal_default_locked(self):
        """Caller MUST hold state/reconcile.lock across its whole disable action.

        Bootstrap uses this helper after disabling triggers/profile under the
        same lock. Reacquiring flock through a different descriptor would fail.
        """
        self.ops.set_log(self.state / "disable-commands.log")
        config = load_config(self.config_path, self.root, require_enabled=False)
        fleet = self._effective_fleet(config)
        normal = fleet.get("normal_fallback", {"entry": config.fallback_entry,
            "sha256": config.raw["fallback_sha256"], "boot_files": config.raw["fallback_files"]})
        environment = self.ops.grub_environment()
        self._check_option_variables(config, environment)
        if environment.get("next_entry") or environment.get("prev_saved_entry"):
            return {"state": "preserved", "reason": "pending GRUB transition", "entry": environment.get("saved_entry")}
        current = environment.get("saved_entry")
        if current == normal["entry"]:
            return {"state": "normal", "entry": current}
        if current != fleet.get("last_ready", {}).get("entry"):
            return {"state": "preserved", "reason": "foreign or unrelated GRUB default", "entry": current}
        entry = self.path(f"/boot/loader/entries/{token(normal['entry'], 'normal entry')}.conf")
        self.trusted(entry)
        if hash_file(entry) != normal["sha256"]:
            raise LifecycleError("normal recovery BLS changed; disable selection requires review")
        kernel, _ = parse_bls(entry.read_bytes(), **self._bls_options(config))
        names = {f"/boot/vmlinuz-{kernel}", f"/boot/initramfs-{kernel}.img"}
        if set(normal["boot_files"]) != names:
            raise LifecycleError("normal recovery files do not match BLS")
        for name, sha in normal["boot_files"].items():
            self.trusted(self.path(name))
            if hash_file(self.path(name)) != sha:
                raise LifecycleError("normal recovery bytes changed; disable selection requires review")
        self.ops.set_default(normal["entry"])
        if self.ops.grub_environment().get("saved_entry") != normal["entry"]:
            raise LifecycleError("normal recovery boot selection did not persist")
        return {"state": "normal", "entry": normal["entry"]}

    def ready_status(self, kernel):
        """Read-only installer gate for the current profile and actual artifacts."""
        kernel = token(kernel)
        plan = self.plan(kernel, require_enabled=False)
        status = self._json(self.state / f"status-{kernel}.json")
        if (status.get("state") != "ready" or status.get("driver") != plan["version"]
                or status.get("generation_sha256") != plan["generation_sha256"]
                or status.get("activation_config_sha256") != plan["activation_config_sha256"]
                or not status.get("deployment")):
            raise LifecycleError("current profile/kernel has not completed a verified lifecycle reconciliation")
        for record in status["deployment"]:
            path = self.path(record["path"])
            self.trusted(path)
            if hash_file(path) != record["after_sha256"]:
                raise LifecycleError("ready deployment artifact changed")
        for name in status["module_metadata"]:
            expected = self.path(f"/usr/lib/modules/{kernel}/updates/vbios-override/{name}")
            if Path(self.ops.selected_module(kernel, name.removesuffix(".ko"))).resolve() != expected.resolve():
                raise LifecycleError("ready deployment lost depmod selection")
        return status

    def plan(self, kernel, *, require_enabled=True):
        kernel = token(kernel)
        config = load_config(self.config_path, self.root, require_enabled=require_enabled)
        version = self.ops.installed_version(config.raw)
        source, inspection = select_source(config, version, self.ops.inspect_source, self.root)
        base = self._base_entry(kernel, config)
        self._fallback(config, self._effective_fleet(config))
        _, bls_values = parse_bls(base.read_bytes(), kernel, **self._bls_options(config))
        for name in bls_values["initrd"].split():
            if name.startswith("/") and name != f"/initramfs-{kernel}.img":
                self.trusted(self.path("/boot" + name))
        payloads = {}
        actual = self.ops.inventory()
        for device in config.devices:
            observed = actual.get(device["bdf"])
            if observed is None or any(observed.get(k) != device[k] for k in ("uuid", "vendor", "device")):
                raise LifecycleError(f"physical GPU UUID/BDF identity unavailable or changed at {device['bdf']}; no module load/reload attempted")
            path = self.path(device["payload_path"])
            self.trusted(path)
            data = path.read_bytes()
            if len(data) != device["size"] or digest(data) != device["sha256"]:
                raise LifecycleError(f"selected ROM bytes changed at {device['bdf']}")
            self.ops.validate_payload(data, device)
            payloads[device["bdf"]] = data
        self.ops.prerequisites(kernel, config.raw)
        activation_bytes = modprobe_configuration(config.devices, version, config.raw.get("parameters"))
        generation = digest((f"initramfs-activation-v{ACTIVATION_GENERATION}:" + kernel + version + config.fingerprint + hash_file(base)).encode())
        tag = generation[:20]
        return {"kernel": kernel, "version": version, "source": source,
                "source_inspection": inspection, "configuration_sha256": config.fingerprint,
                "entry": f"vbios-{kernel}-{tag}", "image": f"initramfs-{kernel}-vbios-{tag}.img",
                "base_entry": str(base), "base_sha256": hash_file(base),
                "generation_sha256": generation, "module_parameters": typed_parameters(config.devices, version, config.raw.get("parameters")),
                "activation_config_sha256": digest(activation_bytes), "activation_bytes": activation_bytes,
                "config": config, "payloads": payloads}

    def dry_run(self, kernel):
        plan = self.plan(kernel)
        return {key: value for key, value in plan.items() if key not in ("config", "payloads", "activation_bytes")}

    def _retained_generation(self, entry):
        """A profile can return to an earlier generation ID still kept by retention. Dracut output
        is not byte-reproducible, so that ID gets a new suffix instead of being rebuilt in place.
        Only intact history-registered generations qualify; unmanaged files still block."""
        from .retention import _history
        try:
            record = _history(self)["generations"].get(entry)
        except (LifecycleError, OSError, KeyError, TypeError, ValueError):
            return False
        return bool(record) and record["state"] != "removed" and all(
            self.path(name).is_file() and hash_file(self.path(name)) == sha256 for name, sha256 in record["files"].items())

    def _publish_boot(self, plan, config, fleet, kernel, workspace, journal, targets):
        if fleet.get("last_ready", {}).get("entry") == plan["entry"] or self._retained_generation(plan["entry"]):
            nonce = digest(journal["id"].encode())[:12]
            plan["entry"] += "-" + nonce
            plan["image"] = plan["image"].removesuffix(".img") + "-" + nonce + ".img"
            # Rollback/recovery must own the actual newly allocated ID,
            # including failures after GRUB selection but before commit.
            journal["entry"] = plan["entry"]
            json_write(self.state / "transaction.json", journal)
        image = self.path("/boot/" + plan["image"])
        self.trusted(image, missing=True)
        fd, tempname = tempfile.mkstemp(prefix=".vbios-initramfs-", suffix=".img", dir=image.parent)
        os.close(fd)
        temporary = Path(tempname)
        try:
            activation_input = workspace / "activation.conf"
            force_input = workspace / "force-drivers.conf"
            atomic_write(activation_input, plan["activation_bytes"])
            atomic_write(force_input, FORCE_BYTES)
            self.ops.initramfs(kernel, temporary, list(targets), activation_config=activation_input, force_config=force_input)
            if self.ops.extract(temporary, ACTIVATION_PATH) != plan["activation_bytes"]:
                raise LifecycleError("initramfs lacks exact typed NVIDIA activation configuration")
            if self.ops.extract(temporary, FORCE_PATH) != FORCE_BYTES:
                raise LifecycleError("initramfs lacks exact NVIDIA force-driver marker")
            for target, data in targets.items():
                relative = str(target.relative_to(self.root))
                alternatives = [relative]
                if relative.startswith("usr/lib/"):
                    alternatives.append(relative.removeprefix("usr/"))
                if not any(self.ops.extract(temporary, name) == data for name in alternatives):
                    raise LifecycleError(f"initramfs lacks exact expected bytes: {target.name}")
            image_bytes = temporary.read_bytes()
            self._validate_existing(config, fleet, kernel, {image: image_bytes})
            self._stage_write(journal, image, image_bytes, mode=0o600, prepared_path=temporary)
        finally:
            temporary.unlink(missing_ok=True)
        entry_path = self.path(f"/boot/loader/entries/{plan['entry']}.conf")
        entry_data = managed_bls(Path(plan["base_entry"]).read_bytes(), kernel, plan["image"], **self._bls_options(config))
        self._validate_existing(config, fleet, kernel, {entry_path: entry_data})
        self._stage_write(journal, entry_path, entry_data)
        base = Path(plan["base_entry"])
        return {"paths": [image, entry_path],
                "normal_fallback": {"entry": base.stem, "sha256": plan["base_sha256"],
                    "boot_files": {name: hash_file(self.path(name)) for name in
                        (f"/boot/vmlinuz-{kernel}", f"/boot/initramfs-{kernel}.img")}},
                "boot_files": [{"path": "/" + str(p.relative_to(self.root)), "sha256": hash_file(p)}
                    for p in (entry_path, image, self.path(f"/boot/vmlinuz-{kernel}"))]}

    def _record_boot_publication(self, fleet, plan, publication, deployment):
        """Portable backends register generation-owned kernels and boot descriptors."""

    def _check_module(self, path, version, kernel, primary=False, signed=False):
        self.trusted(path)
        details = self.ops.modinfo(path)
        if details.get("version") != version or details.get("vermagic", "").split()[:1] != [kernel]:
            raise LifecycleError(f"module version/vermagic mismatch: {path.name}")
        if primary and (details.get("vbios_override_per_gpu") != "1" or not details.get("srcversion")):
            raise LifecycleError("nvidia.ko is missing the per-GPU patch marker/srcversion")
        if signed and not details.get("signer"):
            raise LifecycleError("Secure Boot requires every installed module to be signed")
        return details

    def _stage_write(self, journal, target, data, mode=0o644, *, publish=True, prepared_path=None):
        self.trusted(target, missing=True)
        if prepared_path is not None:
            self.trusted(prepared_path)
            if (not publish or prepared_path == target or prepared_path.parent != target.parent
                    or not prepared_path.is_file() or hash_file(prepared_path) != digest(data)):
                raise LifecycleError("prepared publication must be the verified same-directory file")
        # Persist both before and expected-after hashes before publishing any bytes.
        before = target.read_bytes() if target.exists() else None
        backup = self.state / "transactions" / journal["id"] / "backups" / str(len(journal["files"]))
        if before is not None:
            atomic_write(backup, before, target.stat().st_mode & 0o777)
        record = {"path": "/" + str(target.relative_to(self.root)),
                  "before_sha256": digest(before) if before is not None else None,
                  "after_sha256": digest(data), "backup": str(backup) if before is not None else None,
                  "mode": target.stat().st_mode & 0o777 if before is not None else mode}
        journal["files"].append(record)
        json_write(self.state / "transaction.json", journal)
        if publish:
            if prepared_path is None:
                atomic_write(target, data, mode)
            else:
                # Dracut already produced and byte-verified this file in /boot.
                # Journal first, then publish that inode; do not allocate a second
                # complete initramfs on the same small boot filesystem.
                prepared_path.chmod(mode)
                with prepared_path.open("rb") as stream:
                    os.fsync(stream.fileno())
                os.replace(prepared_path, target)
                directory = os.open(target.parent, os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)

    def _remove_module_stage(self, stage, journal):
        self.trusted(stage)
        allowed = {}
        for record in journal["files"]:
            path = self.path(record["path"])
            if path.suffix == ".ko":
                allowed.setdefault(path.name, set()).update((record["before_sha256"], record["after_sha256"]))
        for path in stage.iterdir():
            self.trusted(path)
            if not path.is_file() or hash_file(path) not in allowed.get(path.name, set()):
                raise LifecycleError("staging cleanup refuses externally changed module bytes")
        shutil.rmtree(stage)

    def _install_modules(self, journal, targets):
        directory = next(iter(targets)).parent
        self.trusted(directory, missing=True)
        directory.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        existed = directory.exists()
        previous_members = sorted(path.name for path in directory.iterdir()) if existed else []
        if set(previous_members) - {path.name for path in targets}:
            raise LifecycleError("managed module directory contains unexpected files")
        stage = self.path("/usr/lib/modules/.vbios-modules-" + journal["id"])
        self.trusted(stage, missing=True)
        journal.setdefault("staging", []).append(str(stage))
        json_write(self.state / "transaction.json", journal)
        stage.mkdir(mode=0o700)
        record = {"path": "/" + str(directory.relative_to(self.root)), "stage": str(stage),
                  "existed": existed, "previous_members": previous_members,
                  "members": sorted(path.name for path in targets),
                  "mode": directory.stat().st_mode & 0o777 if existed else 0o755}
        for target, data in targets.items():
            self._stage_write(journal, target, data, publish=False)
            atomic_write(stage / target.name, data, 0o644)
        stage.chmod(0o755)
        # Only a complete snapshot may be rolled back as a complete directory.
        journal.setdefault("directories", []).append(record)
        json_write(self.state / "transaction.json", journal)
        exchange_directory(stage, directory)
        if stage.exists():
            # The exchanged old set is also preserved in per-file backups.
            self._remove_module_stage(stage, journal)

    def _validate_existing(self, config, fleet, kernel, targets):
        registered = {record["path"]: record["after_sha256"] for record in
                      fleet.get("kernels", {}).get(kernel, {}).get("deployment", [])}
        adopted = config.raw.get("adopt_existing", {})
        for path, data in targets.items():
            self.trusted(path, missing=True)
            if not path.exists():
                continue
            name = "/" + str(path.relative_to(self.root))
            observed = hash_file(path)
            if observed == digest(data):
                continue
            if observed not in (registered.get(name), adopted.get(name)):
                raise LifecycleError(f"existing deployment changed or is unmanaged; explicit adoption required: {path}")

    def _rollback(self, journal):
        token(journal["id"], "transaction id")
        token(journal["kernel"])
        token(journal["entry"], "managed entry")
        if journal.get("boot"):
            from .boot import entry_identity
            entry_identity(journal["previous_default"], journal["boot"]["backend"])
        else:
            token(journal["previous_default"], "previous default")
        for record in journal["files"]:
            target = self.path(record["path"])
            self.trusted(target, missing=True)
            observed = hash_file(target) if target.exists() else None
            if observed not in (record["before_sha256"], record["after_sha256"]):
                raise LifecycleError(f"rollback refuses externally changed file: {target}")
            if record["backup"]:
                backup = Path(record["backup"])
                if not backup.is_relative_to(self.state / "transactions" / journal["id"]):
                    raise LifecycleError("rollback backup outside transaction")
                self.trusted(backup)
                if hash_file(backup) != record["before_sha256"]:
                    raise LifecycleError("rollback backup hash mismatch")
        for directory in journal.get("directories", []):
            target = self.path(directory["path"])
            self.trusted(target, missing=True)
            if target.exists() and {path.name for path in target.iterdir()} not in (
                    set(directory["members"]), set(directory["previous_members"])):
                raise LifecycleError("module rollback refuses unexpected directory members")
        environment = self.ops.grub_environment()
        selected = environment.get("saved_entry")
        if selected == journal.get("entry"):
            self.ops.set_default(journal["previous_default"])
        elif selected != journal["previous_default"]:
            raise LifecycleError("GRUB default changed externally during rollback")
        module_paths = set()
        for directory in journal.get("directories", []):
            target = self.path(directory["path"])
            self.trusted(target, missing=True)
            if target.exists():
                observed_members = {path.name for path in target.iterdir()}
                if observed_members not in (set(directory["members"]), set(directory["previous_members"])):
                    raise LifecycleError("module rollback refuses unexpected directory members")
            records = [record for record in journal["files"] if self.path(record["path"]).parent == target]
            module_paths.update(record["path"] for record in records)
            stage = self.path("/usr/lib/modules/.vbios-rollback-" + journal["id"])
            self.trusted(stage, missing=True)
            if stage.exists():
                raise LifecycleError("interrupted rollback staging directory requires review")
            already_before = (not target.exists() and not directory["existed"]) or (
                target.exists() and directory["existed"]
                and {path.name for path in target.iterdir()} == set(directory["previous_members"])
                and all((hash_file(self.path(record["path"])) if self.path(record["path"]).exists() else None)
                        == record["before_sha256"] for record in records))
            if already_before:
                pass
            elif directory["existed"]:
                stage.mkdir(mode=0o700)
                for record in records:
                    if record["backup"]:
                        atomic_write(stage / self.path(record["path"]).name, Path(record["backup"]).read_bytes(), record["mode"])
                stage.chmod(directory.get("mode", 0o755))
                exchange_directory(stage, target)
                if stage.exists():
                    self._remove_module_stage(stage, journal)
            elif target.exists():
                shutil.rmtree(target)
            staged = Path(directory["stage"])
            if staged.exists():
                self.trusted(staged)
                self._remove_module_stage(staged, journal)
        for record in reversed(journal["files"]):
            if record["path"] in module_paths:
                continue
            target = self.path(record["path"])
            if record["backup"]:
                atomic_write(target, Path(record["backup"]).read_bytes(), record["mode"])
            elif target.exists():
                target.unlink()
        for name in journal.get("staging", []):
            stage = Path(name)
            if stage != self.path("/usr/lib/modules/.vbios-modules-" + journal["id"]):
                raise LifecycleError("invalid module staging path in journal")
            if stage.exists():
                self.trusted(stage)
                self._remove_module_stage(stage, journal)
        self.ops.depmod(journal["kernel"])
        journal["phase"] = "rolled-back"
        json_write(self.state / "transaction.json", journal)

    def _prune_removed_kernels(self):
        """Delete only hash-owned boot artifacts whose kernel image was removed."""
        fleet = self._json(self.state / "fleet.json")
        environment = self.ops.grub_environment()
        protected = {environment.get(name) for name in ("saved_entry", "next_entry", "prev_saved_entry")}
        warnings = []
        changed = False
        for kernel, ready in list(fleet.get("kernels", {}).items()):
            token(kernel)
            if self.path(f"/boot/vmlinuz-{kernel}").exists() or kernel == os.uname().release or ready["entry"] in protected:
                continue
            boot_records = [record for record in ready["deployment"] if
                            record["path"].startswith(f"/boot/initramfs-{kernel}-vbios-") or
                            record["path"].startswith(f"/boot/loader/entries/vbios-{kernel}-")]
            try:
                for record in boot_records:
                    path = self.path(record["path"])
                    self.trusted(path, missing=True)
                    if path.exists() and hash_file(path) != record["after_sha256"]:
                        raise LifecycleError("stale managed boot artifact changed externally")
                for record in boot_records:
                    self.path(record["path"]).unlink(missing_ok=True)
                del fleet["kernels"][kernel]
                changed = True
            except (LifecycleError, OSError) as exc:
                warnings.append(f"{kernel}: {exc}")
        if changed:
            json_write(self.state / "fleet.json", fleet)
        return warnings

    def _retain_boots(self, status, config):
        # Retention cannot invalidate an already committed READY deployment.
        from .retention import prune
        try:
            status["retention"] = prune(self, status, config.raw.get("retain_boot_generations", 3))
        except (LifecycleError, OSError, KeyError, TypeError, ValueError) as exc:
            status["retention"] = {"state": "deferred", "warnings": [str(exc)]}

    def _ready_artifacts_intact(self, status, kernel):
        """Validate a previous disk commit without depending on live GPU/userspace.

        ready_status() still validates the current profile and inventory. Keeping
        this record is not a claim that a failing new request is ready.
        """
        if (status.get("state") != "ready" or status.get("marker") != "VBIOS_READY"
                or status.get("kernel") != kernel or not status.get("deployment")):
            return False
        try:
            fleet = self._json(self.state / "fleet.json")
            if fleet.get("kernels", {}).get(kernel, {}).get("entry") != status.get("entry"):
                return False
            for record in status["deployment"]:
                path = self.path(record["path"])
                self.trusted(path)
                if hash_file(path) != record["after_sha256"]:
                    return False
            for name in status.get("module_metadata", {}):
                expected = self.path(f"/usr/lib/modules/{kernel}/updates/vbios-override/{name}")
                if Path(self.ops.selected_module(kernel, name.removesuffix(".ko"))).resolve() != expected.resolve():
                    return False
            return bool(status.get("module_metadata"))
        except (LifecycleError, OSError, KeyError, TypeError, ValueError):
            return False

    def reconcile(self, kernel, *, dry_run=False):
        if dry_run:
            return self.dry_run(kernel)
        kernel = token(kernel)
        self.trusted(self.state, missing=True)
        self.state.mkdir(mode=0o700, parents=True, exist_ok=True)
        status_path = self.state / f"status-{kernel}.json"
        journal = None
        existing = {}
        attempt_path = self.state / f"attempt-{kernel}.json"
        owns_lock = False
        profile_disabled = False
        with ExitStack() as locks:
            try:
                locks.enter_context(locked(self.state / "reconcile.lock", self.root))
                owns_lock = True
                self.ops.set_log(self.state / f"commands-{kernel}.log")
                previous_status = self._json(status_path)
                if not isinstance(previous_status, dict):
                    raise LifecycleError("invalid prepared-status object")
                existing = previous_status
                config = load_config(self.config_path, self.root, require_enabled=False)
                if not config.raw["enabled"]:
                    profile_disabled = True
                    raise LifecycleError("lifecycle profile is disabled; committed readiness preserved")
                fleet = self._effective_fleet(config)
                old = self._json(self.state / "transaction.json")
                if old.get("phase") not in ("installing", "selecting", "rollback-failed"):
                    self._guard_default(config, fleet)
                # A callback cannot wait for its own parent RPM transaction.
                # Probe and release first, before synchronous systemctl/akmods.
                if hasattr(self.ops, "publication_locks"):
                    self.ops.assert_transaction_idle(self.root)
                    self.ops.coordinate_stock_build(kernel, config.raw)
                    locks.enter_context(self.ops.publication_locks(self.root))
                else:
                    with locked(self.path("/usr/lib/sysimage/rpm/.rpm.lock"), self.root, rpm=True):
                        pass
                    self.ops.coordinate_akmods(kernel, config.raw)
                    locks.enter_context(locked(self.path("/run/akmods/akmods.lock"), self.root, akmods=True))
                    locks.enter_context(locked(self.path("/usr/lib/sysimage/rpm/.rpm.lock"), self.root, rpm=True))
                if old.get("phase") in ("installing", "selecting", "rollback-failed"):
                    # fleet.json is the commit record. A crash after publishing it must
                    # retain the committed artifacts rather than roll them back.
                    committed = fleet.get("transaction_id") == old.get("id")
                    if committed:
                        for record in old["files"]:
                            if hash_file(self.path(record["path"])) != record["after_sha256"]:
                                raise LifecycleError("committed transaction artifact changed after interruption")
                        old["phase"] = "ready"
                        json_write(self.state / "transaction.json", old)
                    else:
                        self._rollback(old)
                previous = self._guard_default(config, fleet)
                # Save the prior committed boot pair before a same-kernel update
                # replaces its fleet slot. Failure only disables this optional cleanup.
                from .retention import remember
                try:
                    remember(self)
                except (LifecycleError, OSError, KeyError, TypeError, ValueError):
                    pass
                plan = self.plan(kernel)
                running = {"state": "running", "kernel": kernel, "started": time.time(),
                           "completion_marker": "VBIOS_READY", "failure_marker": "VBIOS_BLOCKED"}
                json_write(attempt_path, running)
                if existing.get("state") != "ready":
                    json_write(status_path, running)
                if (existing.get("state") == "ready" and existing.get("configuration_sha256") == plan["configuration_sha256"]
                        and existing.get("driver") == plan["version"]
                        and existing.get("generation_sha256") == plan["generation_sha256"]
                        and existing.get("activation_config_sha256") == plan["activation_config_sha256"]
                        and existing.get("base_sha256") == plan["base_sha256"]
                        and existing.get("deployment") and all(
                            self.path(record["path"]).is_file() and not self.path(record["path"]).is_symlink()
                            and self.trusted(self.path(record["path"]))
                            and hash_file(self.path(record["path"])) == record["after_sha256"]
                            for record in existing["deployment"])):
                    for name in existing["module_metadata"]:
                        chosen = Path(self.ops.selected_module(kernel, name.removesuffix(".ko")))
                        if chosen.resolve() != self.path(f"/usr/lib/modules/{kernel}/updates/vbios-override/{name}").resolve():
                            raise LifecycleError("a later module installer changed depmod selection")
                    warnings = self._prune_removed_kernels()
                    if warnings:
                        existing["cleanup_warnings"] = warnings
                    self._retain_boots(existing, config)
                    json_write(status_path, existing)
                    json_write(attempt_path, {"state": "ready", "marker": "VBIOS_READY", "kernel": kernel,
                                              "entry": existing["entry"], "reused": True, "finished": time.time()})
                    return existing
                transaction_id = f"{kernel}-{time.time_ns()}"
                workspace = self.state / "transactions" / transaction_id
                workspace.mkdir(mode=0o700, parents=True)
                prepared = workspace / "source"
                source = self.path(plan["source"]["path"])
                manifest = self.ops.prepare_source(source, prepared)
                if (manifest.get("version") != plan["version"]
                        or manifest.get("module_metadata", {}).get("vbios_override_per_gpu") != "1"
                        or manifest.get("prepared_source") != str(prepared)
                        or manifest.get("prepared_modules") != str(prepared / "kernel-open")
                        or any(manifest.get("source_hashes", {}).get(name) != expected
                               for name, expected in plan["source_inspection"]["source_hashes"].items())):
                    raise LifecycleError("driver adapter did not produce the validated isolated source/hash/module manifest")
                json_write(workspace / "source-manifest.json", manifest)
                self.ops.build(prepared, kernel, config.raw.get("jobs", 1), workspace / "build.log")
                built = prepared / "kernel-open"
                names = list(MODULES)
                if (built / "nvidia-peermem.ko").exists():
                    names.append("nvidia-peermem.ko")
                secure = self.ops.sign([built / name for name in names], kernel, config.raw)
                modules, metadata = {}, {}
                for name in names:
                    path = built / name
                    metadata[name] = self._check_module(path, plan["version"], kernel, name == "nvidia.ko", secure)
                    modules[name] = path.read_bytes()
                # Recheck source, package version, identities and ROM/config bytes after the long build.
                final_plan = self.plan(kernel)
                if any(final_plan[key] != plan[key] for key in ("configuration_sha256", "version", "source_inspection", "base_sha256")):
                    raise LifecycleError("enrollment/source/packages/BLS changed during build")
                targets = {self.path(f"/usr/lib/modules/{kernel}/updates/vbios-override/{name}"): data
                           for name, data in modules.items()}
                for device in config.devices:
                    target = self.path(f"/usr/lib/firmware/nvidia/{plan['version']}/vbios-override/{firmware_filename(device)}")
                    targets[target] = plan["payloads"][device["bdf"]]
                self._validate_existing(config, fleet, kernel, targets)
                journal = {"id": transaction_id, "phase": "installing", "kernel": kernel,
                           "entry": plan["entry"], "previous_default": previous, "files": []}
                if config.raw.get("boot"):
                    # Rollback may run before image publication, including for
                    # nested GRUB defaults that are menu selectors, not tokens.
                    journal["boot"] = config.raw["boot"]
                json_write(self.state / "transaction.json", journal)
                module_targets = {target: data for target, data in targets.items() if target.suffix == ".ko"}
                self._install_modules(journal, module_targets)
                for target, data in targets.items():
                    if target not in module_targets:
                        self._stage_write(journal, target, data)
                self.ops.depmod(kernel)
                for name in names:
                    chosen = self.ops.selected_module(kernel, name.removesuffix(".ko"))
                    if Path(chosen).resolve() != self.path(f"/usr/lib/modules/{kernel}/updates/vbios-override/{name}").resolve():
                        raise LifecycleError(f"depmod did not select managed {name}")
                boot_publication = self._publish_boot(plan, config, fleet, kernel, workspace, journal, targets)
                self.ops.restore_labels([*targets, *boot_publication["paths"]])
                # Byte-check everything at the commit boundary; no action can load a module.
                self._fallback(config, self._effective_fleet(config))
                for record in journal["files"]:
                    if hash_file(self.path(record["path"])) != record["after_sha256"]:
                        raise LifecycleError("staged deployment changed before boot selection")
                commit_plan = self.plan(kernel)
                if any(commit_plan[key] != plan[key] for key in ("configuration_sha256", "version", "source_inspection", "base_sha256", "generation_sha256")):
                    raise LifecycleError("enrollment/source/packages/boot inputs changed during image construction")
                environment = self.ops.grub_environment()
                self._check_option_variables(config, environment)
                if environment.get("saved_entry") != previous or environment.get("next_entry") or environment.get("prev_saved_entry"):
                    raise LifecycleError("GRUB selection changed during reconciliation")
                journal["phase"] = "selecting"
                json_write(self.state / "transaction.json", journal)
                self.ops.set_default(plan["entry"])
                if self.ops.grub_environment().get("saved_entry") != plan["entry"]:
                    raise LifecycleError("GRUB did not select the validated ready entry")
                known_kernels = fleet.get("kernels", {})
                deployment = [record for record in journal["files"] if not record.get("shared_boot")]
                known_kernels[kernel] = {"entry": plan["entry"], "driver": plan["version"], "deployment": deployment}
                fleet = dict(fleet, transaction_id=transaction_id, kernels=known_kernels,
                    normal_fallback=boot_publication["normal_fallback"],
                    last_ready={"entry": plan["entry"], "kernel": kernel, "version": plan["version"],
                                "boot_files": boot_publication["boot_files"]})
                self._record_boot_publication(fleet, plan, boot_publication, deployment)
                json_write(self.state / "fleet.json", fleet)
                journal["phase"] = "ready"
                json_write(self.state / "transaction.json", journal)
                status = {"state": "ready", "marker": "VBIOS_READY", "kernel": kernel,
                          "driver": plan["version"], "entry": plan["entry"], "module_metadata": metadata,
                          "source_manifest": str(workspace / "source-manifest.json"), "finished": time.time(),
                          "runtime_tested": False, "boot_verification": "unverified", "application_verification": "unverified",
                          "enrollment_evidence": {device["bdf"]: device_evidence(device) for device in config.devices},
                          "activation_config_sha256": plan["activation_config_sha256"], "force_driver_sha256": boot_publication.get("force_driver_sha256", digest(FORCE_BYTES)),
                          "activation_generation": ACTIVATION_GENERATION, "module_parameters": plan["module_parameters"],
                          "generation_sha256": plan["generation_sha256"], "configuration_sha256": plan["configuration_sha256"], "base_sha256": plan["base_sha256"],
                          "deployment": deployment}
                # Keep manifests and logs; discard the large expendable working copy.
                if config.raw.get("retain_build_tree") is not True:
                    try:
                        self.trusted(prepared)
                        shutil.rmtree(prepared)
                    except (LifecycleError, OSError) as problem:
                        status.setdefault("cleanup_warnings", []).append(str(problem))
                status.setdefault("cleanup_warnings", []).extend(self._prune_removed_kernels())
                if not status["cleanup_warnings"]:
                    status.pop("cleanup_warnings")
                self._retain_boots(status, config)
                json_write(status_path, status)
                json_write(attempt_path, {"state": "ready", "marker": "VBIOS_READY", "kernel": kernel,
                                          "entry": status["entry"], "reused": False, "finished": time.time()})
                return status
            except Exception as exc:
                if not owns_lock or profile_disabled:
                    # Another owner, or an explicitly disabled profile, keeps
                    # its committed status/recovery. Even writing
                    # "blocked" here would corrupt that owner's active result.
                    raise LifecycleError(str(exc)) from exc
                rollback_error = None
                if journal and journal.get("phase") != "ready":
                    # A durable fleet commit takes precedence over a later status-write error.
                    committed = self._json(self.state / "fleet.json").get("transaction_id") == journal.get("id")
                    try:
                        if committed:
                            journal["phase"] = "ready"
                            json_write(self.state / "transaction.json", journal)
                        else:
                            self._rollback(journal)
                    except Exception as problem:
                        rollback_error = str(problem)
                        journal["phase"] = "rollback-failed"
                        json_write(self.state / "transaction.json", journal)
                status = {"state": "blocked", "marker": "VBIOS_BLOCKED", "kernel": kernel,
                          "error": str(exc), "rollback_error": rollback_error, "finished": time.time()}
                preserved = journal is None and self._ready_artifacts_intact(existing, kernel)
                json_write(attempt_path, dict(status, preserved_ready=preserved,
                                             previous_ready=existing.get("entry") if preserved else None))
                if not preserved:
                    json_write(status_path, status)
                raise LifecycleError(f"{exc}" + (f"; rollback requires review: {rollback_error}" if rollback_error else "")) from exc
