"""Root-owned enrollment and exact driver/source selection."""
from __future__ import annotations
from ..limits import MAX_GPUS
from dataclasses import dataclass
import json
from pathlib import Path
import re
from .security import LifecycleError, checked_path, digest, token, source_tree_hash

HASH = re.compile(r"[0-9a-f]{64}")
BDF = re.compile(r"[0-9a-f]{4,8}:[0-9a-f]{2}:[0-1][0-9a-f]\.[0-7]")


@dataclass(frozen=True)
class Enrollment:
    raw: dict
    fingerprint: str
    devices: tuple[dict, ...]
    sources: tuple[dict, ...]
    fallback_entry: str


def load_config(path: Path, root: Path = Path("/"), *, require_enabled: bool = True) -> Enrollment:
    checked_path(path, root)
    raw_bytes = path.read_bytes()
    try:
        value = json.loads(raw_bytes)
        if value["schema_version"] != 1 or not isinstance(value["enabled"], bool) or (require_enabled and not value["enabled"]):
            raise LifecycleError("lifecycle is disabled or has unsupported configuration")
        devices = value["devices"]
        if not isinstance(devices, list) or not 1 <= len(devices) <= MAX_GPUS:
            raise LifecycleError(f"explicit selection of one through {MAX_GPUS} GPUs is required")
        seen_bdf, seen_uuid = set(), set()
        for device in devices:
            bdf, uuid = device["bdf"], device["uuid"]
            if not BDF.fullmatch(bdf) or not re.fullmatch(r"GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", uuid):
                raise LifecycleError("invalid GPU BDF/UUID")
            if bdf in seen_bdf or uuid in seen_uuid:
                raise LifecycleError("duplicate selected GPU")
            seen_bdf.add(bdf); seen_uuid.add(uuid)
            if device["architecture"] not in ("ampere", "ada", "blackwell-gb20x"):
                raise LifecycleError("GPU architecture outside Ampere/Ada/consumer-workstation GB20x scope")
            representation = device.get("representation")
            if representation not in (None, "ada-relocated-v1"):
                raise LifecycleError("unsupported ROM runtime representation")
            if representation == "ada-relocated-v1" and device["architecture"] != "ada":
                raise LifecycleError("Ada relocation requires an Ada device")
            if device.get("structurally_validated") is not True:
                raise LifecycleError("initial ROM/GPU enrollment requires structural validation")
            if "runtime_tested" in device and not isinstance(device["runtime_tested"], bool):
                raise LifecycleError("legacy runtime_tested evidence must be boolean")
            evidence = device.get("evidence", {})
            if not isinstance(evidence, dict) or evidence.get("boot", "unverified") not in ("unverified", "verified"):
                raise LifecycleError("invalid device boot evidence")
            if evidence.get("application", "unverified") not in ("unverified", "partially-applied", "applied", "not-applied"):
                raise LifecycleError("invalid device application evidence")
            if not isinstance(evidence.get("fields", {}), dict):
                raise LifecycleError("device application fields must be an observation mapping")
            for observation in evidence.get("fields", {}).values():
                if not isinstance(observation, dict) or observation.get("state", "unverified") not in ("unverified", "applied", "not-applied"):
                    raise LifecycleError("invalid per-field application observation")
            if device["vendor"] != 0x10de or not isinstance(device["device"], int):
                raise LifecycleError("invalid NVIDIA PCI identity")
            if not HASH.fullmatch(device["sha256"]) or not HASH.fullmatch(device["source_sha256"]):
                raise LifecycleError("invalid ROM provenance hash")
            if not isinstance(device["size"], int) or not 0 < device["size"] <= 4 * 1024 * 1024:
                raise LifecycleError("invalid ROM payload size")
            if not str(device["payload_path"]).startswith("/"):
                raise LifecycleError("ROM payload path must be absolute")
        retention = value.get("retain_boot_generations", 3)
        if type(retention) is not int or retention not in (2, 3):
            raise LifecycleError("retain_boot_generations must be 2 or 3")
        if "require_p2p_source" in value and not isinstance(value["require_p2p_source"], bool):
            raise LifecycleError("require_p2p_source must be boolean")
        if "auto_source" in value and not isinstance(value["auto_source"], bool):
            raise LifecycleError("auto_source must be boolean")
        sources = value["sources"]
        if not isinstance(sources, list) or not sources:
            raise LifecycleError("driver source registry is empty")
        for source in sources:
            if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", source["version"]):
                raise LifecycleError("invalid driver version in registry")
            if not str(source["path"]).startswith("/") or not isinstance(source["source_hashes"], dict) or not source["source_hashes"]:
                raise LifecycleError("source registration requires absolute path and adapter source_hashes")
            if not HASH.fullmatch(source["tree_sha256"]):
                raise LifecycleError("complete source tree fingerprint is required")
            if "p2p_preferred" in source and not isinstance(source["p2p_preferred"], bool):
                raise LifecycleError("p2p_preferred must be a boolean")
            for name, sha in source["source_hashes"].items():
                if Path(name).is_absolute() or ".." in Path(name).parts or not HASH.fullmatch(sha):
                    raise LifecycleError("invalid source registry hash")
        userspace = value.get("userspace", {"provider": "rpm"})
        if not isinstance(userspace, dict) or userspace.get("provider") not in ("rpm", "deb", "pacman", "manual"):
            raise LifecycleError("userspace requires an explicit rpm, deb, pacman or manual provider")
        if userspace["provider"] == "manual":
            if not isinstance(userspace.get("nvidia_smi"), str) or not Path(userspace["nvidia_smi"]).is_absolute():
                raise LifecycleError("manual userspace requires an absolute nvidia_smi path")
            libraries = userspace.get("libraries")
            if not isinstance(libraries, list) or len(libraries) < 2 or len(set(libraries)) != len(libraries):
                raise LifecycleError("manual userspace requires explicit NVML and CUDA library aliases")
            if any(not isinstance(name, str) or not Path(name).is_absolute() or ".." in Path(name).parts for name in libraries):
                raise LifecycleError("manual userspace library aliases must be absolute trusted paths")
            if not any(Path(name).name.startswith("libnvidia-ml.so") for name in libraries) or not any(Path(name).name.startswith("libcuda.so") for name in libraries):
                raise LifecycleError("manual userspace must validate both NVML and CUDA libraries")
        bls = value.get("bls", {})
        if not isinstance(bls, dict):
            raise LifecycleError("invalid BLS layout configuration")
        if "entry_prefix" in bls:
            prefix = token(bls["entry_prefix"], "normal entry prefix")
            if not prefix.endswith("-") or prefix.startswith("vbios-"):
                raise LifecycleError("normal BLS entry_prefix must end in '-' and identify the reviewed installation")
        variables = bls.get("option_variables", ["tuned_params", "kernelopts"])
        if not isinstance(variables, list):
            raise LifecycleError("BLS option variables must be a reviewed name list")
        for name in variables:
            if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                raise LifecycleError("invalid reviewed BLS option variable")
        supplements = bls.get("supplemental_initrd", ["$tuned_initrd"])
        if not isinstance(supplements, list):
            raise LifecycleError("BLS supplemental initrd must be a reviewed token list")
        for name in supplements:
            if name == "$tuned_initrd":
                continue
            if not isinstance(name, str) or not re.fullmatch(r"/[A-Za-z0-9_./+-]+", name) or ".." in Path(name).parts or "//" in name:
                raise LifecycleError("invalid reviewed supplemental initrd token")
        portable = "boot" in value
        if portable:
            from .boot import validate_config, entry_identity
            boot = validate_config(value)
            normal = value.get("normal_boot")
            if not isinstance(normal, dict) or normal.get("backend") != boot["backend"]:
                raise LifecycleError("portable enrollment requires its normal_boot snapshot")
            entry_identity(normal.get("entry"), boot["backend"])
            token(normal.get("kernel"), "normal kernel")
            if normal["entry"] != value.get("fallback_entry") or not HASH.fullmatch(normal.get("sha256", "")):
                raise LifecycleError("portable normal boot identity/hash mismatch")
            if normal.get("boot_files") != value.get("fallback_files") or normal["sha256"] != value.get("fallback_sha256"):
                raise LifecycleError("portable normal boot fingerprints disagree")
            for name in (normal.get("descriptor_path"), *normal.get("boot_files", {})):
                if not isinstance(name,str) or not Path(name).is_absolute() or ".." in Path(name).parts:
                    raise LifecycleError("unsafe portable boot artifact path")
        if value.get("stock_builder", "none") not in ("none", "dkms"):
            raise LifecycleError("stock_builder must be none or dkms")
        seed = value.get("seed_previous_ready")
        if seed is not None:
            if not isinstance(seed, dict):
                raise LifecycleError("invalid previous-ready seed")
            token(seed["entry"], "seed entry"); token(seed["kernel"])
            if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){2}", seed["version"]):
                raise LifecycleError("seed requires a full previous driver version")
            records = seed["boot_files"]
            if not isinstance(records, list) or len(records) < 3:
                raise LifecycleError("seed requires hashed BLS, kernel and override initramfs")
            paths = set()
            for record in records:
                name = record["path"]
                if not isinstance(name, str) or not name.startswith("/boot/") or ".." in Path(name).parts or not HASH.fullmatch(record["sha256"]) or name in paths:
                    raise LifecycleError("invalid seeded boot artifact")
                paths.add(name)
            required = {f"/boot/loader/entries/{seed['entry']}.conf", f"/boot/vmlinuz-{seed['kernel']}"}
            if portable:
                raise LifecycleError("portable seed migration requires a reviewed boot-generation adapter")
            if not required.issubset(paths) or not any(name.startswith(f"/boot/initramfs-{seed['kernel']}-") and name.endswith(".img") for name in paths):
                raise LifecycleError("seed does not identify the preserved boot entry/kernel/override image")
        if "signing" in value:
            signing = value["signing"]
            if not isinstance(signing, dict) or any(not isinstance(signing.get(name), str) or not Path(signing[name]).is_absolute() for name in ("key", "certificate")):
                raise LifecycleError("signing requires absolute key/certificate paths")
        adopted = value.get("adopt_existing", {})
        if not isinstance(adopted, dict):
            raise LifecycleError("invalid deployment adoption map")
        for name, sha in adopted.items():
            if not str(name).startswith(("/usr/lib/modules/", "/usr/lib/firmware/nvidia/")) or ".." in Path(name).parts or not HASH.fullmatch(sha):
                raise LifecycleError("invalid deployment adoption path/hash")
        fallback = entry_identity(value["fallback_entry"], boot["backend"]) if portable else token(value["fallback_entry"], "fallback BLS entry")
        if fallback.startswith("vbios-"):
            raise LifecycleError("fallback must be a separate normal BLS entry")
        if not HASH.fullmatch(value["fallback_sha256"]):
            raise LifecycleError("normal fallback entry needs its enrollment hash")
        if not isinstance(value["fallback_files"], dict) or (not value["fallback_files"] if portable else len(value["fallback_files"]) != 2):
            raise LifecycleError("fallback kernel and normal initramfs hashes are required")
        for name, sha in value["fallback_files"].items():
            if not (name.startswith("/") if portable else name.startswith("/boot/")) or ".." in Path(name).parts or not HASH.fullmatch(sha):
                raise LifecycleError("invalid normal fallback artifact fingerprint")
        if not isinstance(value.get("jobs", 1), int) or not 1 <= value.get("jobs", 1) <= 256:
            raise LifecycleError("invalid build job count")
        return Enrollment(value, digest(raw_bytes), tuple(devices), tuple(sources), fallback)
    except (KeyError, TypeError, ValueError) as exc:
        raise LifecycleError(f"malformed lifecycle configuration: {exc}") from exc


def resume_command(raw: dict) -> str:
    """The manual command that registers a matching source and rebuilds."""
    return "nvbios system post-install --source PATH" + (" --p2p-preferred" if raw.get("require_p2p_source") else "")


def select_source(config: Enrollment, version: str, inspect, root: Path) -> tuple[dict, dict]:
    candidates = [source for source in config.sources if source["version"] == version]
    candidates.sort(key=lambda item: not bool(item.get("p2p_preferred", False)))
    if not candidates:
        raise LifecycleError(f"no registered source for exact installed userspace version {version}; no driver upgrade performed")
    # A changed preferred source is a block, not permission to silently use stock.
    source = candidates[0]
    if config.raw.get("require_p2p_source", False) and not source.get("p2p_preferred", False):
        raise LifecycleError(f"no enrolled P2P source for installed driver {version}; run post-install with the matching reviewed P2P source")
    path = checked_path(Path(source["path"]) if root == Path("/") else root / source["path"].lstrip("/"), root)
    if source_tree_hash(path, root) != source["tree_sha256"]:
        raise LifecycleError("registered source/build-script tree changed; re-enrollment required")
    report = inspect(path)
    if report.get("version") != version or not report.get("supported"):
        raise LifecycleError(f"driver source structurally unsupported: {report.get('reasons', [])}")
    if report.get("source_hashes") != source["source_hashes"]:
        raise LifecycleError("registered source hashes changed; re-enrollment required")
    for name in source["source_hashes"]:
        checked_path(path / name, root)
    return source, report
