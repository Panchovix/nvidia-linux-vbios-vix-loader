"""Production operations with a fixed executable set and clean environment."""
from __future__ import annotations
import csv
from contextlib import contextmanager, ExitStack
import os
import re
from pathlib import Path
import subprocess
import signal
import sys
import time
from .security import LifecycleError, checked_path, resolve_trusted_file, locked, token
from .platform import FEDORA_PLATFORM, detect_platform, package_transaction_lock

COMMANDS = {
    "bootctl": "/usr/bin/bootctl", "grub-script-check": "/usr/bin/grub-script-check",
    "grub-mkconfig": "/usr/sbin/grub-mkconfig", "update-grub": "/usr/sbin/update-grub",
    "mkinitramfs": "/usr/sbin/mkinitramfs", "unmkinitramfs": "/usr/sbin/unmkinitramfs",
    "update-initramfs": "/usr/sbin/update-initramfs",
    "mkinitcpio": "/usr/bin/mkinitcpio", "lsinitcpio": "/usr/bin/lsinitcpio",
    "ukify": "/usr/lib/systemd/ukify", "objcopy": "/usr/bin/objcopy",
    "sbverify": "/usr/bin/sbverify", "efi-readvar": "/usr/bin/efi-readvar", "openssl": "/usr/bin/openssl",
    "dpkg-query": "/usr/bin/dpkg-query", "pacman": "/usr/bin/pacman", "dkms": "/usr/sbin/dkms",
    "rpm": "/usr/bin/rpm", "modinfo": "/usr/sbin/modinfo", "make": "/usr/bin/make", "patch": "/usr/bin/patch",
    "depmod": "/usr/sbin/depmod", "dracut": "/usr/bin/dracut", "lsinitrd": "/usr/bin/lsinitrd",
    "mokutil": "/usr/bin/mokutil", "nvidia-smi": "/usr/bin/nvidia-smi",
    "systemctl": "/usr/bin/systemctl", "grub2-editenv": "/usr/bin/grub2-editenv", "restorecon": "/usr/sbin/restorecon",
}


AKMODS_UNIT_DIRECTORIES = ("/etc/systemd/system", "/usr/lib/systemd/system")

class SystemOperations:
    def __init__(self):
        if os.geteuid() != 0:
            raise LifecycleError("production reconciliation requires root")
        self._platform = detect_platform()
        self.log = None

    @property
    def platform(self):
        # Legacy isolated tests construct this adapter with __new__.
        return getattr(self, "_platform", FEDORA_PLATFORM)

    def command_path(self, name):
        candidates = {
            "modinfo": ("/usr/sbin/modinfo", "/usr/bin/modinfo"),
            "depmod": ("/usr/sbin/depmod", "/usr/bin/depmod"),
            "dkms": ("/usr/sbin/dkms", "/usr/bin/dkms"),
            "grub-mkconfig": ("/usr/sbin/grub-mkconfig", "/usr/bin/grub-mkconfig", "/usr/sbin/grub2-mkconfig"),
            "grub-script-check": ("/usr/bin/grub-script-check", "/usr/sbin/grub-script-check", "/usr/bin/grub2-script-check"),
            "ukify": ("/usr/lib/systemd/ukify", "/usr/bin/ukify"),
            "grub2-editenv": ("/usr/bin/grub2-editenv", "/usr/bin/grub-editenv", "/usr/sbin/grub-editenv"),
        }.get(name, (COMMANDS.get(name, name),))
        if self.platform.family == "arch" and name in ("modinfo", "depmod", "dkms", "grub-mkconfig"):
            candidates = tuple(sorted(candidates, key=lambda value: "/usr/bin/" not in value))
        for candidate in candidates:
            if Path(candidate).exists():
                return candidate
        return candidates[0]

    def set_log(self, path):
        checked_path(path, missing=True)
        self.log = path

    def _run(self, command, *, cwd=None, log=None, timeout=120, allow_failure=False):
        executable = self.command_path(str(command[0]))
        if not executable.startswith("/"):
            raise LifecycleError("production command must use a fixed absolute executable")
        checked_path(Path(executable).resolve())
        arguments = [executable, *[str(arg) for arg in command[1:]]]
        environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C"}
        destination = log or self.log
        stream = None
        try:
            if destination:
                checked_path(Path(destination), missing=True)
                stream = Path(destination).open("ab")
                stream.write((f"COMMAND_STARTED {time.time()} {arguments!r}\n").encode())
                stream.flush()
            process = subprocess.Popen(arguments, cwd=cwd, env=environment, stdin=subprocess.DEVNULL,
                                       stdout=stream if log else subprocess.PIPE,
                                       stderr=subprocess.STDOUT if log else subprocess.PIPE,
                                       start_new_session=True)
            if stream:
                stream.write(f"COMMAND_PID {process.pid}\n".encode())
                stream.flush()
            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Kill the whole build/process group, including compiler children.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    process.communicate(timeout=10)
                    # A parent can exit while descendants still hold the group.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.communicate(timeout=10)
                if stream:
                    stream.write(f"COMMAND_FAILED timeout pid={process.pid}\n".encode())
                    stream.flush()
                raise LifecycleError(f"{Path(executable).name} timed out; process group stopped; see {destination}") from None
            result = subprocess.CompletedProcess(arguments, process.returncode, stdout=stdout or b"", stderr=stderr or b"")
            if stream:
                if not log:
                    stream.write(result.stderr)
                stream.write((f"COMMAND_COMPLETE exit={result.returncode}\n").encode())
                stream.flush()
            if result.returncode and not allow_failure:
                raise LifecycleError(f"{Path(executable).name} failed ({result.returncode}); see {destination}")
            return result
        except subprocess.TimeoutExpired as exc:
            if stream:
                stream.write(b"COMMAND_FAILED timeout\n")
            raise LifecycleError(f"{Path(executable).name} timed out; see {destination}") from exc
        finally:
            if stream:
                stream.close()

    def _text(self, command, **kwargs):
        return self._run(command, **kwargs).stdout.decode().strip()

    def installed_version(self, config):
        """Resolve installed userspace, never the currently loaded KMD version."""
        provider = config.get("userspace", {"provider": self.platform.package_provider})
        boundary = getattr(self, "filesystem_root", Path("/"))
        def physical(name):
            return boundary / str(name).lstrip("/")
        path = resolve_trusted_file(physical(provider.get("nvidia_smi", "/usr/bin/nvidia-smi")), boundary)
        if provider["provider"] not in ("manual", self.platform.package_provider):
            raise LifecycleError("userspace package provider does not match the detected distribution")
        if self.platform.package_provider == "rpm":
            owner = self._run(["rpm", "--nosignature", "-qf", "--qf", "%{VERSION}\n", path], allow_failure=True)
            query = self._run(["rpm", "--nosignature", "-qa", "--qf", "%{NAME} %{VERSION}\n"])
            packages = []
            for line in query.stdout.decode().splitlines():
                name, _, version = line.partition(" ")
                if name.startswith("nvidia-driver-local-repo-"):
                    # A local repository RPM deploys archives/metadata, not driver
                    # userspace. Validate the narrow exception by actual file list.
                    listing = self._run(["rpm", "--nosignature", "-ql", name])
                    suffix = name.removeprefix("nvidia-driver-local-repo-")
                    base = "/var/" + name
                    allowed_repo = "/etc/yum.repos.d/nvidia-driver-local-" + suffix + ".repo"
                    files = listing.stdout.decode().splitlines()
                    metadata_only = bool(files) and all(
                        file == base or file.startswith(base + "/") or file == allowed_repo
                        or file.startswith("/usr/share/doc/" + name + "/")
                        or file.startswith("/usr/share/licenses/" + name + "/") for file in files)
                    if metadata_only:
                        continue
                actual_family = name.startswith(("xorg-x11-drv-nvidia", "nvidia-driver", "nvidia-kmod-common", "cuda-drivers"))
                versioned_library = name.startswith("libnvidia-") and re.fullmatch(r"\d+\.\d+\.\d+", version)
                if (actual_family or versioned_library) and not name.endswith(("-kmodsrc", "-devel")):
                    packages.append((name, version))
        else:
            owner, packages = self._portable_packages(path)
        label = {"rpm": "RPM", "deb": "dpkg", "pacman": "pacman"}[self.platform.package_provider]
        if provider["provider"] == "manual":
            if owner.returncode == 0 or packages:
                raise LifecycleError(f"mixed {label}/manual NVIDIA userspace is unsupported; no provider reinterpretation performed")
            versions = set()
            for alias in provider["libraries"]:
                alias_path = physical(alias)
                resolved = resolve_trusted_file(alias_path, boundary)
                stem = Path(alias).name.split(".so", 1)[0]
                if not stem.startswith(("libnvidia-", "libcuda", "libGLX_nvidia", "libEGL_nvidia", "libGLES", "libnvoptix")):
                    raise LifecycleError("unrecognized manual NVIDIA library alias")
                match = re.fullmatch(re.escape(stem) + r"\.so\.(\d+\.\d+\.\d+)", resolved.name)
                with resolved.open("rb") as stream:
                    magic = stream.read(4)
                if not match or magic != b"\x7fELF":
                    raise LifecycleError("manual userspace library lacks a full versioned ELF target")
                for checked in {alias_path, resolved}:
                    if self._package_owner(checked).returncode == 0:
                        raise LifecycleError(f"manual userspace library is {label}-owned; mixed provider refused")
                versions.add(match[1])
            if len(versions) != 1:
                raise LifecycleError("manual NVIDIA userspace libraries have mixed full versions")
            with path.open("rb") as stream:
                magic = stream.read(4)
            if path.name != "nvidia-smi" or magic != b"\x7fELF" or not os.access(path, os.X_OK):
                raise LifecycleError("manual nvidia-smi must be a trusted executable ELF file")
            response = self._run([path, "--version"], allow_failure=True)
            version_output = response.stdout.decode()
            smi_versions = re.findall(r"^\s*NVIDIA-SMI(?:\s+version)?\s*:\s*(\d+\.\d+\.\d+)\s*$", version_output, re.M | re.I)
            own_version_lines = [line for line in (version_output + "\n" + response.stderr.decode()).splitlines()
                                 if re.match(r"\s*NVIDIA-SMI", line, re.I)]
            if len(own_version_lines) > 1:
                smi_versions = []
            if response.returncode and not own_version_lines:
                # Some releases initialize NVML before printing --version and
                # stop on the expected old-KMD/new-userspace mismatch. --help
                # identifies this trusted executable without requiring NVML.
                # Never replace an explicit conflicting/partial version report.
                help_response = self._run([path, "--help"], allow_failure=True)
                lines = [line.strip() for line in help_response.stdout.decode().splitlines() if line.strip()]
                headers = [line for line in lines if re.match(r"NVIDIA\s+System\s+Management\s+Interface\b", line, re.I)]
                match = re.fullmatch(r"NVIDIA System Management Interface -- v(\d+\.\d+\.\d+)", headers[0]) if len(headers) == 1 else None
                smi_versions = ([match[1]] if help_response.returncode == 0 and match and lines[0] == headers[0] else [])
            if len(smi_versions) != 1 or smi_versions[0] not in versions:
                raise LifecycleError("manual nvidia-smi and installed libraries do not identify one full matching version")
            return smi_versions[0]
        if provider["provider"] != self.platform.package_provider or owner.returncode:
            raise LifecycleError(f"NVIDIA userspace is not {label}-owned; explicit trusted manual provider required")
        versions = set(owner.stdout.decode().strip().splitlines())
        # Two-part releases (575.64) are detected; the source registry stays
        # three-part, so they reach the driver-drift fail-safe.
        if len(versions) != 1 or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", next(iter(versions))):
            raise LifecycleError(f"ambiguous installed NVIDIA userspace {label} version")
        version = next(iter(versions))
        if any(candidate != version for _, candidate in packages):
            raise LifecycleError(f"mixed NVIDIA userspace {label} versions")
        return version

    @staticmethod
    def _upstream_version(value):
        match = re.fullmatch(r"(?:[0-9]+:)?([0-9]+\.[0-9]+(?:\.[0-9]+)?)(?:[-+~][A-Za-z0-9.+~:-]+)?", value)
        if not match:
            raise LifecycleError("NVIDIA package lacks one full upstream version")
        return match[1]

    @staticmethod
    def _driver_package(name, provider):
        name = name.split(":", 1)[0]
        # Container support and EGL platform bridges have independent releases.
        if name.startswith(("libnvidia-container", "libnvidia-egl-wayland", "libnvidia-egl-gbm", "libnvidia-egl-xlib", "libnvidia-egl-xcb")):
            return False
        if provider == "pacman":
            return bool(re.fullmatch(r"(?:lib32-)?(?:nvidia(?:-[0-9]+xx)?-utils|opencl-nvidia(?:-[0-9]+xx)?)", name))
        if name.endswith(("-dev", "-dkms", "-source")) or name.startswith(("nvidia-dkms-", "nvidia-kernel-source-")):
            return False
        return name.startswith(("libnvidia-", "libcuda1", "libnvcuvid1", "libglx-nvidia", "libegl-nvidia",
                                "libgles-nvidia", "xserver-xorg-video-nvidia", "nvidia-driver", "nvidia-utils",
                                "nvidia-smi", "nvidia-compute-utils", "nvidia-kernel-common"))

    def _package_owner(self, path):
        provider = self.platform.package_provider
        if provider == "rpm":
            return self._run(["rpm", "--nosignature", "-qf", "--qf", "%{VERSION}\n", path], allow_failure=True)
        if provider == "deb":
            result = self._run(["dpkg-query", "-S", path], allow_failure=True)
        else:
            result = self._run(["pacman", "-Qoq", path], allow_failure=True)
        if result.returncode not in (0, 1):
            raise LifecycleError("native package ownership query failed")
        return result

    def _portable_packages(self, path):
        provider = self.platform.package_provider
        owner = self._package_owner(path)
        if provider == "deb":
            query = self._run(["dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${db:Status-Status}\t${db:Status-Eflag}\n"])
            records = {}
            for line in query.stdout.decode().splitlines():
                fields = line.split("\t")
                if len(fields) != 4:
                    raise LifecycleError("malformed dpkg installed package query")
                name, version, status, error = fields
                if name in records:
                    raise LifecycleError("ambiguous dpkg package query")
                records[name] = (version, status, error)
            names = []
            if owner.returncode == 0:
                for line in owner.stdout.decode().splitlines():
                    names_field, separator, owned_path = line.rpartition(": ")
                    if not separator or owned_path != str(path):
                        raise LifecycleError("ambiguous dpkg NVIDIA executable ownership")
                    names.extend(names_field.split(", "))
            packages = []
            for name, (version, status, error) in records.items():
                if self._driver_package(name, provider):
                    if status in ("not-installed", "config-files"):
                        continue
                    if status != "installed" or error != "ok":
                        raise LifecycleError("NVIDIA dpkg package is not fully installed")
                    packages.append((name, self._upstream_version(version)))
            versions = []
            for name in names:
                if name not in records or not self._driver_package(name, provider):
                    raise LifecycleError("NVIDIA executable owner is not a recognized driver package")
                version, status, error = records[name]
                if status != "installed" or error != "ok":
                    raise LifecycleError("NVIDIA dpkg owner is not fully installed")
                versions.append(self._upstream_version(version))
        else:
            query = self._run(["pacman", "-Q"])
            records = {}
            for line in query.stdout.decode().splitlines():
                fields = line.split()
                if len(fields) != 2 or fields[0] in records:
                    raise LifecycleError("malformed or ambiguous pacman installed package query")
                records[fields[0]] = fields[1]
            packages = [(name, self._upstream_version(version)) for name, version in records.items()
                        if self._driver_package(name, provider)]
            names = owner.stdout.decode().splitlines() if owner.returncode == 0 else []
            versions = []
            for name in names:
                if name not in records or not self._driver_package(name, provider):
                    raise LifecycleError("NVIDIA executable owner is not a recognized driver package")
                versions.append(self._upstream_version(records[name]))
        if owner.returncode == 0 and len(names) != 1:
            raise LifecycleError("ambiguous installed NVIDIA userspace executable owner")
        owner = subprocess.CompletedProcess(owner.args, owner.returncode,
                                            stdout=("\n".join(versions) + "\n").encode(), stderr=owner.stderr)
        return owner, packages

    def assert_transaction_idle(self, root=None):
        boundary = Path(root) if root is not None else getattr(self, "filesystem_root", Path("/"))
        with package_transaction_lock(self.platform, boundary):
            pass

    @contextmanager
    def publication_locks(self, root=None):
        boundary = Path(root) if root is not None else getattr(self, "filesystem_root", Path("/"))
        with ExitStack() as stack:
            if self.platform.family == "fedora":
                stack.enter_context(locked(boundary / "run/akmods/akmods.lock", boundary, akmods=True))
            stack.enter_context(package_transaction_lock(self.platform, boundary))
            yield

    def coordinate_stock_build(self, kernel, config):
        if self.platform.family == "fedora":
            return self.coordinate_akmods(kernel, config)
        provider = config.get("stock_builder", "none")
        if provider == "none":
            return
        if provider != "dkms":
            raise LifecycleError("unsupported stock module builder for distribution")
        self._run(["dkms", "autoinstall", "-k", token(kernel)], timeout=3600)

    def inspect_source(self, path):
        from nvidia_vbios.driver import inspect_source
        return inspect_source(path)

    def prepare_source(self, source, destination, before_patch=None):
        from nvidia_vbios.driver import prepare_source
        return prepare_source(source, destination, before_patch=before_patch)

    def patch(self, arguments, *, log):
        """GNU patch with the arguments lifecycle.distribution_patches gives; returns its exit status."""
        if not Path(self.command_path("patch")).exists():
            raise LifecycleError("the distribution's DKMS build fixes need GNU patch: install the patch package")
        return self._run(["patch", *arguments], log=log, allow_failure=True).returncode

    def inventory(self):
        # NVML/nvidia-smi may fail after a userspace RPM update while the old
        # kernel module is still loaded. Its procfs UUID stays usable and avoids
        # any module reload during reconciliation.
        result = {}
        directory = Path("/sys/bus/pci/devices")
        for device in directory.iterdir():
            try:
                vendor = int((device / "vendor").read_text(), 16)
                pci_class = int((device / "class").read_text(), 16) >> 16
            except (FileNotFoundError, ValueError):
                continue
            if vendor != 0x10de or pci_class != 3:
                continue
            domain, bus, slot = device.name.lower().split(":")
            bdf = f"{int(domain, 16):04x}:{bus}:{slot}"
            information = Path("/proc/driver/nvidia/gpus") / device.name / "information"
            uuid = None
            if information.is_file():
                for line in information.read_text().splitlines():
                    key, separator, value = line.partition(":")
                    if separator and key.strip() == "GPU UUID" and value.strip().startswith("GPU-"):
                        uuid = value.strip()
                        break
            result[bdf] = {"bdf": bdf, "uuid": uuid, "vendor": vendor,
                           "device": int((device / "device").read_text(), 16)}
        if any(value["uuid"] is None for value in result.values()):
            response = self._run(["nvidia-smi", "--query-gpu=pci.bus_id,uuid", "--format=csv,noheader"], allow_failure=True)
            if response.returncode == 0:
                for row in csv.reader(response.stdout.decode().splitlines()):
                    if len(row) != 2:
                        raise LifecycleError("unexpected nvidia-smi GPU identity format")
                    bdf, uuid = (item.strip() for item in row)
                    domain, bus, slot = bdf.lower().split(":")
                    bdf = f"{int(domain, 16):04x}:{bus}:{slot}"
                    if bdf in result:
                        result[bdf]["uuid"] = uuid
        return result

    def validate_payload(self, data, device):
        # Kernel parser and known receiver capacity, plus the stricter parser
        # checks when the internal Vix Editor extension is present.
        from nvidia_vbios.payload import PayloadError, check_loadable_payload, optional_editor
        try:
            family = check_loadable_payload(data, device["vendor"], device["device"])
        except PayloadError as exc:
            raise LifecycleError(f"enrolled override payload: {exc}") from None
        if family != device["architecture"]:
            raise LifecycleError("enrolled payload architecture differs from selected GPU scope")
        editor = optional_editor()
        if editor is not None:
            editor.validate_strict(data, device)

    def prerequisites(self, kernel, config):
        # A separate normal entry is only a fallback if override activation is
        # confined to our managed BLS entry. Reject inherited global activation.
        for directory in (Path("/etc/modprobe.d"), Path("/usr/lib/modprobe.d")):
            if directory.exists():
                for configuration in directory.glob("*.conf"):
                    checked_path(configuration)
                    for line in configuration.read_text().splitlines():
                        if line.lstrip().startswith("#"):
                            continue
                        if "RmLinuxVbiosOverride=2" in line or "RmLinuxVbiosOverrideImage=" in line:
                            raise LifecycleError(f"global VBIOS activation must be migrated before lifecycle enrollment: {configuration}")
        build = Path(f"/usr/lib/modules/{kernel}/build")
        if not (build / "Makefile").is_file():
            raise LifecycleError(f"matching kernel-devel missing for {kernel}")
        checked_path(build.resolve())
        checked_path(build.resolve() / "Makefile")
        checked_path(Path(f"/boot/vmlinuz-{kernel}"))
        checked_path(Path(f"/boot/initramfs-{kernel}.img"))
        for name in ("make", "modinfo", "depmod", "dracut", "lsinitrd", "grub2-editenv", "mokutil"):
            checked_path(Path(COMMANDS[name]).resolve())
        import re
        grub = Path("/etc/default/grub")
        checked_path(grub)
        values = grub.read_text()
        if not re.search(r'^GRUB_DEFAULT=[\'"]?saved[\'"]?\s*$', values, re.M) or not re.search(r'^GRUB_ENABLE_BLSCFG=[\'"]?true[\'"]?\s*$', values, re.M):
            raise LifecycleError("GRUB saved default and BLS support must be enabled")
        generated = Path("/boot/grub2/grub.cfg")
        checked_path(generated)
        if not all(value in generated.read_text() for value in ("load_env", "saved_entry", "blscfg")):
            raise LifecycleError("generated GRUB configuration lacks saved-entry/BLS support")
        secure = self._text(["mokutil", "--sb-state"]).lower()
        if "secureboot enabled" in secure or "secure boot enabled" in secure:
            self._signing_paths(kernel, config)
        elif not any(value in secure for value in ("secureboot disabled", "secure boot disabled", "efi variables are not supported")):
            raise LifecycleError("cannot determine Secure Boot state")

    def _signing_paths(self, kernel, config):
        signing = config.get("signing", {})
        if not signing.get("key") or not signing.get("certificate"):
            raise LifecycleError("Secure Boot enabled but enrolled signing key/certificate not configured")
        key, certificate = Path(signing["key"]), Path(signing["certificate"])
        checked_path(key); checked_path(certificate)
        if key.stat().st_mode & 0o077:
            raise LifecycleError("Secure Boot private key must be root-only mode 0600")
        tool = Path(f"/usr/lib/modules/{kernel}/build/scripts/sign-file").resolve()
        checked_path(tool)
        if self._run(["mokutil", "--test-key", certificate], allow_failure=True).returncode:
            raise LifecycleError("Secure Boot signing certificate is not enrolled")
        return tool, key, certificate

    def build(self, source, kernel, jobs, log):
        self._run(["make", "modules", f"-j{jobs}", f"KERNEL_UNAME={kernel}"],
                  cwd=source, log=log, timeout=3600)

    def modinfo(self, path):
        return {field: self._text(["modinfo", "-F", field, path]) for field in
                ("version", "vermagic", "srcversion", "vbios_override_per_gpu", "vbios_override_param_bytes", "signer")}

    def sign(self, modules, kernel, config):
        state = self._text(["mokutil", "--sb-state"]).lower()
        if "secureboot enabled" not in state and "secure boot enabled" not in state:
            if not any(value in state for value in ("secureboot disabled", "secure boot disabled", "efi variables are not supported")):
                raise LifecycleError("cannot determine Secure Boot state before module signing")
            return False
        tool, key, certificate = self._signing_paths(kernel, config)
        for module in modules:
            self._run([tool, "sha256", key, certificate, module])
        return True

    def depmod(self, kernel):
        self._run(["depmod", "-a", kernel])

    def regenerate_initramfs(self, kernel, raw, image=None):
        from .engine import regenerate_argv
        self._run(regenerate_argv(raw, token(kernel), image), timeout=3600)

    def selected_module(self, kernel, name):
        return self._text(["modinfo", "-k", kernel, "-F", "filename", name])

    def initramfs(self, kernel, destination, targets, *, activation_config, force_config):
        # Includes are temporary input files, never installed into the host /etc.
        self._run(["dracut", "--force", "--no-uefi", "--nostrip", "--kver", kernel,
                   "--force-drivers", "nvidia", "--add-drivers", "nvidia-modeset nvidia-drm nvidia-uvm",
                   "--install", " ".join(str(path) for path in targets),
                   "--include", activation_config, "/etc/modprobe.d/zz-vbios-override-test.conf",
                   "--include", force_config, "/etc/cmdline.d/20-force_drivers.conf", destination], timeout=1200)

    def coordinate_akmods(self, kernel, config):
        # Without akmods (for example a .run driver install) there is no stock build to wait for.
        if not any((Path(directory) / "akmods@.service").exists() for directory in AKMODS_UNIT_DIRECTORIES):
            return
        # Run outside our RPM/akmods locks: akmods itself takes both locks.
        # restart also handles RemainAfterExit instances from an earlier update.
        if not Path("/run/systemd/system").exists():
            raise LifecycleError("per-kernel akmods coordination needs running systemd; retry after offline boot")
        self._run(["systemctl", "restart", f"akmods@{kernel}.service"], timeout=3600)

    def extract(self, image, member):
        result = self._run(["lsinitrd", "--file", member, image], allow_failure=True)
        return result.stdout if result.returncode == 0 else None

    def initramfs_members(self, image):
        from .initramfs import parse_lsinitrd
        try:
            return parse_lsinitrd(self._run(["lsinitrd", image]).stdout.decode("utf-8", "strict"))
        except UnicodeError as exc:
            raise LifecycleError("initramfs listing is not valid UTF-8") from exc

    def restore_labels(self, paths):
        if Path(COMMANDS["restorecon"]).exists():
            self._run(["restorecon", *paths])

    def grub_environment(self):
        return dict(line.split("=", 1) for line in self._text(["grub2-editenv", "-", "list"]).splitlines() if "=" in line)

    def set_default(self, entry):
        self._run(["grub2-editenv", "-", "set", "saved_entry=" + entry])

    def start_reconcile(self):
        if not Path("/run/systemd/system").exists():
            raise LifecycleError("systemd is not running; queued update will retry at next normal boot")
        # Fail promptly if this callback's parent still owns the transaction
        # lock. Never synchronously wait for a child which waits for the parent.
        if self.platform.family == "fedora":
            with locked(Path("/usr/lib/sysimage/rpm/.rpm.lock"), Path("/"), rpm=True):
                pass
        else:
            self.assert_transaction_idle()
        self._run(["systemctl", "start", "nvidia-vbios-reconcile.service"], timeout=7200)
        from .__main__ import installed_kernels
        from .engine import STATE, CONFIG
        from .config import load_config
        kernels = installed_kernels()
        if not kernels:
            raise LifecycleError("post-transaction has no installed kernel to reconcile")
        status_path = Path(STATE) / f"status-{kernels[-1]}.json"
        checked_path(status_path)
        import json
        status = json.loads(status_path.read_text())
        if status.get("state") == "driver-drift":
            # The fail-safe parked our modules; the update itself succeeded.
            installed = status.get("installed_driver")
            outcome = ("the normal entry boots the distribution driver without the override" if status.get("boots_normal_driver")
                       else f"the default entry {status.get('entry')} has no NVIDIA {installed} kernel module "
                            f"(depmod selects {status.get('stock_module')}, version {status.get('stock_module_version')})")
            print(f"VBIOS_DRIFT: installed NVIDIA {installed} differs from the built {status.get('built_driver')}; "
                  f"{outcome}. To restore the override: {status.get('resume')}", file=sys.stderr)
            return status
        if status.get("state") != "ready" or status.get("driver") != self.installed_version(load_config(Path(CONFIG)).raw):
            raise LifecycleError("post-transaction service did not leave the latest kernel ready for the installed userspace")
