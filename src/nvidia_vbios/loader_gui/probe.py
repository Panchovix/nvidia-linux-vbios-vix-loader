"""What the loader window shows without a password: GPUs, driver, kernel, Secure Boot, boot and loader state.

Everything here is readable by a normal user: sysfs, procfs, efivars, /etc/default/grub, the /boot listing,
current.json and a few read-only commands with a 10 s timeout. Enrollment, the GRUB default and build status
are root-only; the window shows them through Details. No GTK here.
"""
from __future__ import annotations
import csv
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from ..lifecycle.__main__ import kernel_key
from ..lifecycle.platform import _SUPPORTED as PLATFORMS
from ..system_setup import EDITOR_MARKER, ENROLLED

TIMEOUT = 10
UNITS = ('nvidia-vbios-reconcile.path', 'nvidia-vbios-reconcile.timer')
SERVICE = 'nvidia-vbios-reconcile.service'
SECURE_BOOT = 'sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c'
CURRENT = 'usr/local/lib/nvidia-vbios-tools/current.json'
SOURCES = 'var/lib/nvidia-vbios/sources'
NVIDIA_SMI = '/usr/bin/nvidia-smi'
SMI_NO_DEVICES = 6         # nvidia-smi's exit code for "No devices were found": the driver initialized no GPU
SYSTEMCTL = '/usr/bin/systemctl'
# Who owns nvidia-smi decides --userspace: exit 0 means that package manager, anything else a .run install.
OWNER = {'fedora': (['/usr/bin/rpm', '-qf'], 'rpm'), 'rhel': (['/usr/bin/rpm', '-qf'], 'rpm'),
         'debian': (['/usr/bin/dpkg-query', '-S'], 'deb'), 'arch': (['/usr/bin/pacman', '-Qoq'], 'pacman')}
# `nvbios system VERB` processes that change the system; a Load now would find their locks busy.
VERBS = ('setup', 'install', 'enroll', 'reconcile', 'enable', 'disable', 'pre-install', 'post-install', 'uninstall')
# Code files `nvbios system install` copies into a release (bootstrap.py install).
RELEASE_SUFFIXES = ('.py', '.json', '.patch', '.c', '.h')


@dataclass(frozen=True)
class Gpu:
    bdf: str
    vendor: int
    device: int
    index: int | None          # nvidia-smi index; None when nvidia-smi did not answer or leaves this GPU out
    name: str
    serial: str | None
    vbios: str | None
    requested: str | None      # first 16 hex of the payload sha256 the module was asked to load at boot
    enrolled: str | None = None  # first 16 hex of the enrolled payload sha256 (setup's summary), loaded or not yet


@dataclass(frozen=True)
class System:
    kernel: str
    newest_kernel: str | None
    headers: bool
    distribution: str | None   # os-release ID
    family: str | None         # fedora, rhel, debian or arch; None when the loader does not support it
    secure_boot: bool | None
    grub_saved: bool | None    # GRUB_DEFAULT=saved with BLS; None without /etc/default/grub
    open_modules: bool | None  # None when no NVIDIA kernel module is loaded
    loaded_version: str | None
    installed_version: str | None
    userspace: str | None      # rpm, deb, pacman or manual
    plugin: bool | None        # the package hook plugin enable needs (Fedora/RHEL)
    release: str | None        # installed loader release
    release_has_setup: bool
    release_internal: bool | None
    clone_matches: bool | None
    triggers: bool
    service_active: bool
    running: tuple[str, ...]
    images: tuple[str, ...]    # override boot images for the running kernel
    old_images: bool           # override boot images for any kernel
    boot_free: int | None
    boot_needed: int | None
    saved_source: bool         # an enrolled source snapshot of the installed version exists
    distro_source: bool        # the distribution ships the source of the installed version
    smi: bool                  # nvidia-smi answered: GPU rows, or none found (SMI_NO_DEVICES)


@dataclass(frozen=True)
class Snapshot:
    system: System
    gpus: tuple[Gpu, ...]
    problems: tuple[str, ...]
    enrolled_absent: tuple[str, ...] = ()   # enrolled GPUs that are not in the machine now


def run(argv):
    """(exit code, stdout) of a read-only command; (None, '') when it cannot start or times out."""
    try:
        done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, errors='replace',
                              timeout=TIMEOUT)
    except (OSError, subprocess.SubprocessError):
        return None, ''
    return done.returncode, done.stdout


def _read(path):
    try:
        return Path(path).read_text(errors='replace')
    except OSError:
        return None


def canonical(bdf):
    domain, bus, slot = bdf.strip().lower().split(':')
    return f'{int(domain, 16):04x}:{bus}:{slot}'


def requested(dwords, binary):
    """{bdf: sha16} from the module's per-device registry parameters (the format engine.activation writes)."""
    def scopes(text):
        result, scope = {}, None
        for field in (text or '').strip().split(';'):
            key, _, value = field.partition('=')
            if key == 'pci':
                try:
                    scope = result.setdefault(canonical(value), {})
                except ValueError:
                    scope = None
            elif scope is not None:
                scope[key] = value
        return result
    flags, images, found = scopes(dwords), scopes(binary), {}
    for bdf, values in flags.items():
        image = images.get(bdf, {}).get('RmLinuxVbiosOverrideImage', '')
        match = re.fullmatch(r'[^/]+/vbios-override/' + re.escape(bdf) + r'-([0-9a-f]{16})\.bin', image)
        if values.get('RmLinuxVbiosOverride') == '2' and match:
            found[bdf] = match[1]
    return found


def enrolled_devices(root):
    """{bdf: first 16 hex of the enrolled payload sha256} from setup's world-readable summary; {} without it."""
    try:
        devices = json.loads((root / ENROLLED.lstrip('/')).read_text())['devices']
        return {canonical(device['bdf']): str(device['sha256'])[:16] for device in devices}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def gpus(root, run, problems):
    module = root / 'sys/module/nvidia/parameters'
    asked = requested(_read(module / 'NVreg_RegistryDwordsPerDevice'),
                      _read(module / 'NVreg_RegistryBinaryFilePerDevice'))
    enrolled = enrolled_devices(root)
    smi = {}
    code, out = run([NVIDIA_SMI, '--query-gpu=index,pci.bus_id,name,serial', '--format=csv,noheader'])
    if code == 0:
        for row in csv.reader(out.splitlines()):
            try:
                index, bdf, name, serial = (value.strip() for value in row)
                smi[canonical(bdf)] = (int(index), name, None if serial.startswith('[') else serial)
            except ValueError:
                problems.append(f'nvidia-smi: unexpected line {",".join(row)!r}')
    else:
        problems.append(f'nvidia-smi: {"did not run" if code is None else f"exit code {code}"}')
    found = []
    directory = root / 'sys/bus/pci/devices'
    for device in sorted(directory.iterdir()) if directory.is_dir() else ():
        try:
            vendor, pci_class = int((device / 'vendor').read_text(), 16), int((device / 'class').read_text(), 16)
            number = int((device / 'device').read_text(), 16)
        except (OSError, ValueError):
            continue
        if vendor != 0x10de or pci_class >> 16 != 3:
            continue
        bdf = canonical(device.name)
        info = {}
        for line in (_read(root / 'proc/driver/nvidia/gpus' / device.name / 'information') or '').splitlines():
            key, _, value = line.partition(':')
            info[key.strip()] = value.strip()
        index, name, serial = smi.get(bdf, (None, info.get('Model') or f'10de:{number:04x}', None))
        found.append(Gpu(bdf, vendor, number, index, name, serial, info.get('Video BIOS'), asked.get(bdf),
                         enrolled.get(bdf)))
    return (tuple(sorted(found, key=lambda gpu: (gpu.index is None, gpu.index or 0, gpu.bdf))),
            bool(smi) or code == SMI_NO_DEVICES)


def _release(root, checkout, problems):
    """(release, has setup, internal build, the clone holds the same files) from current.json (0644)."""
    text = _read(root / CURRENT)
    if text is None:
        return None, False, None, None
    try:
        current = json.loads(text)
        release, files = current['release'], {name: value['sha256'] for name, value in current['files'].items()}
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        problems.append(f'{CURRENT}: {exc}')
        return None, False, None, None
    matches = None
    package = Path(checkout or '/nonexistent') / 'src/nvidia_vbios'
    if package.is_dir():
        clone = {f'nvidia_vbios/{path.relative_to(package)}': hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in package.rglob('*') if path.is_file() and path.suffix in RELEASE_SUFFIXES}
        matches = clone == files
    return (release, 'nvidia_vbios/system_setup.py' in files, EDITOR_MARKER in files, matches)


def _running(root):
    """Loader verbs that change the system and are running now (any user's processes; /proc has no hidepid)."""
    verbs = set()
    for process in (root / 'proc').glob('[0-9]*'):
        try:
            argv = (process / 'cmdline').read_bytes().decode(errors='replace').split('\0')
        except OSError:
            continue
        for position, value in enumerate(argv[:-1]):
            if value == 'system' and argv[position + 1] in VERBS and \
                    any(Path(earlier).name == 'nvbios' for earlier in argv[:position]):
                verbs.add(argv[position + 1])
    return tuple(sorted(verbs))


def snapshot(root=Path('/'), run=run, kernel=None, checkout=None):
    root, problems = Path(root), []
    kernel = kernel or os.uname().release
    found, smi = gpus(root, run, problems)
    release = dict(line.partition('=')[::2] for line in (_read(root / 'etc/os-release') or '').splitlines())
    distribution = release.get('ID', '').strip().strip('"\'') or None
    platform = None if (root / 'run/ostree-booted').exists() else PLATFORMS.get(distribution)
    family = platform.family if platform else None

    modules = root / 'usr/lib/modules'
    kernels = sorted((path.name for path in modules.iterdir() if path.is_dir()
                      and (root / f'boot/vmlinuz-{path.name}').is_file()), key=kernel_key) if modules.is_dir() else []

    secure = root / SECURE_BOOT
    try:
        secure_boot = secure.read_bytes()[-1:] == b'\x01'
    except FileNotFoundError:
        secure_boot = False
    except OSError:
        secure_boot = None

    grub = _read(root / 'etc/default/grub')
    grub_saved = None if grub is None else bool(
        re.search(r'^GRUB_DEFAULT=[\'"]?saved[\'"]?\s*$', grub, re.M)
        and re.search(r'^GRUB_ENABLE_BLSCFG=[\'"]?true[\'"]?\s*$', grub, re.M))

    driver = _read(root / 'proc/driver/nvidia/version')
    installed_version = None
    for directory in platform.library_paths if platform else ('/usr/lib64', '/usr/lib'):
        match = re.fullmatch(r'libnvidia-ml\.so\.(\d+\.\d+(?:\.\d+)?)',
                             Path(os.path.realpath(root / directory.lstrip('/') / 'libnvidia-ml.so.1')).name)
        if match:
            installed_version = match[1]
            break

    userspace = plugin = None
    if (root / NVIDIA_SMI.lstrip('/')).exists() and family in OWNER:
        command, provider = OWNER[family]
        userspace = provider if run([*command, NVIDIA_SMI])[0] == 0 else 'manual'
    if family in ('fedora', 'rhel'):
        package = 'libdnf5-plugin-actions' if (root / 'usr/bin/dnf5').exists() else \
            'python3-dnf-plugin-post-transaction-actions'
        plugin = run(['/usr/bin/rpm', '--nosignature', '-q', package])[0] == 0

    loader, has_setup, internal, matches = _release(root, checkout, problems)
    triggers = all(run([SYSTEMCTL, 'is-enabled', unit])[0] == 0 for unit in UNITS)
    state = run([SYSTEMCTL, 'show', '--property=ActiveState', '--value', SERVICE])[1].strip()

    boot = root / 'boot'
    images = tuple(sorted(path.name for path in boot.glob(f'initramfs-{kernel}-vbios-*.img')))
    try:
        stats = os.statvfs(boot)
        boot_free = stats.f_bavail * stats.f_frsize
    except OSError:
        boot_free = None
    try:
        boot_needed = 2 * (boot / f'initramfs-{kernel}.img').stat().st_size
    except OSError:
        boot_needed = None
    version = installed_version or ''
    kmod = root / f'usr/share/nvidia-kmod-{version}'
    system = System(
        kernel=kernel, newest_kernel=kernels[-1] if kernels else None,
        headers=(modules / kernel / 'build/Makefile').is_file(), distribution=distribution, family=family,
        secure_boot=secure_boot, grub_saved=grub_saved,
        open_modules=None if driver is None else 'Open Kernel Module' in driver,
        loaded_version=(_read(root / 'sys/module/nvidia/version') or '').strip() or None,
        installed_version=installed_version, userspace=userspace, plugin=plugin, release=loader,
        release_has_setup=has_setup, release_internal=internal, clone_matches=matches, triggers=triggers,
        service_active=state not in ('', 'inactive', 'failed'), running=_running(root), images=images,
        old_images=any(boot.glob('initramfs-*-vbios-*.img')), boot_free=boot_free, boot_needed=boot_needed,
        saved_source=bool(version) and any((root / SOURCES).glob(f'{version}-*')),
        distro_source=bool(version) and (any(kmod.glob('*.tar.xz')) or (root / f'usr/src/nvidia-{version}').is_dir()),
        smi=smi)
    present = {gpu.bdf for gpu in found}
    absent = tuple(sorted(bdf for bdf in enrolled_devices(root) if bdf not in present))
    return Snapshot(system, found, tuple(problems), absent)
