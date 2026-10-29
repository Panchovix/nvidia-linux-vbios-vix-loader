"""`nvbios system uninstall`: remove the loader completely, also after its boot entry or the NVIDIA driver broke.

In order: the package, kernel and systemd hooks; the boot default; the override boot entries and images; the
loader's modules (then depmod, and a rebuild of a normal initramfs that embeds them); the override firmware; then the
state and, last, the runtime. Only the loader's own names are deleted, on a shared boot or EFI partition only this
system's; anything else is kept and reported. No GPU, driver or package query, no module load or unload. An incomplete
run keeps what a second run needs to finish.
"""
from __future__ import annotations
import argparse
from contextlib import ExitStack, contextmanager
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import time

from .bootstrap import Bootstrap, BootstrapError, BASE, OWNER, RUNTIME, ENABLED, ACTION_TARGETS, UNITS, _platform
from .lifecycle import initramfs
from .lifecycle.__main__ import kernel_key
from .lifecycle.boot import BootAdapter, entry_identity
from .lifecycle.config import load_config
from .lifecycle.engine import CONFIG, STATE, Reconciler, regenerate_command
from .lifecycle.portable import efi_variable
from .lifecycle.portable_hooks import KERNEL_INSTALL_TARGET
from .lifecycle.retention import _sync_parent
from .lifecycle.security import LifecycleError, LockBusy, atomic_write, checked_path, digest, locked

DATA = '/var/lib/nvidia-vbios'
SETUP_LOCK = DATA + '/setup/setup.lock'
FIRMWARE = '/usr/lib/firmware/nvidia'
UNIT_FILES = tuple(directory + name for directory in ('/usr/lib/systemd/system/', '/etc/systemd/system/')
                   for name in ('nvidia-vbios-reconcile.service', *UNITS))
CALLERS = (*ACTION_TARGETS.values(), KERNEL_INSTALL_TARGET, '/etc/kernel/postinst.d/zz-nvidia-vbios',
           '/etc/kernel/postrm.d/zz-nvidia-vbios', *UNIT_FILES)
WANTS = {'/etc/systemd/system/multi-user.target.wants/' + UNITS[0]: UNITS[0],
         '/etc/systemd/system/timers.target.wants/' + UNITS[1]: UNITS[1]}
# install() requires one of these in every hook and unit; every launcher embeds the runtime directory.
MARKERS = (b'/usr/libexec/nvidia-vbios lifecycle', b'Unit=nvidia-vbios-reconcile.service')
LAUNCHERS = ('/usr/local/bin/nvbios', '/usr/local/bin/nvbios-editor', '/usr/libexec/nvidia-vbios')
LAUNCHER = f'base = Path({RUNTIME!r})'.encode()
KERNEL = re.compile(r'[A-Za-z0-9_+-][A-Za-z0-9_.+-]*')  # a kernel release, never '.' or '..'
ENTRY = re.compile(r'vbios-([A-Za-z0-9_.+-]+)-[0-9a-f]{20}(?:-[0-9a-f]{12})?')
IMAGE = re.compile(r'initramfs-([A-Za-z0-9_.+-]+)-vbios-([0-9a-f]{20}(?:-[0-9a-f]{12})?)\.img')
MODULE = re.compile(r'nvidia(?:-current)?\.ko(?:\.(?:xz|gz|zst))?')
MANAGED = b'# Managed by nvidia-vbios lifecycle.'
# What 41_nvidia_vbios (its here-document) puts in a generated grub.cfg: it does nothing once the include is gone.
GUARD = (BootAdapter(Path('/'), {'boot': {'backend': 'grub', 'initramfs': 'dracut'}}).visibility_files()['/etc/grub.d/41_nvidia_vbios']
         .split(b"<<'NVIDIA_VBIOS_GRUB'\n", 1)[1].rsplit(b'NVIDIA_VBIOS_GRUB\n', 1)[0])
SOURCE = re.compile(rb'(?m)^\s*source\s+(?:\$prefix|\$\{prefix\})/nvidia-vbios\.cfg\s*$')
MACHINE = re.compile(rb'(?m)^\s*machine-id\s+(\S+)\s*$')
STATE_CHILDREN = ('bootstrap', 'lifecycle', 'setup', 'sources', 'roms', 'enrolled-devices.json')
ACTIVE = ('the reconcile service is running: wait until it ends (`systemctl status nvidia-vbios-reconcile.service`), '
          'then run uninstall again; stopping it during a DKMS or akmods build can leave that driver\'s modules half installed')
FOREIGN = 'not recorded by this system: another system on this computer may use it'


def _identity(entry):
    """A boot entry ID without the systemd-boot (.conf) or UKI (.efi) suffix."""
    return re.sub(r'\.(?:conf|efi)$', '', entry) if isinstance(entry, str) else None


def _kernel(entry):
    """Kernel of a loader boot entry (GRUB or BLS ID, systemd-boot .conf, UKI .efi), else None."""
    match = ENTRY.fullmatch(_identity(entry)) if isinstance(entry, str) else None
    return match[1] if match else None


def _generation(name):
    """Entry ID of a loader boot file: an entry or UKI, a Fedora image or a generation directory."""
    leaf = PurePosixPath(name).name
    match = IMAGE.fullmatch(leaf)
    return f'vbios-{match[1]}-{match[2]}' if match else _identity(leaf)


def _logical(value):
    return (isinstance(value, str) and re.fullmatch(r'/[A-Za-z0-9_./+-]+', value) is not None
            and '..' not in value.split('/') and '//' not in value)


def _public(value):
    """The report without its internal (underscore) fields."""
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if not key.startswith('_')}
    return value


def _busy(exc):
    return BootstrapError(str(exc).split(';')[0] + ': another nvbios command, a package manager or an akmods build '
                          'is running; run uninstall again when it ends')


class Uninstall(Bootstrap):
    def _boot_operations(self):
        """The profile may be missing or broken: uninstall reads the GRUB environment or the EFI variable itself."""

    def _name(self, path):
        return '/' + str(Path(path).relative_to(self.root))

    def _regular(self, name):
        """Bytes of a trusted regular file, else None."""
        try:
            path = self.path(name)
            return path.read_bytes() if stat.S_ISREG(path.lstat().st_mode) and checked_path(path, self.root) else None
        except (OSError, LifecycleError):
            return None

    def _children(self, name, match, *, directory=False):
        """Entries of a trusted directory whose names match: regular files, or real directories."""
        path = self.path(name)
        try:
            checked_path(path, self.root)
        except LifecycleError:
            return []
        if not path.is_dir():
            return []
        return [f'{name}/{child.name}' for child in sorted(path.iterdir()) if match(child.name)
                and (stat.S_ISDIR if directory else stat.S_ISREG)(child.lstat().st_mode)]

    def _ours(self, name, data):
        return digest(data) == self.owned.get(name) or any(marker in data for marker in MARKERS)

    def plan(self, *, allow_missing_module=False):
        """Read-only: what uninstall removes, keeps or refuses. No lock, no write, no GPU, driver or package query."""
        report = {'schema_version': 1, 'platform': _platform(self.ops).id, 'blocked': [], 'warnings': [], 'kept': [],
                  'next_steps': [], 'default': {}, 'kernels': {}, '_include': [], '_rebuild': {},
                  'remove': {group: [] for group in ('automation', 'boot', 'modules', 'firmware', 'state', 'runtime')}}
        raw = config = None
        if self.path(CONFIG).exists():
            try:
                raw = self._read(CONFIG)
                config = load_config(self.path(CONFIG), self.root, require_enabled=False)
            except (LifecycleError, OSError) as exc:
                report['warnings'].append(f'{CONFIG}: {exc}; the boot layout comes from the recorded boot generations')
            raw = raw if isinstance(raw, dict) else None
        try:
            fleet = self._read(STATE + '/fleet.json')
        except (LifecycleError, OSError) as exc:
            fleet = {}
            report['warnings'].append(f'{STATE}/fleet.json: {exc}')
        fleet = fleet if isinstance(fleet, dict) else {}
        try:
            self.owned = self._owners()['files']
        except (LifecycleError, OSError) as exc:
            self.owned = {}
            report['warnings'].append(f'{OWNER}: {exc}; files are recognized by their loader marker')
        boot = raw.get('boot') if raw else None
        records = fleet.get('boot_generations')
        layouts = [boot, *(record.get('boot') for record in (records.values() if isinstance(records, dict) else ())
                           if isinstance(record, dict))]
        layouts = [layout for layout in layouts if isinstance(layout, dict)]
        # Backend: from the profile, else from a recorded boot generation, else unknown (None).
        backend = ('fedora-bls' if raw is not None and not isinstance(boot, dict) else
                   layouts[0].get('backend') if layouts else 'fedora-bls' if fleet.get('kernels') or fleet.get('last_ready') else None)
        report.update(boot_backend=backend, _boot=layouts[0] if layouts else {})
        uki = boot.get('uki') if isinstance(boot, dict) and isinstance(boot.get('uki'), dict) else {}
        signing = [item for item in (raw.get('signing') if raw else None, uki.get('signing')) if isinstance(item, dict)]
        self.protected = {item[name] for item in signing for name in ('key', 'certificate') if isinstance(item.get(name), str)}
        ids, recorded = self._records(fleet, report)
        self._plan_automation(report)
        self._plan_modules(report, allow_missing_module)
        self._plan_boot(report, layouts, ids)
        self._plan_default(report, config, ids)
        self._plan_images(report)
        self._plan_files(report)
        report['_recorded'] = sorted(name for name in recorded if isinstance(name, str) and name.startswith('/')
                                     and '..' not in name.split('/') and self.path(name).exists())
        work = (any(report['remove'].values()) or report['_include'] or report['_rebuild']
                or any(item['state'] == 'planned' for item in report['default'].values())
                or any(item['_depmod'] for item in report['kernels'].values()))
        report['state'] = 'not-installed' if not work else 'blocked' if report['blocked'] else 'planned'
        return report

    def _records(self, fleet, report):
        """This system's boot entry IDs and the files it recorded as the loader's (modules, firmware, entries, images,
        copies), from its fleet, Fedora boot history and open transaction: gone after a removal."""
        try:
            history = self._read(STATE + '/boot-history.json').get('generations', {})
            journal = self._read(STATE + '/transaction.json')
        except (LifecycleError, OSError, AttributeError) as exc:
            history, journal = {}, {}
            report['warnings'].append(f'{STATE}: {exc}')
        ids, recorded = set(), set()
        try:
            generations, kernels = fleet.get('boot_generations', {}), fleet.get('kernels', {})
            ids.update((fleet.get('last_ready', {}).get('entry'), journal.get('entry'), *generations, *history,
                        *(record.get('managed_id') for record in generations.values()),
                        *(record.get('entry') for record in kernels.values())))
            recorded.update(item['path'] for record in (*generations.values(), *kernels.values()) if record.get('state') != 'removed'
                            for item in record.get('files', record.get('deployment', [])))
            recorded.update(name for record in history.values() if record.get('state') != 'removed' for name in record['files'])
        except (AttributeError, KeyError, TypeError):
            pass
        return {_identity(entry) for entry in ids if isinstance(entry, str)}, recorded

    def _plan_automation(self, report):
        remove = report['remove']['automation']
        for name in CALLERS:
            path = self.path(name)
            try:
                mode = path.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(mode) and name in UNIT_FILES and os.readlink(path) == '/dev/null':
                remove.append(name)  # a mask of the loader's own unit
            elif stat.S_ISREG(mode) and self._ours(name, path.read_bytes()):
                remove.append(name)  # also when edited, as long as it still calls the runner
            else:
                report['kept'].append({'path': name, 'reason': 'no loader marker'})
        for name, unit in WANTS.items():
            path = self.path(name)
            if path.is_symlink() and PurePosixPath(os.readlink(path)).name == unit:
                remove.append(name)
        if self.path(ENABLED).is_file():
            remove.append(ENABLED)

    def _plan_modules(self, report, allow):
        """The loader's module directories per kernel, and whether each installed kernel keeps another nvidia.ko."""
        root = _platform(self.ops).module_root
        base = self.path(root)
        if base.is_symlink() or not base.is_dir():
            return
        kernels, remove = report['kernels'], report['remove']['modules']
        def record(kernel):
            return kernels.setdefault(kernel, {'installed': False, 'loader_modules': [], '_depmod': False, '_nvidia': False})
        for path in sorted(base.iterdir()):
            if path.is_symlink() or not path.is_dir():
                continue
            if path.name.startswith('.vbios-'):
                # Fail-safe parking, staging and rollback leftovers; .vbios-uninstall- is a run that stopped in S4.
                remove.append(self._name(path))
                parked = re.fullmatch(rf'\.vbios-uninstall-({KERNEL.pattern})-[0-9]+', path.name)
                if parked:
                    item = record(parked[1])
                    item['loader_modules'].append(self._name(path))
                    item['_nvidia'] |= (path / 'nvidia.ko').is_file()
                continue
            live = path / 'updates/vbios-override'
            installed = (path / 'kernel').is_dir() or (path / 'modules.builtin').is_file()
            if not KERNEL.fullmatch(path.name) or not (installed or live.is_dir()):
                continue
            item = record(path.name)
            item['installed'] = installed
            if live.is_dir() and not live.is_symlink():
                item['loader_modules'].insert(0, self._name(live))
                item['_nvidia'] |= (live / 'nvidia.ko').is_file()
                remove.append(self._name(live))
            # A module index that still names them (a run that stopped after deleting them) needs depmod too.
            item['_depmod'] = installed and (path / 'modules.dep').is_file() and b'updates/vbios-override/' in (path / 'modules.dep').read_bytes()
        for kernel, item in kernels.items():
            item['_depmod'] = item['installed'] and bool(item['loader_modules'] or item['_depmod'])
            if not item['installed']:
                continue
            other = self._other_module(self.path(f'{root}/{kernel}'))
            item['nvidia_module'] = self._name(other) if other else 'missing'
            if item['_nvidia'] and not other:
                # While the loader's module is there, DKMS refuses a module that is not newer than it, unless --force.
                dkms = (f'`dkms autoinstall -k {kernel}`' if allow else f'`dkms install --force NAME/VERSION -k {kernel}` (as '
                        f'`dkms status` lists it: DKMS can refuse to install over the loader\'s module)')
                fix = (f'with a .run driver `sh NVIDIA-Linux-x86_64-VERSION.run --kernel-module-only --kernel-name={kernel}`; with a '
                       f'package driver `akmods --force --kernels {kernel}`, a reinstall of its kernel module package or {dkms}')
                if allow:
                    report['next_steps'].append(f'{kernel} has no NVIDIA kernel module now: install the driver\'s own module for it ({fix})')
                else:
                    report['blocked'].append(f'{kernel} would be left without an NVIDIA kernel module (the loader\'s are its only ones): '
                                             f'install the driver\'s own module for it ({fix}) and run uninstall again, '
                                             f'or add --allow-missing-module and install it afterwards')

    def _other_module(self, directory):
        """An nvidia.ko of this kernel outside the loader's directory (distribution, DKMS, akmods, .run), else None."""
        skip = {directory / 'build', directory / 'source', directory / 'updates/vbios-override'}
        seen = set()
        for current, names, files in os.walk(directory, followlinks=True):
            info = os.stat(current)
            if (info.st_dev, info.st_ino) in seen:
                names[:] = []
                continue
            seen.add((info.st_dev, info.st_ino))
            names[:] = [name for name in names if Path(current, name) not in skip]
            for name in sorted(files):
                if MODULE.fullmatch(name) and os.path.isfile(os.path.join(current, name)):
                    return Path(current, name)
        return None

    def _plan_default(self, report, config, ids):
        """The loader's default boot choice and the normal entry that replaces it; any other choice is kept. The EFI
        variable serves every system on the computer: it is cleared only for an entry of this system."""
        backend = report['boot_backend']
        grubenv = any(self.path(name).is_file() for name in ('/boot/grub2/grubenv', '/boot/grub/grubenv'))
        if backend in ('fedora-bls', 'grub') or (backend not in ('systemd-boot', 'uki') and grubenv):
            try:
                saved = self.ops.grub_environment().get('saved_entry')
            except (LifecycleError, OSError) as exc:
                report['blocked'].append(f'cannot read the GRUB boot selection ({exc}): mount /boot (and the EFI partition '
                                         f'if it is separate), then run uninstall again')
            else:
                ours = bool(saved) and (_kernel(saved) is not None or _identity(saved) in ids)
                report['default']['grub'] = ({'from': saved, 'to': self._normal(saved, report, config), 'state': 'planned'}
                                             if ours else {'from': saved, 'state': 'kept'})
                if ours and backend == 'grub' and re.search(rb'(?m)^GRUB_DEFAULT=[\'"]?saved[\'"]?\s*$',
                                                           self._regular('/etc/default/grub') or b''):
                    menu = report['_boot'].get('grub_config', '/boot/grub/grub.cfg')
                    report['next_steps'].append(f'optional: /etc/default/grub keeps GRUB_DEFAULT=saved; if you set it only for '
                                                f'the loader, set GRUB_DEFAULT=0 again, run `update-grub` (or `grub-mkconfig '
                                                f'-o {menu}`) and `grub-set-default 0`: GRUB then starts the newest kernel')
        try:
            current = efi_variable(self.root, 'LoaderEntryDefault')
        except (LifecycleError, OSError) as exc:
            current = ''
            report['warnings'].append(f'LoaderEntryDefault: {exc}')
        if current and _identity(current) in ids:
            report['default']['efi'] = {'from': current, 'to': '', 'state': 'planned'}

    def _normal(self, saved, report, config):
        """The normal GRUB entry that replaces the loader's, preferring a kernel that keeps an NVIDIA module: with BLS
        (Fedora, which makes each new kernel the default) the kernel the loader's entry booted, else the newest one,
        whose entry in a generated grub.cfg is the top-level one that follows later kernels; '0' (GRUB's first entry)
        when none resolves."""
        kernels, backend = report['kernels'], report['boot_backend']
        newest = sorted((kernel for kernel, item in kernels.items() if item['installed']), key=kernel_key, reverse=True)
        order = newest if backend == 'grub' else [_kernel(saved), *newest]
        try:
            finder = BootAdapter(self.root, {'boot': report['_boot']}) if backend == 'grub' else Reconciler(self.root, self.ops)
        except (LifecycleError, OSError, ValueError):
            return '0'
        found = []
        for kernel in dict.fromkeys(kernel for kernel in order if kernel):
            try:
                entry = finder.discover(kernel).entry_id if backend == 'grub' else finder._drift_normal(config, kernel)
                found.append((kernels.get(kernel, {}).get('nvidia_module', 'missing') != 'missing', entry_identity(entry, 'grub')))
            except (LifecycleError, OSError, ValueError, KeyError):
                continue
        return next((entry for usable, entry in found if usable), found[0][1] if found else '0')

    def _plan_boot(self, report, layouts, ids):
        """Boot files under the loader's own names, in deletion order: GRUB include and generator, descriptors,
        images and generation directories, then temporaries of an interrupted write. A boot or EFI partition can
        hold another system's loader files too: entries, images and generation directories go only under an ID
        this system recorded, or for a Type #1 entry with this system's machine-id; the others are kept."""
        roots = []
        for layout in layouts:
            # BootAdapter's roots: without an esp, boot_root or xbootldr key, systemd-boot and UKI use /boot.
            base = layout.get('xbootldr', layout.get('boot_root', layout.get('esp', '/boot')))
            roots += [base, layout.get('esp', base)] if layout.get('backend') in ('systemd-boot', 'uki') else []
            roots += [layout[key] for key in ('boot_root', 'xbootldr', 'esp') if key in layout]
        recorded = list(dict.fromkeys(name for name in roots if _logical(name)))
        menus = dict.fromkeys(('/boot/grub/grub.cfg', '/boot/grub2/grub.cfg',
                               *(layout['grub_config'] for layout in layouts if _logical(layout.get('grub_config')))))
        for name in recorded:
            path = self.path(name)
            if path.is_dir() and not os.path.ismount(path) and not any(
                    (path / child).is_dir() for child in ('loader', 'EFI', 'grub', 'grub2', 'nvidia-vbios')):
                report['blocked'].append(f'{name} looks unmounted (no loader, EFI or grub directory): mount the boot or EFI '
                                         f'partition there, then run uninstall again')
        first, entries, images, temporary = [], [], [], []
        for menu in menus:
            directory = str(PurePosixPath(menu).parent)
            include, data = directory + '/nvidia-vbios.cfg', self._regular(directory + '/nvidia-vbios.cfg')
            if data is not None and MANAGED not in data:
                report['kept'].append({'path': include, 'reason': 'no loader marker'})
            elif data is not None:
                text = self._regular(menu) or b''
                if SOURCE.search(text.replace(GUARD, b'')):
                    # A hand-written grub.cfg sources it unguarded: GRUB reports a missing file at every boot.
                    if data != MANAGED + b'\n':
                        report['_include'].append(include)
                    report['kept'].append({'path': include, 'reason': f'{menu} sources it; left empty'})
                    report['next_steps'].append(f'delete the line `source $prefix/nvidia-vbios.cfg` from {menu}, then delete {include}')
                else:
                    first.append(include)
                    if GUARD in text:
                        report['next_steps'].append(f'optional: `update-grub` (or `grub-mkconfig -o {menu}`) drops the inactive '
                                                    f'nvidia-vbios block from {menu}')
            entries += self._children(directory, lambda name: name == 'nvidia-vbios-entries', directory=True)
            temporary += self._children(directory, lambda name: name.startswith('.vbios-'))
        hook = '/etc/grub.d/41_nvidia_vbios'
        data = self._regular(hook)
        if data is not None:
            if MANAGED in data:
                first.append(hook)
            else:
                report['kept'].append({'path': hook, 'reason': 'no loader marker'})
        temporary += self._children('/etc/grub.d', lambda name: name.startswith('.vbios-'))
        scan = list(dict.fromkeys(('/boot', '/efi', '/boot/efi', *recorded)))
        descriptors = [name for root in scan for name in (
            *self._children(root + '/loader/entries', lambda name: name.endswith('.conf') and _kernel(name) is not None),
            *self._children(root + '/EFI/Linux', lambda name: name.endswith('.efi') and _kernel(name) is not None))]
        machine = (self._regular('/etc/machine-id') or b'').strip()
        for name in descriptors:
            match = MACHINE.search(self._regular(name) or b'') if name.endswith('.conf') else None
            if machine and match and match[1] == machine:
                ids.add(_generation(name))  # this system's entry, also when no record names it
        for root in scan:
            images += self._children(root, lambda name: IMAGE.fullmatch(name) is not None)
            images += self._children(root + '/nvidia-vbios', lambda name: True, directory=True)
            for directory in ('', '/loader/entries', '/EFI/Linux'):
                temporary += self._children(root + directory, lambda name: name.startswith('.vbios-'))
        foreign = [name for name in descriptors + images if _generation(name) not in ids]
        report['kept'] += [{'path': name, 'reason': FOREIGN} for name in foreign]
        if foreign:
            report['next_steps'].append('if no other system on this computer uses the loader, delete by hand: ' + ', '.join(foreign))
        report['remove']['boot'] += list(dict.fromkeys(name for name in first + entries + descriptors + images + temporary
                                                       if name not in foreign))

    def _normal_image(self, kernel, backend, boot):
        """(image, state) of the normal initramfs of `kernel`: 'contains-override', 'without-override' or 'unknown'."""
        try:
            if backend == 'fedora-bls':
                image = f'/boot/initramfs-{kernel}.img'
                members = self.ops.initramfs_members(checked_path(self.path(image), self.root))
            elif boot:
                image = BootAdapter(self.root, {'boot': boot}).discover(kernel).initrd_path
                path = checked_path(self.path(image), self.root)
                members = (self.ops.portable_members(path) if hasattr(self.ops, 'portable_members')
                           else initramfs.list_members(self.ops, path, config={'boot': boot}))
            else:
                return None, 'unknown'
        except (LifecycleError, OSError, ValueError, KeyError):
            return None, 'unknown'
        pattern = re.compile(rf'(?:usr/)?lib/modules/{re.escape(kernel)}/updates/vbios-override/')
        return image, 'contains-override' if any(pattern.match(member) for member in members) else 'without-override'

    def _plan_images(self, report):
        """Normal initramfs images that early-load the loader's module: they are rebuilt after depmod. A normal UKI
        embeds its initrd: dracut or update-initramfs would write a bare initramfs over it, so it is left to the tool
        that made it, except mkinitcpio -P, which also rebuilds the UKIs of its presets."""
        backend, boot = report['boot_backend'], report['_boot']
        profile = {'boot': boot} if boot else {}
        for kernel, item in report['kernels'].items():
            if not item['installed']:
                continue
            image, state = self._normal_image(kernel, backend, boot)
            uki = bool(image) and image.endswith('.efi')
            manual = uki and boot.get('initramfs') != 'mkinitcpio'
            output = image if boot and boot.get('initramfs') == 'dracut' else None
            command = (f'kernel-install add {kernel} /usr/lib/modules/{kernel}/vmlinuz' if manual else
                       regenerate_command(profile, kernel, output) if backend else None)
            item.update(normal_initramfs=state, rebuild=command if state == 'contains-override' else None)
            if state == 'contains-override':
                report['_rebuild'][kernel] = {'image': image, 'profile': profile, 'output': output, 'uki': uki, 'manual': manual}
            elif state == 'unknown' and (item['loader_modules'] or item['_depmod']):
                report['next_steps'].append(f'check that the normal initramfs of {kernel} has no updates/vbios-override module, '
                                            f'or rebuild it' + (f' with `{command}`' if command else ''))

    def _plan_files(self, report):
        """Firmware, state and runtime: the loader's own directories; their other children are kept."""
        firmware = self.path(FIRMWARE)
        if firmware.is_dir() and not firmware.is_symlink():
            for version in sorted(firmware.iterdir()):
                target = version / 'vbios-override'
                if not version.is_symlink() and target.is_dir() and not target.is_symlink():
                    report['remove']['firmware'].append(self._name(target))
        state, runtime = report['remove']['state'], report['remove']['runtime']
        for name in LAUNCHERS:
            data = self._regular(name)
            if data is not None and (digest(data) == self.owned.get(name) or LAUNCHER in data):
                runtime.append(name)
            elif data is not None:
                report['kept'].append({'path': name, 'reason': 'not a loader launcher'})
        for name, sha in self.owned.items():
            # Owned files outside the loader directories (internal builds: the archived legacy state).
            if isinstance(name, str) and name not in (*CALLERS, *LAUNCHERS) and not name.startswith(
                    ('/etc/nvidia-vbios/', DATA + '/', RUNTIME + '/')):
                data = self._regular(name)
                if data is not None and digest(data) == sha:
                    state.append(name)
        for directory, known in (('/etc/nvidia-vbios', ('lifecycle.json',)), (DATA, STATE_CHILDREN)):
            path = self.path(directory)
            if path.is_symlink() or not path.is_dir():
                continue
            for child in sorted(path.iterdir()):
                if child.name in known or child.name.startswith('.vbios-'):
                    state.append(f'{directory}/{child.name}')
                else:
                    report['kept'].append({'path': f'{directory}/{child.name}', 'reason': 'not created by the loader'})
        if self.path(RUNTIME).is_dir() and not self.path(RUNTIME).is_symlink():
            runtime.append(RUNTIME)

    @contextmanager
    def _package_locks(self):
        """The locks reconcile takes: no package transaction, kernel hook or akmods build runs during the removal."""
        if hasattr(self.ops, 'publication_locks'):
            with self.ops.publication_locks(self.root):
                yield
            return
        with locked(self.path('/run/akmods/akmods.lock'), self.root, akmods=True), \
                locked(self.path('/usr/lib/sysimage/rpm/.rpm.lock'), self.root, rpm=True):
            yield

    def uninstall(self, *, dry_run=False, allow_missing_module=False):
        report = self.plan(allow_missing_module=allow_missing_module)
        if dry_run or report['state'] != 'planned':
            return dict(_public(report), dry_run=dry_run)
        if self.ops.reconcile_active():
            raise BootstrapError(ACTIVE)
        try:
            with ExitStack() as stack:
                if self.path(STATE).is_dir():
                    stack.enter_context(locked(self.path(STATE + '/reconcile.lock'), self.root))
                if self.ops.reconcile_active():
                    raise BootstrapError(ACTIVE)
                stack.enter_context(self._package_locks())
                report = self.plan(allow_missing_module=allow_missing_module)  # again, under the locks
                if report['state'] != 'planned':
                    return dict(_public(report), dry_run=False)
                if self.path(STATE).is_dir():
                    self.ops.set_log(self.path(STATE + '/uninstall-commands.log'))
                report.update(removed={group: [] for group in report['remove']}, problems=[])
                self._automation(report)
                if self._default(report):
                    self._boot(report)
                    self._modules(report, allow_missing_module)
                    self._images(report)
                    self._firmware(report)
                final = self.plan(allow_missing_module=True)
                report['problems'] += self._leftovers(final)
                if not report['problems']:
                    self._final(report, final)
        except LockBusy as exc:
            raise _busy(exc) from None
        report['state'] = 'incomplete' if report['problems'] else 'uninstalled'
        if not report['problems']:
            report['next_steps'].append('reboot: until then the running system keeps the modules it loaded '
                                        '(do not suspend or start CUDA work before the reboot)')
        report['next_steps'] = list(dict.fromkeys(report['next_steps']))
        del report['remove']  # the plan; `removed` says what went
        return dict(_public(report), dry_run=False)

    def _delete(self, name, report, group):
        """Remove a planned file, link (never followed) or whole loader directory, unless it holds a signing key."""
        if any(key == name or key.startswith(name + '/') for key in self.protected):
            report['kept'].append({'path': name, 'reason': 'holds a signing key or certificate named in the profile'})
            return
        path = self.path(name)
        try:
            mode = path.lstat().st_mode
            checked_path(path.parent, self.root)
        except FileNotFoundError:
            return
        except LifecycleError as exc:
            report['kept'].append({'path': name, 'reason': str(exc)})
            return
        if stat.S_ISDIR(mode):
            shutil.rmtree(path)
        else:
            path.unlink()
        _sync_parent(path)
        report['removed'][group].append(name)

    def _rmdir(self, name):
        try:
            os.rmdir(self.path(name))
        except OSError:
            pass  # not empty, or already gone

    def _automation(self, report):
        """S1: hooks and units first: a hook left behind would call the runner that S7 deletes."""
        names = report['remove']['automation']
        units = any(name.startswith(('/usr/lib/systemd/', '/etc/systemd/')) for name in names)
        if units:
            self.ops.retire_triggers()
        for name in names:
            data = self._regular(name)
            if name != ENABLED and data is not None and not self._ours(name, data):
                report['kept'].append({'path': name, 'reason': 'changed during uninstall'})
                continue
            self._delete(name, report, 'automation')
        if units:
            self.ops.daemon_reload()

    def _default(self, report):
        """S2, before any entry is deleted: a normal GRUB entry becomes the default, the loader's systemd-boot
        default is cleared. False when GRUB kept the loader's entry: its files then stay, so the computer boots."""
        grub = report['default'].get('grub', {})
        if grub.get('state') == 'planned':
            try:
                self.ops.set_default(grub['to'])
                selected = self.ops.grub_environment().get('saved_entry')
            except (LifecycleError, OSError) as exc:
                selected = str(exc)
            grub['state'] = 'selected' if selected == grub['to'] else 'failed'
            if grub['state'] == 'failed':
                report['problems'].append(f'could not make {grub["to"]} the GRUB default ({selected}); the loader boot '
                                          f'entries, modules and files stay')
                return False
        efi = report['default'].get('efi', {})
        if efi.get('state') == 'planned':
            boot = report['_boot']
            esp = boot.get('esp') or boot.get('xbootldr') or boot.get('boot_root') or ('/boot' if boot else None)
            arguments = ['bootctl', *([f'--esp-path={esp}'] if _logical(esp) else []),
                         *([f'--boot-path={boot["xbootldr"]}'] if _logical(boot.get('xbootldr')) else [])]
            try:
                self.ops._run([*arguments, 'set-default', ''])  # an empty ID unsets LoaderEntryDefault
                current = efi_variable(self.root, 'LoaderEntryDefault')
                error = None if current != efi['from'] and _kernel(current) is None else f'it is still {current}'
            except (LifecycleError, OSError) as exc:
                error = str(exc)
            efi['state'] = 'failed' if error else 'cleared'
            if error:
                # systemd-boot skips a default whose entry is gone, so the next boot still takes another entry.
                report['warnings'].append(f'could not clear LoaderEntryDefault {efi["from"]}: {error}')
                report['next_steps'].append("after booting the installed system, run `sudo bootctl set-default ''`")
        return True

    def _boot(self, report):
        """S3: the GRUB include first (left empty when a hand-written grub.cfg sources it), then entries, then images."""
        for name in report['_include']:
            if MANAGED in (self._regular(name) or b''):
                atomic_write(self.path(name), MANAGED + b'\n', 0o644)
        for name in report['remove']['boot']:
            self._delete(name, report, 'boot')
            if PurePosixPath(name).parent.name == 'nvidia-vbios':
                self._rmdir(str(PurePosixPath(name).parent))  # once no generation, of any system, is left in it

    def _selected(self, kernel):
        """The nvidia.ko depmod now selects for `kernel`, and its version; 'missing' without one."""
        try:
            module = Path(self.ops.selected_module(kernel, 'nvidia'))
        except LifecycleError:
            return 'missing', None
        name = self._name(module) if module.is_relative_to(self.root) else str(module)
        try:
            return name, self.ops.modinfo(module).get('version')
        except (LifecycleError, OSError, ValueError):
            return name, None

    def _modules(self, report, allow):
        """S4: park a kernel's loader modules outside its tree, run depmod, and delete them once depmod selects another
        nvidia.ko. Without one (and without --allow-missing-module) they go back and the run is incomplete."""
        root = _platform(self.ops).module_root
        claimed = set()
        for kernel, item in report['kernels'].items():
            claimed.update(item['loader_modules'])
            live = f'{root}/{kernel}/updates/vbios-override'
            if not item['installed']:
                for name in item['loader_modules']:
                    self._delete(name, report, 'modules')
                self._rmdir(f'{root}/{kernel}/updates')
                self._rmdir(f'{root}/{kernel}')
                continue
            if not item['_depmod']:
                continue
            parked = [name for name in item['loader_modules'] if name != live]
            if live in item['loader_modules']:
                # Outside {kernel}/, which depmod scans; the name tells a later run whose modules these are.
                parked.append(f'{root}/.vbios-uninstall-{kernel}-{time.time_ns()}')
                checked_path(self.path(live), self.root)
                os.rename(self.path(live), self.path(parked[-1]))
            failure = None
            try:
                self.ops.depmod(kernel)
                module, version = self._selected(kernel)
                if module == 'missing' and item['_nvidia'] and not allow:
                    failure = (f'depmod selects no other nvidia.ko for {kernel} (found {item["nvidia_module"]}): the loader '
                               f'modules stay; install the driver\'s own module for it and run uninstall again, or add '
                               f'--allow-missing-module')
            except (LifecycleError, OSError) as exc:
                module, version, failure = 'missing', None, f'depmod {kernel}: {exc}; the loader modules stay'
            item.update(nvidia_module=module, nvidia_module_version=version, _restored=bool(failure))
            if failure:
                if parked and not self.path(live).exists():
                    os.rename(self.path(parked[-1]), self.path(live))
                    try:
                        self.ops.depmod(kernel)
                    except (LifecycleError, OSError) as exc:
                        failure += f'; depmod after restoring them: {exc}'
                report['problems'].append(failure)
                continue
            for name in parked:
                self._delete(name, report, 'modules')
        for name in report['remove']['modules']:
            if name not in claimed:
                self._delete(name, report, 'modules')

    def _images(self, report):
        """S5: rebuild normal images that embed the loader's module, now that depmod selects another one."""
        done = set()
        for kernel, rebuild in report['_rebuild'].items():
            item = report['kernels'][kernel]
            if item.get('_restored') or rebuild['manual']:
                continue  # its modules went back (a rebuild would embed them again), or a normal UKI: see _leftovers
            if item['rebuild'] not in done:  # mkinitcpio -P rebuilds every kernel at once
                done.add(item['rebuild'])
                path = self.path(rebuild['image'])
                try:
                    if shutil.disk_usage(path.parent).free < 2 * path.stat().st_size:
                        raise LifecycleError(f'not enough free space in {PurePosixPath(rebuild["image"]).parent}')
                    self.ops.regenerate_initramfs(kernel, rebuild['profile'], rebuild['output'])
                except (LifecycleError, OSError) as exc:
                    report['warnings'].append(f'`{item["rebuild"]}`: {exc}')
            item['normal_initramfs'] = self._normal_image(kernel, report['boot_backend'], report['_boot'])[1]

    def _firmware(self, report):
        """S6: the override payloads given to the driver; a version directory goes too when only they were in it."""
        for name in report['remove']['firmware']:
            self._delete(name, report, 'firmware')
            self._rmdir(str(PurePosixPath(name).parent))
        if report['remove']['firmware']:
            self._rmdir(FIRMWARE)

    @staticmethod
    def _leftovers(final):
        """What a complete removal took away; the run is incomplete while any of it is left."""
        problems = [f'{group} files remain: {", ".join(final["remove"][group])}'
                    for group in ('automation', 'boot', 'modules', 'firmware') if final['remove'][group]]
        if final['default'].get('grub', {}).get('state') == 'planned':
            problems.append(f'the GRUB default is still the loader entry {final["default"]["grub"]["from"]}')
        problems += [f'the normal UKI {rebuild["image"]} still embeds the loader module: regenerate it with the tool that made '
                     f'it, for example `{final["kernels"][kernel]["rebuild"]}`' if rebuild['uki'] else
                     f'the normal initramfs of {kernel} still embeds the loader module: rebuild it with '
                     f'`{final["kernels"][kernel]["rebuild"]}`' for kernel, rebuild in final['_rebuild'].items()]
        problems += [f'the module index of {kernel} still names the loader modules: run `depmod -a {kernel}`'
                     for kernel, item in final['kernels'].items() if item['_depmod'] and not item['loader_modules']]
        if final['_recorded']:
            problems.append('files the loader recorded remain: ' + ', '.join(final['_recorded']))
        return problems + final['blocked']

    def _final(self, report, final):
        """S7, only after a complete removal: launchers, state and, last, the runtime. Nothing runs after it."""
        for name in final['remove']['runtime']:
            if name != RUNTIME:
                self._delete(name, report, 'runtime')
        for name in final['remove']['state']:
            self._delete(name, report, 'state')
        for name in ('/etc/nvidia-vbios', DATA):
            self._rmdir(name)
        if RUNTIME in final['remove']['runtime']:
            self._delete(RUNTIME, report, 'runtime')


def main(argv=None):
    parser = argparse.ArgumentParser(prog='nvbios system uninstall', description=__doc__.splitlines()[0])
    parser.add_argument('--dry-run', action='store_true', help='list what would be removed; change nothing')
    parser.add_argument('--allow-missing-module', action='store_true',
                        help="also remove modules that are a kernel's only NVIDIA modules (it then starts without the driver)")
    args = parser.parse_args(argv)
    try:
        worker = Uninstall()
        with ExitStack() as stack:
            for name in (() if args.dry_run else (SETUP_LOCK, BASE + '/bootstrap.lock')):
                if worker.path(name).parent.is_dir():  # a lock never recreates a removed directory
                    stack.enter_context(locked(worker.path(name), worker.root))
            result = worker.uninstall(dry_run=args.dry_run, allow_missing_module=args.allow_missing_module)
        print(json.dumps(result, indent=2, sort_keys=True))
        if result['state'] == 'blocked':
            print('UNINSTALL_BLOCKED: nothing was changed: ' + '; '.join(result['blocked']), file=sys.stderr)
        elif result['state'] == 'incomplete':
            print('UNINSTALL_BLOCKED: incomplete, run uninstall again after fixing: ' + '; '.join(result['problems']), file=sys.stderr)
        return 1 if result['state'] in ('blocked', 'incomplete') else 0
    except LockBusy as exc:
        print(f'UNINSTALL_BLOCKED: {_busy(exc)}', file=sys.stderr)
        return 1
    except (LifecycleError, OSError, ValueError, KeyError) as exc:
        print(f'UNINSTALL_BLOCKED: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
