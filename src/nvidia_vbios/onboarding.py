"""Read-only Linux GPU discovery and reviewable first-use enrollment profiles.

Preparing a profile never enrolls it, installs files, builds modules, changes boot
selection, or writes GPU state. Bootstrap.enroll remains the enrollment authority.
"""
from __future__ import annotations
from .limits import MAX_GPUS

import argparse
import csv
import ctypes
import errno
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile

from .bootstrap import BootstrapError, BootstrapOperations, _external, _input_path, _platform
from .lifecycle.engine import parse_bls
from .lifecycle.security import LifecycleError, digest, token
from .payload import PayloadError, check_loadable_payload, optional_editor

UUID = re.compile(r'GPU-[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}')
BDF = re.compile(r'([0-9a-fA-F]{4}|[0-9a-fA-F]{8}):([0-9a-fA-F]{2}):([01][0-9a-fA-F]\.[0-7])')
REPRESENTATION = 'ada-relocated-v1'
MANUAL_LIBRARIES = ['/usr/lib64/libnvidia-ml.so.1', '/usr/lib64/libcuda.so.1']


def canonical_bdf(value):
    match = BDF.fullmatch(str(value))
    if match is None or int(match[1], 16) > 0xffff:
        raise BootstrapError(f'invalid physical PCI BDF: {value}')
    return f'{int(match[1], 16):04x}:{match[2].lower()}:{match[3].lower()}'


def _publish(stage, destination):
    """Atomic Linux publication that cannot replace even an empty directory."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = getattr(libc, 'renameat2', None)
    if rename is None:
        raise BootstrapError('atomic no-overwrite directory publication requires Linux renameat2')
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1):
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise BootstrapError('output already exists; choose a new directory')
        raise OSError(error, os.strerror(error), str(destination))


class Onboarding:
    def __init__(self, root=Path('/'), operations=None):
        self.root = _input_path(root)
        if operations is None:
            if self.root != Path('/'):
                raise BootstrapError('alternate root requires explicitly injected operations')
            operations = BootstrapOperations()
        self.ops = operations

    def _query(self):
        # The injected hook returns a CompletedProcess with the same CSV shape.
        if hasattr(self.ops, 'gpu_query'):
            return self.ops.gpu_query()
        return self.ops._run(['nvidia-smi', '--query-gpu=index,pci.bus_id,uuid,name',
                              '--format=csv,noheader'], allow_failure=True)

    def devices(self):
        response = self._query()
        if response.returncode:
            raise BootstrapError('NVIDIA-SMI/NVML GPU discovery failed; no index selection is safe')
        actual = self.ops.inventory()
        if not isinstance(actual, dict):
            raise BootstrapError('invalid physical GPU inventory')
        inventory, uuids = {}, set()
        for key, value in actual.items():
            bdf = canonical_bdf(key)
            if not isinstance(value, dict) or canonical_bdf(value.get('bdf', key)) != bdf:
                raise BootstrapError('conflicting physical inventory BDF')
            uuid = value.get('uuid')
            if not isinstance(uuid, str) or UUID.fullmatch(uuid) is None:
                raise BootstrapError('physical procfs GPU UUID is unavailable or invalid')
            if bdf in inventory or uuid in uuids:
                raise BootstrapError('duplicate physical GPU identity')
            if value.get('vendor') != 0x10de or type(value.get('device')) is not int or not 0 <= value['device'] <= 0xffff:
                raise BootstrapError('invalid NVIDIA physical PCI identity')
            inventory[bdf] = dict(value, bdf=bdf)
            uuids.add(uuid)
        try:
            rows = list(csv.reader(response.stdout.decode('utf-8').splitlines()))
        except UnicodeError as exc:
            raise BootstrapError('invalid NVIDIA-SMI discovery text') from exc
        devices, indices, seen_bdf, seen_uuid = [], set(), set(), set()
        for row in rows:
            if len(row) != 4:
                raise BootstrapError('unexpected NVIDIA-SMI discovery format')
            index, supplied_bdf, uuid, name = (part.strip() for part in row)
            if re.fullmatch(r'0|[1-9][0-9]*', index) is None or not name:
                raise BootstrapError('invalid NVIDIA-SMI index/name')
            index, bdf = int(index), canonical_bdf(supplied_bdf)
            if index in indices or bdf in seen_bdf or uuid in seen_uuid:
                raise BootstrapError('duplicate NVIDIA-SMI GPU index or identity')
            observed = inventory.get(bdf)
            if observed is None or observed['uuid'] != uuid:
                raise BootstrapError('NVIDIA-SMI and procfs/sysfs physical GPU identities disagree')
            devices.append(dict(observed, index=index, name=name))
            indices.add(index); seen_bdf.add(bdf); seen_uuid.add(uuid)
        if seen_bdf != set(inventory):
            raise BootstrapError('NVIDIA-SMI and physical inventory GPU sets disagree')
        if not devices:
            raise BootstrapError('first-use profile discovery requires at least one physical GPU')
        return sorted(devices, key=lambda value: value['index'])

    @staticmethod
    def select(selector, devices):
        selector = str(selector)
        if re.fullmatch(r'0|[1-9][0-9]*', selector):
            matches = [device for device in devices if device['index'] == int(selector)]
        elif UUID.fullmatch(selector):
            matches = [device for device in devices if device['uuid'] == selector]
        else:
            bdf = canonical_bdf(selector)
            matches = [device for device in devices if device['bdf'] == bdf]
        if len(matches) != 1:
            raise BootstrapError(f'selector does not identify exactly one physical GPU: {selector}')
        return matches[0]

    def _fallback(self, entry, boot=None):
        kernel = token(self.ops.current_kernel(), 'running kernel')
        if boot:
            from .lifecycle.boot import BootAdapter
            adapter = BootAdapter(self.root, {'boot':boot})
            baseline = adapter.discover(kernel, entry)
            hashes = {str(self.root / name.lstrip('/')):value for name,value in baseline.metadata['fingerprints'].items()}
            # Snapshot the whole input file here to detect changes during prepare;
            # enrollment pins only the selected GRUB stanza.
            source = self.root / baseline.descriptor_path.lstrip('/')
            hashes[str(source)] = digest(_external(source))
            return baseline.entry_id, hashes
        directory = _input_path(self.root / 'boot/loader/entries')
        if entry is not None:
            entry = token(entry, 'normal fallback entry')
            candidates = [directory / (entry + '.conf')]
        else:
            candidates = sorted(directory.glob('*.conf'))
        accepted = []
        for path in candidates:
            if path.stem.startswith('vbios-'):
                if entry is not None:
                    raise BootstrapError('fallback must be a separate normal BLS entry')
                continue
            data = _external(path)
            try:
                parse_bls(data, kernel)
            except LifecycleError:
                if entry is not None:
                    raise
                continue
            accepted.append((path.stem, data))
        if len(accepted) != 1:
            raise BootstrapError('require exactly one normal BLS entry for the running kernel; supply --fallback-entry')
        name, data = accepted[0]
        # Check the same conventional fallback artifacts enrollment will hash.
        artifacts = {str(path): digest(_external(path)) for path in
                     (self.root / f'boot/vmlinuz-{kernel}', self.root / f'boot/initramfs-{kernel}.img')}
        artifacts[str(directory / (name + '.conf'))] = digest(data)
        return name, artifacts

    def prepare(self, *, devices, driver_source, output, p2p_preferred=False, no_auto_source=False,
                userspace=None, fallback_entry=None, jobs=1, representations=(),
                nvidia_smi='/usr/bin/nvidia-smi', libraries=None, boot_backend=None, initramfs=None,
                boot_root=None, esp=None, xbootldr=None, grub_config=None, signing_key=None, signing_certificate=None,
                uki_key=None, uki_certificate=None):
        platform = _platform(self.ops)
        userspace = userspace or platform.package_provider
        boot = None
        backend = boot_backend or ('fedora-bls' if platform.family in ('fedora','rhel') else 'grub')
        if backend != 'fedora-bls':
            builder = initramfs or {'fedora':'dracut','rhel':'dracut','debian':'initramfs-tools','arch':'mkinitcpio'}[platform.family]
            boot = {'backend':backend,'initramfs':builder}
            if platform.family == 'arch':
                kernel = token(self.ops.current_kernel(), 'running kernel')
                pkgbase = self.root / f'usr/lib/modules/{kernel}/pkgbase'
                boot['kernel_package'] = token(_external(pkgbase).decode().strip(), 'kernel package base')
            for key,value in (('boot_root',boot_root),('esp',esp),('xbootldr',xbootldr),('grub_config',grub_config)):
                if value is not None:
                    boot[key] = str(value)
            if bool(uki_key) != bool(uki_certificate):
                raise BootstrapError('UKI signing requires both key and certificate')
            if uki_key:
                boot['uki']={'signing':{'key':str(uki_key),'certificate':str(uki_certificate),'trust':'firmware-db'}}
            from .lifecycle.boot import validate_config
            validate_config({'boot':boot})
        elif platform.family not in ('fedora','rhel'):
            raise BootstrapError('fedora-bls requires an RPM/BLS distribution')
        elif any((initramfs,boot_root,esp,xbootldr,grub_config,uki_key,uki_certificate)):
            raise BootstrapError('portable boot options require an explicit portable backend')
        if bool(signing_key) != bool(signing_certificate):
            raise BootstrapError('module signing requires both key and certificate')
        if not 1 <= len(devices) <= MAX_GPUS:
            raise BootstrapError(f'select one through {MAX_GPUS} GPUs with --device SELECTOR ROM')
        if type(jobs) is not int or not 1 <= jobs <= 256:
            raise BootstrapError('jobs must be between 1 and 256')
        destination = _input_path(output)
        if destination.exists():
            raise BootstrapError('output already exists; choose a new directory')
        if not destination.parent.is_dir():
            raise BootstrapError('output parent directory must already exist')
        source = _input_path(driver_source)
        if not source.is_dir():
            raise BootstrapError('driver source must be an existing directory')
        if destination.is_relative_to(source):
            raise BootstrapError('output must be separate from the driver source tree')
        source_info = self.ops.inspect_source(source)
        if not source_info.get('supported') or source_info.get('capabilities', {}).get('already_patched'):
            raise BootstrapError(f'unsupported or already VBIOS-patched driver source: {source_info.get("reasons", [])}')
        if userspace not in ('rpm', 'deb', 'pacman', 'manual'):
            raise BootstrapError('userspace provider must be rpm, deb, pacman or manual')
        provider = {'provider': userspace}
        if userspace == 'manual':
            defaults = MANUAL_LIBRARIES
            if platform.family in ('debian','arch'):
                candidates = [[directory+'/'+name for name in ('libnvidia-ml.so.1','libcuda.so.1')]
                              for directory in platform.library_paths]
                defaults = next((pair for pair in candidates if all((self.root/name.lstrip('/')).exists() for name in pair)), candidates[0])
            provider.update(nvidia_smi=str(nvidia_smi), libraries=list(defaults if libraries is None else libraries))
            if not Path(provider['nvidia_smi']).is_absolute() or '..' in Path(provider['nvidia_smi']).parts:
                raise BootstrapError('manual nvidia-smi path must be absolute')
            aliases = provider['libraries']
            if len(aliases) < 2 or len(set(aliases)) != len(aliases) or any(not Path(alias).is_absolute() or '..' in Path(alias).parts for alias in aliases):
                raise BootstrapError('manual userspace needs distinct absolute NVML and CUDA library aliases')
            if not any(Path(alias).name.startswith('libnvidia-ml.so') for alias in aliases) or not any(Path(alias).name.startswith('libcuda.so') for alias in aliases):
                raise BootstrapError('manual userspace needs both NVML and CUDA library aliases')
        elif libraries is not None or nvidia_smi != '/usr/bin/nvidia-smi':
            raise BootstrapError('userspace path overrides require --userspace manual')
        version = self.ops.installed_version({'userspace': provider})
        if source_info.get('version') != version:
            raise BootstrapError('driver source must match the exact installed userspace version')
        fallback, fallback_hashes = self._fallback(fallback_entry, boot)
        inventory = self.devices()
        selected = [(self.select(selector, inventory), _input_path(rom)) for selector, rom in devices]
        if len({gpu['bdf'] for gpu, _ in selected}) != len(selected):
            raise BootstrapError('duplicate selected GPU through index/UUID/BDF aliases')
        recipes = {}
        for selector, representation in representations:
            gpu = self.select(selector, inventory)
            if gpu['bdf'] in recipes or representation != REPRESENTATION:
                raise BootstrapError('duplicate or unsupported explicit representation')
            recipes[gpu['bdf']] = representation
        if not set(recipes).issubset({gpu['bdf'] for gpu, _ in selected}):
            raise BootstrapError('representation selector must identify a selected GPU')
        records, files, original_hashes = [], {}, {}
        editor = optional_editor()
        for gpu, rom in selected:
            archive = _external(rom)
            original_hashes[str(rom)] = digest(archive)
            representation = recipes.get(gpu['bdf'])
            if editor is not None:
                payload, family, versions = editor.prepare_payload(archive, str(rom), gpu, representation)
            elif representation is not None:
                raise BootstrapError('payload representations need a full ROM parser; supply the payload your VBIOS editor exported')
            else:
                # The open loader enrolls an already single-chain payload, checked by the kernel's own rule.
                try:
                    family = check_loadable_payload(archive, gpu['vendor'], gpu['device'])
                except PayloadError as exc:
                    raise BootstrapError(f'{gpu["bdf"]}: {exc}') from None
                payload, versions = archive, []
            stem = gpu['bdf'].replace(':', '-').replace('.', '-')
            archive_name, payload_name = f'archives/{stem}.rom', f'payloads/{stem}.bin'
            record = {key: gpu[key] for key in ('uuid', 'bdf', 'vendor', 'device')}
            record.update(architecture=family, archive=str(destination / archive_name),
                          payload=str(destination / payload_name), source_sha256=digest(archive),
                          source_size=len(archive), sha256=digest(payload), size=len(payload),
                          evidence={'boot': 'unverified', 'application': 'unverified', 'fields': {}})
            if representation:
                record['representation'] = representation
            serial = gpu.get('serial')
            if isinstance(serial, str) and re.fullmatch(r'[A-Za-z0-9._-]{6,64}', serial) and any(char.isdigit() for char in serial) and serial.encode('ascii') in archive:
                record['serial'] = serial
            actual_version = gpu.get('vbios_version')
            if isinstance(actual_version, str) and actual_version.upper() in [value.upper() for value in versions]:
                record['vbios_version'] = actual_version
            self.ops.archive_identity(archive, payload, record)
            records.append(record)
            files[archive_name], files[payload_name] = archive, payload
        profile = {'devices': records, 'driver_sources': [{'path': str(source), 'p2p_preferred': bool(p2p_preferred)}],
                   'userspace': provider, 'fallback_entry': fallback, 'jobs': jobs,
                   # After a package-manager driver upgrade, fetch the matching upstream tag.
                   'auto_source': userspace in ('rpm', 'deb', 'pacman') and not p2p_preferred and not no_auto_source,
                   'discovery': [{'index': gpu['index'], 'name': gpu['name'], 'uuid': gpu['uuid'], 'bdf': gpu['bdf']} for gpu, _ in selected]}
        if boot:
            profile['boot'] = boot
        if signing_key:
            profile['signing'] = {'key':str(signing_key),'certificate':str(signing_certificate)}
        # Recheck mutable inputs and physical identities before publishing anything.
        current = {gpu['bdf']: gpu for gpu in self.devices()}
        for gpu, _ in selected:
            observed = current.get(gpu['bdf'], {})
            if any(observed.get(key) != gpu.get(key) for key in ('index', 'uuid', 'vendor', 'device', 'serial', 'vbios_version')):
                raise BootstrapError('selected physical GPU identity changed during preparation')
        for path, expected_hash in {**original_hashes, **fallback_hashes}.items():
            if digest(_external(path)) != expected_hash:
                raise BootstrapError('ROM or normal fallback changed during preparation')
        if self.ops.inspect_source(source) != source_info or self.ops.installed_version({'userspace': provider}) != version:
            raise BootstrapError('driver source or installed userspace changed during preparation')
        files['profile.json'] = (json.dumps(profile, indent=2, sort_keys=True, allow_nan=False) + '\n').encode()
        _input_path(destination)
        stage = Path(tempfile.mkdtemp(prefix='.nvbios-prepare-', dir=destination.parent))
        try:
            stage.chmod(0o700)
            for name, data in files.items():
                path = stage / name
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                path.write_bytes(data)
                path.chmod(0o600)
            _input_path(destination)
            _publish(stage, destination)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        return {'state': 'prepared', 'profile': str(destination / 'profile.json'), 'device_count': len(records),
                'version': version, 'scope': 'offline-structural-validation-only',
                'hardware_application': 'unverified', 'enrolled': False}


def main(argv=None, *, root=Path('/'), operations=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('devices', help='list physical NVIDIA-SMI indices, UUIDs and PCI identities')
    prepare = commands.add_parser('prepare', help='create a new directory with a reviewable enrollment profile')
    prepare.add_argument('--device', action='append', nargs=2, metavar=('SELECTOR', 'ROM'), required=True)
    prepare.add_argument('--driver-source', type=Path, required=True)
    prepare.add_argument('--p2p-preferred', action='store_true')
    prepare.add_argument('--no-auto-source', action='store_true',
                         help='never download the matching open-gpu-kernel-modules tag after a driver package upgrade')
    prepare.add_argument('--userspace', choices=('rpm', 'deb', 'pacman', 'manual'))
    prepare.add_argument('--nvidia-smi', default='/usr/bin/nvidia-smi')
    prepare.add_argument('--library', action='append', dest='libraries')
    prepare.add_argument('--output', type=Path, required=True)
    prepare.add_argument('--fallback-entry')
    prepare.add_argument('--boot-backend', choices=('fedora-bls','grub','systemd-boot','uki'))
    prepare.add_argument('--initramfs', choices=('dracut','initramfs-tools','mkinitcpio'))
    for flag in ('boot-root','esp','xbootldr','grub-config','signing-key','signing-certificate','uki-key','uki-certificate'):
        prepare.add_argument('--'+flag, type=Path)
    prepare.add_argument('--jobs', type=int, default=1)
    if optional_editor() is not None:
        prepare.add_argument('--representation', action='append', nargs=2, metavar=('SELECTOR', 'NAME'), default=[])
    args = parser.parse_args(argv)
    try:
        worker = Onboarding(root, operations)
        if args.action == 'devices':
            result = {'devices': worker.devices(), 'scope': 'physical-discovery-only'}
        else:
            values = vars(args).copy()
            values.pop('action')
            values['devices'] = values.pop('device')
            values['representations'] = values.pop('representation', [])
            result = worker.prepare(**values)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (LifecycleError, OSError, ValueError, KeyError, TypeError) as exc:
        print(f'PREPARE_BLOCKED: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
