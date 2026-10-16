"""Distribution-specific, installed-wheel lifecycle callback templates.

APT callbacks follow apt.conf(5); pacman callbacks follow alpm-hooks(5).
Callbacks use the fixed installed runner and defer reconciliation until the
parent package manager releases its native transaction lock.
"""
from __future__ import annotations

from pathlib import Path, PurePosixPath
import re
from .security import LifecycleError, resolve_trusted_file
from .templates import hook_templates

RUNTIME = '/usr/libexec/nvidia-vbios'
APT_TARGET = '/etc/apt/apt.conf.d/99-nvidia-vbios'
PACMAN_TARGET = '/etc/pacman.d/hooks/99-nvidia-vbios.hook'
DNF_TARGETS = {
    'dnf5': '/etc/dnf/libdnf5-plugins/actions.d/nvidia-vbios.actions',
    'dnf4': '/etc/dnf/plugins/post-transaction-actions.d/nvidia-vbios.action',
}
SERVICE_TARGET = '/usr/lib/systemd/system/nvidia-vbios-reconcile.service'
KERNEL_INSTALL_TARGET = '/usr/lib/kernel/install.d/99-nvidia-vbios.install'

_APT = b'''// Queue after dpkg; APT may still own its frontend transaction lock.
DPkg::Post-Invoke { "/usr/libexec/nvidia-vbios lifecycle post-transaction --defer"; };
'''
_PACMAN = b'''# Native DKMS/initramfs hooks complete before this deferred callback.
[Trigger]
Operation = Install
Operation = Upgrade
Operation = Remove
Type = Package
Target = linux*
Target = nvidia*
Target = lib32-nvidia*
Target = libnvidia*
Target = opencl-nvidia*
Target = lib32-opencl-nvidia*
Target = dkms

[Action]
Description = Queue NVIDIA VBIOS lifecycle reconciliation
When = PostTransaction
Exec = /usr/libexec/nvidia-vbios lifecycle post-transaction --defer
'''


def activation_provider(platform):
    provider = platform.hook_provider
    if provider not in (*DNF_TARGETS, 'apt', 'pacman'):
        raise LifecycleError('unsupported lifecycle activation provider')
    return provider


def returnactivationtemplates(provider):
    """Return the single activation callback as {destination: bytes}."""
    if provider in DNF_TARGETS:
        destination = DNF_TARGETS[provider]
        return {destination: hook_templates()[destination]['data']}
    if provider == 'apt':
        return {APT_TARGET: _APT}
    if provider == 'pacman':
        return {PACMAN_TARGET: _PACMAN}
    raise LifecycleError('unsupported lifecycle activation provider')


activation_templates = returnactivationtemplates


def _boot_paths(boot):
    if boot is None:
        return ['/boot', '-/etc/grub.d']
    if hasattr(boot, 'config'):
        boot = boot.config
    elif hasattr(boot, 'raw'):
        boot = boot.raw.get('boot', {})
    if not isinstance(boot, dict):
        raise LifecycleError('invalid boot layout for lifecycle service')
    paths = ['/boot']
    for name in ('boot_root', 'xbootldr', 'esp'):
        if name not in boot:
            continue
        value = boot[name]
        if (not isinstance(value, str) or not re.fullmatch(r'/[A-Za-z0-9_./+-]+', value)
                or any(part in ('.', '..') for part in value.split('/')[1:]) or '//' in value):
            raise LifecycleError('unsafe writable boot path for lifecycle service')
        canonical = str(PurePosixPath(value))
        if canonical == '/':
            raise LifecycleError('boot publication cannot make the entire system writable')
        paths.append(canonical)
    if boot.get('backend', 'grub') == 'grub':
        paths.append('-/etc/grub.d')
        grub_config = boot.get('grub_config')
        if grub_config is not None:
            if (not isinstance(grub_config, str) or not re.fullmatch(r'/[A-Za-z0-9_./+-]+', grub_config)
                    or any(part in ('.', '..') for part in grub_config.split('/')[1:]) or '//' in grub_config):
                raise LifecycleError('unsafe GRUB configuration path for lifecycle service')
            parent = str(PurePosixPath(grub_config).parent)
            # The publication adapter only supports GRUB files under /boot.
            if parent != '/boot' and not parent.startswith('/boot/'):
                raise LifecycleError('GRUB configuration writable path must be beneath /boot')
            paths.append(parent)
    return list(dict.fromkeys(paths))


def _service(platform, boot):
    after = 'local-fs.target' + (' akmods.service' if platform.family == 'fedora' else '')
    # /etc/nvidia-vbios: automatic source registration updates the enrollment.
    paths = ['/var/lib/nvidia-vbios', '/etc/nvidia-vbios', platform.module_root, '/usr/lib/firmware/nvidia', *_boot_paths(boot)]
    if platform.package_provider == 'rpm':
        paths.extend(['-/usr/lib/sysimage/rpm', '-/var/lib/rpm'])
        if platform.family == 'fedora':
            paths.append('-/run/akmods')
    elif platform.package_provider == 'deb':
        paths.append('/var/lib/dpkg')
    elif platform.package_provider == 'pacman':
        paths.append('/var/lib/pacman')
    else:
        raise LifecycleError('unsupported lifecycle package lock provider')
    return f'''[Unit]
Description=Validate and reconcile NVIDIA VBIOS override for the latest installed kernel
After={after}
ConditionPathExists=/etc/nvidia-vbios/lifecycle.json
ConditionPathExists=!/run/ostree-booted

[Service]
Type=oneshot
ExecStart=/usr/bin/systemd-inhibit --what=shutdown:sleep --mode=block --who=nvidia-vbios --why=Validating-NVIDIA-kernel-update {RUNTIME} lifecycle reconcile
TimeoutStartSec=2h
UMask=0077
Nice=10
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths={' '.join(dict.fromkeys(paths))}
'''.encode()


def _debian_kernel_hook(action):
    return f'''#!/bin/sh
# Queue only; the enclosing package manager may still hold its native lock.
set -eu
[ -f /etc/nvidia-vbios/lifecycle.json ] || exit 0
exec {RUNTIME} lifecycle queue {action} "${{1-}}"
'''.encode()


def hook_templates_for(platform, boot=None):
    """Return installable {destination: {data: bytes, mode: int}} templates.

    Fedora's existing BLS bundle remains byte-identical when no portable boot
    layout is requested. Other distributions install only their native package
    activation callback alongside architecture-neutral systemd units.
    """
    legacy = hook_templates()
    provider = activation_provider(platform)
    if platform.family == 'fedora' and boot is None:
        return legacy
    result = {name: dict(value) for name, value in legacy.items() if name not in DNF_TARGETS.values()}
    result[SERVICE_TARGET] = {'data': _service(platform, boot), 'mode': 0o644}
    for destination, data in returnactivationtemplates(provider).items():
        result[destination] = {'data': data, 'mode': 0o644}
    if platform.family == 'debian':
        for leaf, action in (('postinst', 'add'), ('postrm', 'remove')):
            result[f'/etc/kernel/{leaf}.d/zz-nvidia-vbios'] = {'data': _debian_kernel_hook(action), 'mode': 0o755}
    return result


def provider_available(ops, provider):
    """Check fixed executables and package availability without installing.

    Accepts either SystemOperations or BootstrapOperations (its .system).
    All package operations below query metadata only.
    """
    if provider not in (*DNF_TARGETS, 'apt', 'pacman'):
        raise LifecycleError('unsupported lifecycle activation provider')
    system = getattr(ops, 'system', ops)
    root = Path(getattr(system, 'filesystem_root', Path('/')))
    required = {'dnf5': ('/usr/bin/dnf5', '/usr/bin/rpm'),
                'dnf4': ('/usr/bin/dnf', '/usr/bin/rpm'),
                'apt': ('/usr/bin/apt-get', '/usr/bin/dpkg-query'),
                'pacman': ('/usr/bin/pacman',)}[provider]
    try:
        for logical in required:
            executable = resolve_trusted_file(root / logical.lstrip('/'), root)
            if not executable.stat().st_mode & 0o111:
                return False
        if provider in DNF_TARGETS:
            package = 'libdnf5-plugin-actions' if provider == 'dnf5' else 'python3-dnf-plugin-post-transaction-actions'
            return system._run(['rpm', '--nosignature', '-q', package], allow_failure=True).returncode == 0
        if provider == 'apt':
            response = system._run(['dpkg-query', '-W', '-f=${binary:Package}\\t${db:Status-Status}\\t${db:Status-Eflag}\\n', 'apt', 'dpkg'], allow_failure=True)
            records = [line.split('\t') for line in response.stdout.decode().splitlines()]
            return response.returncode == 0 and sorted(records) == [['apt', 'installed', 'ok'], ['dpkg', 'installed', 'ok']]
        response = system._run(['pacman', '-Q', 'pacman'], allow_failure=True)
        fields = response.stdout.decode().split()
        return response.returncode == 0 and len(fields) == 2 and fields[0] == 'pacman'
    except (OSError, LifecycleError, UnicodeError):
        return False
