"""Transactional source preparation for structurally compatible open modules.

No API builds, installs, or modifies a supplied source tree. Structural support
is a host-source finding, not certification of a GPU/firmware combination.
"""
from __future__ import annotations

import hashlib
import fcntl
import stat
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from ..limits import REGISTRY_STRING_MAX_BYTES
from ._payload import (CACHED_ARGUMENTS_ABI, HELPERS, LOADER_FUNCTIONS, LOADER_LICENSE,
                       PARSER_HEADER, REGISTRY_STRING_PARAMETERS)

__all__ = ["DriverPatchError", "inspect_source", "prepare_source", "apply_to_tree"]

SCHEMA_VERSION = 1
MODULE_METADATA = {"vbios_override_per_gpu": "1",
                   "vbios_override_param_bytes": str(REGISTRY_STRING_MAX_BYTES)}
WORKING_COPY_MARKER = ".nvidia-vbios-working-copy.json"
MANIFEST_NAME = ".nvidia-vbios-manifest.json"
GSP = "src/nvidia/src/kernel/gpu/gsp/kernel_gsp.c"
GSP_HEADER = "src/nvidia/generated/g_kernel_gsp_nvoc.h"
ARGS = "src/nvidia/inc/kernel/gpu/gsp/gsp_init_args.h"
REGISTRY = "src/nvidia/arch/nvalloc/unix/src/registry.c"
NV = "kernel-open/nvidia/nv.c"
REG_H = "kernel-open/nvidia/nv-reg.h"
OS_REG = "kernel-open/nvidia/os-registry.c"
PROTO = "kernel-open/common/inc/nv-proto.h"
PCI = "kernel-open/nvidia/nv-pci.c"
PARSER = "src/nvidia/inc/kernel/gpu/gsp/vbios_override_image.h"
CHIP_H = "src/nvidia/generated/g_rmconfig_private.h"
CHIP_C = "src/nvidia/generated/g_rmconfig_util.c"
REQUIRED = ("version.mk", GSP, GSP_HEADER, ARGS, REGISTRY, NV, REG_H, OS_REG, PROTO, PCI,
            CHIP_H, CHIP_C, "kernel-open/common/inc/nv.h", "src/nvidia/inc/kernel/core/prelude.h")
CHIPS = ("TU102", "TU104", "TU106", "TU116", "TU117",
         "GA100", "GA102", "GA103", "GA104", "GA106", "GA107", "AD102", "AD103", "AD104",
         "AD106", "AD107", "GB202", "GB203", "GB205", "GB206", "GB207")


class DriverPatchError(RuntimeError):
    """Unsupported source, unsafe destination, or failed transaction."""


def _hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _once(text: str, old: str, new: str, label: str) -> str:
    count = text.count(old)
    if count != 1:
        raise DriverPatchError(f"{label}: expected exactly one anchor, found {count}")
    return text.replace(old, new, 1)


def _mask_c(text: str) -> str:
    """Keep offsets while removing comments and literals for brace matching."""
    pattern = r'/\*[\s\S]*?\*/|//[^\n]*|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''
    return re.sub(pattern, lambda m: ''.join('\n' if c == '\n' else ' ' for c in m[0]), text)


def _function_span(text: str, name: str) -> tuple[int, int]:
    masked = _mask_c(text)
    pattern = r'\b' + re.escape(name) + r'\s*\([^;{}]*\)\s*\{'
    matches = list(re.finditer(pattern, masked))
    if len(matches) != 1:
        raise DriverPatchError(f"{name}: expected one function definition, found {len(matches)}")
    start = matches[0].start()
    opening = masked.index('{', start)
    depth = 1
    for end in range(opening + 1, len(masked)):
        depth += (masked[end] == '{') - (masked[end] == '}')
        if depth == 0:
            return start, end + 1
    raise DriverPatchError(f"{name}: unterminated function")


def _edit_function(text: str, name: str, edit) -> str:
    start, end = _function_span(text, name)
    return text[:start] + edit(text[start:end]) + text[end:]


def _normalize(text: str) -> str:
    return re.sub(r'\s+', '', re.sub(r'/\*[\s\S]*?\*/|//[^\n]*', '', text))


def _abi_valid(text: str) -> bool:
    # Compare the complete wire declarations, including the nested structs.
    start = text.find('typedef struct NV_ABI_STABLE MESSAGE_QUEUE_INIT_ARGUMENTS')
    end = text.find('} GSP_ARGUMENTS_CACHED;')
    return start >= 0 and end > start and _normalize(text[start:end + len('} GSP_ARGUMENTS_CACHED;')]) == _normalize(CACHED_ARGUMENTS_ABI)


def _read_required(tree: Path) -> dict[str, str]:
    contents = {}
    for name in REQUIRED:
        path = tree / name
        if not path.is_file() or path.is_symlink() or not path.resolve().is_relative_to(tree):
            raise DriverPatchError(f"missing or unsafe source file: {name}")
        try:
            contents[name] = path.read_text(encoding='utf-8')
        except (OSError, UnicodeError) as exc:
            raise DriverPatchError(f"cannot read {name}: {exc}") from exc
    return contents


def _native_loader(contents: dict[str, str]) -> bool:
    indicators = [
        '__NV_REGISTRY_BINARY_FILE_PER_DEVICE' in contents[REG_H],
        'nv_parse_per_device_binary_option_string' in contents[OS_REG],
        'nv_parse_per_device_binary_option_string' in contents[PROTO],
        'nv_parse_per_device_binary_option_string' in contents[PCI],
    ]
    if any(indicators) and not all(indicators):
        raise DriverPatchError('incomplete native per-device binary loader')
    return all(indicators)


def _backport_loader(contents: dict[str, str]) -> None:
    """Backport probe-scoped 615 binary loading without rewriting dword/P2P code."""
    reg = contents[REG_H]
    define = '#define __NV_REGISTRY_DWORDS_PER_DEVICE RegistryDwordsPerDevice\n'
    contents[REG_H] = _once(reg, define, define + '\n/* Probe-scoped binary registry firmware (NVIDIA 615 backport). */\n#define __NV_REGISTRY_BINARY_FILE_PER_DEVICE RegistryBinaryFilePerDevice\n#define NV_REG_REGISTRY_BINARY_FILE_PER_DEVICE NV_REG_STRING(__NV_REGISTRY_BINARY_FILE_PER_DEVICE)\n', REG_H)
    entry = 'NV_DEFINE_REG_STRING_ENTRY(__NV_REGISTRY_DWORDS_PER_DEVICE, NULL);'
    contents[REG_H] = _once(contents[REG_H], entry, entry + '\nNV_DEFINE_REG_STRING_ENTRY(__NV_REGISTRY_BINARY_FILE_PER_DEVICE, NULL);', REG_H)
    osreg = contents[OS_REG]
    _, end = _function_span(osreg, 'pci_str_to_bdf')
    # The binary parser is declared after pci_str_to_bdf; its two helpers precede it.
    parser_start = LOADER_FUNCTIONS.index('NV_STATUS nv_parse_per_device_binary_option_string')
    helpers = LOADER_FUNCTIONS[:parser_start]
    parser = LOADER_FUNCTIONS[parser_start:]
    osreg = osreg[:end] + '\n\n' + parser + osreg[end:]
    include = '#include "nv-gpu-info.h"\n'
    contents[OS_REG] = _once(osreg, include, include + '#include <linux/firmware.h>\n\n' + LOADER_LICENSE + '#define NV_BINARY_REGISTRY_FIRMWARE_DIR "nvidia/"\n\n' + helpers, OS_REG)
    proto = contents[PROTO]
    declarations = list(re.finditer(r'NV_STATUS\s+nv_parse_per_device_option_string\s*\([^;]*\);', proto))
    if len(declarations) != 1:
        raise DriverPatchError('per-device dword prototype is absent or ambiguous')
    end = declarations[0].end()
    contents[PROTO] = proto[:end] + '\nNV_STATUS nv_parse_per_device_binary_option_string(nvidia_stack_t *sp, nv_state_t *current_nv);' + proto[end:]
    pci = contents[PCI]
    calls = list(re.finditer(r'    nv_parse_per_device_option_string\(sp(?:, nv)?\);', pci))
    if len(calls) != 1:
        raise DriverPatchError('per-device dword probe call is absent or ambiguous')
    end = calls[0].end()
    hook = '''

    /* Read only the currently probing GPU's binary firmware. */
    {
        NV_STATUS parse_status = nv_parse_per_device_binary_option_string(sp, nv);
        if (parse_status != NV_OK)
            NV_DEV_PRINTF(NV_DBG_WARNINGS, nv,
                          "Per-device binary registry parsing failed (status=0x%x)\\n",
                          parse_status);
    }'''
    contents[PCI] = pci[:end] + hook + pci[end:]


def _validate_loader(contents: dict[str, str]) -> None:
    if not _native_loader(contents):
        raise DriverPatchError('binary loader backport did not establish all components')
    for name in ('nv_parse_binary_registry_token', 'nv_write_binary_registry_file', 'nv_parse_per_device_binary_option_string'):
        _function_span(contents[OS_REG], name)
    for name in ('nv_parse_binary_registry_token', 'nv_write_binary_registry_file', 'nv_parse_per_device_binary_option_string'):
        start, end = _function_span(contents[OS_REG], name)
        expected_start, expected_end = _function_span(LOADER_FUNCTIONS, name)
        if _normalize(contents[OS_REG][start:end]) != _normalize(LOADER_FUNCTIONS[expected_start:expected_end]):
            raise DriverPatchError(f'binary loader implementation differs from reviewed native/backport body: {name}')
    for anchor in ('#define __NV_REGISTRY_BINARY_FILE_PER_DEVICE RegistryBinaryFilePerDevice',
                   '#define NV_REG_REGISTRY_BINARY_FILE_PER_DEVICE NV_REG_STRING(__NV_REGISTRY_BINARY_FILE_PER_DEVICE)',
                   'NV_DEFINE_REG_STRING_ENTRY(__NV_REGISTRY_BINARY_FILE_PER_DEVICE, NULL);'):
        if contents[REG_H].count(anchor) != 1:
            raise DriverPatchError(f'binary parameter declaration absent or ambiguous: {anchor}')
    start, end = _function_span(contents[OS_REG], 'nv_parse_per_device_binary_option_string')
    function = contents[OS_REG][start:end]
    checks = ('nv_state_t *current_nv', 'current_nv->pci_info.domain == domain',
              'current_nv->pci_info.bus == bus', 'current_nv->pci_info.slot == slot',
              'current_nv->pci_info.function == func', 'nv = current_nv;', 'nv = NULL;',
              'nv_write_binary_registry_file(sp, nv, name,', 'os_free_mem(option_string);')
    for check in checks:
        if check not in function:
            raise DriverPatchError(f'native loader lacks reviewed device-scoping anchor: {check}')
    if 'find_pci(' in function:
        raise DriverPatchError('binary loader must scope to the currently probing GPU')
    if not re.search(r'nv_parse_per_device_binary_option_string\(sp, nv\)', contents[PCI]):
        raise DriverPatchError('binary loader probe call does not pass this GPU')
    if not re.search(r'NV_STATUS\s+nv_parse_per_device_binary_option_string\s*\(nvidia_stack_t \*sp,\s*nv_state_t \*current_nv\);', contents[PROTO]):
        raise DriverPatchError('binary loader prototype does not match expected signature')
    start, end = _function_span(contents[OS_REG], 'nv_write_binary_registry_file')
    writer = contents[OS_REG][start:end]
    for check in ('request_firmware(&fw, firmware_path, nvl->dev)', 'rm_write_registry_binary(sp, nv, key_name,', 'release_firmware(fw)'):
        if check not in writer:
            raise DriverPatchError(f'binary writer missing anchor: {check}')


def _patch_registry_parameters(contents: dict[str, str]) -> None:
    """Replace only aggregate registry charp registrations, preserving parsers."""
    for key in ('__NV_REGISTRY_DWORDS', '__NV_REGISTRY_DWORDS_PER_DEVICE',
                '__NV_REGISTRY_BINARY_FILE_PER_DEVICE'):
        contents[REG_H] = _once(contents[REG_H],
            f'NV_DEFINE_REG_STRING_ENTRY({key}, NULL);',
            f'NV_DEFINE_VBIOS_REG_STRING_ENTRY({key}, NULL);', f'{key} parameter')
    payload = REGISTRY_STRING_PARAMETERS.replace(
        '@REGISTRY_STRING_MAX_BYTES@', str(REGISTRY_STRING_MAX_BYTES))
    contents[OS_REG] = _once(contents[OS_REG], '#include "nv-reg.h"\n',
        payload + '\n#include "nv-reg.h"\n', 'bounded registry parameter helpers')


def _prepared_module_metadata(contents: dict[str, str]) -> dict[str, str]:
    """Read actual markers so verified legacy manifests never claim new limits."""
    metadata = {}
    for key in MODULE_METADATA:
        values = re.findall(r'MODULE_INFO\(\s*' + re.escape(key) + r'\s*,\s*"([^"\n]+)"\s*\);', contents[NV])
        if len(values) > 1:
            raise DriverPatchError(f'ambiguous module metadata: {key}')
        if values:
            metadata[key] = values[0]
    return metadata


def _expect_signature(text: str, name: str, parameters: str) -> None:
    start, end = _function_span(text, name)
    opening = text.index('{', start, end)
    if _normalize(text[start:opening]) != _normalize(name + '(' + parameters + ')'):
        raise DriverPatchError(f'{name}: function parameters changed')


def _plan(contents: dict[str, str]) -> dict[str, str]:
    planned = dict(contents)
    if not _abi_valid(planned[ARGS]):
        raise DriverPatchError('GSP VBIOS override ABI absent or changed; host fields cannot backport opaque GSP firmware support')
    for name, parameters in (
        ('kgspConstructEngine_IMPL', 'OBJGPU *pGpu, KernelGsp *pKernelGsp, ENGDESCRIPTOR engDesc'),
        ('kgspPopulateGspRmInitArgs_IMPL', 'OBJGPU *pGpu, KernelGsp *pKernelGsp, GSP_SR_INIT_ARGUMENTS *pGspInitArgs'),
        ('kgspAllocBootArgsCommon', 'OBJGPU *pGpu, KernelGsp *pKernelGsp, NvU64 memdescFlags'),
        ('kgspFreeBootArgsCommon', 'OBJGPU *pGpu, KernelGsp *pKernelGsp')):
        _expect_signature(planned[GSP], name, parameters)
    if planned[GSP].count('GSP_ARGUMENTS_CACHED *pGspArgs = pKernelGsp->pGspArgumentsCached;') != 1:
        raise DriverPatchError('cached argument pointer absent or ambiguous')
    for chip in CHIPS:
        if not re.search(r'#define\s+Is' + chip + r'\(pGpu\)\s+rmcfg_Is' + chip + r'\(pGpu\)', planned[CHIP_H]):
            raise DriverPatchError(f'missing exact chip predicate: Is{chip}')
        start, end = _function_span(planned[CHIP_C], 'rmcfg_Is' + chip)
        if f'return gpuIsImplementation(pGpu, HAL_IMPL_{chip});' not in planned[CHIP_C][start:end]:
            raise DriverPatchError(f'chip predicate is no longer an exact implementation check: {chip}')
    if '#include "g_rmconfig_private.h"' not in planned['src/nvidia/inc/kernel/core/prelude.h']:
        raise DriverPatchError('chip predicates are not available through RM prelude')
    if not _native_loader(planned):
        _backport_loader(planned)
    _validate_loader(planned)
    _patch_registry_parameters(planned)
    if 'rm_write_registry_binary' not in planned['kernel-open/common/inc/nv.h']:
        raise DriverPatchError('binary registry write API unavailable')
    planned[GSP_HEADER] = _once(planned[GSP_HEADER], '    NvP64 pGspArgumentsMappingPriv;\n',
        '    NvP64 pGspArgumentsMappingPriv;\n    // Host override ownership belongs to this KernelGsp instance.\n    MEMORY_DESCRIPTOR *pVbiosOverrideDescriptor;\n    NvU64 vbiosOverrideSize;\n', GSP_HEADER)
    gsp = _once(planned[GSP], '#include "gpu/gsp/kernel_gsp.h"\n', '#include "gpu/gsp/kernel_gsp.h"\n#include "gpu/gsp/vbios_override_image.h"\n', GSP)
    gsp = _edit_function(gsp, 'kgspConstructEngine_IMPL', lambda text: _once(text,
        '    NV_STATUS nvStatus = NV_OK;\n',
        '    NV_STATUS nvStatus = NV_OK;\n\n    pKernelGsp->pVbiosOverrideDescriptor = NULL;\n    pKernelGsp->vbiosOverrideSize = 0;\n', 'KernelGsp construction'))
    publish = '''
    // Clear both fields on every populate, including mode/kill fallback.
    pGspArgs->vbiosOverrideArgs.pa = 0;
    pGspArgs->vbiosOverrideArgs.size = 0;
    if (pKernelGsp->pVbiosOverrideDescriptor != NULL)
    {
        pGspArgs->vbiosOverrideArgs.pa =
            memdescGetPhysAddr(pKernelGsp->pVbiosOverrideDescriptor, AT_GPU, 0);
        pGspArgs->vbiosOverrideArgs.size = pKernelGsp->vbiosOverrideSize;
    }
'''
    gsp = _edit_function(gsp, 'kgspPopulateGspRmInitArgs_IMPL', lambda text: text[:-1] + publish + '}')
    # Helpers precede the common allocation/free definitions and do not escape this TU.
    anchor = 'NV_STATUS\nkgspAllocBootArgsCommon\n'
    gsp = _once(gsp, anchor, HELPERS + '\n' + anchor, 'common allocation definition')
    gsp = _edit_function(gsp, 'kgspAllocBootArgsCommon', lambda text: _once(text,
        '    return nvStatus;\n\nexit_cleanup:',
        '    _kgspVbiosOverridePrepare(pGpu, pKernelGsp, memdescFlags);\n    return nvStatus;\n\nexit_cleanup:', 'common allocation success'))
    gsp = _edit_function(gsp, 'kgspFreeBootArgsCommon', lambda text: text[:text.index('{') + 1] + '\n    _kgspVbiosOverrideFree(pKernelGsp);\n' + text[text.index('{') + 1:])
    planned[GSP] = gsp
    reg = planned[REGISTRY]
    skip = '''        // Host staging data must never enter the GSP registry RPC.
        if (portStringCompare(pRegEntry->regParmStr, "RmLinuxVbiosOverrideImage",
                              sizeof("RmLinuxVbiosOverrideImage")) == 0)
        {
            pRegEntry = pRegEntry->next;
            continue;
        }
'''
    for function in ('regCountEntriesAndSize', 'regCopyEntriesToPackedBuffer'):
        reg = _edit_function(reg, function, lambda text: _once(text,
            '    while ((pRegEntry != NULL) && (pRegEntry->regParmStr != NULL))\n    {\n',
            '    while ((pRegEntry != NULL) && (pRegEntry->regParmStr != NULL))\n    {\n' + skip, function))
    planned[REGISTRY] = reg
    planned[NV] = _once(planned[NV], 'MODULE_VERSION(NV_VERSION_STRING);\n',
        'MODULE_VERSION(NV_VERSION_STRING);\n' + ''.join(
            f'MODULE_INFO({key}, "{value}");\n' for key, value in MODULE_METADATA.items()), 'module metadata')
    planned[PARSER] = PARSER_HEADER
    return {name: text for name, text in planned.items() if name not in contents or text != contents[name]}


def _applied_report(tree: Path) -> dict | None:
    path = tree / MANIFEST_NAME
    if not path.exists():
        return None
    if path.is_symlink():
        raise DriverPatchError('manifest cannot be a symlink')
    try:
        report = json.loads(path.read_text())
        if report['schema_version'] != SCHEMA_VERSION or report['prepared_source'] != str(tree):
            raise DriverPatchError('manifest schema/path mismatch')
        hashes = report['patched_hashes']
        if not isinstance(hashes, dict) or not hashes:
            raise DriverPatchError('manifest has no patched hashes')
        for name, expected in hashes.items():
            target = tree / name
            if not target.resolve().is_relative_to(tree) or target.is_symlink() or _hash(target.read_bytes()) != expected:
                raise DriverPatchError(f'prepared source changed after patching: {name}')
        return report
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise DriverPatchError(f'invalid patch manifest: {exc}') from exc


def inspect_source(path) -> dict:
    """Inspect without mutation; version is read from version.mk, never the name."""
    tree = Path(path).expanduser().resolve()
    result = {'schema_version': SCHEMA_VERSION, 'source': str(tree), 'version': None,
              'capabilities': {}, 'supported': False, 'reasons': [], 'source_hashes': {}}
    try:
        contents = _read_required(tree)
        versions = re.findall(r'^NVIDIA_VERSION\s*=\s*(\d+\.\d+\.\d+)\s*$', contents['version.mk'], re.M)
        if len(versions) != 1:
            raise DriverPatchError('version.mk must contain one numeric NVIDIA_VERSION')
        result['version'] = versions[0]
        result['source_hashes'] = {name: _hash(text.encode()) for name, text in contents.items()}
        native = _native_loader(contents)
        result['capabilities'] = {'native_per_device_binary_loader': native,
            'binary_loader_backport_needed': not native,
            'gsp_vbios_override_abi': _abi_valid(contents[ARGS]),
            'common_boot_argument_lifecycle': 'kgspAllocBootArgsCommon' in contents[GSP] and 'kgspFreeBootArgsCommon' in contents[GSP],
            'explicit_chip_scope': list(CHIPS), 'module_metadata': dict(MODULE_METADATA),
            'registry_string_max_bytes': REGISTRY_STRING_MAX_BYTES}
        applied = _applied_report(tree)
        if applied:
            result['capabilities']['already_patched'] = True
            metadata = _prepared_module_metadata(contents)
            result['capabilities']['module_metadata'] = metadata
            capacity = metadata.get('vbios_override_param_bytes', '1024')
            if not capacity.isdecimal():
                raise DriverPatchError('invalid prepared module registry parameter capacity')
            result['capabilities']['registry_string_max_bytes'] = int(capacity)
        else:
            for name, text in contents.items():
                if any(marker in text for marker in ('_kgspVbiosOverride', 'pVbiosOverrideDescriptor', 'vbios_override_per_gpu', 'kgspVbiosOverrideStage')):
                    raise DriverPatchError(f'pre-existing or partial override patch without a verified manifest: {name}')
            if (tree / PARSER).exists():
                raise DriverPatchError('pre-existing override parser without a verified manifest')
            _plan(contents)
        result['supported'] = True
    except (OSError, DriverPatchError) as exc:
        result['reasons'].append(str(exc))
    return result


def _working_copy(tree: Path) -> dict:
    marker = tree / WORKING_COPY_MARKER
    if marker.is_symlink():
        raise DriverPatchError('working-copy marker cannot be a symlink')
    try:
        data = json.loads(marker.read_text())
        if not isinstance(data, dict):
            raise DriverPatchError('working-copy marker must be a JSON object')
        if data.get('schema_version') != SCHEMA_VERSION or data.get('prepared_source') != str(tree):
            raise DriverPatchError('working-copy marker schema/path mismatch')
        source = Path(data['source']).resolve()
        if tree == source or tree.is_relative_to(source) or source.is_relative_to(tree):
            raise DriverPatchError('working copy overlaps its original source')
        return data
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise DriverPatchError('apply_to_tree requires a working copy emitted by prepare_source') from exc


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.vbios-txn-', dir=path.parent)
    try:
        if path.exists():
            os.fchmod(fd, path.stat().st_mode & 0o777)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _apply_to_tree_locked(tree, *, dry_run: bool = False) -> dict:
    """Apply atomically with rollback on errors, solely to a marked working copy."""
    tree = Path(tree).expanduser().resolve()
    marker = _working_copy(tree)
    info = inspect_source(tree)
    if not info['supported']:
        raise DriverPatchError('; '.join(info['reasons']))
    existing = _applied_report(tree)
    if existing:
        if info['capabilities']['module_metadata'] != MODULE_METADATA:
            raise DriverPatchError(
                'prepared source uses a legacy registry parameter capacity; '
                'prepare a fresh copy from the unpatched original source and rebuild')
        return dict(existing, status='already_applied', dry_run=dry_run, changed_files=[])
    contents = _read_required(tree)
    planned = _plan(contents)
    originals = {}
    for name in planned:
        path = tree / name
        if path.is_symlink() or not path.resolve().is_relative_to(tree):
            raise DriverPatchError(f'unsafe patch target: {name}')
        originals[name] = path.read_bytes() if path.exists() else None
    report = {'schema_version': SCHEMA_VERSION, 'status': 'dry_run' if dry_run else 'applied',
              'dry_run': dry_run, 'source': marker['source'], 'prepared_source': str(tree),
              'version': info['version'], 'capabilities': info['capabilities'],
              'source_hashes': marker['source_hashes'],
              'patched_hashes': {**info['source_hashes'], **{name: _hash(text.encode()) for name, text in planned.items()}},
              'changed_files': sorted(planned), 'module_metadata': dict(MODULE_METADATA),
              'prepared_modules': str(tree / 'kernel-open'), 'manifest_path': str(tree / MANIFEST_NAME)}
    if dry_run:
        return report
    written = []
    try:
        for name, text in planned.items():
            # Detect another writer between inspection and replacement.
            target = tree / name
            current = target.read_bytes() if target.exists() else None
            if current != originals[name]:
                raise DriverPatchError(f'source changed during patch preparation: {name}')
            written.append(name)
            _atomic_write(target, text.encode())
        _atomic_write(tree / MANIFEST_NAME, (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    except BaseException:
        # Restore with the independent primitive, including simulated writer failures.
        for name in reversed(written):
            target = tree / name
            if originals[name] is None:
                target.unlink(missing_ok=True)
            else:
                target.write_bytes(originals[name])
        (tree / MANIFEST_NAME).unlink(missing_ok=True)
        raise
    return report


def apply_to_tree(tree, *, dry_run: bool = False) -> dict:
    """Serialize API writers using the copy marker, then apply transactionally."""
    tree = Path(tree).expanduser().resolve()
    _working_copy(tree)
    with (tree / WORKING_COPY_MARKER).open('rb') as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        return _apply_to_tree_locked(tree, dry_run=dry_run)


_EXCLUDED_DIRS = {'.git', '.github', '__pycache__', 'build', 'dist', '.pytest_cache', '.venv'}
_EXCLUDED_SUFFIXES = {'.rom', '.bin', '.exe', '.ko', '.o', '.a', '.so', '.zip', '.run', '.pyc', '.cmd'}


def _source_files(source: Path):
    for parent, directories, files in os.walk(source, followlinks=False):
        for directory in directories:
            if directory not in _EXCLUDED_DIRS and (Path(parent) / directory).is_symlink():
                raise DriverPatchError(f'source directory symlink is not copied: {Path(parent) / directory}')
        directories[:] = sorted(d for d in directories if d not in _EXCLUDED_DIRS)
        for name in sorted(files):
            path = Path(parent) / name
            if path.suffix.lower() in _EXCLUDED_SUFFIXES or name.endswith('_binary') or name.startswith('.nvidia-vbios-') or '.ko.' in name:
                continue
            if path.is_symlink():
                raise DriverPatchError(f'source symlink is not copied: {path.relative_to(source)}')
            if not stat.S_ISREG(path.stat().st_mode):
                raise DriverPatchError(f'source is not a regular file: {path}')
            yield path


def prepare_source(source, destination, *, before_patch=None) -> dict:
    """Create a new isolated source copy with provenance and apply the patch.

    `before_patch(copy)`, when given, changes the new copy first (the lifecycle
    applies a distribution's DKMS build fixes there); every file this patch
    reads must come out of it unchanged.
    """
    source = Path(source).expanduser().resolve()
    destination = Path(destination).expanduser().absolute()
    if destination.is_symlink() or destination.exists():
        raise DriverPatchError('destination must not exist')
    destination = destination.resolve()
    if destination == source or destination.is_relative_to(source) or source.is_relative_to(destination):
        raise DriverPatchError('destination must be separate from the source tree')
    info = inspect_source(source)
    if not info['supported']:
        raise DriverPatchError('; '.join(info['reasons']))
    if info['capabilities'].get('already_patched'):
        raise DriverPatchError('prepare_source expects an unpatched original source')
    created = False
    try:
        destination.mkdir(parents=True, exist_ok=False)
        created = True
        hashes = {}
        for path in _source_files(source):
            relative = path.relative_to(source)
            data = path.read_bytes()
            hashes[str(relative)] = _hash(data)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(path.stat().st_mode & 0o777)
        for name, expected in info['source_hashes'].items():
            if hashes.get(name) != expected:
                raise DriverPatchError(f'source changed during copying: {name}')
        marker = {'schema_version': SCHEMA_VERSION, 'source': str(source),
                  'prepared_source': str(destination), 'source_hashes': hashes}
        _atomic_write(destination / WORKING_COPY_MARKER, (json.dumps(marker, indent=2, sort_keys=True) + '\n').encode())
        if before_patch is not None:
            before_patch(destination)
            for name, expected in info['source_hashes'].items():
                target = destination / name
                if target.is_symlink() or not target.is_file() or _hash(target.read_bytes()) != expected:
                    raise DriverPatchError(f'{name} changed before the VBIOS override patch, which needs the original file')
            if (destination / PARSER).exists() or (destination / PARSER).is_symlink():
                raise DriverPatchError(f'{PARSER} exists before the VBIOS override patch')
        return apply_to_tree(destination)
    except BaseException:
        if created:
            shutil.rmtree(destination)
        raise
