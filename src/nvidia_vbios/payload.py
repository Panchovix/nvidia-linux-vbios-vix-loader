"""Override payload check that mirrors the patched kernel loader (driver/_payload.py).

The patched driver loads a payload only when it holds exactly one NVIDIA legacy PCI image,
for this GPU's PCI ID, with a zero checksum (scanned on 512-byte boundaries, at most 4 MiB).
Checking the same rule before enrollment means an enrolled payload is one the kernel accepts.
check_loadable_payload additionally enforces known GSP receiver capacities.
This module does not decode or edit VBIOS tables; editing belongs to a VBIOS editor.
"""
from __future__ import annotations
import importlib
import importlib.util
import struct
from .families import GA100_DEVICE_IDS, architecture

MAX_SIZE = 4 * 1024 * 1024
GA10X_MAX_SIZE = 512 * 1024
ADA_MAX_SIZE = GA10X_MAX_SIZE  # Compatibility name: AD10x has the same audited capacity.
SCOPE = ('ampere', 'ada', 'blackwell-gb20x')


class PayloadError(ValueError):
    pass


def find_legacy(data: bytes, vendor: int, device: int) -> int:
    """Offset of the single legacy image the kernel would select, or PayloadError."""
    size = len(data)
    if not 0x200 <= size <= MAX_SIZE:
        raise PayloadError(f'payload is {size} bytes; the loader accepts 512 B to 4 MiB')
    pci_id = vendor | device << 16
    found = []
    for offset in range(0, size - 0x200 + 1, 0x200):
        if data[offset:offset + 2] != b'\x55\xaa':
            continue
        relative = struct.unpack_from('<H', data, offset + 0x18)[0]
        if relative > size - offset - 0x18:
            continue
        pcir = offset + relative
        if data[pcir:pcir + 4] != b'PCIR' or data[pcir + 0x14] != 0:
            continue
        image_id = struct.unpack_from('<I', data, pcir + 4)[0]
        length = struct.unpack_from('<H', data, pcir + 0x10)[0] * 512
        if image_id != pci_id:
            raise PayloadError(f'legacy image at {offset:#x} is for PCI ID '
                               f'{image_id & 0xffff:04x}:{image_id >> 16:04x}, not {vendor:04x}:{device:04x}')
        if length == 0 or length > size - offset or relative > length or length - relative < 0x18:
            raise PayloadError(f'legacy image at {offset:#x} has an invalid length')
        if sum(data[offset:offset + length]) & 0xff:
            raise PayloadError(f'legacy image at {offset:#x} has a nonzero checksum')
        found.append(offset)
    if len(found) != 1:
        hint = (' (a full ROM with two banks?); load a single-chain payload instead: Vix Editor saves one as '
                '<name>-loader.bin next to an edited Ampere or Ada copy, and its `normalize` command exports '
                'one from any ROM' if len(found) > 1 else '')
        raise PayloadError(f'payload has {len(found)} legacy images; the driver needs exactly one{hint}')
    return found[0]


def gsp_bytes(data: bytes, vendor: int, device: int) -> int:
    """Bytes the patched driver hands to the GSP: from the selected legacy image to the end of the file."""
    return len(data) - find_legacy(data, vendor, device)


def check_payload(data: bytes, vendor: int, device: int) -> str:
    """Validate a payload for this GPU and return its architecture family."""
    if vendor != 0x10de:
        raise PayloadError('only NVIDIA GPUs are supported')
    family = architecture(device)['family']
    if family not in SCOPE:
        raise PayloadError(f'PCI device {device:04x} is outside the supported Ampere/Ada/GB20x scope')
    find_legacy(data, vendor, device)
    return family


def check_loadable_payload(data: bytes, vendor: int, device: int) -> str:
    """Kernel parser checks plus the audited GA10x/AD10x GSP receiver capacity.

    The driver sends everything from the selected legacy image to the end of the
    payload. Prefix bytes are not sent. GA100 uses different, unaudited firmware;
    no 512 KiB capacity is inferred for it or for Blackwell from this audit.
    """
    family = check_payload(data, vendor, device)
    if family == 'ada' or (family == 'ampere' and device not in GA100_DEVICE_IDS):
        size = gsp_bytes(data, vendor, device)
        if size > GA10X_MAX_SIZE:
            chip = 'Ampere GA10x' if family == 'ampere' else 'Ada AD10x'
            representation = 'ampere-relocated-v1' if family == 'ampere' else 'ada-relocated-v2'
            hint = ('Load an experimental relocated payload instead: Vix Editor saves one as <name>-loader.bin '
                    'next to an edited copy, or export it with `nvbios normalize edited.rom payload.bin '
                    f'--representation {representation}`.')
            raise PayloadError(f'{chip} GSP accepts at most 512 KiB (524288 bytes) from the legacy image; '
                               f'this payload sends {size} bytes. {hint}')
    return family


def optional_editor():
    """Optional extension module that can normalize full ROM dumps; None when it is not installed.

    Without it, profile preparation accepts single-chain payloads only."""
    name = __package__ + '._editor_bridge'
    return importlib.import_module(name) if importlib.util.find_spec(name) is not None else None
