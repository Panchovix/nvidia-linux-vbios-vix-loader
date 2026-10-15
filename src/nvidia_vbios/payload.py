"""Override payload check that mirrors the patched kernel loader (driver/_payload.py).

The patched driver loads a payload only when it holds exactly one NVIDIA legacy PCI image,
for this GPU's PCI ID, with a zero checksum (scanned on 512-byte boundaries, at most 4 MiB).
Checking the same rule before enrollment means an enrolled payload is one the kernel accepts.
This module does not decode or edit VBIOS tables; editing belongs to a VBIOS editor.
"""
from __future__ import annotations
import importlib
import importlib.util
import struct
from .families import architecture

MAX_SIZE = 4 * 1024 * 1024
ADA_MAX_SIZE = 512 * 1024
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
        hint = (' (a full ROM with two banks?); export a single-chain payload with your VBIOS editor, '
                "for example the `normalize` command of Vix Editor's command-line tool" if len(found) > 1 else '')
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


def optional_editor():
    """Optional extension module that can normalize full ROM dumps; None when it is not installed.

    Without it, profile preparation accepts single-chain payloads only."""
    name = __package__ + '._editor_bridge'
    return importlib.import_module(name) if importlib.util.find_spec(name) is not None else None
