"""Per-GPU setting of NVIDIA's MSVDD black-screen workaround through the lifecycle's preserved registry parameters.

On GB202..GB207 boards in NVIDIA's built-in list, the driver lowers the MSVDD reliability limit by
50 mV unless the FixBlackScreenIssue registry dword says otherwise: 1 always applies it, 2 never
does, absent keeps NVIDIA's board list (KMD 617/621 and GSP-RM 615/620). Confirmed on an RTX 5090,
5080 and 5070 Ti: with 'off' the MSVDD reliability offset reads 0 instead of -50 mV. This command only changes the optional "parameters" of the enrolled
profile for one enrolled Blackwell GPU, in one bootstrap ownership transaction. It never queries or
touches a GPU. The reconcile service rebuilds the boot image and the setting applies at the next boot.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from .config import BDF, load_config
from .engine import CONFIG
from .registry import PARAMETER, scopes, with_value
from .security import LifecycleError

KEY = "FixBlackScreenIssue"
MODES = {"on": "1", "off": "2", "default": None}
NEXT_STEP = "The reconcile service rebuilds the boot image; the setting applies at the next boot."


def settings(parameters: dict) -> dict[str, str]:
    """BDF -> 'on', 'off' or the raw value, for every GPU with an explicit setting."""
    names = {value: name for name, value in MODES.items() if value}
    return {bdf: names.get(values[KEY], values[KEY])
            for bdf, values in scopes(parameters.get(PARAMETER, "")).items() if KEY in values}


def with_mode(parameters: dict, bdf: str, mode: str) -> dict:
    """Copy of parameters with the workaround set for bdf; 'default' removes the key."""
    if not BDF.fullmatch(bdf):
        raise LifecycleError("GPU BDF must be canonical, e.g. 0000:06:00.0")
    if mode not in MODES:
        raise LifecycleError("mode must be on, off or default")
    return with_value(parameters, bdf, KEY, MODES[mode])


def update(bdf: str, mode: str, *, root: Path = Path("/"), operations=None, dry_run: bool = False) -> dict:
    """Publish the setting for one enrolled Blackwell GPU, chosen by its PCI address only."""
    from ..bootstrap import Bootstrap
    bootstrap = Bootstrap(root, operations)
    devices = {device["bdf"]: device for device in
               load_config(bootstrap.path(CONFIG), root, require_enabled=False).devices}
    if bdf not in devices:
        raise LifecycleError(f"{bdf} is not an enrolled GPU")
    if devices[bdf].get("architecture") != "blackwell-gb20x":
        raise LifecycleError("the black-screen workaround exists only on Blackwell GB20x GPUs")
    report = bootstrap.update_parameters(lambda current: with_mode(current, bdf, mode), dry_run=dry_run)
    result = dict(report, gpu=bdf, mode=mode, settings=settings(report["parameters"]))
    if report["state"] == "published":
        result["next"] = NEXT_STEP
    return result


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="nvbios system black-screen-fix", description=__doc__.split("\n")[0])
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("show", help="list GPUs with an explicit setting")
    action = actions.add_parser("set", help="on, off or default (NVIDIA's board list) for one enrolled GPU")
    action.add_argument("--device", required=True, help="PCI address of an enrolled GPU, e.g. 0000:06:00.0")
    action.add_argument("mode", choices=sorted(MODES))
    action.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.action == "show":
            profile = load_config(Path(CONFIG), require_enabled=False)
            result = {"settings": settings(profile.raw.get("parameters") or {})}
        else:
            result = update(args.device, args.mode, dry_run=args.dry_run)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (LifecycleError, OSError, ValueError) as exc:
        print(f"VBIOS_BLOCKED: {exc}", file=sys.stderr)
        return 1
