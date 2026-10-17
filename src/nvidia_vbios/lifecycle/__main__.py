"""Internal hook/service entrypoint; top-level CLI integration belongs to root."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import sys
import time
from .config import load_config
from .engine import CONFIG, STATE, Reconciler
from .security import LifecycleError, LockBusy, checked_path, json_write, token

DEFERRED = "VBIOS_DEFERRED: reconcile running; queued"


def queue_event(action, kernel, root=Path("/"), operations=None):
    """Coalesce events without invoking builds inside an RPM transaction."""
    root = Path(root)
    token(kernel)
    if action not in ("add", "remove", "changed"):
        raise LifecycleError("invalid update event")
    config = root / CONFIG.lstrip("/")
    if not config.exists():
        return {"state": "not-enrolled"}
    profile = load_config(config, root, require_enabled=False)
    if not profile.raw["enabled"]:
        return {"state": "disabled"}
    directory = root / STATE.lstrip("/") / "pending"
    checked_path(directory, root, missing=True)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    event = {"action": action, "kernel": kernel, "queued": time.time()}
    json_write(directory / (kernel + ".json"), event)
    if root == Path("/") or operations is not None:
        try:
            event["retained_default"] = Reconciler(root, operations).guard_default()
        except LockBusy:
            # A running reconcile owns the lock, for example while akmods runs a
            # nested package transaction for it. The queued event is already on
            # disk; that run, the path unit or the timer picks it up.
            event["deferred"] = True
    return event


def after_drift(worker, kernel, result):
    """Driver drift: register the exact upstream tag once, then build the override again."""
    from ..driver_update import DriverUpdate
    try:
        fetched = DriverUpdate(worker.root, worker.ops).auto_source(result["installed_driver"])
    except (LifecycleError, OSError) as exc:
        fetched = {"state": "failed", "error": str(exc)}
    if fetched.get("state") != "registered":
        return dict(result, source_fetch=fetched)
    # A failed build rolls back to the normal entry: the fail-safe again.
    return dict(worker.reconcile(kernel), source_fetch=fetched)


def kernel_key(kernel):
    # Fedora kernel-release numeric components; avoid lexical 6.9 > 6.10.
    return tuple((1, int(value)) if value.isdigit() else (0, value)
                 for value in re.findall(r"\d+|[^\d]+", kernel))


def installed_kernels(root=Path("/")):
    root = Path(root)
    configuration = root / CONFIG.lstrip("/")
    if configuration.exists():
        profile = load_config(configuration, root, require_enabled=False)
        if profile.raw.get("boot"):
            from .boot import BootAdapter
            adapter = BootAdapter(root, profile.raw)
            kernels = []
            for release in adapter.installed_kernels():
                try:
                    adapter.discover(release)
                except LifecycleError:
                    continue
                kernels.append(release)
            return sorted(kernels, key=kernel_key)
    directory = root / "usr/lib/modules"
    checked_path(directory, root)
    return sorted((path.name for path in directory.iterdir() if path.is_dir()
                   and (root / f"boot/vmlinuz-{path.name}").is_file()), key=kernel_key)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    queue = sub.add_parser("queue")
    queue.add_argument("event", choices=("add", "remove", "changed"))
    queue.add_argument("kernel")
    sub.add_parser("guard")
    post = sub.add_parser("post-transaction")
    post.add_argument("--defer", action="store_true")
    reconcile = sub.add_parser("reconcile")
    reconcile.add_argument("--kernel")
    reconcile.add_argument("--dry-run", action="store_true")
    # Explicit only (`nvbios system setup`); hooks and the service never pass it.
    reconcile.add_argument("--select-default", action="store_true",
                           help="keep the normal entry of --kernel as the previous default and select the new build")
    args = parser.parse_args(argv)
    if args.action == "reconcile" and args.select_default and not args.kernel:
        parser.error("--select-default requires --kernel")
    try:
        if args.action == "queue":
            result = queue_event(args.event, args.kernel)
            if result.get("deferred"):
                print(DEFERRED, file=sys.stderr)
        elif args.action in ("guard", "post-transaction"):
            if not Path(CONFIG).exists():
                return 0
            profile = load_config(Path(CONFIG), require_enabled=False)
            if not profile.raw["enabled"]:
                return 0
            worker = Reconciler()
            if args.action == "post-transaction":
                event = queue_event("changed", "userspace", operations=worker.ops)
                if isinstance(event, dict) and event.get("deferred"):
                    # Starting the service synchronously here would wait on the
                    # running job, which may itself wait on this transaction.
                    print(DEFERRED, file=sys.stderr)
                    return 0
                if args.defer:
                    # Native APT/libalpm callbacks still hold their parent lock.
                    # Start a service without waiting; it retries lock acquisition
                    # under its shutdown inhibitor after the parent exits.
                    worker.ops._run(["systemctl", "start", "--no-block", "nvidia-vbios-reconcile.service"])
                else:
                    worker.ops.start_reconcile()
                return 0
            result = {"retained_default": worker.guard_default()}
        else:
            worker = Reconciler()
            # Enumerate after the package transaction releases its lock. APT or
            # pacman may not have published the new normal entry when they queue us.
            deadline = time.monotonic() + 180
            delay = 0.5
            while True:
                try:
                    platform = getattr(worker.ops, "platform", None)
                    if not args.dry_run and getattr(platform, "package_provider", "rpm") in ("deb", "pacman"):
                        worker.ops.assert_transaction_idle()
                    kernels = installed_kernels()
                    if not kernels:
                        raise LifecycleError("no installed kernel with a supported normal boot entry found")
                    kernel = args.kernel or kernels[-1]
                    result = worker.reconcile(kernel, dry_run=args.dry_run, select_default=args.select_default)
                    break
                except LifecycleError as exc:
                    platform = getattr(worker.ops, "platform", None)
                    if args.dry_run or getattr(platform, "package_provider", "rpm") not in ("deb", "pacman") or "lock busy" not in str(exc) or time.monotonic() >= deadline:
                        raise
                    time.sleep(delay)
                    delay = min(delay * 2, 5)
            if not args.dry_run and result.get("state") == "driver-drift":
                result = after_drift(worker, kernel, result)
            if not args.dry_run:
                pending = Path(STATE) / "pending"
                if pending.exists():
                    for event in pending.glob("*.json"):
                        checked_path(event)
                        event.unlink()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (LifecycleError, OSError, ImportError) as exc:
        print(f"VBIOS_BLOCKED: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
