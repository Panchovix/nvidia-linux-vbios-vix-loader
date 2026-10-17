"""nvbios: per-GPU VBIOS override loader for Linux (system lifecycle and driver source preparation)."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys
from . import __version__


class UsageError(ValueError):
    code = 'INVALID_ARGUMENT'


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise UsageError(message)


def emit(value):
    print(json.dumps(value, indent=2, sort_keys=True, allow_nan=False))


def add_driver_parser(commands):
    p = commands.add_parser('driver', help='inspect or prepare an isolated NVIDIA source tree')
    actions = p.add_subparsers(dest='driver_action', required=True)
    for name in ('inspect', 'matrix'):
        q = actions.add_parser(name)
        q.add_argument('sources', type=Path, nargs='+' if name == 'matrix' else 1)
        q.add_argument('--json', action='store_true')
    q = actions.add_parser('prepare')
    q.add_argument('--source', type=Path, required=True)
    q.add_argument('--destination', type=Path, required=True)
    q.add_argument('--json', action='store_true')
    q = actions.add_parser('apply')
    q.add_argument('working_copy', type=Path)
    q.add_argument('--dry-run', action='store_true')
    q.add_argument('--json', action='store_true')


def execute_driver(args):
    from .driver import inspect_source, prepare_source, apply_to_tree
    if args.driver_action == 'prepare':
        return prepare_source(args.source, args.destination)
    if args.driver_action == 'apply':
        return apply_to_tree(args.working_copy, dry_run=args.dry_run)
    reports = [inspect_source(path) for path in args.sources]
    return reports if args.driver_action == 'matrix' else reports[0]


SYSTEM_USAGE = '''usage: nvbios system COMMAND [options]

  devices        list GPUs with their nvidia-smi index, UUID and PCI address
  prepare        write a profile from one payload per GPU (no system changes)
  install        install the runtime, hooks and units
  enroll         enroll a prepared profile
  reconcile      build modules and the boot entry for a kernel
  enable         turn on automatic rebuilds after updates
  status         show readiness and what is loaded
  disable        stop automatic rebuilds and restore the normal boot entry
  rollback       undo one install, enroll or enable transaction
  pre-install    pause automation before a manual driver change
  post-install   register the new driver source and rebuild
  setup          prepare, install, enroll, build and enable in one step (used by the window)

Run `nvbios system COMMAND --help` for the options of one command.'''


def system_main(argv):
    """`nvbios system ...`: GPU selection, enrollment, kernel/driver updates and status."""
    if not argv or argv[0] in ('-h', '--help', 'help'):
        print(SYSTEM_USAGE)
        return 0 if argv else 2
    if argv and argv[0] in {'devices', 'prepare'}:
        from .onboarding import main as onboarding_main
        return onboarding_main(argv)
    if argv and argv[0] == 'pre-install':
        from .driver_update import pre_install_main
        return pre_install_main(argv[1:])
    if argv and argv[0] == 'post-install':
        from .driver_update import main as post_install_main
        return post_install_main(argv[1:])
    if argv and argv[0] == 'setup':
        from .system_setup import main as setup_main
        return setup_main(argv[1:])
    if argv and argv[0] in {'install', 'enroll', 'enable', 'status', 'disable', 'rollback'}:
        from .bootstrap import main as bootstrap_main
        return bootstrap_main(argv)
    from .lifecycle.__main__ import main as lifecycle_main
    return lifecycle_main(argv)


def parser():
    root = Parser(prog='nvbios', description=__doc__)
    root.add_argument('--version', action='version', version=f'nvbios {__version__}')
    root.add_argument('--json', action='store_true', help='JSON is the default command output')
    commands = root.add_subparsers(dest='command', required=True)
    add_driver_parser(commands)
    commands.add_parser('system', help='Linux: GPU selection, enrollment, updates and status', add_help=False)
    return root


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    # Lifecycle hooks have their own stable noninteractive command set.
    if argv and argv[0] == 'system':
        return system_main(argv[1:])
    operation = None
    try:
        args = parser().parse_args(argv)
        operation = args.command
        result = execute_driver(args)
        emit(dict(schema_version=1, ok=True, operation=operation, result=result))
        return 0
    except (ValueError, OSError, RuntimeError) as exc:
        emit(dict(schema_version=1, ok=False, operation=operation,
                  error=dict(code=getattr(exc, 'code', 'IO_ERROR' if isinstance(exc, OSError) else 'OPERATION_FAILED'),
                             message=str(exc), details=getattr(exc, 'details', {}))))
        return 2
    except KeyboardInterrupt:
        emit(dict(schema_version=1, ok=False, operation=operation,
                  error=dict(code='INTERRUPTED', message='operation interrupted', details={})))
        return 130
