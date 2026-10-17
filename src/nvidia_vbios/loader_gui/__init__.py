"""vbios-loader-gui: a GTK 4 window that loads a VBIOS override per GPU with the Linux loader.

It runs as the desktop user and asks for the password (pkexec) once per Load, Remove or Details.
GTK is imported only when main runs; probe, runner and controller never import it.
"""
from __future__ import annotations
import argparse
import os
import sys

PROG = 'vbios-loader-gui'
MIN_GTK = (4, 10)     # Gtk.FileDialog and Gtk.AlertDialog


def main(argv=None):
    from .. import __version__
    parser = argparse.ArgumentParser(prog=PROG, description=__doc__.split('\n')[0])
    parser.add_argument('--version', action='version', version=f'{PROG} {__version__}')
    parser.add_argument('--lang', choices=('en', 'es'), help='language (default: from LC_ALL, LC_MESSAGES or LANG)')
    args = parser.parse_args(argv)
    if os.geteuid() == 0:
        print(f'{PROG}: run it as your normal user, without sudo; it asks for the password when needed',
              file=sys.stderr)
        return 1
    try:
        import gi
        gi.require_version('Gtk', '4.0')
        from gi.repository import Gtk
    except (ImportError, ValueError) as exc:
        print(f'{PROG}: needs GTK 4 and PyGObject (Fedora: sudo dnf install python3-gobject gtk4): {exc}',
              file=sys.stderr)
        return 2
    if (Gtk.get_major_version(), Gtk.get_minor_version()) < MIN_GTK:
        print(f'{PROG}: needs GTK {MIN_GTK[0]}.{MIN_GTK[1]} or newer; this system has '
              f'{Gtk.get_major_version()}.{Gtk.get_minor_version()}', file=sys.stderr)
        return 2
    from .gui import run
    return run(args)


__all__ = ['main']
