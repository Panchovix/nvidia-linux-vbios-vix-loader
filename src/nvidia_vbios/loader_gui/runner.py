"""Run one privileged loader command through pkexec and say how it ended. No GTK here.

stdout is read line by line (setup's progress events) while a second thread drains stderr, so a long
traceback can never fill a pipe and stall the root side.
"""
from __future__ import annotations
from dataclasses import dataclass
import re
import shlex
import subprocess
import threading

# Without a graphical polkit agent pkexec then fails with 127 instead of asking in a terminal nobody sees.
PKEXEC = ['/usr/bin/pkexec', '--disable-internal-agent']
BLOCKED = re.compile(r'^(?:SETUP|PREPARE|BOOTSTRAP|VBIOS|PRE_INSTALL|POST_INSTALL)_BLOCKED: (.*)$')


@dataclass(frozen=True)
class Outcome:
    returncode: int
    stdout: tuple[str, ...]
    stderr: str


def stream(argv, on_line):
    """Run argv with cwd '/', call on_line(line) for every stdout line, and return the Outcome."""
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd='/', text=True, encoding='utf-8', errors='replace')
    except OSError as exc:
        return Outcome(127, (), f'{argv[0]}: {exc}')
    errors, lines = [], []
    with process:
        drain = threading.Thread(target=lambda: errors.append(process.stderr.read()), daemon=True)
        drain.start()
        for line in process.stdout:
            line = line.rstrip('\n')
            lines.append(line)
            on_line(line)
        drain.join()
    return Outcome(process.returncode, tuple(lines), ''.join(errors))


def _tail(text, count=5):
    return '\n'.join(text.strip().splitlines()[-count:])


def classify(outcome):
    """(kind, detail): ok, cancelled, no-agent, not-authorized, pkexec-error, blocked, usage or crash."""
    code, errors = outcome.returncode, outcome.stderr
    if code == 0:
        return 'ok', ''
    if code == 126:
        return 'cancelled', ''
    if code == 127:
        if 'No authentication agent' in errors:
            return 'no-agent', ''
        return ('not-authorized', '') if 'Not authorized' in errors else ('pkexec-error', _tail(errors))
    if code == 1:
        messages = [match[1] for match in map(BLOCKED.match, errors.splitlines()) if match]
        # Without a *_BLOCKED line it is an uncaught exception: show the end of the traceback.
        return ('blocked', messages[-1]) if messages else ('crash', _tail(errors))
    return ('usage' if code == 2 else 'crash'), _tail(errors)


def sudo_text(argv):
    """The same command for a terminal, when no polkit agent can ask for the password."""
    return 'sudo ' + shlex.join(value for value in argv[len(PKEXEC):] if value != '--progress')
