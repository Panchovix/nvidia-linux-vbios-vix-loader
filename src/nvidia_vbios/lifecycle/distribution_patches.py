"""Build fixes a distribution's DKMS package applies to the NVIDIA open kernel modules.

Ubuntu ships the unmodified source of the open modules in nvidia-kernel-source-*
and carries build fixes for its own kernels in the nvidia-dkms-* package: PATCH[n]
and PATCH_MATCH[n] entries of /usr/src/nvidia-VERSION/dkms.conf, with the files in
patches/ beside it. The loader builds the same release from its own copy, so it
applies the patches DKMS would select for the target kernel, in the same order and
from the same source root (the top of kernel-open when the package holds that
directory's contents, as Ubuntu's does), before the override patch.

dkms.conf is shell, but it is only read here, never run. An entry counts when it
is a plain top-level PATCH[n]=value or PATCH_MATCH[n]=value assignment whose value
needs no expansion, and a PATCH_MATCH regular expression only within a subset that
bash reads the same way in every locale; the loader evaluates it without
backtracking. Any other mention of PATCH or PATCH_MATCH, even inside a string, and
any shell block the reader cannot follow make every entry unknown. Entries it
cannot read are skipped with the reason in the build record, and the build then
sees the source as it did before this step.

The patches come only from the package's patches/ directory, under the trust rules
of every other root-owned input. Each one is first tried on a throwaway copy of the
source, in both directions: exactly, then with GNU patch's default fuzz, which DKMS
applies them with. A patch the source already has (a pre-patched --driver-source)
applies only in reverse and is recorded as already applied. One that applies in
neither direction, or in both and changes the source either way, stops the build.
The finished source must have every file the override patch reads as it was.
"""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shutil
import stat

from .security import LifecycleError, atomic_write, checked_path, digest

PACKAGE = "usr/src/nvidia-{version}"
MAX_CONF = 1 << 16
MAX_PATCH = 4 << 20
MAX_MATCH = 256
MAX_GROUPS = 32
_NAME = re.compile(r"[A-Za-z0-9._+-]+")
_ENTRY = re.compile(r"[ \t]*(PATCH|PATCH_MATCH)\[(0|[1-9][0-9]{0,3})\]=(.*)", re.S)
_MENTION = re.compile(r"\bPATCH(?:_MATCH)?\b")
_PLAIN = re.compile(r"[A-Za-z0-9._+,:=@%^/*?\[\]-]*")
# Tokens that open or close a shell block, in order: words, subshells, command substitutions, backquotes.
_TOKENS = re.compile(r"\$\(|[()`]|[^\s;&|()<>`]+")
# Compound commands: an assignment inside one may be conditional, a loop or a function body.
_BLOCKS = {"if": "fi", "case": "esac", "for": "done", "while": "done", "until": "done", "select": "done", "{": "}"}
_CLOSERS = set(_BLOCKS.values())
# Commands that run other shell code or stop reading the file.
_STOPS = {"eval", "source", ".", "exit", "return"}
# Regular expressions whose matches are the same for bash's POSIX ERE in any locale and for this reader:
# no classes, backreferences, lazy or possessive repetition, (?...) groups or backslashes inside brackets.
_REGEX = re.compile(r"""
    (?P<escape>\\[.^$*+?()\[\]{}|\\-])
  | (?P<bracket>\[\^?(?:[A-Za-z0-9._,@%/ ](?:-[A-Za-z0-9._,@%/ ])?)+\])
  | (?P<interval>\{[0-9]{1,3}(?:,[0-9]{0,3})?\})
  | (?P<repeat>[*+?])
  | (?P<group>\()
  | (?P<alternative>\|)
  | (?P<operator>[.^$)])
  | (?P<literal>[A-Za-z0-9_,:=@%/~ !-])
""", re.X)
_BRACKET_ITEM = re.compile(r"([A-Za-z0-9._,@%/ ])(?:-([A-Za-z0-9._,@%/ ]))?")
# GNU patch, without --fuzz: apply() tries every patch exactly first, then with GNU patch's default fuzz (2),
# which is what DKMS's `patch -p1 < patches/NAME` allows.
PATCH_ARGUMENTS = ("-p1", "--batch", "--forward", "--no-backup-if-mismatch")
FUZZ = (0, 2)


class Unsupported(ValueError):
    """An entry the loader cannot read without running the shell."""


def _logical_lines(text):
    """[(line number, code, mask)] for each logical line of the shell text.

    Comments are dropped and an unquoted backslash-newline joins two lines. `mask`
    is `code` with every quoted character replaced by 'x', so that keywords inside
    strings never open or close a block. Code None marks a quote left open.
    """
    lines, code, mask = [], [], []
    number = first = 1
    quote, previous, index = None, "\n", 0
    while index < len(text):
        char, following = text[index], text[index + 1:index + 2]
        if quote:
            if char == quote:
                quote = None
                code.append(char); mask.append(char)
            elif quote == '"' and char == "\\" and following:
                code.append(char + following); mask.append("xx")
                number += following == "\n"
                index += 1
            else:
                code.append(char); mask.append("x")
                number += char == "\n"
            previous = "x"
        elif char == "\\" and following == "\n":
            number += 1
            index += 2
            continue
        elif char == "\\" and following:
            code.append(char + following); mask.append("xx")
            previous = "x"
            index += 1
        elif char == "#" and previous in " \t\n;&|()<>":
            while index < len(text) and text[index] != "\n":
                index += 1
            continue
        elif char == "\n":
            lines.append((first, "".join(code), "".join(mask)))
            code, mask, previous = [], [], "\n"
            number += 1
            first = number
        else:
            if char in "'\"":
                quote = char
            code.append(char); mask.append(char)
            previous = char
        index += 1
    if quote:
        lines.append((first, None, None))
    elif code:
        lines.append((first, "".join(code), "".join(mask)))
    return lines


def _blocks(stack, mask):
    """Follow the shell blocks one logical line opens and closes; False when they do not nest."""
    for token in _TOKENS.findall(mask):
        if token == "`":
            if stack and stack[-1] == "`":
                stack.pop()
            else:
                stack.append("`")
        elif token in ("(", "$("):
            stack.append("(")
        elif token == ")":
            if stack and stack[-1] == "(":
                stack.pop()
            elif not (stack and stack[-1] == "case"):   # inside case, ")" ends a pattern
                return False
        elif token in _BLOCKS:
            stack.append(token)
        elif token in _CLOSERS:
            if not stack or _BLOCKS.get(stack[-1]) != token:
                return False
            stack.pop()
    return True


def _value(raw):
    """The literal value of one assignment word, or Unsupported when a shell would change it.

    DKMS sources dkms.conf, prints each value and sources it again inside double
    quotes, so a value must also stay the same when read that second time."""
    raw = raw.rstrip(" \t")
    if raw[:1] in ("'", '"'):
        quote, body = raw[0], raw[1:-1]
        if len(raw) < 2 or raw[-1] != quote or quote in body:
            raise Unsupported("is not one quoted word")
        if "\n" in body:
            raise Unsupported("spans lines")
        if quote == '"':
            if "$" in body or "`" in body:
                raise Unsupported("needs shell expansion")
            body = body.replace("\\\\", "\\")
        value = body
    elif _PLAIN.fullmatch(raw):
        value = raw
    else:
        raise Unsupported("needs shell quoting or expansion")
    if '"' in value or "`" in value or re.search(r"\\[$`\"\\]|\$[^|)]", value):
        raise Unsupported("would change when DKMS reads it a second time (quotes, $, backquotes or backslashes)")
    return value


class _Pattern:
    """A PATCH_MATCH within the subset, found anywhere in the kernel release as bash's =~ does.

    The tree is matched by following every reachable position at once, so the time
    grows with the pattern and the kernel string, never exponentially."""
    def __init__(self, pattern, tree):
        self.pattern, self._tree = pattern, tree

    def search(self, text):
        size, memo = len(text), {}

        def step(node, positions):
            return {stop for position in positions for stop in ends(node, position)}

        def ends(node, start):
            key = (id(node), start)
            if key in memo:
                return memo[key]
            kind = node[0]
            if kind == "char":
                found = {start + 1} if start < size and node[1](text[start]) else set()
            elif kind == "start":
                found = {start} if start == 0 else set()
            elif kind == "end":
                found = {start} if start == size else set()
            elif kind == "group":
                found = ends(node[1], start)
            elif kind == "sequence":
                found = {start}
                for child in node[1]:
                    found = step(child, found)
            elif kind == "alternatives":
                found = set().union(*(ends(child, start) for child in node[1]))
            else:   # repeat: `low` times, then up to `high` (None: unbounded)
                _, child, low, high = node
                found = {start}
                for _ in range(low):
                    found = step(child, found)
                frontier, count = set(found), low
                while frontier and (high is None or count < high):
                    # A position reached earlier has at least as many repetitions left.
                    frontier = step(child, frontier) - found
                    found |= frontier
                    count += 1
            memo[key] = frozenset(found)
            return memo[key]

        return any(ends(self._tree, start) for start in range(size + 1))


def _bracket(text):
    """A predicate for one bracket expression; ranges only within digits, lower or upper case letters."""
    negated, body = text[1:2] == "^", text[2 if text[1:2] == "^" else 1:-1]
    singles, ranges = set(), []
    for item in _BRACKET_ITEM.finditer(body):
        low, high = item[1], item[2]
        if high is None:
            singles.add(low)
            continue
        if not any(low in group and high in group for group in ("0123456789", "abcdefghijklmnopqrstuvwxyz",
                                                                "ABCDEFGHIJKLMNOPQRSTUVWXYZ")):
            raise Unsupported(f"has a range whose meaning depends on the locale: {low}-{high}")
        if low > high:
            raise Unsupported(f"is not a valid regular expression: range {low}-{high} is reversed")
        ranges.append((low, high))
    return lambda char: (char in singles or any(low <= char <= high for low, high in ranges)) != negated


def _regex(value):
    """PATCH_MATCH as a _Pattern, or Unsupported outside the subset that bash reads the same way."""
    if len(value) > MAX_MATCH:
        raise Unsupported(f"is longer than {MAX_MATCH} characters")
    tokens, position = [], 0
    while position < len(value):
        token = _REGEX.match(value, position)
        if token is None:
            raise Unsupported(f"uses regular expression syntax the loader does not evaluate: {value[position:]!r}")
        tokens.append((token.lastgroup, token.group()))
        position = token.end()
    tokens.append(("end", ""))
    index = 0

    def alternatives(depth):
        nonlocal index
        branches = [sequence(depth)]
        while tokens[index][0] == "alternative":
            index += 1
            branches.append(sequence(depth))
        return branches[0] if len(branches) == 1 else ("alternatives", branches)

    def sequence(depth):
        nonlocal index
        items = []
        while tokens[index][0] not in ("alternative", "end") and tokens[index] != ("operator", ")"):
            kind, text = tokens[index]
            index += 1
            if kind in ("repeat", "interval"):
                if not items or items[-1][0] in ("repeat", "start", "end"):
                    raise Unsupported("has a repetition bash and Python read differently")
                if kind == "repeat":
                    low, high = {"*": (0, None), "+": (1, None), "?": (0, 1)}[text]
                else:
                    first, comma, last = text[1:-1].partition(",")
                    low = int(first)
                    high = (int(last) if last else None) if comma else low
                    if high is not None and low > high:
                        raise Unsupported(f"is not a valid regular expression: {text} is reversed")
                items[-1] = ("repeat", items[-1], low, high)
            elif kind == "group":
                if depth >= MAX_GROUPS:
                    raise Unsupported(f"nests groups deeper than {MAX_GROUPS}")
                inner = alternatives(depth + 1)
                if tokens[index] != ("operator", ")"):
                    raise Unsupported("is not a valid regular expression: a group is not closed")
                index += 1
                items.append(("group", inner))
            elif text == "^":
                if depth or items:
                    raise Unsupported("uses ^ other than at the start of the pattern or of a top-level alternative")
                items.append(("start",))
            elif text == "$":
                if depth or tokens[index][0] not in ("alternative", "end"):
                    raise Unsupported("uses $ other than at the end of the pattern or of a top-level alternative")
                items.append(("end",))
            elif kind == "bracket":
                items.append(("char", _bracket(text)))
            elif text == ".":
                items.append(("char", lambda char: True))
            else:
                literal = text[-1]
                items.append(("char", lambda char, literal=literal: char == literal))
        if not items:
            raise Unsupported("has an empty group or alternative")
        return items[0] if len(items) == 1 else ("sequence", items)

    tree = alternatives(0)
    if tokens[index][0] != "end":
        raise Unsupported("is not a valid regular expression: ) without (")
    return _Pattern(value, tree)


def parse(data):
    """Read the PATCH and PATCH_MATCH entries of dkms.conf bytes without running anything.

    Returns {"PATCH": {index: value}, "PATCH_MATCH": {index: value or _Pattern},
    "unsupported": {(key, index): reason}, "certain": {PATCH indices always set},
    "problem": reason or None}. A problem means the entries cannot be known at all:
    PATCH or PATCH_MATCH mentioned anywhere else, even inside a string, eval,
    source, exit or return, or shell blocks that do not nest. Unsupported entries
    are known to exist but have a value the loader does not evaluate, or sit inside
    an if block, loop, function, subshell or command substitution, or after &&, ||
    or |; such a PATCH entry may not be set, so DKMS may count one entry fewer. A
    later assignment replaces an earlier one, as in the shell.
    """
    result = {"PATCH": {}, "PATCH_MATCH": {}, "unsupported": {}, "certain": set(), "problem": None}
    text = data.decode("latin-1").replace("\r\n", "\n")   # DKMS drops the CR that ends each value
    if "\0" in text:
        result["problem"] = "dkms.conf contains NUL bytes"
        return result
    stack, condition = [], False
    for number, code, mask in _logical_lines(text):
        if code is None:
            result["problem"] = f"dkms.conf line {number}: a quote is never closed"
            return result
        if "<<" in mask or "$'" in mask:
            result["problem"] = f"dkms.conf line {number}: here-documents and $'...' strings are not read"
            return result
        if any(word in _STOPS for word in re.findall(r"[^\s;&|()<>`]+", mask)):
            result["problem"] = (f"dkms.conf line {number}: eval, source, exit or return changes what the shell "
                                 "reads, and the loader does not follow it")
            return result
        outer, conditional = bool(stack), condition
        condition = bool(re.search(r"(?:&&|\|)[ \t]*$", mask))
        if not _blocks(stack, mask):
            result["problem"] = f"dkms.conf line {number}: shell blocks do not nest"
            return result
        entry = _ENTRY.fullmatch(code)
        if entry is None:
            if _MENTION.search(code):
                result["problem"] = f"dkms.conf line {number}: PATCH is used outside a plain PATCH[n]=value assignment"
                return result
            continue
        key, index = entry[1], int(entry[2])
        raw, rest = entry[3], mask[entry.start(3):].rstrip(" \t")
        # PATCH[0]="fix.patch"; and, in a case branch, PATCH[0]="fix.patch" ;;
        for ending in ((";;", ";") if stack and stack[-1] == "case" else (";",)):
            if rest.endswith(ending):
                raw, rest = raw[:len(rest) - len(ending)], rest[:-len(ending)]
                break
        if re.search(r"[\s;&|<>()]", rest.rstrip(" \t")):
            result["problem"] = f"dkms.conf line {number}: {key}[{index}] is followed by more shell code"
            return result
        result[key].pop(index, None)
        result["unsupported"].pop((key, index), None)
        try:
            if outer:
                raise Unsupported("is inside a shell block (if, case, loop, function, subshell or command substitution)")
            if conditional:
                raise Unsupported("is conditional (the line before ends with &&, || or |)")
            if key == "PATCH":
                result["certain"].add(index)
            value = _value(raw)
            result[key][index] = _regex(value) if key == "PATCH_MATCH" and value else value
        except Unsupported as exc:
            result[key][index] = None
            result["unsupported"][(key, index)] = f"dkms.conf line {number}: {key}[{index}] {exc}"
    if stack:
        result["problem"] = "dkms.conf ends inside a shell block"
    return result


def select(parsed, kernel):
    """([(index, name, regex text)], [skipped]) for the target kernel, as DKMS chooses them.

    DKMS visits PATCH[0] up to PATCH[count - 1], where count is the number of
    PATCH entries, and takes each non-empty one whose PATCH_MATCH is empty or
    found anywhere in the kernel release (bash's =~). With conditional entries
    the count is only known to lie between the entries always set and all of
    them, and an index in between is skipped.
    """
    if parsed["problem"]:
        return [], [{"index": None, "name": None, "reason": parsed["problem"]}]
    patches, matches, unsupported = parsed["PATCH"], parsed["PATCH_MATCH"], parsed["unsupported"]
    low, high = len(parsed["certain"]), len(patches)
    selected, skipped = [], []
    for index in sorted(patches):
        name = patches[index]
        if name == "":
            continue  # DKMS skips an empty entry too
        if index >= high:
            skipped.append({"index": index, "name": name,
                            "reason": f"DKMS reads only PATCH[0] to PATCH[{high - 1}] when {high} are set"})
            continue
        problem = unsupported.get(("PATCH", index)) or unsupported.get(("PATCH_MATCH", index))
        if problem:
            skipped.append({"index": index, "name": name, "reason": problem})
            continue
        if index >= low:
            skipped.append({"index": index, "name": name,
                            "reason": f"DKMS reads PATCH[{index}] only if the conditional PATCH entries are set"})
            continue
        match = matches.get(index) or ""
        if match == "" or match.search(kernel):
            selected.append((index, name, match if isinstance(match, str) else match.pattern))
    return selected, skipped


def _layout(package):
    """Where the DKMS source root sits in an NVIDIA release tree: "kernel-open" when the package holds
    that directory's contents at its top (Ubuntu), "." when it holds the release or a kernel-open
    directory, None when it holds neither."""
    if (package / "kernel-open").is_dir():
        return "."
    if (package / "Kbuild").is_file() and (package / "nvidia").is_dir():
        return "kernel-open"
    return None


def _trusted_bytes(path, root, limit, label):
    try:
        checked_path(path, root)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except (LifecycleError, OSError) as exc:
        raise LifecycleError(f"{label}: {exc}") from None
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise LifecycleError(f"{label} is not a regular file")
    with os.fdopen(fd, "rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise LifecycleError(f"{label} is larger than {limit} bytes")
    return data


def plan(root, version, kernel):
    """What the distribution's dkms.conf applies to `version` for `kernel`, or None without one.

    Reads dkms.conf and the selected patches now, under the trust rules of every
    root-owned input (LifecycleError when one fails). The record says which file
    was read; apply() fills in what each patch did.
    """
    root = Path(root)
    package = root / PACKAGE.format(version=version)
    conf = package / "dkms.conf"
    if not (conf.exists() or conf.is_symlink()):
        return None
    shown = "/" + conf.relative_to(root).as_posix()
    directory = shown.removesuffix("dkms.conf") + "patches"
    data = _trusted_bytes(conf, root, MAX_CONF, f"distribution DKMS configuration {shown}")
    selected, skipped = select(parse(data), kernel)
    layout = _layout(package)
    if selected and layout is None:
        skipped += [{"index": index, "name": name, "reason": "the package's source layout is not recognised"}
                    for index, name, _ in selected]
        selected = []
    patches = []
    for index, name, match in selected:
        label = f"dkms.conf PATCH[{index}]"
        parts = name.split("/")
        if not all(_NAME.fullmatch(part) and part not in (".", "..") for part in parts):
            raise LifecycleError(f"{label} is not a file name inside {directory}: {name!r}")
        path = package.joinpath("patches", *parts)
        if not (path.exists() or path.is_symlink()):
            raise LifecycleError(f"{label} names {name}, which is missing from {directory}")
        content = _trusted_bytes(path, root, MAX_PATCH, f"{label} ({name})")
        patches.append({"index": index, "name": name, "match": match, "sha256": digest(content), "data": content})
    record = {"dkms_conf": shown, "dkms_conf_sha256": digest(data), "kernel": kernel, "source_root": layout,
              "applied": [], "already_applied": [], "skipped": skipped}
    return {"record": record, "patches": patches, "source_root": layout}


def preview(planned):
    """The record before any patch ran (reconcile --dry-run)."""
    return dict(planned["record"], selected=[{key: patch[key] for key in ("index", "name", "sha256", "match")}
                                             for patch in planned["patches"]])


def changed_selection(previous, planned):
    """Whether a prepared build no longer has the patches dkms.conf selects now (by index, name and SHA-256).

    A build made before the loader applied distribution patches has no record and is kept as it is."""
    if not isinstance(previous, dict) or "distribution_patches" not in previous:
        return False
    record = previous["distribution_patches"] if isinstance(previous["distribution_patches"], dict) else {}
    built = sorted((item.get("index"), item.get("name"), item.get("sha256"))
                   for key in ("applied", "already_applied") for item in record.get(key, []) if isinstance(item, dict))
    wanted = sorted((patch["index"], patch["name"], patch["sha256"]) for patch in (planned or {}).get("patches", []))
    return built != wanted


def _state(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return "not-a-regular-file"
    return digest(path.read_bytes())


def _snapshot(directory):
    """{relative path: (type, mode, content)} of everything below `directory`, without following links."""
    found = {}
    for parent, directories, names in os.walk(directory):
        for name in (*directories, *names):
            path = Path(parent) / name
            info = path.lstat()
            content = (digest(path.read_bytes()) if stat.S_ISREG(info.st_mode)
                       else os.readlink(path) if stat.S_ISLNK(info.st_mode) else None)
            found[path.relative_to(directory).as_posix()] = (stat.S_IFMT(info.st_mode), stat.S_IMODE(info.st_mode), content)
    return found


def _plain_files(base, tree):
    for directory, directories, names in os.walk(base):
        for name in (*directories, *names):
            path = Path(directory) / name
            mode = path.lstat().st_mode
            if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise LifecycleError(f"after the distribution patches the driver source has a link or special file: "
                                     f"{path.relative_to(tree)}")


def apply(planned, tree, ops, *, guarded, log, work, record=None):
    """Apply the planned patches inside the new working copy `tree`, before the override patch.

    Each step is tried first on a throwaway copy of the source root, where GNU
    patch really runs: a dry run would check a second section for the same file
    against the original. Patches the source already has (a pre-patched
    --driver-source) come out first, newest first, so that a later patch whose
    context overlaps an earlier one cannot hide it; then each patch goes in, in
    index order, and the record calls it already applied when the source had it.
    Trials go to trials.log in `work`, the changes to `log`. A patch that applies
    in neither direction, or in both and changes the source either way, stops the
    build, which never sees a half-patched tree. `guarded` names the files
    (relative to `tree`) that must come out unchanged. Fills `record` (a copy of
    the planned record when None) as it goes, so that a failure still shows what
    ran, and returns it.
    """
    record = json.loads(json.dumps(planned["record"])) if record is None else record
    base = tree if planned["source_root"] == "." else tree / planned["source_root"]
    if base.is_symlink() or not base.is_dir():
        raise LifecycleError(f"the driver source has no {planned['source_root']} directory for the distribution patches")
    before = {name: _state(tree / name) for name in guarded}
    work.mkdir(mode=0o700, exist_ok=True)
    trials = work / "trials.log"
    files = {}
    for patch in planned["patches"]:
        files[patch["index"]] = work / (f"{patch['index']:04d}-" + patch["name"].replace("/", "-"))
        atomic_write(files[patch["index"]], patch["data"], 0o600)

    def label(patch):
        return f"distribution patch {patch['name']} (dkms.conf PATCH[{patch['index']}])"

    def run(patch, directory, fuzz, options, output):
        arguments = [*PATCH_ARGUMENTS, f"--fuzz={fuzz}", *options, "-d", str(directory),
                     "-i", str(files[patch["index"]])]
        return ops.patch(arguments, log=output) == 0

    def trial(patch, fuzz, *options):
        copy = work / ("trial" + "".join(options))
        if copy.exists() or copy.is_symlink():
            shutil.rmtree(copy)
        shutil.copytree(base, copy, symlinks=True)
        if run(patch, copy, fuzz, options, trials):
            return copy
        shutil.rmtree(copy)
        return None

    def decide(patch):
        """(verdict, fuzz): "forward", "reverse" (already in the source), "unchanged", "both" or None."""
        for fuzz in FUZZ:
            forward = reverse = None
            try:
                forward, reverse = trial(patch, fuzz), trial(patch, fuzz, "-R")
                if forward and reverse:
                    # An empty patch, or one that only sets a mode or renames a file the source already has.
                    original = _snapshot(base)
                    moved = (_snapshot(forward) != original, _snapshot(reverse) != original)
                    verdict = {(True, False): "forward", (False, True): "reverse", (False, False): "unchanged"}
                    return verdict.get(moved, "both"), fuzz
                if forward or reverse:
                    return ("forward" if forward else "reverse"), fuzz
            finally:
                for copy in (forward, reverse):
                    if copy is not None:
                        shutil.rmtree(copy)
        return None, None

    def change(patch, fuzz, *options):
        if not run(patch, base, fuzz, options, log):
            raise LifecycleError(f"{label(patch)} failed after it applied to a copy of the source; see {log}")
        _plain_files(base, tree)

    present = set()
    for patch in reversed(planned["patches"]):
        verdict, fuzz = decide(patch)
        if verdict == "reverse":
            change(patch, fuzz, "-R")
            present.add(patch["index"])
    touched = {}
    for patch in planned["patches"]:
        verdict, fuzz = decide(patch)
        entry = dict({key: patch[key] for key in ("index", "name", "sha256", "match")}, fuzz=fuzz)
        if verdict == "forward":
            states = {name: _state(tree / name) for name in guarded}
            change(patch, fuzz)
            touched.update({name: patch for name in guarded if _state(tree / name) != states[name]})
            record["already_applied" if patch["index"] in present else "applied"].append(entry)
        elif verdict == "reverse":
            record["already_applied"].append(entry)
        elif verdict == "unchanged":
            record["applied"].append(dict(entry, no_change=True))
        elif verdict == "both":
            raise LifecycleError(f"{label(patch)} applies both forward and in reverse, so it is unclear whether the "
                                 f"driver source already has it; see {trials}")
        else:
            raise LifecycleError(f"{label(patch)} does not apply to the driver source, exactly or with the fuzz DKMS "
                                 f"allows, and is not already in it (a modified --driver-source must already contain "
                                 f"it); see {trials}")
    _plain_files(base, tree)
    for name in guarded:
        if _state(tree / name) != before[name]:
            culprit = label(touched[name]) if name in touched else "a distribution patch"
            raise LifecycleError(f"{culprit} changes {name}, which the VBIOS override patch reads; not building")
    return record


def summary(record):
    """The short form `nvbios system status` shows, or None without a record."""
    if not isinstance(record, dict):
        return None
    def names(key):
        return [str(item.get("name")) + (f" (fuzz {item['fuzz']})" if item.get("fuzz") else "")
                + (" (no change)" if item.get("no_change") else "")
                for item in record.get(key, []) if isinstance(item, dict)]
    skipped = [(f"PATCH[{item['index']}]: " if item.get("index") is not None else "") + str(item.get("reason"))
               for item in record.get("skipped", []) if isinstance(item, dict)]
    return {"kernel": record.get("kernel"), "dkms_conf": record.get("dkms_conf"), "applied": names("applied"),
            "already_applied": names("already_applied"), "skipped": skipped}
