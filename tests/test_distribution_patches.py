"""Distribution DKMS build fixes: reading dkms.conf, choosing by kernel, applying before the override patch.

Synthetic roots and source trees only. dkms.conf is read as text and never run; GNU patch applies the
synthetic patches to copies inside the test directory.
"""
import difflib
import json
import os
from pathlib import Path
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests"))
import test_lifecycle as lifecycle_fixtures
import test_source_fetch as fetch_fixtures
from test_lifecycle import FakeOperations, NEW, OLD, VERSION
from nvidia_vbios.bootstrap import Bootstrap
from nvidia_vbios.lifecycle import Reconciler, distribution_patches as dkms
from nvidia_vbios.lifecycle.engine import STATE
from nvidia_vbios.lifecycle.platform import DEBIAN_PLATFORM
from nvidia_vbios.lifecycle.security import LifecycleError, atomic_write, digest, json_write, source_tree_hash
from nvidia_vbios.lifecycle.system import SystemOperations

PATCH = shutil.which("patch")
needs_patch = unittest.skipUnless(PATCH, "GNU patch is not installed")

# The dkms.conf of Ubuntu's nvidia-dkms-615-open 615.71.09-0ubuntu0.26.04.2, which builds 7.0.0 kernels
# only with the last two patches.
UBUNTU = r'''PACKAGE_NAME="nvidia"
PACKAGE_VERSION="615.71.09"
CLEAN="make clean"
BUILT_MODULE_NAME[0]="nvidia"
DEST_MODULE_LOCATION[0]="/kernel/drivers/char/drm"
PROCS_NUM=`nproc`
[ $PROCS_NUM -gt 16 ] && PROCS_NUM=16
MAKE[0]="unset ARCH; [ ! -h /usr/bin/cc ] && export CC=/usr/bin/gcc; env NV_VERBOSE=1 \
    'make' -j$PROCS_NUM NV_EXCLUDE_BUILD_MODULES='' KERNEL_UNAME=${kernelver} IGNORE_XEN_PRESENCE=1 IGNORE_CC_MISMATCH=1 SYSSRC=$kernel_source_dir LD=/usr/bin/ld.bfd CONFIG_X86_KERNEL_IBT= modules"
BUILT_MODULE_NAME[1]="nvidia-modeset"
DEST_MODULE_LOCATION[1]="/kernel/drivers/char/drm"
BUILT_MODULE_NAME[2]="nvidia-drm"
DEST_MODULE_LOCATION[2]="/kernel/drivers/char/drm"
AUTOINSTALL="yes"
PATCH[0]="disable_fstack-clash-protection_fcf-protection.patch"
PATCH[1]="buildfix_kernel_7.0-dma_buf_invalidate_mappings.patch"
PATCH[2]="buildfix_kernel_7.0-cxl_structs.patch"
# Apply from v4 to v5.12 kernels
#PATCH[2]="buildfix_kernel_6.8-nv_drm_ioctls-DRM_UNLOCKED-is-now-the-default-behavi.patch"
#PATCH[3]="buildfix_kernel_6.8-gpl-pfn_valid.patch"
# v5.13 kernels already disable both by default
# v5.19 kernels may need cf-protection=branch
PATCH_MATCH[0]='^(4\.[0-9]*)|(5\.[0-9]\.0)|(5\.1[0-2]\.0)'
# Workarounds for partial backports in Ubuntu 7.0 kernels
PATCH_MATCH[1]='^(7\.0\.0)'
PATCH_MATCH[2]='^(7\.0\.0)'
BUILT_MODULE_NAME[3]="nvidia-uvm"
DEST_MODULE_LOCATION[3]="/kernel/drivers/char/drm"
BUILT_MODULE_NAME[4]="nvidia-peermem"
DEST_MODULE_LOCATION[4]="/kernel/drivers/char/drm"
#PATCH[2]="buildfix_kernel_4.9_amd64_only.patch"
'''

CONFTEST = "#!/bin/sh\n" + "".join(f"test_{number}() {{ echo {number}; }}\n" for number in range(1, 13))
HEADER = "struct nv_linux_state {\n    int cxl;\n};\n"
NV_C = "int nv_init(void) { return 0; }\n"
KERNEL_OPEN = {"Kbuild": "obj-m += nvidia/\n", "conftest.sh": CONFTEST, "common/inc/nv-linux.h": HEADER,
               "nvidia/nv.c": NV_C}
FIRST = CONFTEST.replace("echo 5;", "echo five;")
SECOND = FIRST.replace("echo 6;", "echo six;")
# Made against a conftest.sh whose third line differs: GNU patch needs its default fuzz (2) for it, as DKMS uses.
DRIFTED = CONFTEST.replace("echo 3;", "echo three;")


def unified(name, old, new):
    return "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True), f"a/{name}", f"b/{name}")).encode()


# The second patch's context holds the first one's change: only index order applies both.
PATCHES = {"first.patch": unified("conftest.sh", CONFTEST, FIRST),
           "second.patch": unified("conftest.sh", FIRST, SECOND),
           "header.patch": unified("common/inc/nv-linux.h", HEADER, HEADER.replace("int cxl;", "long cxl;")),
           "override.patch": unified("nvidia/nv.c", NV_C, NV_C.replace("return 0", "return 1")),
           "fuzzy.patch": unified("conftest.sh", DRIFTED, DRIFTED.replace("echo 5;", "echo five;")),
           # Two sections for one file, as a concatenated patch series: a dry run checks the second
           # against the original file and fails, a real run applies both.
           "series.patch": unified("conftest.sh", CONFTEST, FIRST) + unified("conftest.sh", FIRST, SECOND),
           "empty.patch": b"",
           "sub/nested.patch": unified("conftest.sh", CONFTEST, FIRST)}


def write_files(base, files):
    for name, text in files.items():
        atomic_write(base / name, text.encode() if isinstance(text, str) else text,
                     0o755 if name.endswith(".sh") else 0o644)


def package(root, conf, patches=PATCHES, files=KERNEL_OPEN, version=VERSION):
    """/usr/src/nvidia-VERSION as Ubuntu's two packages leave it: kernel-open's contents, dkms.conf, patches/."""
    directory = root / f"usr/src/nvidia-{version}"
    write_files(directory, files)
    if conf is not None:
        atomic_write(directory / "dkms.conf", conf.encode(), 0o644)
    write_files(directory / "patches", patches)
    for parent in [path for path in (directory / "patches").rglob("*") if path.is_dir()]:
        parent.chmod(0o755)
    return directory


def run_patch(arguments, log):
    with open(log, "ab") as stream:
        return subprocess.run([PATCH, *arguments], stdout=stream, stderr=subprocess.STDOUT,
                              env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}).returncode


class PatchOperations:
    def patch(self, arguments, *, log):
        return run_patch(arguments, log)


class ParseTests(unittest.TestCase):
    def test_ubuntu_dkms_conf_selects_the_kernel_7_fixes_by_index(self):
        parsed = dkms.parse(UBUNTU.encode())
        self.assertIsNone(parsed["problem"])
        self.assertEqual(parsed["unsupported"], {})
        self.assertEqual(parsed["PATCH"], {0: "disable_fstack-clash-protection_fcf-protection.patch",
                                           1: "buildfix_kernel_7.0-dma_buf_invalidate_mappings.patch",
                                           2: "buildfix_kernel_7.0-cxl_structs.patch"})
        names = lambda kernel: [name for _, name, _ in dkms.select(parsed, kernel)[0]]
        self.assertEqual(names("7.0.0-42-generic"), ["buildfix_kernel_7.0-dma_buf_invalidate_mappings.patch",
                                                     "buildfix_kernel_7.0-cxl_structs.patch"])
        self.assertEqual(dkms.select(parsed, "7.0.0-42-generic")[0][0][2], r"^(7\.0\.0)")
        # The same choices as bash's =~: the unanchored alternatives of PATCH_MATCH[0] match 5.4.0 too.
        for kernel, expected in (("6.8.0-50-generic", []), ("7.0.1-3-generic", []), ("5.15.0-136-generic", []),
                                 ("5.4.0-100-generic", [0]), ("4.15.0-20-generic", [0]), ("5.10.0-1-amd64", [0])):
            with self.subTest(kernel=kernel):
                self.assertEqual([index for index, _, _ in dkms.select(parsed, kernel)[0]], expected)
        # DKMS drops the carriage return that ends each value of a CRLF file.
        self.assertEqual(dkms.parse(UBUNTU.replace("\n", "\r\n").encode())["PATCH"], parsed["PATCH"])

    def test_quoting_forms_comments_and_continuations(self):
        conf = ("PATCH[0]=plain.patch\n"
                "PATCH[1]='single.patch'  # trailing comment\n"
                'PATCH[2]="dou\\\\ble.patch";\n'         # "dou\\ble.patch"; in the file
                '#PATCH[3]="commented.patch"\n'
                "PATCH[4]=jo\\\nined.patch\n"             # a backslash-newline joins the two lines
                "PATCH_MATCH[0]=\nPATCH_MATCH[1]=''\n"
                'PATCH_MATCH[2]="^7\\.0"\n'
                "PATCH_MATCH[4]='^7'\nPATCHES=1\n")
        parsed = dkms.parse(conf.encode())
        self.assertIsNone(parsed["problem"])
        self.assertEqual(parsed["PATCH"], {0: "plain.patch", 1: "single.patch", 2: "dou\\ble.patch", 4: "joined.patch"})
        self.assertEqual(parsed["PATCH_MATCH"][2].pattern, r"^7\.0")
        # Four PATCH entries are set, so DKMS never reaches PATCH[4].
        selected, skipped = dkms.select(parsed, "7.0.0-1")
        self.assertEqual([index for index, _, _ in selected], [0, 1, 2])
        self.assertEqual([(item["index"], item["name"]) for item in skipped], [(4, "joined.patch")])
        self.assertIn("PATCH[0] to PATCH[3]", skipped[0]["reason"])

    def test_later_assignment_wins_and_empty_patch_is_not_applied(self):
        parsed = dkms.parse(b'PATCH[0]="old.patch"\nPATCH[0]="new.patch"\nPATCH[1]=""\nPATCH[2]="c.patch"\n')
        self.assertEqual([name for _, name, _ in dkms.select(parsed, "7.0.0")[0]], ["new.patch", "c.patch"])

    def test_values_that_need_the_shell_are_skipped_with_a_reason(self):
        cases = {'PATCH[0]="$(curl https://example.invalid)"': "expansion",
                 'PATCH[0]="${kernelver}.patch"': "expansion",
                 "PATCH[0]=`id`.patch": "quoting or expansion",
                 "PATCH[0]=~/fix.patch": "quoting or expansion",
                 "PATCH[0]=a\\.patch": "quoting or expansion",
                 'PATCH[0]="a.patch"b': "one quoted word",
                 # DKMS reads each value a second time inside double quotes.
                 "PATCH[0]='$HOME.patch'": "second time",
                 "PATCH_MATCH[0]='^7\\\\.0'": "second time",
                 "PATCH_MATCH[0]='^7\\d'": "regular expression syntax",
                 "PATCH_MATCH[0]='^[[:digit:]]'": "regular expression syntax",
                 "PATCH_MATCH[0]='^[\\.]7'": "regular expression syntax",
                 "PATCH_MATCH[0]='(7)\\1'": "regular expression syntax",
                 "PATCH_MATCH[0]='(?i)^7'": "repetition",
                 "PATCH_MATCH[0]='^7+?'": "repetition",
                 "PATCH_MATCH[0]='^7{1}*'": "repetition",
                 "PATCH_MATCH[0]='^7[9-0]'": "not a valid regular expression",
                 "PATCH_MATCH[0]='^7{3,1}'": "not a valid regular expression",
                 "PATCH_MATCH[0]='^(7'": "not a valid regular expression",
                 "PATCH_MATCH[0]='^7)'": "not a valid regular expression",
                 "PATCH_MATCH[0]='^7|'": "empty group or alternative",
                 # Where bash and the reader could disagree: anchors inside groups, ranges across classes.
                 "PATCH_MATCH[0]='(^7)'": "uses ^",
                 "PATCH_MATCH[0]='7^'": "uses ^",
                 "PATCH_MATCH[0]='(7$)?'": "uses $",
                 "PATCH_MATCH[0]='^[.-9]'": "locale",
                 "PATCH_MATCH[0]='^[A-z]'": "locale",
                 "PATCH_MATCH[0]='" + "7" * 300 + "'": "longer than"}
        for line, reason in cases.items():
            with self.subTest(line=line):
                conf = ('PATCH[0]="a.patch"\n' if line.startswith("PATCH_MATCH") else "") + line + '\nPATCH[1]="b.patch"\n'
                parsed = dkms.parse(conf.encode())
                self.assertIsNone(parsed["problem"])
                selected, skipped = dkms.select(parsed, "7.0.0-42-generic")
                self.assertEqual([name for _, name, _ in selected], ["b.patch"])
                self.assertEqual(len(skipped), 1)
                self.assertEqual(skipped[0]["index"], 0)
                self.assertIn(reason, skipped[0]["reason"])

    def test_conditional_entries_are_skipped_and_make_the_count_uncertain(self):
        # When the condition is false DKMS counts two entries, reads PATCH[0] and PATCH[1] (unset) and never
        # reaches PATCH[2]: the loader cannot tell, so it skips the conditional entry and every index DKMS may
        # not read.
        blocks = {'if [ "$arch" = x86_64 ]; then\n  PATCH[1]="b.patch"\nfi': "inside a shell block",
                  'while false; do\n  PATCH[1]="b.patch"\ndone': "inside a shell block",
                  "f() {\n  PATCH[1]=b.patch\n}": "inside a shell block",
                  '(\n  PATCH[1]="b.patch"\n)': "inside a shell block",
                  'X=$(\n  PATCH[1]="b.patch"\n)': "inside a shell block",
                  'X=`\nPATCH[1]="b.patch"\n`': "inside a shell block",
                  'f() (\n  PATCH[1]="b.patch"\n)': "inside a shell block",
                  'case "$arch" in\n  x86_64)\n    PATCH[1]="b.patch" ;;\nesac': "inside a shell block",
                  '[ -n "$x" ] &&\n  PATCH[1]="b.patch"': "conditional",
                  'false ||\n  PATCH[1]="b.patch"': "conditional",
                  'true |\n  PATCH[1]="b.patch"': "conditional"}
        for block, reason in blocks.items():
            with self.subTest(block=block):
                parsed = dkms.parse(f'PATCH[0]="a.patch"\n{block}\nPATCH[2]="c.patch"\n'.encode())
                self.assertIsNone(parsed["problem"])
                selected, skipped = dkms.select(parsed, "7.0.0")
                self.assertEqual([name for _, name, _ in selected], ["a.patch"])
                self.assertEqual([item["index"] for item in skipped], [1, 2])
                self.assertIn(reason, skipped[0]["reason"])
                self.assertIn("only if the conditional PATCH entries are set", skipped[1]["reason"])
        # A top-level entry keeps its index certain even when a later conditional one may replace its value.
        parsed = dkms.parse(b'PATCH[0]="a.patch"\nPATCH[1]="b.patch"\nif x; then\n  PATCH[0]="z.patch"\nfi\n')
        selected, skipped = dkms.select(parsed, "7.0.0")
        self.assertEqual(([name for _, name, _ in selected], [item["index"] for item in skipped]), (["b.patch"], [0]))

    def test_shell_that_could_set_patch_entries_skips_every_entry(self):
        cases = {'[ -n "$x" ] && PATCH[0]="a.patch"': "outside a plain",
                 'PATCH=("a.patch" "b.patch")': "outside a plain",
                 'PATCH+=("a.patch")': "outside a plain",
                 "eval 'PATCH[0]=a.patch'": "eval, source, exit or return",
                 'declare "PATCH[0]=a.patch"': "outside a plain",
                 ". /etc/nvidia-patches.conf": "eval, source, exit or return",
                 "return 0": "eval, source, exit or return",
                 'PATCH[0]="a.patch"; echo set': "more shell code",
                 'PATCH[0]="a.patch" PATCH[1]="b.patch"': "more shell code",
                 "cat <<EOF\nPATCH[0]=a.patch\nEOF": "here-documents",
                 'PATCH[0]="a.patch': "never closed",
                 "PATCH[01]=a.patch": "outside a plain",
                 # A keyword used as an argument breaks the nesting the reader follows.
                 'if false; then\n  echo fi\n  PATCH[0]="a.patch"\nfi': "do not nest",
                 'echo done\nPATCH[0]="a.patch"': "do not nest",
                 'if true; then\nPATCH[0]="a.patch"': "ends inside a shell block",
                 'X=`date\nPATCH[0]="a.patch"': "ends inside a shell block"}
        for line, reason in cases.items():
            with self.subTest(line=line):
                parsed = dkms.parse(('PATCH[2]="c.patch"\n' + line + "\n").encode())
                self.assertIn(reason, parsed["problem"])
                selected, skipped = dkms.select(parsed, "7.0.0")
                self.assertEqual((selected, [item["index"] for item in skipped]), ([], [None]))
        self.assertIn("NUL", dkms.parse(b'PATCH[0]="a.patch"\0\n')["problem"])

    def test_shell_keywords_inside_strings_do_not_count_but_any_other_patch_mention_does(self):
        conf = 'MAKE[0]="if true; then make; fi; done"\nPATCH[0]="a.patch"\n'
        self.assertEqual(dkms.parse(conf.encode())["PATCH"], {0: "a.patch"})
        conf = 'case "$arch" in\n  x86_64) X=1 ;;\nesac\nPATCH[0]="a.patch"\n'
        self.assertEqual(dkms.select(dkms.parse(conf.encode()), "7.0.0")[0], [(0, "a.patch", "")])
        # PATCH in any other place, even inside a string such as `declare "PATCH[0]=..."`, makes every
        # entry unknown: the reader does not follow what the shell may do with it.
        for line in ('MAKE[0]="echo PATCH"', 'POST_BUILD="PATCH_MATCH.sh"'):
            with self.subTest(line=line):
                self.assertIn("outside a plain", dkms.parse(f'{line}\nPATCH[0]="a.patch"\n'.encode())["problem"])


class RegexTests(unittest.TestCase):
    """PATCH_MATCH is evaluated without backtracking and agrees with Python's re on the subset."""
    KERNELS = ("7.0.0-42-generic", "6.8.0-1015-nvidia-64k", "5.4.0-100-generic", "6.17.0-5-generic",
               "7.3.0-10-lowlatency", "6.19.9-200.fc44.x86_64", "4.15.0-20-generic", "5.10.0-1-amd64")

    def test_hostile_patterns_finish_quickly(self):
        kernel = "6.8.0-1015-nvidia-64k-" + "a" * 42      # 64 characters, the kernel release limit
        for pattern in (r"^((.+)+)+X", r"(a|a)*X", r"^(.|[0-9a-z.])*X", ".*" * 40 + "X",
                        r"((((((((((a*)*)*)*)*)*)*)*)*)*)X", r"(.?){30}.{30}X", r"(a{1,99}){1,99}X"):
            with self.subTest(pattern=pattern[:30]):
                start = time.monotonic()
                self.assertFalse(dkms._regex(pattern).search(kernel))
                self.assertLess(time.monotonic() - start, 2)

    def test_random_patterns_match_like_python(self):
        atoms = ["7", "0", ".", r"\.", "-", "[0-9]", "[a-z]", "[^0-9]", "g", "e", "n", "(7|6)", r"(\.[0-9])"]
        generator = random.Random(615)
        for _ in range(1500):
            pattern = "".join(generator.choice(atoms) + generator.choice(["", "", "*", "+", "?", "{1,2}"])
                              for _ in range(generator.randint(1, 5)))
            pattern = generator.choice(["", "^"]) + pattern + generator.choice(["", "$", "|^5"])
            compiled = dkms._regex(pattern)
            for kernel in self.KERNELS:
                with self.subTest(pattern=pattern, kernel=kernel):
                    self.assertEqual(compiled.search(kernel), re.search(pattern, kernel) is not None)


class PlanTests(unittest.TestCase):
    """Which files are read, and the trust rules for them."""
    def setUp(self):
        (REPO / ".private").mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(prefix="distribution-patches-", dir=REPO / ".private")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def conf(self, *entries):
        return "".join(f"{line}\n" for line in entries)

    def test_no_dkms_conf_is_a_no_op(self):
        self.assertIsNone(dkms.plan(self.root, VERSION, "7.0.0-42-generic"))
        package(self.root, None)
        self.assertIsNone(dkms.plan(self.root, VERSION, "7.0.0-42-generic"))

    def test_record_names_the_selected_patches_and_their_hashes(self):
        directory = package(self.root, self.conf('PATCH[0]="first.patch"', "PATCH_MATCH[0]='^7\\.0'",
                                                 'PATCH[1]="header.patch"', "PATCH_MATCH[1]='^6\\.'"))
        planned = dkms.plan(self.root, VERSION, "7.0.0-42-generic")
        self.assertEqual(planned["source_root"], "kernel-open")
        self.assertEqual([(patch["index"], patch["name"], patch["match"], patch["sha256"]) for patch in planned["patches"]],
                         [(0, "first.patch", "^7\\.0", digest(PATCHES["first.patch"]))])
        self.assertEqual(planned["record"], {
            "dkms_conf": f"/usr/src/nvidia-{VERSION}/dkms.conf",
            "dkms_conf_sha256": digest((directory / "dkms.conf").read_bytes()), "kernel": "7.0.0-42-generic",
            "source_root": "kernel-open", "applied": [], "already_applied": [], "skipped": []})
        self.assertEqual(dkms.plan(self.root, VERSION, "6.8.0-1")["patches"][0]["name"], "header.patch")
        self.assertEqual(dkms.plan(self.root, VERSION, "5.15.0-1")["patches"], [])

    def test_whole_release_layout_patches_from_the_top(self):
        files = {"kernel-open/" + name: text for name, text in KERNEL_OPEN.items()}
        package(self.root, self.conf('PATCH[0]="first.patch"'), files=files)
        self.assertEqual(dkms.plan(self.root, VERSION, "7.0.0")["source_root"], ".")

    def test_unrecognised_package_layout_skips_with_a_reason(self):
        package(self.root, self.conf('PATCH[0]="first.patch"'), files={})
        planned = dkms.plan(self.root, VERSION, "7.0.0")
        self.assertEqual(planned["patches"], [])
        self.assertIn("layout", planned["record"]["skipped"][0]["reason"])

    def test_patch_names_stay_inside_patches(self):
        for name, message in (("../../etc/shadow", "not a file name inside"), ("sub/../first.patch", "not a file name"),
                              ("..", "not a file name"), ("/etc/shadow", "not a file name"),
                              ("sub//nested.patch", "not a file name"), ("missing.patch", "missing")):
            with self.subTest(name=name):
                package(self.root, self.conf(f'PATCH[0]="{name}"'))
                with self.assertRaisesRegex(LifecycleError, message):
                    dkms.plan(self.root, VERSION, "7.0.0")
        # DKMS also takes a patch from a subdirectory of patches/.
        package(self.root, self.conf('PATCH[0]="sub/nested.patch"'))
        self.assertEqual([patch["name"] for patch in dkms.plan(self.root, VERSION, "7.0.0")["patches"]],
                         ["sub/nested.patch"])

    def test_trust_rules_for_dkms_conf_patches_directory_and_patch_files(self):
        directory = package(self.root, self.conf('PATCH[0]="first.patch"', 'PATCH[1]="sub/nested.patch"'))
        conf, patches, first = directory / "dkms.conf", directory / "patches", directory / "patches/first.patch"
        self.assertEqual(len(dkms.plan(self.root, VERSION, "7.0.0")["patches"]), 2)
        cases = [("dkms.conf writable by its group", lambda: conf.chmod(0o664), lambda: conf.chmod(0o644)),
                 ("patches/ writable by others", lambda: patches.chmod(0o777), lambda: patches.chmod(0o700)),
                 ("patches/sub/ writable by its group", lambda: (patches / "sub").chmod(0o775),
                  lambda: (patches / "sub").chmod(0o755)),
                 ("patch writable by its group", lambda: first.chmod(0o664), lambda: first.chmod(0o644))]
        for label, change, restore in cases:
            with self.subTest(label=label):
                change()
                try:
                    with self.assertRaisesRegex(LifecycleError, "untrusted"):
                        dkms.plan(self.root, VERSION, "7.0.0")
                finally:
                    restore()
        with mock.patch("nvidia_vbios.lifecycle.security.os.geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(LifecycleError, "untrusted"):
                dkms.plan(self.root, VERSION, "7.0.0")
        first.rename(directory / "real.patch")
        first.symlink_to("real.patch")
        with self.assertRaisesRegex(LifecycleError, "symlink"):
            dkms.plan(self.root, VERSION, "7.0.0")
        first.unlink()
        first.mkdir(mode=0o755)
        with self.assertRaisesRegex(LifecycleError, "not a regular file"):
            dkms.plan(self.root, VERSION, "7.0.0")
        first.rmdir()
        conf.rename(directory / "real.conf")
        conf.symlink_to("real.conf")
        with self.assertRaisesRegex(LifecycleError, "dkms.conf: .*symlink"):
            dkms.plan(self.root, VERSION, "7.0.0")

    def test_a_ready_build_keeps_its_patches_until_the_selection_changes(self):
        package(self.root, self.conf('PATCH[0]="first.patch"', 'PATCH[1]="header.patch"', "PATCH_MATCH[1]='^6\\.'"))
        planned = dkms.plan(self.root, VERSION, "7.0.0")
        entry = {"index": 0, "name": "first.patch", "sha256": digest(PATCHES["first.patch"]), "match": "", "fuzz": 0}
        built = dict(planned["record"], applied=[entry])
        self.assertFalse(dkms.changed_selection({"distribution_patches": built}, planned))
        self.assertFalse(dkms.changed_selection({"distribution_patches": dict(built, applied=[], already_applied=[entry])},
                                                planned))
        self.assertTrue(dkms.changed_selection({"distribution_patches": built}, dkms.plan(self.root, VERSION, "6.8.0")))
        self.assertTrue(dkms.changed_selection({"distribution_patches": None}, planned))
        self.assertTrue(dkms.changed_selection({"distribution_patches": built}, None))
        self.assertFalse(dkms.changed_selection({"distribution_patches": None}, None))
        # Built before the loader applied distribution patches: no record, kept as it is.
        self.assertFalse(dkms.changed_selection({}, planned))


@needs_patch
class ApplyTests(unittest.TestCase):
    """GNU patch on a copy of a synthetic release tree, as reconcile runs it."""
    def setUp(self):
        (REPO / ".private").mkdir(exist_ok=True)
        directory = tempfile.TemporaryDirectory(prefix="distribution-apply-", dir=REPO / ".private")
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.tree = self.root / "work/source"
        write_files(self.tree, {"version.mk": VERSION, **{"kernel-open/" + name: text for name, text in KERNEL_OPEN.items()}})
        self.log = self.root / "work/build.log"
        self.work = self.root / "work/distribution-patches"

    def apply(self, conf, kernel="7.0.0-42-generic", guarded=("version.mk", "kernel-open/nvidia/nv.c")):
        package(self.root, conf)
        planned = dkms.plan(self.root, VERSION, kernel)
        return dkms.apply(planned, self.tree, PatchOperations(), guarded=list(guarded), log=self.log, work=self.work)

    def conftest(self):
        return (self.tree / "kernel-open/conftest.sh").read_text()

    def entry(self, index, name, fuzz=0):
        return {"index": index, "name": name, "sha256": digest(PATCHES[name]), "match": "", "fuzz": fuzz}

    def test_matching_patches_apply_in_index_order_from_kernel_open(self):
        # Listed out of order in the file: DKMS and the loader go by index.
        record = self.apply('PATCH[1]="second.patch"\nPATCH[0]="first.patch"\nPATCH[2]="header.patch"\n'
                            "PATCH_MATCH[2]='^6\\.'\n")
        self.assertEqual(self.conftest(), SECOND)
        self.assertEqual((self.tree / "kernel-open/common/inc/nv-linux.h").read_text(), HEADER)
        self.assertEqual(record["applied"], [self.entry(0, "first.patch"), self.entry(1, "second.patch")])
        self.assertEqual((record["already_applied"], record["skipped"]), ([], []))
        self.assertFalse(list(self.tree.rglob("*.orig")) + list(self.tree.rglob("*.rej")))
        # build.log has the changes only; the trials, with GNU patch's "Skipping patch" lines, have their own log.
        self.assertEqual(self.log.read_text().count("patching file conftest.sh"), 2)
        self.assertNotIn("Skipping patch", self.log.read_text())
        self.assertIn("Skipping patch", (self.work / "trials.log").read_text())
        self.assertEqual(sorted(path.name for path in self.work.iterdir()),
                         ["0000-first.patch", "0001-second.patch", "trials.log"])

    def test_a_patch_that_does_not_apply_stops_with_its_name(self):
        with self.assertRaisesRegex(LifecycleError, r"second.patch \(dkms.conf PATCH\[0\]\) does not apply to the "
                                                    r"driver source.*must already contain it"):
            self.apply('PATCH[0]="second.patch"\nPATCH[1]="first.patch"\n')
        self.assertEqual(self.conftest(), CONFTEST)

    def test_patches_already_in_the_source_are_skipped(self):
        write_files(self.tree, {"kernel-open/conftest.sh": FIRST})
        record = self.apply('PATCH[0]="first.patch"\nPATCH[1]="second.patch"\n')
        self.assertEqual(self.conftest(), SECOND)
        self.assertEqual([item["name"] for item in record["already_applied"]], ["first.patch"])
        self.assertEqual([item["name"] for item in record["applied"]], ["second.patch"])
        write_files(self.tree, {"kernel-open/conftest.sh": SECOND})
        record = self.apply('PATCH[0]="first.patch"\nPATCH[1]="second.patch"\n')
        self.assertEqual([item["name"] for item in record["already_applied"]], ["first.patch", "second.patch"])
        self.assertEqual((record["applied"], self.conftest()), ([], SECOND))

    def test_a_patch_needing_fuzz_applies_as_dkms_applies_it(self):
        record = self.apply('PATCH[0]="fuzzy.patch"\n')
        self.assertEqual((self.conftest(), record["applied"]), (FIRST, [self.entry(0, "fuzzy.patch", fuzz=2)]))
        self.assertEqual(dkms.summary(record)["applied"], ["fuzzy.patch (fuzz 2)"])
        # The same tree again: the fix is already there, found in reverse with the same fuzz.
        record = self.apply('PATCH[0]="fuzzy.patch"\n')
        self.assertEqual((self.conftest(), record["applied"], record["already_applied"]),
                         (FIRST, [], [self.entry(0, "fuzzy.patch", fuzz=2)]))

    def test_a_patch_with_two_sections_for_one_file_and_an_empty_patch_apply(self):
        record = self.apply('PATCH[0]="series.patch"\nPATCH[1]="empty.patch"\n')
        self.assertEqual(self.conftest(), SECOND)
        self.assertEqual(record["applied"], [self.entry(0, "series.patch"),
                                             dict(self.entry(1, "empty.patch"), no_change=True)])

    def test_patch_that_applies_both_ways_is_refused(self):
        twice = CONFTEST + "\n# copy\n" + FIRST.split("\n", 1)[1]
        write_files(self.tree, {"kernel-open/conftest.sh": twice})
        with self.assertRaisesRegex(LifecycleError, "both forward and in reverse"):
            self.apply('PATCH[0]="first.patch"\n')
        self.assertEqual(self.conftest(), twice)

    def test_a_patch_changing_a_file_the_override_reads_is_refused(self):
        with self.assertRaisesRegex(LifecycleError, r"override.patch \(dkms.conf PATCH\[1\]\) changes "
                                                    r"kernel-open/nvidia/nv.c, which the VBIOS override"):
            self.apply('PATCH[0]="first.patch"\nPATCH[1]="override.patch"\n')

    def test_a_source_that_already_has_a_fix_in_a_file_the_override_reads_is_accepted(self):
        # The registered source already has it (a --driver-source patched by hand): the file stays as
        # registered, and the override patch checks it against that.
        write_files(self.tree, {"kernel-open/nvidia/nv.c": NV_C.replace("return 0", "return 1")})
        record = self.apply('PATCH[0]="first.patch"\nPATCH[1]="override.patch"\n')
        self.assertEqual(([item["name"] for item in record["applied"]], [item["name"] for item in record["already_applied"]]),
                         (["first.patch"], ["override.patch"]))
        self.assertEqual((self.tree / "kernel-open/nvidia/nv.c").read_text(), NV_C.replace("return 0", "return 1"))

    def test_source_without_the_patch_root_is_refused(self):
        shutil.rmtree(self.tree / "kernel-open")
        with self.assertRaisesRegex(LifecycleError, "no kernel-open directory"):
            self.apply('PATCH[0]="first.patch"\n')


class Operations(FakeOperations):
    """FakeOperations whose prepare_source runs the distribution step on the copy, with GNU patch."""
    def __init__(self, root, config, guarded):
        super().__init__(root, config)
        self.guarded, self.hooks, self.built = guarded, [], []

    def current_kernel(self):
        return NEW

    def inspect_source(self, path):
        return dict(super().inspect_source(path),
                    source_hashes={name: digest((path / name).read_bytes()) for name in self.guarded})

    def prepare_source(self, source, destination, before_patch=None):
        self.hooks.append(before_patch is not None)
        shutil.copytree(source, destination)
        if before_patch is not None:
            before_patch(destination)
        return {"version": (source / "version.mk").read_text().strip(), "prepared_source": str(destination),
                "prepared_modules": str(destination / "kernel-open"),
                "module_metadata": {"vbios_override_per_gpu": "1", "vbios_override_param_bytes": "4094"},
                "source_hashes": self.inspect_source(source)["source_hashes"]}

    def build(self, source, kernel, jobs, log):
        self.built.append((source / "kernel-open/conftest.sh").read_text())
        return super().build(source, kernel, jobs, log)

    def patch(self, arguments, *, log):
        return run_patch(arguments, log)


@needs_patch
class ReconcileTests(unittest.TestCase):
    """reconcile applies the selected fixes to its copy, records them, and never builds a half-patched tree."""
    MATCH = "'^6\\.19\\.10'"   # NEW only

    def setUp(self):
        self.case = lifecycle_fixtures.LifecycleTests("runTest")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)
        self.root = self.case.root
        self.source = self.root / "var/lib/nvidia-vbios/sources/p2p"
        write_files(self.source, {"kernel-open/" + name: text for name, text in KERNEL_OPEN.items()})
        self.register()

    def register(self, guarded=("version.mk",)):
        source = self.case.config["sources"][0]
        source["source_hashes"] = {name: digest((self.source / name).read_bytes()) for name in guarded}
        source["tree_sha256"] = source_tree_hash(self.source, self.root)
        self.case.write_config()
        self.ops = Operations(self.root, self.case.config, guarded)
        self.worker = lifecycle_fixtures.Reconciler(self.root, self.ops)

    def conf(self, *patches):
        lines = [f'PATCH[{index}]="{name}"' for index, name in enumerate(patches)]
        return "\n".join([*lines, f"PATCH_MATCH[0]={self.MATCH}", f"PATCH_MATCH[1]={self.MATCH}",
                          "PATCH_MATCH[2]='^7\\.0\\.0'"]) + "\n"

    def state(self, name):
        return json.loads((self.root / STATE.lstrip("/") / name).read_text())

    def test_matching_fixes_are_built_recorded_and_shown_in_status(self):
        package(self.root, self.conf("first.patch", "second.patch", "header.patch"))
        preview = self.worker.reconcile(NEW, dry_run=True)["distribution_patches"]
        self.assertEqual([item["name"] for item in preview["selected"]], ["first.patch", "second.patch"])
        self.assertEqual(self.ops.builds, 0)
        result = self.worker.reconcile(NEW)
        self.assertEqual(result["state"], "ready")
        self.assertEqual((self.ops.hooks, self.ops.built), ([True], [SECOND]))
        self.assertEqual((self.source / "kernel-open/conftest.sh").read_text(), CONFTEST)  # the snapshot stays as registered
        record = self.state(f"status-{NEW}.json")["distribution_patches"]
        self.assertEqual((record["kernel"], record["dkms_conf"], record["source_root"]),
                         (NEW, f"/usr/src/nvidia-{VERSION}/dkms.conf", "kernel-open"))
        self.assertEqual([(item["index"], item["name"], item["match"], item["sha256"], item["fuzz"])
                          for item in record["applied"]],
                         [(0, "first.patch", "^6\\.19\\.10", digest(PATCHES["first.patch"]), 0),
                          (1, "second.patch", "^6\\.19\\.10", digest(PATCHES["second.patch"]), 0)])
        self.assertEqual(json.loads(Path(result["source_manifest"]).read_text())["distribution_patches"], record)
        status = Bootstrap(self.root, self.ops).status()["distribution_patches"]
        self.assertEqual(status, {"kernel": NEW, "dkms_conf": f"/usr/src/nvidia-{VERSION}/dkms.conf",
                                  "applied": ["first.patch", "second.patch"], "already_applied": [], "skipped": []})
        # Another kernel takes no entry: the build sees the source as registered.
        self.case.add_kernel(lifecycle_fixtures.NEXT)
        self.ops.environment["saved_entry"] = "normal-" + lifecycle_fixtures.NEXT
        self.worker.reconcile(lifecycle_fixtures.NEXT)
        self.assertEqual((self.ops.hooks[-1], self.ops.built[-1]), (False, CONFTEST))
        self.assertEqual(self.state(f"status-{lifecycle_fixtures.NEXT}.json")["distribution_patches"]["applied"], [])

    def test_without_dkms_conf_nothing_changes(self):
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["state"], self.ops.hooks, self.ops.built), ("ready", [False], [CONFTEST]))
        self.assertIsNone(self.state(f"status-{NEW}.json")["distribution_patches"])
        self.assertNotIn("distribution_patches", json.loads(Path(result["source_manifest"]).read_text()))
        self.assertNotIn("distribution_patches", self.worker.reconcile(NEW, dry_run=True))
        self.assertIsNone(Bootstrap(self.root, self.ops).status()["distribution_patches"])
        self.assertTrue(self.worker.reconcile(NEW)["state"] == "ready" and self.ops.builds == 1)

    def test_a_failing_patch_blocks_before_the_build_and_keeps_the_default(self):
        package(self.root, self.conf("second.patch", "first.patch"))
        with self.assertRaisesRegex(LifecycleError, "second.patch .* does not apply"):
            self.worker.reconcile(NEW)
        self.assertEqual((self.ops.builds, self.ops.environment["saved_entry"]), (0, "normal-" + OLD))
        status = self.state(f"status-{NEW}.json")
        self.assertEqual(status["state"], "blocked")
        self.assertIn("second.patch", status["error"])
        self.assertEqual(status["distribution_patches"]["kernel"], NEW)
        self.assertEqual(self.state(f"attempt-{NEW}.json")["distribution_patches"], status["distribution_patches"])
        self.assertFalse(list((self.root / STATE.lstrip("/") / "transactions").glob("*/source")))

    def test_a_failed_build_still_shows_what_was_applied_and_skipped(self):
        package(self.root, 'PATCH[0]="first.patch"\nPATCH[1]="$(echo second.patch)"\n'
                           f"PATCH_MATCH[0]={self.MATCH}\n")
        self.ops.fault = "build"
        with self.assertRaisesRegex(LifecycleError, "make failed"):
            self.worker.reconcile(NEW)
        record = self.state(f"status-{NEW}.json")["distribution_patches"]
        self.assertEqual(([item["name"] for item in record["applied"]], [item["index"] for item in record["skipped"]]),
                         (["first.patch"], [1]))
        self.assertEqual(self.state(f"attempt-{NEW}.json")["distribution_patches"], record)
        status = Bootstrap(self.root, self.ops).status()
        self.assertEqual(status["distribution_patches"]["applied"], ["first.patch"])
        self.assertIn("PATCH[1]: dkms.conf line 2: PATCH[1] needs shell expansion", status["distribution_patches"]["skipped"])
        self.assertEqual(status["last_attempt"]["distribution_patches"], record)

    def test_a_ready_kernel_is_rebuilt_only_when_the_selection_changes(self):
        directory = package(self.root, self.conf("first.patch"))
        self.assertEqual(self.worker.reconcile(NEW)["state"], "ready")
        self.assertEqual(self.ops.builds, 1)
        # A new revision of the package that selects the same patches: the READY build is kept.
        atomic_write(directory / "dkms.conf", ("# revision 2\n" + self.conf("first.patch")).encode(), 0o644)
        self.assertTrue(self.worker.reconcile(NEW)["state"] == "ready" and self.ops.builds == 1)
        # One that adds a fix for this kernel: built again, as DKMS does when the package changes.
        atomic_write(directory / "dkms.conf", self.conf("first.patch", "second.patch").encode(), 0o644)
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["state"], self.ops.builds, self.ops.built[-1]), ("ready", 2, SECOND))
        self.assertEqual([item["name"] for item in self.state(f"status-{NEW}.json")["distribution_patches"]["applied"]],
                         ["first.patch", "second.patch"])
        self.assertTrue(self.worker.reconcile(NEW)["state"] == "ready" and self.ops.builds == 2)
        # A READY build from before the loader applied these patches has no record: it is kept as it is.
        status = self.state(f"status-{NEW}.json")
        status.pop("distribution_patches")
        json_write(self.root / STATE.lstrip("/") / f"status-{NEW}.json", status)
        atomic_write(directory / "dkms.conf", self.conf("first.patch").encode(), 0o644)
        self.assertTrue(self.worker.reconcile(NEW)["state"] == "ready" and self.ops.builds == 2)

    def test_a_pre_patched_registered_source_is_built_as_it_is(self):
        write_files(self.source, {"kernel-open/conftest.sh": SECOND})
        self.register()
        package(self.root, self.conf("first.patch", "second.patch"))
        self.assertEqual(self.worker.reconcile(NEW)["state"], "ready")
        record = self.state(f"status-{NEW}.json")["distribution_patches"]
        self.assertEqual(([item["name"] for item in record["already_applied"]], record["applied"]),
                         (["first.patch", "second.patch"], []))
        self.assertEqual(self.ops.built, [SECOND])

    def test_a_fix_touching_an_override_file_is_refused(self):
        self.register(("version.mk", "kernel-open/nvidia/nv.c"))
        package(self.root, self.conf("override.patch"))
        with self.assertRaisesRegex(LifecycleError, "changes kernel-open/nvidia/nv.c, which the VBIOS override patch reads"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.builds, 0)

    def test_untrusted_package_files_block_the_build(self):
        directory = package(self.root, self.conf("first.patch"))
        (directory / "patches/first.patch").chmod(0o666)
        with self.assertRaisesRegex(LifecycleError, "untrusted"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.builds, 0)


def with_distribution_step(ops):
    """Give a fixture's operations a prepare_source that runs the distribution step, and GNU patch."""
    def prepare_source(source, destination, before_patch=None):
        shutil.copytree(source, destination)
        if before_patch is not None:
            before_patch(destination)
        ops.built.append((destination / "kernel-open/conftest.sh").read_text())
        return {"version": (source / "version.mk").read_text().strip(), "prepared_source": str(destination),
                "prepared_modules": str(destination / "kernel-open"),
                "module_metadata": {"vbios_override_per_gpu": "1", "vbios_override_param_bytes": "4094"},
                "source_hashes": ops.inspect_source(source)["source_hashes"]}
    ops.built, ops.prepare_source, ops.patch = [], prepare_source, lambda arguments, *, log: run_patch(arguments, log)
    return ops


@needs_patch
class PortableReconcileTests(unittest.TestCase):
    """The Ubuntu path: GRUB, deb packages and PortableReconciler."""
    def test_debian_grub_reconcile_applies_records_and_shows_the_fixes(self):
        import test_bootstrap_portable as portable_fixtures
        case = portable_fixtures.PortableBootstrapTests("test_fresh_debian_apt_install_enroll_reconcile_enable_disable_resume")
        case.setUp()
        self.addCleanup(case.doCleanups)
        case.setup_platform(DEBIAN_PLATFORM, "grub")
        write_files(case.fixture.source, {"kernel-open/" + name: text for name, text in KERNEL_OPEN.items()})
        with_distribution_step(case.ops)
        package(case.root, "PATCH[0]=first.patch\nPATCH[1]=second.patch\nPATCH_MATCH[0]='^6\\.19\\.9'\n"
                           "PATCH_MATCH[1]='^6\\.19\\.9'\n")
        case.worker.install(case.fixture.repository)
        case.worker.enroll(case.profile)
        case.ops.config = case.configuration()
        worker = Reconciler(case.root, case.ops)
        self.assertEqual(type(worker).__name__, "PortableReconciler")
        preview = worker.reconcile(OLD, dry_run=True)["distribution_patches"]
        self.assertEqual([item["name"] for item in preview["selected"]], ["first.patch", "second.patch"])
        self.assertEqual(worker.reconcile(OLD)["state"], "ready")
        self.assertEqual(case.ops.built, [SECOND])
        self.assertEqual(case.worker.status()["distribution_patches"]["applied"], ["first.patch", "second.patch"])


@needs_patch
class AutoSourceTests(unittest.TestCase):
    """After a package driver upgrade the downloaded tag gets the distribution's fixes too."""
    def setUp(self):
        self.case = fetch_fixtures.AutoSourceTests("test_package_upgrade_registers_the_tag_and_the_next_reconcile_is_ready")
        self.case.setUp()
        self.addCleanup(self.case.doCleanups)

    def test_the_downloaded_tag_is_built_with_the_matching_fixes(self):
        f = self.case.f
        conftest = fetch_fixtures.KERNEL_OPEN["conftest.sh"].decode()
        fixed = conftest.replace("echo conftest", "echo conftest-fixed")
        # Ubuntu's layout of the new version: kernel-open's contents as in the tag, dkms.conf and patches/.
        package(f.root, f"PATCH[0]=fix.patch\nPATCH_MATCH[0]='^{re.escape(OLD.split('-')[0])}'\n",
                patches={"fix.patch": unified("conftest.sh", conftest, fixed)},
                files=fetch_fixtures.KERNEL_OPEN, version=fetch_fixtures.VERSION)
        with_distribution_step(f.ops)
        self.case.drift()
        fetched = self.case.auto()
        self.assertEqual((fetched["state"], fetched["cross_check"]), ("registered", "kernel-open-only"))
        ready = Reconciler(f.root, f.ops).reconcile(OLD)
        self.assertEqual((ready["state"], ready["driver"]), ("ready", fetch_fixtures.VERSION))
        self.assertEqual(f.ops.built, [fixed])
        record = json.loads((f.root / STATE.lstrip("/") / f"status-{OLD}.json").read_text())["distribution_patches"]
        self.assertEqual([(item["name"], item["fuzz"]) for item in record["applied"]], [("fix.patch", 0)])
        self.assertEqual(f.worker.status()["distribution_patches"]["applied"], ["fix.patch"])


class SystemPatchTests(unittest.TestCase):
    def test_runs_the_fixed_gnu_patch_with_a_clean_environment_and_reports_its_status(self):
        operations = SystemOperations.__new__(SystemOperations)
        calls = []
        def run(command, **options):
            calls.append((command, options))
            return subprocess.CompletedProcess(command, 1)
        with mock.patch.object(operations, "_run", run), mock.patch("nvidia_vbios.lifecycle.system.Path.exists", return_value=True):
            self.assertEqual(operations.patch(["-p1", "--dry-run"], log=Path("/x/build.log")), 1)
        self.assertEqual(calls, [(["patch", "-p1", "--dry-run"], {"log": Path("/x/build.log"), "allow_failure": True})])
        with mock.patch("nvidia_vbios.lifecycle.system.Path.exists", return_value=False):
            with self.assertRaisesRegex(LifecycleError, "install the patch package"):
                operations.patch(["-p1"], log=Path("/x/build.log"))


if __name__ == "__main__":
    unittest.main()
