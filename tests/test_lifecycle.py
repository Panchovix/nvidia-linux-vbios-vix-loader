"""Synthetic Fedora roots exercise transaction boundaries without touching host state."""
import base64
import copy
import fcntl
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
from nvidia_vbios.lifecycle import LifecycleError, Reconciler, source_tree_hash
from nvidia_vbios.lifecycle.__main__ import installed_kernels, kernel_key, queue_event
from nvidia_vbios.lifecycle.engine import MODULES, STATE
from nvidia_vbios.lifecycle.security import atomic_write, digest, json_write

OLD = "6.19.9-200.fc44.x86_64"
NEW = "6.19.10-200.fc44.x86_64"
NEXT = "6.20.1-200.fc44.x86_64"
VERSION = "615.71.09"


class FakeOperations:
    def __init__(self, root, config):
        self.root, self.config = root, config
        self.version = VERSION
        self.environment = {"saved_entry": "normal-" + OLD}
        self.events, self.builds = [], 0
        self.fault = None
        self.after_build = None
        self.after_initramfs = None
        self.secure = False
        self.loaded_version = VERSION

    def set_log(self, path):
        self.log = path

    def installed_version(self, config):
        return self.version

    def inspect_source(self, path):
        version = (path / "version.mk").read_text().strip()
        return {"version": version, "supported": self.fault != "unsupported",
                "reasons": ["missing structural anchor"] if self.fault == "unsupported" else [],
                "source_hashes": {"version.mk": digest((path / "version.mk").read_bytes())}}

    def prepare_source(self, source, destination):
        import shutil
        shutil.copytree(source, destination)
        return {"version": (source / "version.mk").read_text().strip(),
                "prepared_source": str(destination), "prepared_modules": str(destination / "kernel-open"),
                "module_metadata": {"vbios_override_per_gpu": "1", "vbios_override_param_bytes": "4094"},
                "source_hashes": self.inspect_source(source)["source_hashes"]}

    def inventory(self):
        return {d["bdf"]: {k: d[k] for k in ("bdf", "uuid", "vendor", "device")}
                for d in self.config["devices"]}

    def validate_payload(self, data, device):
        if not data.startswith(b"REVIEWED ROM"):
            raise LifecycleError("bad ROM structure")

    def prerequisites(self, kernel, config):
        if self.fault == "headers":
            raise LifecycleError("matching kernel-devel missing")
        if self.secure and not config.get("signing"):
            raise LifecycleError("Secure Boot signing key/certificate missing")

    def build(self, source, kernel, jobs, log):
        self.builds += 1
        self.events.append("build")
        atomic_write(log, b"BUILD_STARTED\nBUILD_COMPLETE\n")
        if self.fault == "build":
            raise LifecycleError("make failed; see build.log")
        modules = source / "kernel-open"
        modules.mkdir(exist_ok=True)
        for name in MODULES:
            metadata = {"version": self.version, "vermagic": kernel + " SMP preempt mod_unload",
                        "srcversion": "A1B2C3", "vbios_override_per_gpu": "1", "vbios_override_param_bytes": "4094", "signer": "",
                        "name": name, "build_generation": self.builds}
            if self.fault in ("version", "vermagic", "vbios_override_per_gpu", "vbios_override_param_bytes") and name == "nvidia.ko":
                metadata[self.fault] = "wrong"
            atomic_write(modules / name, json.dumps(metadata).encode())
        if self.after_build:
            self.after_build()

    def modinfo(self, path):
        return json.loads(path.read_bytes())

    def sign(self, modules, kernel, config):
        if self.secure:
            for path in modules:
                data = self.modinfo(path)
                data["signer"] = "enrolled-test-key"
                atomic_write(path, json.dumps(data).encode())
        return self.secure

    def depmod(self, kernel):
        self.events.append("depmod")
        if self.fault == "depmod":
            self.fault = None
            raise LifecycleError("depmod failure")

    def selected_module(self, kernel, name):
        managed = self.root / f"usr/lib/modules/{kernel}/updates/vbios-override/{name}.ko"
        if self.fault == "selection" or not managed.exists():
            return str(self.root / f"usr/lib/modules/{kernel}/extra/{name}.ko")
        return str(managed)

    def coordinate_akmods(self, kernel, config):
        self.events.append("akmods:" + kernel)
        if self.fault == "akmods":
            raise LifecycleError("per-kernel akmods coordination failed")

    def initramfs(self, kernel, destination, targets, *, activation_config, force_config):
        self.events.append("dracut")
        if self.fault == "dracut":
            raise LifecycleError("dracut failure")
        members = {str(path.relative_to(self.root)): base64.b64encode(path.read_bytes()).decode()
                   for path in targets}
        members["etc/modprobe.d/zz-vbios-override-test.conf"] = base64.b64encode(activation_config.read_bytes()).decode()
        members["etc/cmdline.d/20-force_drivers.conf"] = base64.b64encode(force_config.read_bytes()).decode()
        atomic_write(destination, json.dumps(members).encode())
        if self.after_initramfs:
            self.after_initramfs()

    def initramfs_members(self, image):
        if self.fault == "listing":
            raise LifecycleError("lsinitrd failed")
        try:
            return list(json.loads(image.read_bytes()))
        except ValueError:
            return []  # a normal image written by the fixture: no NVIDIA module

    def extract(self, image, member):
        if self.fault == "extract":
            return b"wrong bytes"
        try:
            value = json.loads(image.read_bytes()).get(member)
        except ValueError:
            return None  # a normal image written by the fixture, not by this fake dracut
        return base64.b64decode(value) if value is not None else None

    def restore_labels(self, paths):
        if self.fault == "labels":
            raise LifecycleError("restorecon failure")

    def grub_environment(self):
        return dict(self.environment)

    def set_default(self, entry):
        self.events.append("default:" + entry)
        self.environment["saved_entry"] = entry
        if self.fault == "default" and entry.startswith("vbios-"):
            self.fault = None
            raise LifecycleError("grub wrote then failed")


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        (REPO / ".private").mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="lifecycle-test-", dir=REPO / ".private")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.add_kernel(OLD)
        self.add_kernel(NEW)
        source = self.root / "var/lib/nvidia-vbios/sources/p2p"
        atomic_write(source / "version.mk", VERSION.encode())
        atomic_write(source / "Makefile", b"reviewed build script\n")
        payload = b"REVIEWED ROM payload for board 0"
        atomic_write(self.root / "var/lib/nvidia-vbios/roms/gpu0.bin", payload)
        self.config = {"schema_version": 1, "enabled": True, "jobs": 2,
            "fallback_entry": "normal-" + OLD,
            "fallback_sha256": digest(self.bls(OLD).read_bytes()),
            "fallback_files": {name: digest((self.root / name.lstrip("/")).read_bytes()) for name in
                               (f"/boot/vmlinuz-{OLD}", f"/boot/initramfs-{OLD}.img")},
            "devices": [{"bdf": "0000:03:00.0", "uuid": "GPU-00000000-0000-0000-0000-000000000001",
                         "vendor": 0x10de, "device": 0x2bb4, "architecture": "blackwell-gb20x",
                         "runtime_tested": True, "structurally_validated": True,
                         "payload_path": "/var/lib/nvidia-vbios/roms/gpu0.bin", "size": len(payload),
                         "sha256": digest(payload), "source_sha256": digest(payload)}],
            "sources": [{"version": VERSION, "path": "/var/lib/nvidia-vbios/sources/p2p",
                         "source_hashes": {"version.mk": digest(VERSION.encode())},
                         "tree_sha256": source_tree_hash(source, self.root), "p2p_preferred": True}]}
        self.write_config()
        self.ops = FakeOperations(self.root, self.config)
        self.worker = Reconciler(self.root, self.ops)

    def add_kernel(self, kernel):
        atomic_write(self.root / f"boot/vmlinuz-{kernel}", ("KERNEL " + kernel).encode())
        atomic_write(self.root / f"boot/initramfs-{kernel}.img", ("NORMAL IMAGE " + kernel).encode())
        atomic_write(self.root / f"boot/loader/entries/normal-{kernel}.conf",
                     (f"title Fedora {kernel}\nversion {kernel}\nlinux /vmlinuz-{kernel}\n"
                      f"initrd /initramfs-{kernel}.img\noptions root=UUID=test ro quiet\n").encode())
        (self.root / f"usr/lib/modules/{kernel}").mkdir(parents=True, exist_ok=True)

    def bls(self, kernel):
        return self.root / f"boot/loader/entries/normal-{kernel}.conf"

    def write_config(self):
        json_write(self.root / "etc/nvidia-vbios/lifecycle.json", self.config)

    def status(self, kernel=NEW):
        return json.loads((self.root / STATE.lstrip("/") / f"status-{kernel}.json").read_text())

    def snapshot_normal(self):
        return {str(path): path.read_bytes() for path in (self.bls(OLD), self.bls(NEW),
                        self.root / f"boot/initramfs-{OLD}.img", self.root / f"boot/initramfs-{NEW}.img")}

    def test_dry_run_is_read_only_and_names_explicit_gpu(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*"))
        result = self.worker.reconcile(NEW, dry_run=True)
        self.assertEqual(result["version"], VERSION)
        self.assertIn("pci=0000:03:00.0", " ".join(result["module_parameters"].values()))
        self.assertEqual(before, sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*")))
        self.assertEqual(self.ops.builds, 0)

    def test_success_installs_every_module_and_exact_initramfs_before_default(self):
        normal = self.snapshot_normal()
        result = self.worker.reconcile(NEW)
        self.assertEqual(result["state"], "ready")
        self.assertEqual(self.ops.environment["saved_entry"], result["entry"])
        self.assertFalse(result["runtime_tested"])
        self.assertEqual(normal, self.snapshot_normal())
        self.assertLess(self.ops.events.index("dracut"), self.ops.events.index("default:" + result["entry"]))
        for name in MODULES:
            self.assertTrue((self.root / f"usr/lib/modules/{NEW}/updates/vbios-override/{name}").exists())
        self.assertEqual(self.ops.loaded_version, VERSION)
        entry = (self.root / f"boot/loader/entries/{result['entry']}.conf").read_text()
        self.assertNotIn("NVreg_", entry)
        image_path = next(record["path"] for record in result["deployment"] if record["path"].startswith("/boot/initramfs-"))
        config = self.ops.extract(self.root / image_path.lstrip("/"), "etc/modprobe.d/zz-vbios-override-test.conf")
        self.assertIn(b"RmLinuxVbiosOverrideDisable=0", config)

    def test_later_kernel_becomes_ready_without_fixed_old_default(self):
        first = self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        self.ops.environment["saved_entry"] = "normal-" + NEXT  # RPM may change default.
        second = self.worker.reconcile(NEXT)
        self.assertNotEqual(first["entry"], second["entry"])
        self.assertEqual(self.ops.environment["saved_entry"], second["entry"])
        self.assertTrue((self.root / f"boot/loader/entries/{first['entry']}.conf").exists())
        self.assertEqual(self.ops.builds, 2)

    def test_ready_audit_does_not_rebuild(self):
        first = self.worker.reconcile(NEW)
        second = self.worker.reconcile(NEW)
        self.assertEqual(first, second)
        self.assertEqual(self.ops.builds, 1)

    def test_build_and_install_failure_matrix_restores_bytes_and_default(self):
        for fault in ("akmods", "build", "version", "vermagic", "vbios_override_per_gpu", "vbios_override_param_bytes", "depmod",
                      "selection", "dracut", "extract", "labels", "default"):
            with self.subTest(fault=fault):
                # Each scenario starts from its own synthetic root.
                case = LifecycleTests(methodName="runTest")
                case.setUp()
                try:
                    normal = case.snapshot_normal()
                    case.ops.fault = fault
                    with self.assertRaises(LifecycleError):
                        case.worker.reconcile(NEW)
                    self.assertEqual(case.ops.environment["saved_entry"], "normal-" + OLD)
                    self.assertEqual(normal, case.snapshot_normal())
                    self.assertEqual(case.status()["state"], "blocked")
                    self.assertIsNone(case.status()["rollback_error"])
                    self.assertFalse(list((case.root / f"usr/lib/modules/{NEW}").rglob("*.ko")))
                    self.assertFalse(list((case.root / "boot/loader/entries").glob("vbios-*")))
                finally:
                    case.doCleanups()

    def test_missing_header_or_secure_boot_key_is_a_real_block(self):
        for fault in ("headers", "secure"):
            with self.subTest(fault=fault):
                self.ops.fault = "headers" if fault == "headers" else None
                self.ops.secure = fault == "secure"
                with self.assertRaisesRegex(LifecycleError, "kernel-devel|signing key"):
                    self.worker.reconcile(NEW)
                self.assertEqual(self.ops.builds, 0)
                self.assertEqual(self.status()["state"], "blocked")

    def test_secure_boot_signs_all_modules(self):
        self.ops.secure = True
        self.config["signing"] = {"key": "/test/key", "certificate": "/test/cert"}
        self.write_config()
        result = self.worker.reconcile(NEW)
        self.assertTrue(all(info["signer"] for info in result["module_metadata"].values()))

    def test_exact_userspace_version_never_silently_upgrades(self):
        self.ops.version = "615.78.08"
        with self.assertRaisesRegex(LifecycleError, "exact installed userspace"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.builds, 0)

    def fleet(self):
        return json.loads((self.root / STATE.lstrip("/") / "fleet.json").read_text())

    def managed_modules(self, kernel=NEW):
        return self.root / f"usr/lib/modules/{kernel}/updates/vbios-override"

    def stock(self, kernel, version):
        """The distribution's own nvidia.ko for `kernel` (akmods/DKMS)."""
        atomic_write(self.root / f"usr/lib/modules/{kernel}/extra/nvidia.ko", json.dumps({"version": version}).encode())

    def register_source(self, version):
        source = self.root / f"var/lib/nvidia-vbios/sources/{version}"
        atomic_write(source / "version.mk", version.encode())
        atomic_write(source / "Makefile", b"reviewed new driver build script")
        self.config["sources"].append({"version": version, "path": f"/var/lib/nvidia-vbios/sources/{version}",
             "source_hashes": {"version.mk": digest(version.encode())},
             "tree_sha256": source_tree_hash(source, self.root), "p2p_preferred": True})
        self.write_config()

    def test_driver_drift_parks_modules_and_boots_newest_normal_entry(self):
        ready = self.worker.reconcile(NEW)
        modules = self.managed_modules()
        files = {path.name: path.read_bytes() for path in modules.iterdir()}
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["state"], result["marker"]), ("driver-drift", "VBIOS_DRIFT"))
        self.assertEqual(self.ops.builds, 1)
        self.assertFalse(modules.exists())
        parked = self.root / result["parked"][0].lstrip("/")
        self.assertEqual(parked.parent, self.root / "usr/lib/modules")
        self.assertTrue(parked.name.startswith(".vbios-parked-" + NEW + "-"))
        self.assertEqual({path.name: path.read_bytes() for path in parked.iterdir()}, files)
        self.assertEqual(result["stock_module"], str(self.root / f"usr/lib/modules/{NEW}/extra/nvidia.ko"))
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)
        self.assertEqual(result["entry"], "normal-" + NEW)
        self.assertEqual((result["installed_driver"], result["built_driver"]), ("615.78.08", VERSION))
        self.assertEqual(result["normal_image"], "clean")
        self.assertIn("exact installed userspace", result["error"])
        self.assertEqual(result["resume"], "nvbios system post-install --source PATH")
        state = self.root / STATE.lstrip("/")
        self.assertEqual(self.status(), result)
        self.assertEqual(json.loads((state / f"attempt-{NEW}.json").read_text()), result)
        drift = self.fleet()["drift"]
        self.assertEqual((drift["version"], drift["kernel"], drift["entry"]), ("615.78.08", NEW, "normal-" + NEW))
        # The previous READY entry and image stay for an explicit return.
        self.assertTrue((self.root / f"boot/loader/entries/{ready['entry']}.conf").exists())
        self.assertEqual(self.fleet()["last_ready"]["entry"], ready["entry"])

    def test_driver_drift_after_run_installer_emptied_the_override_directory(self):
        # nvidia-installer backs up every nvidia*.ko under the running kernel, ours included.
        self.worker.reconcile(NEW)
        for member in self.managed_modules().iterdir():
            member.unlink()
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["state"], result["parked"]), ("driver-drift", []))
        self.assertEqual(result["stock_module"], str(self.root / f"usr/lib/modules/{NEW}/extra/nvidia.ko"))
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)

    def test_driver_drift_parks_the_remaining_modules_and_refuses_foreign_files(self):
        self.worker.reconcile(NEW)
        for member in self.managed_modules().iterdir():
            if member.name != "nvidia-uvm.ko":
                member.unlink()
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEW)
        parked = self.root / result["parked"][0].lstrip("/")
        self.assertEqual([path.name for path in parked.iterdir()], ["nvidia-uvm.ko"])
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)
        atomic_write(self.managed_modules() / "nvidia.ko", b"FOREIGN")
        with self.assertRaisesRegex(LifecycleError, "exact installed userspace"):
            self.worker.reconcile(NEW)
        attempt = json.loads((self.root / STATE.lstrip("/") / f"attempt-{NEW}.json").read_text())
        self.assertIn("not parked", attempt["fail_safe_error"])

    def test_driver_drift_on_new_kernel_selects_its_normal_entry_and_parks_older_kernels(self):
        ready = self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        self.ops.environment["saved_entry"] = "normal-" + NEXT
        self.stock(NEXT, "615.78.08")
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEXT)
        self.assertEqual(result["state"], "driver-drift")
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEXT)
        self.assertEqual(result["stock_module"], str(self.root / f"usr/lib/modules/{NEXT}/extra/nvidia.ko"))
        # The older kernel's normal entry would otherwise still load our old modules.
        self.assertFalse(self.managed_modules(NEW).exists())
        self.assertEqual([Path(path).name.rsplit("-", 1)[0] for path in result["parked"]], [".vbios-parked-" + NEW])
        self.assertIn("default:" + ready["entry"], self.ops.events)

    def test_drift_parks_the_kernel_of_a_user_chosen_normal_default_and_reports_its_module(self):
        # The timer reconciles the newest kernel, while the user chose an older kernel's normal entry.
        self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        self.stock(NEW, "615.78.08")
        self.ops.environment["saved_entry"] = "normal-" + NEW
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEXT)
        self.assertEqual((result["state"], self.ops.environment["saved_entry"]), ("driver-drift", "normal-" + NEW))
        self.assertFalse(self.managed_modules(NEW).exists())
        self.assertEqual((result["entry"], result["stock_module"], result["stock_module_version"], result["boots_normal_driver"]),
                         ("normal-" + NEW, str(self.root / f"usr/lib/modules/{NEW}/extra/nvidia.ko"), "615.78.08", True))

    def test_kernel_update_during_drift_moves_our_normal_default_forward(self):
        # GRUB_DEFAULT=saved (Debian, Arch) keeps normal-NEW after NEXT is installed.
        self.worker.reconcile(NEW)
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        self.stock(NEXT, "615.78.08")
        self.assertEqual(queue_event("add", NEXT, self.root, self.ops)["retained_default"], "normal-" + NEW)
        result = self.worker.reconcile(NEXT)
        self.assertEqual((result["state"], result["entry"]), ("driver-drift", "normal-" + NEXT))
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEXT)
        self.assertEqual(queue_event("changed", "userspace", self.root, self.ops)["retained_default"], "normal-" + NEXT)
        self.register_source("615.78.08")
        ready = self.worker.reconcile(NEXT)
        self.assertEqual((ready["state"], self.ops.environment["saved_entry"]), ("ready", ready["entry"]))

    def test_kernel_update_during_drift_keeps_a_default_whose_module_matches(self):
        self.worker.reconcile(NEW)
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        self.assertEqual(self.worker.reconcile(NEW)["entry"], "normal-" + NEW)
        self.add_kernel(NEXT)  # DKMS/akmods could not build the module for NEXT
        queue_event("add", NEXT, self.root, self.ops)
        result = self.worker.reconcile(NEXT)
        self.assertEqual((result["entry"], result["boots_normal_driver"]), ("normal-" + NEW, True))
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)

    def test_drift_selects_the_newest_normal_entry_whose_module_matches(self):
        # One upgrade brought kernel NEXT and the new driver; its module built for NEW only.
        self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        queue_event("add", NEXT, self.root, self.ops)  # the guard keeps READY
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEXT)
        self.assertEqual((result["state"], self.ops.environment["saved_entry"]), ("driver-drift", "normal-" + NEW))
        self.assertEqual((result["stock_module_version"], result["boots_normal_driver"]), ("615.78.08", True))
        self.assertEqual(queue_event("changed", "userspace", self.root, self.ops)["retained_default"], "normal-" + NEW)

    def test_drift_without_a_matching_distribution_module_keeps_the_ready_default(self):
        # .run --no-kernel-modules or a failed akmods/DKMS build: no normal entry loads the new
        # driver, and the READY image still loads a module, so post-install can read GPU identity.
        ready = self.worker.reconcile(NEW)
        self.stock(NEW, VERSION)
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["state"], result["entry"], result["boots_normal_driver"]), ("driver-drift", ready["entry"], False))
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])
        self.assertFalse(self.managed_modules().exists())
        self.assertEqual(queue_event("add", NEW, self.root, self.ops)["retained_default"], ready["entry"])
        self.stock(NEW, "615.78.08")  # built later
        self.assertEqual(self.worker.reconcile(NEW)["entry"], "normal-" + NEW)
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)

    def test_deliberate_same_kernel_normal_default_still_gets_our_modules_parked(self):
        self.worker.reconcile(NEW)
        self.ops.environment["saved_entry"] = "normal-" + NEW
        events = len(self.ops.events)
        with self.assertRaisesRegex(LifecycleError, "foreign or unrelated"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.events[events:], [])  # no drift: refused before any package lock
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["state"], result["entry"]), ("driver-drift", "normal-" + NEW))
        self.assertFalse(self.managed_modules().exists())
        self.assertNotIn("default:normal-" + NEW, self.ops.events)
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)

    def test_fail_safe_says_whether_the_normal_entry_has_a_matching_stock_module(self):
        self.worker.reconcile(NEW)
        stock = self.root / f"usr/lib/modules/{NEW}/extra/nvidia.ko"
        atomic_write(stock, json.dumps({"version": VERSION}).encode())  # the new kmod failed to build
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["stock_module_version"], result["boots_normal_driver"]), (VERSION, False))
        atomic_write(stock, json.dumps({"version": "615.78.08"}).encode())
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["stock_module_version"], result["boots_normal_driver"]), ("615.78.08", True))
        stock.unlink()  # .run --no-kernel-modules
        self.assertEqual(self.worker.reconcile(NEW)["boots_normal_driver"], False)

    def test_driver_drift_second_run_changes_nothing(self):
        self.worker.reconcile(NEW)
        self.ops.version = "615.78.08"
        first = self.worker.reconcile(NEW)
        fleet, events = self.fleet(), list(self.ops.events)
        second = self.worker.reconcile(NEW)
        self.assertEqual(second["state"], "driver-drift")
        self.assertEqual(second["parked"], first["parked"])
        self.assertEqual(self.fleet(), fleet)
        self.assertFalse([event for event in self.ops.events[len(events):] if event.startswith(("default:", "build"))])
        self.assertTrue((self.root / first["parked"][0].lstrip("/")).is_dir())

    def test_guard_under_drift_keeps_normal_moves_managed_and_preserves_foreign(self):
        ready = self.worker.reconcile(NEW)
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        self.ops.environment["saved_entry"] = "normal-" + NEXT
        self.assertEqual(queue_event("add", NEXT, self.root, self.ops)["retained_default"], "normal-" + NEXT)
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEXT)
        self.ops.environment["saved_entry"] = ready["entry"]
        self.assertEqual(queue_event("add", NEXT, self.root, self.ops)["retained_default"], "normal-" + NEW)
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)
        for environment in ({"saved_entry": "windows-other-os"}, {"saved_entry": "normal-" + OLD},
                            {"saved_entry": ready["entry"], "next_entry": "some-other-test"}):
            self.ops.environment = dict(environment)
            with self.subTest(environment=environment), self.assertRaisesRegex(LifecycleError, "foreign or unrelated|transition is pending"):
                queue_event("add", NEXT, self.root, self.ops)
            self.assertEqual(self.ops.environment, environment)

    def normal_image(self, kernel, members):
        """A normal initramfs holding these (member, modinfo version) modules."""
        atomic_write(self.root / f"boot/initramfs-{kernel}.img", json.dumps(
            {name: base64.b64encode(json.dumps({"version": version}).encode()).decode()
             for name, version in members.items()}).encode())

    def test_normal_image_with_another_nvidia_build_is_not_selected(self):
        ready = self.worker.reconcile(NEW)
        # The rootfs module is the new driver, but the image early-loads the old stock build.
        stale = f"usr/lib/modules/{NEW}/extra/nvidia/nvidia.ko.xz"
        self.normal_image(NEW, {stale: VERSION, "usr/lib/modules/other-kernel/extra/nvidia.ko": "1.0.0"})
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["state"], result["normal_image"], result["boots_normal_driver"]),
                         ("driver-drift", "mismatched", False))
        self.assertEqual((self.ops.environment["saved_entry"], result["entry"]), (ready["entry"], ready["entry"]))
        self.assertFalse(self.managed_modules().exists())
        # Regenerated with the distribution's new build, the image is verified and selected.
        self.normal_image(NEW, {stale: "615.78.08", f"usr/lib/modules/{NEW}/extra/nvidia/nvidia-drm.ko.zst": "615.78.08"})
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["normal_image"], result["boots_normal_driver"], result["entry"]),
                         ("matching", True, "normal-" + NEW))
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)
        # One stale companion module is enough to refuse the image.
        self.normal_image(NEW, {stale: "615.78.08", f"lib/modules/{NEW}/updates/dkms/nvidia-current-uvm.ko": VERSION})
        from nvidia_vbios.lifecycle.config import load_config
        config = load_config(self.worker.config_path, self.root, require_enabled=False)
        self.assertEqual(self.worker._normal_image_state(config, NEW, "615.78.08"), "mismatched")

    def test_unreadable_normal_image_is_neither_selected_nor_reported_bootable(self):
        ready = self.worker.reconcile(NEW)
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        for fault in ("listing", "extract"):
            with self.subTest(fault=fault):
                self.normal_image(NEW, {f"usr/lib/modules/{NEW}/extra/nvidia.ko": "615.78.08"})
                self.ops.fault = fault
                result = self.worker.reconcile(NEW)
                self.assertEqual((result["state"], result["normal_image"], result["boots_normal_driver"]),
                                 ("driver-drift", "unknown", False))
                self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])
        self.ops.fault = None
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["normal_image"], result["boots_normal_driver"]), ("matching", True))
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)

    def test_normal_image_with_our_module_blocks_until_it_is_regenerated(self):
        ready = self.worker.reconcile(NEW)
        member = f"usr/lib/modules/{NEW}/updates/vbios-override/nvidia.ko"
        atomic_write(self.root / f"boot/initramfs-{NEW}.img",
                     json.dumps({member: base64.b64encode(b"OUR MODULE").decode()}).encode())
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        # Both entries load the old module from their image: not a successful fail-safe.
        with self.assertRaisesRegex(LifecycleError, f"fail-safe: .*regenerate it with `dracut -f --kver {NEW}`"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.status()["state"], "blocked")
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])
        self.assertFalse(self.managed_modules().exists())
        self.assertEqual(self.fleet()["drift"]["entry"], ready["entry"])
        self.assertEqual(queue_event("add", NEW, self.root, self.ops)["retained_default"], ready["entry"])
        # After the regeneration (with our modules parked) the next run boots the normal entry.
        atomic_write(self.root / f"boot/initramfs-{NEW}.img", b"REGENERATED NORMAL IMAGE")
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["state"], result["normal_image"]), ("driver-drift", "clean"))
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)
        from nvidia_vbios.lifecycle.engine import regenerate_command
        self.assertEqual([regenerate_command({"boot": {"initramfs": name}}, NEW) for name in ("initramfs-tools", "mkinitcpio")],
                         [f"update-initramfs -u -k {NEW}", "mkinitcpio -P"])

    def test_lock_busy_or_early_failure_under_drift_stays_plain_blocked(self):
        from unittest.mock import patch
        from nvidia_vbios.lifecycle.security import LockBusy
        ready = self.worker.reconcile(NEW)
        self.ops.version = "615.78.08"
        lock = self.root / "run/akmods/akmods.lock"
        atomic_write(lock, b"")
        with lock.open("rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(LifecycleError, "lock busy"):
                self.worker.reconcile(NEW)
        with patch("nvidia_vbios.lifecycle.engine.select_source", side_effect=LockBusy("update/build lock busy: other")):
            with self.assertRaisesRegex(LifecycleError, "lock busy"):
                self.worker.reconcile(NEW)
        self.ops.environment["saved_entry"] = "windows-other-os"
        with self.assertRaisesRegex(LifecycleError, "foreign or unrelated"):
            self.worker.reconcile(NEW)
        self.assertTrue(self.managed_modules().exists())
        self.assertNotIn("drift", self.fleet())
        attempt = json.loads((self.root / STATE.lstrip("/") / f"attempt-{NEW}.json").read_text())
        self.assertEqual(attempt["state"], "blocked")
        self.assertNotIn("fail_safe_error", attempt)
        self.assertEqual(self.status()["entry"], ready["entry"])

    def test_same_version_failure_stays_blocked_with_preserved_ready(self):
        ready = self.worker.reconcile(NEW)
        self.ops.fault = "headers"
        with self.assertRaisesRegex(LifecycleError, "kernel-devel"):
            self.worker.reconcile(NEW)
        attempt = json.loads((self.root / STATE.lstrip("/") / f"attempt-{NEW}.json").read_text())
        self.assertEqual((attempt["state"], attempt["preserved_ready"]), ("blocked", True))
        self.assertEqual(self.status()["state"], "ready")
        self.assertTrue(self.managed_modules().exists())
        self.assertNotIn("drift", self.fleet())
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])

    def test_build_failure_under_drift_rolls_back_to_the_normal_entry(self):
        self.worker.reconcile(NEW)
        self.stock(NEW, "615.78.08")
        self.ops.version = "615.78.08"
        self.worker.reconcile(NEW)
        self.register_source("615.78.08")
        self.ops.fault = "default"
        result = self.worker.reconcile(NEW)
        self.assertEqual(result["state"], "driver-drift")
        self.assertIn("grub wrote then failed", result["error"])
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)
        self.assertFalse(self.managed_modules().exists())
        journal = json.loads((self.root / STATE.lstrip("/") / "transaction.json").read_text())
        self.assertEqual((journal["phase"], journal["previous_default"]), ("rolled-back", "normal-" + NEW))

    def test_failed_rollback_of_an_interrupted_transaction_is_no_fail_safe(self):
        self.worker.reconcile(NEW)
        self.ops.version = "615.78.08"
        self.worker.reconcile(NEW)
        self.register_source("615.78.08")
        def kernel_update_during_build():
            self.add_kernel(NEXT)
            self.ops.environment["saved_entry"] = "normal-" + NEXT
        self.ops.after_build = kernel_update_during_build
        with self.assertRaisesRegex(LifecycleError, "rollback requires review"):
            self.worker.reconcile(NEW)
        self.ops.after_build = None
        # The next run resumes that journal; its rollback fails again and needs review.
        with self.assertRaisesRegex(LifecycleError, "rollback requires review: GRUB default changed externally"):
            self.worker.reconcile(NEXT)
        self.assertEqual(self.status(NEXT)["state"], "blocked")
        self.assertIn("GRUB default changed externally", self.status(NEXT)["rollback_error"])
        journal = json.loads((self.root / STATE.lstrip("/") / "transaction.json").read_text())
        self.assertEqual(journal["phase"], "rollback-failed")

    def test_failed_builds_do_not_pile_up_source_copies(self):
        self.ops.fault = "build"
        for _ in range(2):
            with self.assertRaisesRegex(LifecycleError, "make failed"):
                self.worker.reconcile(NEW)
            self.ops.fault = "build"
        workspaces = list((self.root / STATE.lstrip("/") / "transactions").iterdir())
        self.assertEqual(len(workspaces), 2)
        for workspace in workspaces:
            self.assertFalse((workspace / "source").exists())
            self.assertTrue((workspace / "build.log").is_file())
            self.assertTrue((workspace / "source-manifest.json").is_file())

    def test_registered_new_source_ends_drift_and_removes_parked_modules(self):
        first = self.worker.reconcile(NEW)
        self.ops.version = "615.78.08"
        drift = self.worker.reconcile(NEW)
        parked = self.root / drift["parked"][0].lstrip("/")
        self.register_source("615.78.08")
        ready = self.worker.reconcile(NEW)
        self.assertEqual((ready["state"], ready["driver"]), ("ready", "615.78.08"))
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])
        self.assertNotEqual(ready["entry"], first["entry"])
        self.assertNotIn("drift", self.fleet())
        self.assertFalse(parked.exists())
        self.assertNotIn("cleanup_warnings", ready)
        self.assertTrue(self.managed_modules().exists())
        self.assertEqual(self.worker.ready_status(NEW)["entry"], ready["entry"])

    def test_changed_parked_modules_are_left_in_place_with_a_warning(self):
        self.worker.reconcile(NEW)
        self.ops.version = "615.78.08"
        parked = self.root / self.worker.reconcile(NEW)["parked"][0].lstrip("/")
        atomic_write(parked / "nvidia.ko", b"CHANGED AFTER PARKING")
        self.register_source("615.78.08")
        ready = self.worker.reconcile(NEW)
        self.assertEqual(ready["state"], "ready")
        self.assertTrue(parked.exists())
        self.assertTrue(any("left in place" in warning for warning in ready["cleanup_warnings"]))

    def test_drift_without_a_bootable_normal_image_stays_blocked(self):
        ready = self.worker.reconcile(NEW)
        (self.root / f"boot/initramfs-{NEW}.img").unlink()
        self.ops.version = "615.78.08"
        with self.assertRaisesRegex(LifecycleError, "exact installed userspace"):
            self.worker.reconcile(NEW)
        attempt = json.loads((self.root / STATE.lstrip("/") / f"attempt-{NEW}.json").read_text())
        self.assertEqual(attempt["state"], "blocked")
        self.assertIn(f"initramfs-{NEW}.img", attempt["fail_safe_error"])
        self.assertTrue(self.managed_modules().exists())
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])

    def test_two_part_installed_version_still_reaches_the_fail_safe(self):
        from nvidia_vbios.lifecycle.system import SystemOperations
        self.assertEqual(SystemOperations._upstream_version("575.64-1"), "575.64")
        self.assertEqual(SystemOperations._upstream_version("1:580.82.07-0ubuntu1"), "580.82.07")
        self.worker.reconcile(NEW)
        self.stock(NEW, "615.80")
        self.ops.version = "615.80"
        result = self.worker.reconcile(NEW)
        self.assertEqual((result["state"], result["installed_driver"]), ("driver-drift", "615.80"))
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)

    def test_changed_rom_and_unselected_identity_are_rejected(self):
        atomic_write(self.root / self.config["devices"][0]["payload_path"].lstrip("/"), b"different bytes")
        with self.assertRaisesRegex(LifecycleError, "ROM bytes changed"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.builds, 0)

    def test_changed_build_script_blocks_even_when_adapter_anchors_match(self):
        atomic_write(self.root / "var/lib/nvidia-vbios/sources/p2p/Makefile", b"untrusted recipe")
        with self.assertRaisesRegex(LifecycleError, "source/build-script tree changed"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.builds, 0)

    def test_registry_prefers_p2p_and_does_not_fall_back_when_it_changes(self):
        stock = self.root / "var/lib/nvidia-vbios/sources/stock"
        atomic_write(stock / "version.mk", VERSION.encode())
        atomic_write(stock / "Makefile", b"stock")
        entry = copy.deepcopy(self.config["sources"][0])
        entry.update(path="/var/lib/nvidia-vbios/sources/stock", tree_sha256=source_tree_hash(stock, self.root), p2p_preferred=False)
        self.config["sources"].insert(0, entry)
        self.write_config()
        self.assertTrue(self.worker.dry_run(NEW)["source"]["p2p_preferred"])
        atomic_write(self.root / "var/lib/nvidia-vbios/sources/p2p/Makefile", b"changed")
        with self.assertRaisesRegex(LifecycleError, "tree changed"):
            self.worker.reconcile(NEW)

    def test_source_or_configuration_mutation_during_build_is_blocked(self):
        self.ops.after_build = lambda: atomic_write(self.root / "var/lib/nvidia-vbios/sources/p2p/Makefile", b"changed after build")
        with self.assertRaisesRegex(LifecycleError, "tree changed"):
            self.worker.reconcile(NEW)
        self.assertFalse(list((self.root / f"usr/lib/modules/{NEW}").rglob("*.ko")))

    def test_up_to_32_gpu_selection_is_explicit_and_scoped(self):
        sample = self.config["devices"][0]
        self.config["devices"] = [dict(sample, bdf=f"0000:{i+3:02x}:00.0",
            uuid=f"GPU-00000000-0000-0000-0000-{i+1:012x}") for i in range(32)]
        self.write_config()
        result = self.worker.reconcile(NEW)
        image_path = next(record["path"] for record in result["deployment"] if record["path"].startswith("/boot/initramfs-"))
        configuration = self.ops.extract(self.root / image_path.lstrip("/"), "etc/modprobe.d/zz-vbios-override-test.conf").decode()
        for device in self.config["devices"]:
            self.assertIn("pci=" + device["bdf"], configuration)
        self.assertNotIn("pci=0000:23:00.0", configuration)
        self.config["devices"].append(dict(sample, bdf="0000:23:00.0", uuid="GPU-00000000-0000-0000-0000-000000000033"))
        self.write_config()
        with self.assertRaisesRegex(LifecycleError, "one through 32"):
            self.worker.reconcile(NEW)

    def test_hopper_datacenter_and_unvalidated_enrollment_are_excluded(self):
        for architecture in ("hopper", "blackwell-gb100", "unknown"):
            self.config["devices"][0]["architecture"] = architecture
            self.write_config()
            with self.assertRaisesRegex(LifecycleError, "outside"):
                self.worker.reconcile(NEW)
        self.config["devices"][0]["architecture"] = "ampere"
        self.config["devices"][0]["runtime_tested"] = False
        self.write_config()
        self.assertEqual(self.worker.reconcile(NEW)["state"], "ready")
        self.config["devices"][0]["structurally_validated"] = False
        self.write_config()
        with self.assertRaisesRegex(LifecycleError, "structural validation"):
            self.worker.reconcile(NEW)

    def test_turing_enrollment_is_accepted(self):
        # Experimental: TU10x/TU11x take the same override path; no Turing board has loaded one.
        from nvidia_vbios.lifecycle.config import load_config
        self.config["devices"][0].update(architecture="turing", device=0x1e07)
        self.write_config()
        self.assertEqual(load_config(self.worker.config_path, self.root).devices[0]["architecture"], "turing")

    def test_external_mutation_is_not_overwritten_by_rollback(self):
        target = self.root / f"usr/lib/modules/{NEW}/updates/vbios-override/nvidia.ko"
        def mutate():
            atomic_write(target, b"EXTERNAL OWNER BYTES")
            self.ops.fault = "extract"
        self.ops.after_initramfs = mutate
        with self.assertRaisesRegex(LifecycleError, "rollback requires review"):
            self.worker.reconcile(NEW)
        self.assertEqual(target.read_bytes(), b"EXTERNAL OWNER BYTES")
        self.assertIn("externally changed", self.status()["rollback_error"])
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + OLD)

    def test_pending_grub_transition_is_preserved(self):
        self.ops.environment["next_entry"] = "some-other-test"
        with self.assertRaisesRegex(LifecycleError, "transition is pending"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.environment["next_entry"], "some-other-test")
        self.assertEqual(self.ops.builds, 0)

    def test_writable_and_symlink_profiles_are_rejected(self):
        path = self.root / "etc/nvidia-vbios/lifecycle.json"
        path.chmod(0o666)
        with self.assertRaisesRegex(LifecycleError, "untrusted"):
            self.worker.reconcile(NEW)
        path.chmod(0o600)
        path.rename(path.with_name("other.json"))
        path.symlink_to("other.json")
        with self.assertRaisesRegex(LifecycleError, "symlink"):
            self.worker.reconcile(NEW)

    def test_akmods_lock_contention_blocks_and_reports_retry(self):
        lock = self.root / "run/akmods/akmods.lock"
        atomic_write(lock, b"")
        with lock.open("rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(LifecycleError, "lock busy"):
                self.worker.reconcile(NEW)
        self.assertEqual(self.status()["state"], "blocked")
        self.assertEqual(self.ops.builds, 0)

    def test_recovery_restores_a_journaled_interrupted_install(self):
        state = self.root / STATE.lstrip("/")
        state.mkdir(parents=True)
        target = self.root / f"usr/lib/modules/{NEW}/updates/vbios-override/nvidia.ko"
        atomic_write(target, b"ORIGINAL")
        journal = {"id": "interrupted", "phase": "installing", "kernel": NEW,
                   "entry": "vbios-interrupted", "previous_default": "normal-" + OLD, "files": []}
        self.worker._stage_write(journal, target, b"PARTIAL NEW MODULE")
        self.ops.fault = "build"
        with self.assertRaisesRegex(LifecycleError, "make failed"):
            self.worker.reconcile(NEW)
        self.assertEqual(target.read_bytes(), b"ORIGINAL")
        self.assertEqual(json.loads((state / "transaction.json").read_text())["phase"], "rolled-back")

    def test_failure_on_new_kernel_retains_last_ready_even_if_rpm_changed_default(self):
        ready = self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        self.ops.environment["saved_entry"] = "normal-" + NEXT
        self.ops.fault = "headers"
        with self.assertRaisesRegex(LifecycleError, "kernel-devel"):
            self.worker.reconcile(NEXT)
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])

    def test_normal_fallback_initramfs_mutation_is_a_block(self):
        atomic_write(self.root / f"boot/initramfs-{OLD}.img", b"DAMAGED FALLBACK")
        with self.assertRaisesRegex(LifecycleError, "fallback kernel/initramfs bytes changed"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.builds, 0)

    def test_queue_safeguard_retains_ready_default_during_kernel_transaction(self):
        ready = self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        self.ops.environment["saved_entry"] = "normal-" + NEXT
        event = queue_event("add", NEXT, self.root, self.ops)
        self.assertEqual(event["retained_default"], ready["entry"])
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])
        self.assertEqual(self.ops.builds, 1)

    def test_reapply_atomically_restores_owned_module_set_on_failure(self):
        ready = self.worker.reconcile(NEW)
        folder = self.root / f"usr/lib/modules/{NEW}/updates/vbios-override"
        before = {path.name: path.read_bytes() for path in folder.iterdir()}
        self.config["jobs"] = 3
        self.write_config()
        self.ops.fault = "extract"
        with self.assertRaisesRegex(LifecycleError, "exact"):
            self.worker.reconcile(NEW)
        self.assertEqual(before, {path.name: path.read_bytes() for path in folder.iterdir()})
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])
        self.assertIsNone(self.status()["rollback_error"])

    def test_external_module_mutation_before_reapply_requires_explicit_adoption(self):
        self.worker.reconcile(NEW)
        path = self.root / f"usr/lib/modules/{NEW}/updates/vbios-override/nvidia.ko"
        atomic_write(path, b"EXTERNAL MODULE")
        with self.assertRaisesRegex(LifecycleError, "existing deployment changed"):
            self.worker.reconcile(NEW)
        self.assertEqual(path.read_bytes(), b"EXTERNAL MODULE")

    def test_unmanaged_module_can_only_be_adopted_by_its_root_enrolled_hash(self):
        path = self.root / f"usr/lib/modules/{NEW}/updates/vbios-override/nvidia.ko"
        old = b"REVIEWED EXISTING INSTALLATION"
        atomic_write(path, old)
        with self.assertRaisesRegex(LifecycleError, "adoption required"):
            self.worker.reconcile(NEW)
        self.config["adopt_existing"] = {"/" + str(path.relative_to(self.root)): digest(old)}
        self.write_config()
        self.ops.fault = "extract"
        with self.assertRaises(LifecycleError):
            self.worker.reconcile(NEW)
        self.assertEqual(path.read_bytes(), old)
        self.assertEqual(set(file.name for file in path.parent.iterdir()), {"nvidia.ko"})

    def test_atomic_exchange_failure_leaves_old_set_intact(self):
        from unittest.mock import patch
        self.worker.reconcile(NEW)
        folder = self.root / f"usr/lib/modules/{NEW}/updates/vbios-override"
        before = {path.name: path.read_bytes() for path in folder.iterdir()}
        self.config["jobs"] = 3
        self.write_config()
        with patch("nvidia_vbios.lifecycle.engine.exchange_directory", side_effect=LifecycleError("atomic exchange unavailable")):
            with self.assertRaisesRegex(LifecycleError, "atomic exchange unavailable"):
                self.worker.reconcile(NEW)
        self.assertEqual(before, {path.name: path.read_bytes() for path in folder.iterdir()})
        self.assertIsNone(self.status()["rollback_error"])

    def test_preserved_p2p_registry_settings_survive_without_inheriting_old_selection(self):
        self.config["parameters"] = {
            "NVreg_RegistryDwords": "RmP2P=1;RmLinuxVbiosOverride=2",
            "NVreg_RegistryDwordsPerDevice": "pci=0000:04:00.0;Other=9;RmLinuxVbiosOverride=2;RmLinuxVbiosOverrideSize=12",
            "NVreg_RegistryBinaryFilePerDevice": "pci=0000:04:00.0;RmLinuxVbiosOverrideImage=old.bin"}
        self.write_config()
        args = list(self.worker.dry_run(NEW)["module_parameters"].values())
        self.assertIn("RmP2P=1", args[0])
        self.assertIn("pci=0000:04:00.0;Other=9", args[1])
        self.assertNotIn("old.bin", args[2])
        self.assertNotIn("Size=12", args[1])
        self.config["parameters"]["NVreg_RegistryDwords"] = "RmP2P=1$(touch /tmp/bad)"
        self.write_config()
        with self.assertRaisesRegex(LifecycleError, "unsafe syntax"):
            self.worker.dry_run(NEW)

    def test_procfs_uuid_survives_nvml_userspace_driver_mismatch(self):
        from unittest.mock import patch
        from nvidia_vbios.lifecycle.system import SystemOperations
        bdf = self.config["devices"][0]["bdf"]
        sysfs = self.root / "sys/bus/pci/devices" / bdf
        for name, data in (("vendor", b"0x10de"), ("device", b"0x2bb4"), ("class", b"0x030000")):
            atomic_write(sysfs / name, data)
        atomic_write(self.root / "proc/driver/nvidia/gpus" / bdf / "information",
                     ("GPU UUID: " + self.config["devices"][0]["uuid"] + "\n").encode())
        operations = SystemOperations.__new__(SystemOperations)
        with patch("nvidia_vbios.lifecycle.system.Path", side_effect=lambda value: self.root / str(value).lstrip("/")), \
             patch.object(operations, "_run", side_effect=AssertionError("NVML must not be invoked")):
            actual = operations.inventory()
        self.assertEqual(actual[bdf]["uuid"], self.config["devices"][0]["uuid"])

    def test_removed_kernel_prunes_only_hash_owned_managed_boot_files(self):
        old = self.worker.reconcile(OLD)
        new = self.worker.reconcile(NEW)
        normal = self.bls(OLD).read_bytes()
        (self.root / f"boot/vmlinuz-{OLD}").unlink()
        self.worker.reconcile(NEW)
        self.assertFalse((self.root / f"boot/loader/entries/{old['entry']}.conf").exists())
        self.assertEqual(self.bls(OLD).read_bytes(), normal)
        self.assertTrue((self.root / f"boot/loader/entries/{new['entry']}.conf").exists())

    @unittest.skipUnless(os.geteuid() == 0, 'command paths are checked for root ownership')
    def test_real_runner_has_clean_environment_and_never_invokes_shell(self):
        from unittest.mock import patch, MagicMock
        import subprocess
        from nvidia_vbios.lifecycle.system import SystemOperations
        operations = SystemOperations.__new__(SystemOperations)
        operations.log = None
        process = MagicMock(pid=12345, returncode=0)
        process.communicate.return_value = (b"ok", b"")
        with patch("nvidia_vbios.lifecycle.system.subprocess.Popen", return_value=process) as run:
            result = operations._run(["make", "modules", "KERNEL_UNAME=" + NEW], timeout=42)
        self.assertEqual(result.returncode, 0)
        args, kwargs = run.call_args
        self.assertEqual(args[0][0], "/usr/bin/make")
        self.assertFalse(kwargs.get("shell", False))
        self.assertEqual(kwargs["env"], {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C", "LC_ALL": "C"})
        self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(kwargs["start_new_session"])
        process.communicate.assert_called_once_with(timeout=42)

    def test_driver_only_update_accepts_stock_dracut_change_and_builds_exact_new_version(self):
        first = self.worker.reconcile(NEW)
        self.ops.version = "615.78.08"
        source = self.root / "var/lib/nvidia-vbios/sources/615.78.08"
        atomic_write(source / "version.mk", self.ops.version.encode())
        atomic_write(source / "Makefile", b"reviewed new driver build script")
        self.config["sources"].append({"version": self.ops.version, "path": "/var/lib/nvidia-vbios/sources/615.78.08",
             "source_hashes": {"version.mk": digest(self.ops.version.encode())},
             "tree_sha256": source_tree_hash(source, self.root), "p2p_preferred": True})
        self.write_config()
        atomic_write(self.root / f"boot/initramfs-{NEW}.img", b"LEGITIMATE STOCK DRACUT DRIVER UPDATE")
        self.ops.environment["saved_entry"] = "normal-" + NEW
        queue_event("add", NEW, self.root, self.ops)
        second = self.worker.reconcile(NEW)
        self.assertEqual(second["driver"], "615.78.08")
        self.assertNotEqual(first["entry"], second["entry"])
        self.assertEqual(self.ops.loaded_version, VERSION)
        self.assertEqual(self.ops.environment["saved_entry"], second["entry"])
        self.assertTrue((self.root / f"boot/loader/entries/{first['entry']}.conf").exists())

    def test_preexisting_unmanaged_boot_artifact_is_preserved(self):
        plan = self.worker.dry_run(NEW)
        image = self.root / "boot" / plan["image"]
        atomic_write(image, b"UNMANAGED EXISTING IMAGE")
        with self.assertRaisesRegex(LifecycleError, "adoption required"):
            self.worker.reconcile(NEW)
        self.assertEqual(image.read_bytes(), b"UNMANAGED EXISTING IMAGE")
        self.assertFalse(list((self.root / f"usr/lib/modules/{NEW}").rglob("*.ko")))

    def test_missing_normal_image_after_stock_failure_still_retains_ready_default(self):
        first = self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        (self.root / f"boot/initramfs-{NEW}.img").unlink()
        self.ops.environment["saved_entry"] = "normal-" + NEXT
        with self.assertRaises(LifecycleError):
            self.worker.reconcile(NEXT)
        self.assertEqual(self.ops.environment["saved_entry"], first["entry"])

    @unittest.skipUnless(os.geteuid() == 0, 'command paths are checked for root ownership')
    def test_command_timeout_stops_process_group_and_records_failure(self):
        from unittest.mock import patch, MagicMock
        import signal
        import subprocess
        from nvidia_vbios.lifecycle.system import SystemOperations
        operations = SystemOperations.__new__(SystemOperations)
        operations.log = self.root / "commands.log"
        process = MagicMock(pid=12345, returncode=-15)
        process.communicate.side_effect = [subprocess.TimeoutExpired(["make"], 42), (b"", b"")]
        from nvidia_vbios.lifecycle.security import checked_path
        def check_test_path(path, **kwargs):
            boundary = self.root if Path(path).is_relative_to(self.root) else Path("/")
            return checked_path(path, boundary, **kwargs)
        with patch("nvidia_vbios.lifecycle.system.checked_path", side_effect=check_test_path), \
             patch("nvidia_vbios.lifecycle.system.subprocess.Popen", return_value=process), \
             patch("nvidia_vbios.lifecycle.system.os.killpg") as kill:
            with self.assertRaisesRegex(LifecycleError, "process group stopped"):
                operations._run(["make", "modules"], timeout=42)
        self.assertEqual(kill.call_args_list[0].args, (12345, signal.SIGTERM))
        self.assertEqual(kill.call_args_list[-1].args, (12345, signal.SIGKILL))
        log = operations.log.read_text()
        self.assertIn("COMMAND_PID 12345", log)
        self.assertIn("COMMAND_FAILED timeout", log)

    def seed_legacy(self):
        legacy = "7ca123456789abcdef-" + OLD + "-vbios-test-abc123def456"
        image = f"/boot/initramfs-{OLD}-vbios-test-abc123def456.img"
        original = self.bls(OLD).read_bytes()
        entry = self.root / f"boot/loader/entries/{legacy}.conf"
        atomic_write(entry, original.replace(f"/initramfs-{OLD}.img".encode(), ("/" + Path(image).name).encode()))
        atomic_write(self.root / image.lstrip("/"), b"LEGACY KNOWN WORKING IMAGE")
        files = ["/" + str(entry.relative_to(self.root)), image, f"/boot/vmlinuz-{OLD}"]
        self.config["seed_previous_ready"] = {"entry": legacy, "kernel": OLD, "version": VERSION,
            "boot_files": [{"path": name, "sha256": digest((self.root / name.lstrip("/")).read_bytes())} for name in files]}
        self.write_config()
        self.ops.environment["saved_entry"] = legacy
        return legacy, entry, self.root / image.lstrip("/")

    def test_legacy_selected_seed_and_adopted_module_survive_failure_then_publish(self):
        legacy, entry, image = self.seed_legacy()
        old_entry, old_image = entry.read_bytes(), image.read_bytes()
        module = self.root / f"usr/lib/modules/{OLD}/updates/vbios-override/nvidia.ko"
        atomic_write(module, b"LEGACY PATCHED MODULE")
        self.config["adopt_existing"] = {"/" + str(module.relative_to(self.root)): digest(module.read_bytes())}
        self.write_config()
        self.ops.fault = "dracut"
        with self.assertRaises(LifecycleError):
            self.worker.reconcile(OLD)
        self.assertEqual(self.ops.environment["saved_entry"], legacy)
        self.assertEqual(module.read_bytes(), b"LEGACY PATCHED MODULE")
        self.assertEqual(entry.read_bytes(), old_entry)
        self.assertEqual(image.read_bytes(), old_image)
        self.ops.fault = None
        ready = self.worker.reconcile(OLD)
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])
        self.assertEqual(entry.read_bytes(), old_entry)
        self.assertEqual(image.read_bytes(), old_image)

    def test_legacy_seed_requires_exact_protected_bytes(self):
        legacy, _, image = self.seed_legacy()
        atomic_write(image, b"EXTERNALLY MODIFIED LEGACY IMAGE")
        with self.assertRaisesRegex(LifecycleError, "last ready boot artifact changed"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.environment["saved_entry"], legacy)
        self.assertEqual(self.ops.builds, 0)

    def test_foreign_or_same_kernel_normal_default_is_preserved(self):
        ready = self.worker.reconcile(NEW)
        for entry in ("windows-other-os", "unrelated-user-choice", "normal-" + NEW, "normal-" + OLD):
            self.ops.environment["saved_entry"] = entry
            with self.assertRaisesRegex(LifecycleError, "foreign or unrelated"):
                self.worker.reconcile(NEW)
            self.assertEqual(self.ops.environment["saved_entry"], entry)
        self.assertEqual(self.ops.builds, 1)
        self.ops.environment["saved_entry"] = ready["entry"]

    def test_tuned_bls_preserves_options_and_supplement_without_registry_arguments(self):
        base = self.bls(NEW)
        content = base.read_bytes().replace(f"/initramfs-{NEW}.img\n".encode(), f"/initramfs-{NEW}.img $tuned_initrd\n".encode()).replace(b"ro quiet", b"ro quiet $tuned_params")
        atomic_write(base, content)
        ready = self.worker.reconcile(NEW)
        managed = (self.root / f"boot/loader/entries/{ready['entry']}.conf").read_text()
        self.assertIn(".img $tuned_initrd", managed)
        self.assertIn("options root=UUID=test ro quiet $tuned_params", managed)
        self.assertNotIn("NVreg_", managed)
        self.assertEqual(base.read_bytes(), content)

    def test_reviewed_supplemental_image_preserves_order_and_unreviewed_is_blocked(self):
        from nvidia_vbios.lifecycle import managed_bls, parse_bls
        content = self.bls(NEW).read_bytes().replace(b"initrd /", b"initrd /intel-ucode.img /")
        with self.assertRaisesRegex(LifecycleError, "unreviewed supplemental"):
            parse_bls(content, NEW)
        converted = managed_bls(content, NEW, "override.img", supplemental_initrd=["/intel-ucode.img", "$tuned_initrd"])
        self.assertIn(b"initrd /intel-ucode.img /override.img", converted)
        for unsafe in ("$unreviewed", "$(bad)", "/../evil.img"):
            bad = self.bls(NEW).read_bytes().replace(f"/initramfs-{NEW}.img".encode(), f"/initramfs-{NEW}.img {unsafe}".encode())
            with self.assertRaises(LifecycleError):
                parse_bls(bad, NEW)

    def test_activation_uses_exact_typed_kmod_values_and_force_bytes(self):
        import shlex
        from nvidia_vbios.lifecycle.engine import FORCE_BYTES, FORCE_PATH, ACTIVATION_PATH, typed_parameters
        ready = self.worker.reconcile(NEW)
        image_name = next(record["path"] for record in ready["deployment"] if record["path"].startswith("/boot/initramfs-"))
        image = self.root / image_name.lstrip("/")
        configuration = self.ops.extract(image, ACTIVATION_PATH).decode()
        words = shlex.split(next(line for line in configuration.splitlines() if line.startswith("options ")))
        observed = dict(word.split("=", 1) for word in words[2:])
        expected = typed_parameters(self.config["devices"], VERSION)
        self.assertEqual(observed, expected)
        self.assertEqual(observed["NVreg_RegistryDwords"], "RmLinuxVbiosOverrideDisable=0")
        self.assertIn("RmLinuxVbiosOverrideSize=" + str(self.config["devices"][0]["size"]), observed["NVreg_RegistryDwordsPerDevice"])
        self.assertEqual(self.ops.extract(image, FORCE_PATH), FORCE_BYTES)
        self.assertFalse((self.root / "etc/modprobe.d/zz-vbios-override-test.conf").exists())
        self.assertLess(self.ops.events.index("akmods:" + NEW), self.ops.events.index("dracut"))

    def test_force_or_activation_corruption_blocks_before_boot_selection(self):
        from nvidia_vbios.lifecycle.engine import FORCE_PATH, ACTIVATION_PATH
        for member in (FORCE_PATH, ACTIVATION_PATH):
            original = self.ops.extract
            def damaged(image, name, member=member, original=original):
                return b"CORRUPTED" if name == member else original(image, name)
            self.ops.extract = damaged
            with self.assertRaisesRegex(LifecycleError, "exact"):
                self.worker.reconcile(NEW)
            self.assertEqual(self.ops.environment["saved_entry"], "normal-" + OLD)
            self.assertFalse(list((self.root / "boot/loader/entries").glob("vbios-*")))
            self.ops.extract = original

    def test_boot_and_field_evidence_are_independent_and_unverified_enrollment_is_allowed(self):
        device = self.config["devices"][0]
        device.pop("runtime_tested")
        device["evidence"] = {"boot": "verified", "application": "partially-applied",
            "fields": {"power_w": {"requested": 90, "observed": 70, "state": "not-applied"},
                       "memory_mhz": {"requested": 1100, "observed": 1100, "state": "applied"}}}
        self.write_config()
        ready = self.worker.reconcile(NEW)
        self.assertEqual(ready["boot_verification"], "unverified")
        self.assertEqual(ready["application_verification"], "unverified")
        self.assertEqual(ready["enrollment_evidence"][device["bdf"]], device["evidence"])
        self.assertFalse(ready["runtime_tested"])

    def test_ready_gate_and_disable_do_not_fabricate_verification_or_remove_files(self):
        ready = self.worker.reconcile(NEW)
        self.assertEqual(self.worker.ready_status(NEW), ready)
        self.config["enabled"] = False
        self.write_config()
        files = {record["path"]: (self.root / record["path"].lstrip("/")).read_bytes() for record in ready["deployment"]}
        report = self.worker.restore_normal_default()
        self.assertEqual(report, {"state": "normal", "entry": "normal-" + NEW})
        for name, data in files.items():
            self.assertEqual((self.root / name.lstrip("/")).read_bytes(), data)
        self.ops.environment["saved_entry"] = "another-OS"
        self.assertEqual(self.worker.restore_normal_default()["state"], "preserved")
        self.assertEqual(self.ops.environment["saved_entry"], "another-OS")

    def test_disable_preserves_one_time_and_refuses_modified_normal_image(self):
        ready = self.worker.reconcile(NEW)
        self.ops.environment["next_entry"] = "foreign-one-time"
        self.assertEqual(self.worker.restore_normal_default()["state"], "preserved")
        self.assertEqual(self.ops.environment["next_entry"], "foreign-one-time")
        self.ops.environment.pop("next_entry")
        atomic_write(self.root / f"boot/initramfs-{NEW}.img", b"UNREVIEWED NORMAL CHANGE")
        with self.assertRaisesRegex(LifecycleError, "normal recovery bytes changed"):
            self.worker.restore_normal_default()
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])

    def test_ready_gate_refuses_stale_profile_or_changed_module(self):
        self.worker.reconcile(NEW)
        self.config["jobs"] = 3
        self.write_config()
        with self.assertRaisesRegex(LifecycleError, "current profile"):
            self.worker.ready_status(NEW)
        self.config["jobs"] = 2
        self.write_config()
        atomic_write(self.root / f"usr/lib/modules/{NEW}/updates/vbios-override/nvidia.ko", b"CHANGED")
        with self.assertRaisesRegex(LifecycleError, "artifact changed"):
            self.worker.ready_status(NEW)

    def test_disabled_profile_kernel_event_is_a_noop(self):
        self.config["enabled"] = False
        self.write_config()
        self.assertEqual(queue_event("add", NEXT, self.root, self.ops), {"state": "disabled"})
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + OLD)
        self.assertFalse((self.root / STATE.lstrip("/") / "pending").exists())

    def test_other_linux_normal_entry_with_different_installation_id_is_preserved(self):
        self.worker.reconcile(NEW)
        self.add_kernel(NEXT)
        foreign = self.root / f"boot/loader/entries/foreign-os-{NEXT}.conf"
        atomic_write(foreign, self.bls(NEXT).read_bytes())
        self.ops.environment["saved_entry"] = foreign.stem
        with self.assertRaisesRegex(LifecycleError, "foreign or unrelated"):
            self.worker.reconcile(NEXT)
        self.assertEqual(self.ops.environment["saved_entry"], foreign.stem)
        self.assertEqual(self.ops.builds, 1)

    def test_same_generation_repair_nonce_is_owned_before_default_or_fleet_failure(self):
        from unittest.mock import patch
        from nvidia_vbios.lifecycle import engine
        for failure in ("default", "fleet"):
            with self.subTest(failure=failure):
                fixture = LifecycleTests(methodName="runTest")
                fixture.setUp()
                try:
                    ready = fixture.worker.reconcile(NEW)
                    previous_bls = fixture.root / f"boot/loader/entries/{ready['entry']}.conf"
                    image_name = next(record["path"] for record in ready["deployment"] if record["path"].startswith("/boot/initramfs-"))
                    previous_image = fixture.root / image_name.lstrip("/")
                    before = previous_bls.read_bytes(), previous_image.read_bytes()
                    # Force an actual same-generation repair, not a cached audit.
                    (fixture.root / f"usr/lib/modules/{NEW}/updates/vbios-override/nvidia-uvm.ko").unlink()
                    write = engine.json_write
                    def fail_before_commit(path, value):
                        if failure == "fleet" and path.name == "fleet.json":
                            raise OSError("fleet write failed before commit")
                        write(path, value)
                    if failure == "default":
                        fixture.ops.fault = "default"
                    with patch("nvidia_vbios.lifecycle.engine.json_write", side_effect=fail_before_commit):
                        with self.assertRaises(LifecycleError):
                            fixture.worker.reconcile(NEW)
                    self.assertEqual(fixture.ops.environment["saved_entry"], ready["entry"])
                    self.assertEqual((previous_bls.read_bytes(), previous_image.read_bytes()), before)
                    self.assertIsNone(fixture.status()["rollback_error"])
                    transaction = json.loads((fixture.root / STATE.lstrip("/") / "transaction.json").read_text())
                    self.assertNotEqual(transaction["entry"], ready["entry"])
                    self.assertEqual(transaction["phase"], "rolled-back")
                    self.assertFalse((fixture.root / f"boot/loader/entries/{transaction['entry']}.conf").exists())
                finally:
                    fixture.doCleanups()

    def test_legacy_runtime_tested_means_boot_only_and_never_field_acceptance(self):
        from nvidia_vbios.lifecycle import device_evidence
        device = self.config["devices"][0]
        observed = device_evidence(device)
        self.assertEqual(observed["boot"], "verified")
        self.assertEqual(observed["application"], "unverified")
        self.assertEqual(observed["fields"], {})
        device["runtime_tested"] = False
        self.assertEqual(device_evidence(device)["boot"], "unverified")
        self.assertEqual(self.worker.reconcile(NEW)["state"], "ready")

    def test_real_tuned_and_all_reviewed_option_variable_values_are_validated(self):
        for variable in ("kernelopts", "tuned_params", "site_params"):
            self.config["bls"] = {"option_variables": ["kernelopts", "tuned_params", "site_params"]}
            self.write_config()
            for bad in ("nvidia.NVreg_RegistryDwords=RmLinuxVbiosOverride=2", "quiet; unsafe", "$(bad)", "bad\nvalue", "$unreviewed"):
                self.ops.environment[variable] = bad
                with self.assertRaisesRegex(LifecycleError, variable):
                    self.worker.reconcile(NEW)
                self.assertEqual(self.ops.environment["saved_entry"], "normal-" + OLD)
                self.assertEqual(self.ops.builds, 0)
            self.ops.environment.pop(variable)
        self.ops.environment["tuned_params"] = "transparent_hugepage=never intel_pstate=active"
        self.assertEqual(self.worker.reconcile(NEW)["state"], "ready")

    def test_tuned_variable_injection_during_build_cannot_be_committed(self):
        self.ops.after_initramfs = lambda: self.ops.environment.update(tuned_params="nvidia.NVreg_RegistryDwords=RmLinuxVbiosOverride=2")
        with self.assertRaisesRegex(LifecycleError, "tuned_params.*activation"):
            self.worker.reconcile(NEW)
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + OLD)
        self.assertIsNone(self.status()["rollback_error"])

    def test_bootstrap_disable_can_hold_one_lock_across_config_change_and_restore(self):
        from nvidia_vbios.lifecycle.security import locked
        self.worker.reconcile(NEW)
        with locked(self.root / STATE.lstrip("/") / "reconcile.lock", self.root):
            self.config["enabled"] = False
            self.write_config()
            self.assertEqual(self.worker._restore_normal_default_locked(), {"state": "normal", "entry": "normal-" + NEW})

    def test_busy_reconcile_lock_never_overwrites_other_owners_status_or_journal(self):
        from nvidia_vbios.lifecycle.security import locked
        self.worker.reconcile(NEW)
        state = self.root / STATE.lstrip("/")
        status = state / f"status-{NEW}.json"
        transaction = state / "transaction.json"
        before = status.read_bytes(), transaction.read_bytes()
        with locked(state / "reconcile.lock", self.root):
            with self.assertRaisesRegex(LifecycleError, "lock busy"):
                self.worker.reconcile(NEW)
            self.assertEqual((status.read_bytes(), transaction.read_bytes()), before)
        self.assertEqual(self.ops.builds, 1)

    def test_restore_normal_validates_real_tuned_options_before_success_or_selection(self):
        ready = self.worker.reconcile(NEW)
        self.ops.environment["tuned_params"] = "nvidia.NVreg_RegistryDwords=RmLinuxVbiosOverride=2"
        with self.assertRaisesRegex(LifecycleError, "tuned_params.*activation"):
            self.worker.restore_normal_default()
        self.assertEqual(self.ops.environment["saved_entry"], ready["entry"])
        self.ops.environment["saved_entry"] = "normal-" + NEW
        with self.assertRaisesRegex(LifecycleError, "tuned_params.*activation"):
            self.worker.restore_normal_default()
        self.assertEqual(self.ops.environment["saved_entry"], "normal-" + NEW)

    def test_disabled_reconcile_preserves_committed_readiness_for_later_resume(self):
        self.worker.reconcile(NEW)
        state = self.root / STATE.lstrip("/")
        status, journal = state / f"status-{NEW}.json", state / "transaction.json"
        before = status.read_bytes(), journal.read_bytes()
        self.config["enabled"] = False
        self.write_config()
        with self.assertRaisesRegex(LifecycleError, "disabled.*readiness preserved"):
            self.worker.reconcile(NEW)
        self.assertEqual((status.read_bytes(), journal.read_bytes()), before)
        self.config["enabled"] = True
        self.write_config()
        self.assertEqual(self.worker.ready_status(NEW)["state"], "ready")
        self.assertEqual(self.ops.builds, 1)

    def test_each_typed_string_accepts_4094_and_rejects_4095_including_preserved_extras(self):
        from nvidia_vbios.lifecycle.engine import typed_parameters
        prefixes = {"NVreg_RegistryDwords": "Extra=",
                    "NVreg_RegistryDwordsPerDevice": "pci=0000:04:00.0;Extra=",
                    "NVreg_RegistryBinaryFilePerDevice": "pci=0000:04:00.0;OtherFile="}
        for name, prefix in prefixes.items():
            with self.subTest(parameter=name):
                base = typed_parameters(self.config["devices"], VERSION, {name: prefix + "x"})[name]
                count = 4094 - len(base.encode("utf-8")) + 1
                preserved = {name: prefix + "x" * count}
                actual = typed_parameters(self.config["devices"], VERSION, preserved)
                self.assertEqual(len(actual[name].encode("utf-8")), 4094)
                preserved[name] += "x"
                with self.assertRaisesRegex(LifecycleError, name + ".*4095.*4094"):
                    typed_parameters(self.config["devices"], VERSION, preserved)
                self.config["parameters"] = preserved
                self.write_config()
                with self.assertRaisesRegex(LifecycleError, name + ".*4095.*4094"):
                    self.worker.reconcile(NEW)
                self.assertEqual(self.ops.builds, 0)
                self.assertFalse(list((self.root / "usr/lib/modules").rglob("*.ko")))
                self.assertFalse(list((self.root / "boot/loader/entries").glob("vbios-*")))

    def test_parameter_limit_measures_bytes_not_unicode_codepoints(self):
        from nvidia_vbios.lifecycle.engine import _validate_parameter_lengths
        _validate_parameter_lengths({"Example": "é" * 2047})
        with self.assertRaisesRegex(LifecycleError, "4095.*4094"):
            _validate_parameter_lengths({"Example": "é" * 2047 + "x"})

    def test_eight_gpu_short_paths_fit_and_full_hash_integrity_still_applies(self):
        import shlex
        from nvidia_vbios.lifecycle.engine import firmware_filename, typed_parameters, ACTIVATION_PATH
        sample = self.config["devices"][0]
        self.config["devices"] = [dict(sample, bdf=f"0000:{index+3:02x}:00.0",
            uuid=f"GPU-00000000-0000-0000-0000-{index+1:012x}") for index in range(8)]
        self.write_config()
        expected = typed_parameters(self.config["devices"], VERSION)
        self.assertEqual(len(expected["NVreg_RegistryBinaryFilePerDevice"].encode()), 815)
        self.assertTrue(all(len(value.encode()) <= 1024 for value in expected.values()))
        ready = self.worker.reconcile(NEW)
        self.assertEqual(ready["activation_generation"], 4)
        self.assertEqual(ready["module_parameters"], expected)
        image_name = next(record["path"] for record in ready["deployment"] if record["path"].startswith("/boot/initramfs-"))
        image = self.root / image_name.lstrip("/")
        line = next(line for line in self.ops.extract(image, ACTIVATION_PATH).decode().splitlines() if line.startswith("options "))
        observed = dict(word.split("=", 1) for word in shlex.split(line)[2:])
        self.assertEqual(observed, expected)
        firmware = [record for record in ready["deployment"] if record["path"].startswith("/usr/lib/firmware/")]
        self.assertEqual(len(firmware), 8)
        for device in self.config["devices"]:
            filename = firmware_filename(device)
            self.assertEqual(filename, f"{device['bdf']}-{device['sha256'][:16]}.bin")
            relative = f"nvidia/{VERSION}/vbios-override/{filename}"
            record = next(record for record in firmware if record["path"].endswith("/" + filename))
            payload = self.ops.extract(image, "usr/lib/firmware/" + relative)
            self.assertEqual(digest(payload), device["sha256"])
            self.assertEqual(record["after_sha256"], device["sha256"])
            self.assertEqual(len(record["after_sha256"]), 64)
            self.assertIn(f"RmLinuxVbiosOverrideImage={VERSION}/vbios-override/{filename}", observed["NVreg_RegistryBinaryFilePerDevice"])

    def test_v3_invalidates_old_generation_without_removing_long_named_fallback_files(self):
        from unittest.mock import patch
        from nvidia_vbios.lifecycle import engine
        short_name = engine.firmware_filename
        with patch.object(engine, "ACTIVATION_GENERATION", 2), \
             patch.object(engine, "firmware_filename", side_effect=lambda device: f"{device['bdf']}-{device['sha256']}.bin"):
            old = self.worker.reconcile(NEW)
        previous = {record["path"]: (self.root / record["path"].lstrip("/")).read_bytes()
                    for record in old["deployment"] if record["path"].startswith(("/boot/", "/usr/lib/firmware/"))}
        with self.assertRaisesRegex(LifecycleError, "current profile"):
            self.worker.ready_status(NEW)
        plan = self.worker.dry_run(NEW)
        self.assertNotEqual(plan["generation_sha256"], old["generation_sha256"])
        new = self.worker.reconcile(NEW)
        self.assertEqual(self.ops.builds, 2)
        self.assertNotEqual(new["entry"], old["entry"])
        self.assertEqual(new["activation_generation"], 4)
        for name, data in previous.items():
            self.assertEqual((self.root / name.lstrip("/")).read_bytes(), data)
        self.assertTrue(any(record["path"].endswith("/" + short_name(self.config["devices"][0])) for record in new["deployment"]))

    def test_17_and_32_distinct_payload_assignments_survive_long_activation(self):
        from nvidia_vbios.lifecycle.engine import typed_parameters, firmware_filename, ACTIVATION_PATH
        import shlex
        sample = self.config["devices"][0]
        for count in (17, 32):
            with self.subTest(count=count):
                devices = []
                for index in range(count):
                    payload = b"REVIEWED ROM unique board " + str(index).encode()
                    path = f"/var/lib/nvidia-vbios/roms/board-{index}.bin"
                    atomic_write(self.root / path.lstrip("/"), payload)
                    devices.append(dict(sample, bdf=f"0000:{index+3:02x}:00.0",
                        uuid=f"GPU-00000000-0000-0000-0000-{index+1:012x}",
                        payload_path=path, sha256=digest(payload), source_sha256=digest(payload), size=len(payload)))
                self.config["devices"] = devices
                self.write_config()
                expected = typed_parameters(devices, VERSION)
                self.assertGreater(len(expected["NVreg_RegistryBinaryFilePerDevice"]), 1024)
                ready = self.worker.reconcile(NEW)
                image_record = next(r for r in ready["deployment"] if r["path"].startswith("/boot/initramfs-"))
                image = self.root / image_record["path"].lstrip("/")
                line = self.ops.extract(image, ACTIVATION_PATH).decode().splitlines()[1]
                self.assertEqual(dict(word.split("=", 1) for word in shlex.split(line)[2:]), expected)
                self.assertEqual(ready["module_parameters"], expected)
                for device in devices:
                    member = f"usr/lib/firmware/nvidia/{VERSION}/vbios-override/{firmware_filename(device)}"
                    self.assertEqual(digest(self.ops.extract(image, member)), device["sha256"])
                self.assertNotIn(b"NVreg_Registry", self.bls(NEW).read_bytes())

    def test_old_capacity_marker_is_refused_before_publication(self):
        from unittest.mock import patch
        prepare = self.ops.prepare_source
        def old_manifest(*args):
            result = prepare(*args)
            result["module_metadata"].pop("vbios_override_param_bytes")
            return result
        with patch.object(self.ops, "prepare_source", old_manifest):
            with self.assertRaisesRegex(LifecycleError, "manifest"):
                self.worker.reconcile(NEW)
        self.assertEqual(self.ops.builds, 0)
        self.ops.fault = "vbios_override_param_bytes"
        with self.assertRaisesRegex(LifecycleError, "string-capacity"):
            self.worker.reconcile(NEW)
        self.assertFalse(list((self.root / "boot/loader/entries").glob("vbios-*")))

    def test_old_capacity_module_is_refused_by_ready_and_reuse_checks(self):
        from unittest.mock import patch
        self.worker.reconcile(NEW)
        modinfo = self.ops.modinfo
        def old_module(path):
            details = modinfo(path)
            details.pop("vbios_override_param_bytes", None)
            return details
        with patch.object(self.ops, "modinfo", old_module):
            with self.assertRaisesRegex(LifecycleError, "string-capacity"):
                self.worker.ready_status(NEW)
            with self.assertRaisesRegex(LifecycleError, "string-capacity"):
                self.worker.reconcile(NEW)
        self.assertEqual(self.ops.builds, 1)

    def test_v4_invalidates_v3_with_unchanged_profile_and_activation_bytes(self):
        from unittest.mock import patch
        from nvidia_vbios.lifecycle import engine
        with patch.object(engine, "ACTIVATION_GENERATION", 3):
            old = self.worker.reconcile(NEW)
        with self.assertRaisesRegex(LifecycleError, "current profile"):
            self.worker.ready_status(NEW)
        new = self.worker.reconcile(NEW)
        self.assertEqual(new["activation_config_sha256"], old["activation_config_sha256"])
        self.assertNotEqual(new["generation_sha256"], old["generation_sha256"])
        self.assertEqual(self.ops.builds, 2)

    def test_queue_and_numeric_kernel_selection(self):
        queue_event("add", NEW, self.root)
        queue_event("remove", OLD, self.root)
        self.assertEqual(installed_kernels(self.root)[-1], NEW)
        self.assertGreater(kernel_key("6.20.1"), kernel_key("6.19.100"))
        self.assertEqual(self.ops.builds, 0)
        self.assertEqual(len(list((self.root / STATE.lstrip("/") / "pending").glob("*.json"))), 2)

    def test_alternate_root_cannot_accidentally_execute_host_commands(self):
        with self.assertRaisesRegex(LifecycleError, "injected operations"):
            Reconciler(self.root)


if __name__ == "__main__":
    unittest.main()
