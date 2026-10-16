"""Manual userspace and update-ordering regressions use synthetic ELF/library files."""
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import MagicMock, patch

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "tests"))
import test_lifecycle as fixtures
from nvidia_vbios.lifecycle import LifecycleError
from nvidia_vbios.lifecycle.security import atomic_write, locked
from nvidia_vbios.lifecycle.system import SystemOperations


class ManualProviderTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.LifecycleTests(methodName="runTest")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.operations = SystemOperations.__new__(SystemOperations)
        self.operations.filesystem_root = self.root
        self.operations.log = None
        self.version = "615.78.08"
        self.smi_version = self.version
        self.packages = ""
        self.owned = set()
        self.repo_files = ["/var/nvidia-driver-local-repo-fedora41-570.158.01",
                           "/var/nvidia-driver-local-repo-fedora41-570.158.01/nvidia-driver-570.158.01.rpm",
                           "/etc/yum.repos.d/nvidia-driver-local-fedora41-570.158.01.repo"]
        self.provider = {"provider": "manual", "nvidia_smi": "/usr/bin/nvidia-smi",
                         "libraries": ["/usr/lib64/libnvidia-ml.so.1", "/usr/lib64/libcuda.so.1"]}
        self.config = {"userspace": self.provider}
        atomic_write(self.root / "usr/bin/nvidia-smi", b"\x7fELFtrusted-smi", 0o755)
        self.library("libnvidia-ml", self.version)
        self.library("libcuda", self.version)
        self.operations._run = MagicMock(side_effect=self.command)

    def library(self, stem, version):
        directory = self.root / "usr/lib64"
        target = directory / f"{stem}.so.{version}"
        atomic_write(target, b"\x7fELFtrusted-library", 0o644)
        alias = directory / (stem + ".so.1")
        alias.unlink(missing_ok=True)
        alias.symlink_to(target.name)
        return target, alias

    def command(self, command, **kwargs):
        if command[0] == "rpm" and "-qa" in command:
            return subprocess.CompletedProcess(command, 0, stdout=self.packages.encode(), stderr=b"")
        if command[0] == "rpm" and "-ql" in command:
            return subprocess.CompletedProcess(command, 0, stdout=("\n".join(self.repo_files) + "\n").encode(), stderr=b"")
        if command[0] == "rpm" and "-qf" in command:
            owned = str(command[-1]) in self.owned
            return subprocess.CompletedProcess(command, 0 if owned else 1,
                stdout=(self.version + "\n").encode() if owned else b"not owned", stderr=b"")
        if str(command[0]).endswith("/nvidia-smi") and command[1:] == ["--version"]:
            text = (f"NVIDIA-SMI version  : {self.smi_version}\nNVML version       : 615.78\n"
                    "KMD version        : 615.71.09\n")
            return subprocess.CompletedProcess(command, 0, stdout=text.encode(), stderr=b"")
        raise AssertionError(f"unexpected production operation: {command}")

    def test_manual_installed_version_ignores_still_loaded_old_kmd(self):
        self.assertEqual(self.operations.installed_version(self.config), "615.78.08")

    def test_real_nvml_mismatch_uses_exact_help_version_without_kmd_inference(self):
        original=self.command
        def mismatch(command, **kwargs):
            if str(command[0]).endswith('/nvidia-smi'):
                if command[1:]==['--version']:
                    return subprocess.CompletedProcess(command,18,stdout=b'Failed to initialize NVML: Driver/library version mismatch\nNVML library version: 615.78\n',stderr=b'')
                if command[1:]==['--help']:
                    return subprocess.CompletedProcess(command,0,stdout=b'NVIDIA System Management Interface -- v615.78.08\n\nUsage details\n',stderr=b'')
            return original(command,**kwargs)
        self.operations._run.side_effect=mismatch
        self.assertEqual(self.operations.installed_version(self.config),'615.78.08')

    def test_help_fallback_rejects_partial_conflicting_duplicate_or_failed_headers(self):
        original=self.command
        responses=[(0,b'NVIDIA System Management Interface -- v615.78\n'),
                   (0,b'NVIDIA System Management Interface -- v615.71.09\n'),
                   (0,b'NVIDIA System Management Interface -- v615.78.08\nNVIDIA System Management Interface -- v615.78.08\n'),
                   (0,b'NVIDIA System Management Interface -- v615.78.08\nNVIDIA System Management Interface -- v615.78\n'),
                   (0,b'Error before help\nNVIDIA System Management Interface -- v615.78.08\n'),
                   (1,b'NVIDIA System Management Interface -- v615.78.08\n'),
                   (0,b'')]
        for rc,output in responses:
            def mismatch(command, **kwargs):
                if str(command[0]).endswith('/nvidia-smi'):
                    if command[1:]==['--version']:
                        return subprocess.CompletedProcess(command,18,stdout=b'Failed to initialize NVML: Driver/library version mismatch\nNVML library version: 615.78\n',stderr=b'')
                    if command[1:]==['--help']:
                        return subprocess.CompletedProcess(command,rc,stdout=output,stderr=b'')
                return original(command,**kwargs)
            self.operations._run.side_effect=mismatch
            with self.subTest(rc=rc,output=output),self.assertRaisesRegex(LifecycleError,'full matching version'):
                self.operations.installed_version(self.config)

    def test_failed_explicit_version_report_cannot_be_overridden_by_help(self):
        original=self.command
        for version in ('615.71.09','615.78'):
            def reported(command, **kwargs):
                if str(command[0]).endswith('/nvidia-smi'):
                    self.assertEqual(command[1:],['--version'],'must not conceal explicit version with help')
                    return subprocess.CompletedProcess(command,18,stdout=('NVIDIA-SMI version: '+version+'\n').encode(),stderr=b'')
                return original(command,**kwargs)
            self.operations._run.side_effect=reported
            with self.subTest(version=version),self.assertRaisesRegex(LifecycleError,'full matching version'):
                self.operations.installed_version(self.config)

    def test_missing_or_malformed_primary_report_does_not_hide_behind_help(self):
        original=self.command
        cases=[(0,b'NVML version: 615.78\n',b''),
               (18,b'NVIDIA-SMI version = 615.78.08\n',b''),
               (18,b'NVIDIA-SMI unknown format\n',b''),
               (18,b'',b'nvidia-smi malformed own version\n'),
               (18,b'NVIDIA-SMI version: 615.78.08\nNVIDIA-SMI version: 615.78\n',b''),
               (0,b'NVIDIA-SMI version: 615.78.08\nNVIDIA-SMI version: 615.78.08\n',b'')]
        for rc,out,err in cases:
            def primary(command, **kwargs):
                if str(command[0]).endswith('/nvidia-smi'):
                    self.assertEqual(command[1:],['--version'],'no fallback permitted')
                    return subprocess.CompletedProcess(command,rc,stdout=out,stderr=err)
                return original(command,**kwargs)
            self.operations._run.side_effect=primary
            with self.subTest(rc=rc,out=out,err=err),self.assertRaisesRegex(LifecycleError,'full matching version'):
                self.operations.installed_version(self.config)

    def test_local_repository_metadata_is_not_installed_driver_userspace(self):
        self.packages = "nvidia-driver-local-repo-fedora41-570.158.01 1.0\n"
        self.assertEqual(self.operations.installed_version(self.config), self.version)
        self.repo_files.append("/usr/lib64/libnvidia-ml.so.570.158.01")
        with self.assertRaisesRegex(LifecycleError, "mixed RPM/manual"):
            self.operations.installed_version(self.config)

    def test_metadata_queries_do_not_load_keyring_while_publication_lock_is_held(self):
        self.operations.installed_version(self.config)
        queries = [call.args[0] for call in self.operations._run.call_args_list if call.args[0][0] == "rpm"]
        self.assertTrue(queries)
        self.assertTrue(all("--nosignature" in command for command in queries))

    def test_packaged_templates_match_reviewed_files_and_host_only_errors_are_visible(self):
        import json
        from nvidia_vbios.lifecycle import hook_templates
        from importlib.resources import files
        resource = json.loads(files("nvidia_vbios.lifecycle").joinpath("hook_templates.json").read_text())
        templates = hook_templates()
        self.assertEqual(len(templates), 6)
        for entry in resource["templates"]:
            self.assertEqual(templates[entry["destination"]]["data"], (REPO / "packaging" / entry["source"]).read_bytes())
        action = templates["/etc/dnf/libdnf5-plugins/actions.d/nvidia-vbios.actions"]["data"].decode()
        fields = next(line for line in action.splitlines() if not line.startswith("#")).split(":", 4)
        self.assertEqual(fields[3].split(), ["enabled=host-only", "raise_error=1"])
        self.assertEqual(fields[4], "/usr/libexec/nvidia-vbios lifecycle post-transaction")

    def test_path_watches_only_queue_and_profile_not_its_own_rpm_activity(self):
        from nvidia_vbios.lifecycle import hook_templates
        target = "/usr/lib/systemd/system/nvidia-vbios-reconcile.path"
        text = hook_templates()[target]["data"].decode()
        watched = [line.split("=", 1)[1] for line in text.splitlines() if line.startswith("PathChanged=")]
        self.assertEqual(watched, ["/var/lib/nvidia-vbios/lifecycle/pending", "/etc/nvidia-vbios/lifecycle.json"])
        self.assertNotIn("/usr/lib/sysimage/rpm", text)
        self.assertNotIn("RPM", next(line for line in text.splitlines() if line.startswith("Description=")))
        self.assertEqual(text.encode(), (REPO / "packaging/systemd/nvidia-vbios-reconcile.path").read_bytes())

    def test_reconcile_service_can_update_the_enrollment_in_every_unit_copy(self):
        from nvidia_vbios.lifecycle import hook_templates
        from nvidia_vbios.lifecycle.platform import ARCH_PLATFORM, DEBIAN_PLATFORM, FEDORA_PLATFORM
        from nvidia_vbios.lifecycle.portable_hooks import SERVICE_TARGET, hook_templates_for
        copies = [(REPO / "packaging/systemd/nvidia-vbios-reconcile.service").read_text(),
                  hook_templates()["/usr/lib/systemd/system/nvidia-vbios-reconcile.service"]["data"].decode()]
        copies += [hook_templates_for(platform, {"backend": "grub"})[SERVICE_TARGET]["data"].decode()
                   for platform in (FEDORA_PLATFORM, DEBIAN_PLATFORM, ARCH_PLATFORM)]
        for text in copies:
            paths = next(line for line in text.splitlines() if line.startswith("ReadWritePaths=")).split("=", 1)[1].split()
            self.assertIn("/etc/nvidia-vbios", paths)
            self.assertIn("ProtectSystem=strict", text)

    def test_templates_load_from_a_zip_package_outside_the_checkout(self):
        import json
        import zipfile
        archive = self.root / "package.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            for path in (REPO / "src/nvidia_vbios").rglob("*"):
                if path.is_file() and "__pycache__" not in path.parts:
                    zipped.write(path, path.relative_to(REPO / "src"))
        code = ("import sys,json; sys.path.insert(0,sys.argv[1]); "
                "from nvidia_vbios.lifecycle import hook_templates; "
                "print(json.dumps({name:record['data'].decode() for name,record in hook_templates().items()}))")
        result = subprocess.run([sys.executable, "-I", "-c", code, str(archive)], cwd=self.root,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20, check=True)
        data = json.loads(result.stdout)
        self.assertEqual(len(data), 6)
        self.assertIn("enabled=host-only raise_error=1", data["/etc/dnf/libdnf5-plugins/actions.d/nvidia-vbios.actions"])

    def test_candidate_template_bytes_can_be_used_without_executing_candidate_code(self):
        from nvidia_vbios.lifecycle import hook_templates
        candidate = (REPO / "src/nvidia_vbios/lifecycle/hook_templates.json").read_bytes()
        with patch("nvidia_vbios.lifecycle.templates.files", side_effect=AssertionError("candidate bytes are already snapshotted")):
            templates = hook_templates(resource_bytes=candidate)
        self.assertEqual(len(templates), 6)

    def test_fedora_shared_akmods_directory_is_exception_only_for_fixed_lock(self):
        import types
        from nvidia_vbios.lifecycle.security import checked_path
        directory = self.root / "run/akmods"
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o770)
        lock = directory / "akmods.lock"
        atomic_write(lock, b"", 0o644)
        group = types.SimpleNamespace(gr_gid=directory.stat().st_gid, gr_mem=[])
        with patch("nvidia_vbios.lifecycle.security.grp.getgrnam", return_value=group):
            with locked(lock, self.root, akmods=True):
                self.assertEqual(lock.stat().st_mode & 0o777, 0o644)
            with self.assertRaisesRegex(LifecycleError, "untrusted"):
                checked_path(directory, self.root)
            with self.assertRaisesRegex(LifecycleError, "fixed lock path"):
                with locked(directory / "source.c", self.root, akmods=True):
                    pass
        self.assertEqual(directory.stat().st_mode & 0o777, 0o770)

    def test_akmods_exception_rejects_untrusted_group_world_write_and_symlink_leaf(self):
        import types
        directory = self.root / "run/akmods"
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o770)
        lock = directory / "akmods.lock"
        atomic_write(lock, b"", 0o644)
        group = types.SimpleNamespace(gr_gid=directory.stat().st_gid, gr_mem=["unrelated-user"])
        with patch("nvidia_vbios.lifecycle.security.grp.getgrnam", return_value=group):
            with self.assertRaisesRegex(LifecycleError, "untrusted shared group"):
                with locked(lock, self.root, akmods=True):
                    pass
        group.gr_mem = []
        with patch("nvidia_vbios.lifecycle.security.grp.getgrnam", return_value=group):
            directory.chmod(0o777)
            with self.assertRaisesRegex(LifecycleError, "untrusted akmods coordination"):
                with locked(lock, self.root, akmods=True):
                    pass
            directory.chmod(0o770)
            lock.unlink()
            lock.symlink_to(self.root / "usr/bin/nvidia-smi")
            with self.assertRaisesRegex(LifecycleError, "untrusted akmods lock"):
                with locked(lock, self.root, akmods=True):
                    pass

    def test_opened_lock_inode_is_checked_and_never_replaced_by_us(self):
        import os
        directory = self.root / "run/akmods"
        directory.mkdir(parents=True, exist_ok=True)
        lock = directory / "akmods.lock"
        atomic_write(lock, b"original", 0o644)
        original_open = os.open
        def raced(path, flags, mode=0o777, **kwargs):
            fd = original_open(path, flags, mode, **kwargs)
            if Path(path) == lock:
                lock.rename(directory / "external-old-inode")
                atomic_write(lock, b"external replacement", 0o644)
            return fd
        with patch("nvidia_vbios.lifecycle.security.os.open", side_effect=raced):
            with self.assertRaisesRegex(LifecycleError, "inode was replaced"):
                with locked(lock, self.root, akmods=True):
                    pass
        self.assertEqual(lock.read_bytes(), b"external replacement")
        self.assertEqual((directory / "external-old-inode").read_bytes(), b"original")

    def test_library_chain_and_smi_full_versions_must_agree(self):
        self.library("libcuda", "615.71.09")
        with self.assertRaisesRegex(LifecycleError, "mixed full versions"):
            self.operations.installed_version(self.config)
        self.library("libcuda", self.version)
        self.smi_version = "615.71.09"
        with self.assertRaisesRegex(LifecycleError, "full matching version"):
            self.operations.installed_version(self.config)

    def test_partial_library_or_smi_version_is_not_inferred_from_kmd(self):
        self.library("libnvidia-ml", "615.78")
        with self.assertRaisesRegex(LifecycleError, "full versioned ELF"):
            self.operations.installed_version(self.config)
        self.library("libnvidia-ml", self.version)
        self.smi_version = "615.78"
        with self.assertRaisesRegex(LifecycleError, "full matching version"):
            self.operations.installed_version(self.config)

    def test_mixed_rpm_manual_installation_is_not_reinterpreted_even_same_version(self):
        self.owned.add(str(self.root / "usr/bin/nvidia-smi"))
        with self.assertRaisesRegex(LifecycleError, "mixed RPM/manual"):
            self.operations.installed_version(self.config)
        self.owned.clear()
        self.packages = "nvidia-driver-libs 615.78.08\n"
        with self.assertRaisesRegex(LifecycleError, "mixed RPM/manual"):
            self.operations.installed_version(self.config)
        self.packages = ""
        self.owned.add(str(self.root / "usr/lib64/libnvidia-ml.so.1"))
        with self.assertRaisesRegex(LifecycleError, "RPM-owned"):
            self.operations.installed_version(self.config)

    def test_writable_library_parent_and_alias_escape_are_refused(self):
        directory = self.root / "usr/lib64"
        directory.chmod(0o777)
        with self.assertRaisesRegex(LifecycleError, "untrusted"):
            self.operations.installed_version(self.config)
        directory.chmod(0o755)
        alias = directory / "libcuda.so.1"
        alias.unlink()
        alias.symlink_to("../../../../../../outside.so.615.78.08")
        with self.assertRaisesRegex(LifecycleError, "escapes"):
            self.operations.installed_version(self.config)

    def test_non_elf_executable_and_library_are_refused(self):
        target, _ = self.library("libcuda", self.version)
        atomic_write(target, b"untrusted text pretending to be a library")
        with self.assertRaisesRegex(LifecycleError, "ELF"):
            self.operations.installed_version(self.config)
        self.library("libcuda", self.version)
        atomic_write(self.root / "usr/bin/nvidia-smi", b"#!/bin/sh\necho fake-version", 0o755)
        with self.assertRaisesRegex(LifecycleError, "executable ELF"):
            self.operations.installed_version(self.config)

    def test_explicit_rpm_provider_does_not_fall_back_to_manual(self):
        with self.assertRaisesRegex(LifecycleError, "explicit trusted manual provider"):
            self.operations.installed_version({"userspace": {"provider": "rpm"}})
        self.owned.add(str(self.root / "usr/bin/nvidia-smi"))
        self.packages = "nvidia-driver-libs 615.71.09\n"
        with self.assertRaisesRegex(LifecycleError, "mixed NVIDIA userspace RPM"):
            self.operations.installed_version({"userspace": {"provider": "rpm"}})

    def test_dracut_receives_temporary_config_include_and_force_driver(self):
        from nvidia_vbios.lifecycle.engine import ACTIVATION_PATH, FORCE_PATH
        self.operations._run = MagicMock()
        config, force = self.root / "activation.conf", self.root / "force.conf"
        image = self.root / "image.img"
        self.operations.initramfs(fixtures.NEW, image, [], activation_config=config, force_config=force)
        command = self.operations._run.call_args.args[0]
        self.assertEqual(command[command.index("--force-drivers") + 1], "nvidia")
        includes = [(str(command[index + 1]), command[index + 2])
                    for index, word in enumerate(command) if word == "--include"]
        self.assertEqual(includes, [(str(config), "/" + ACTIVATION_PATH), (str(force), "/" + FORCE_PATH)])
        self.assertFalse(any("NVreg_" in str(word) for word in command))

    def test_per_kernel_akmods_completes_outside_our_locks(self):
        worker = self.fixture.worker
        operations = self.fixture.ops
        original = operations.coordinate_akmods
        def coordinate(kernel, config):
            with locked(self.root / "run/akmods/akmods.lock", self.root):
                with locked(self.root / "usr/lib/sysimage/rpm/.rpm.lock", self.root, rpm=True):
                    original(kernel, config)
        operations.coordinate_akmods = coordinate
        self.assertEqual(worker.reconcile(fixtures.NEW)["state"], "ready")
        self.assertLess(operations.events.index("akmods:" + fixtures.NEW), operations.events.index("build"))

    def test_posttransaction_parent_lock_busy_does_not_start_or_wait_for_child_service(self):
        (self.root / "run/systemd/system").mkdir(parents=True)
        def busy(*args, **kwargs):
            raise LifecycleError("parent RPM transaction lock busy; retry later")
        with patch("nvidia_vbios.lifecycle.system.Path", side_effect=lambda value: self.root / str(value).lstrip("/")), \
             patch("nvidia_vbios.lifecycle.system.locked", side_effect=busy):
            with self.assertRaisesRegex(LifecycleError, "parent RPM"):
                self.operations.start_reconcile()
        self.operations._run.assert_not_called()

    def test_synchronous_start_accepts_driver_drift_and_prints_resume_command(self):
        import contextlib
        import io
        from nvidia_vbios.lifecycle.security import json_write
        (self.root / "run/systemd/system").mkdir(parents=True)
        status = {"state": "driver-drift", "marker": "VBIOS_DRIFT", "installed_driver": "615.78.08",
                  "built_driver": "615.71.09", "resume": "nvbios system post-install --source PATH"}
        json_write(self.root / f"var/lib/nvidia-vbios/lifecycle/status-{fixtures.NEW}.json", status)
        self.operations._run = MagicMock(return_value=subprocess.CompletedProcess([], 0, b"", b""))
        stderr = io.StringIO()
        with patch("nvidia_vbios.lifecycle.system.Path", side_effect=lambda value: self.root / str(value).lstrip("/")), \
             patch("nvidia_vbios.lifecycle.system.checked_path"), \
             patch("nvidia_vbios.lifecycle.__main__.installed_kernels", return_value=[fixtures.OLD, fixtures.NEW]), \
             contextlib.redirect_stderr(stderr):
            self.assertEqual(self.operations.start_reconcile(), status)
        self.assertIn("VBIOS_DRIFT: installed NVIDIA 615.78.08", stderr.getvalue())
        self.assertIn("nvbios system post-install --source PATH", stderr.getvalue())
        self.assertNotIn("boots the distribution driver", stderr.getvalue())
        self.assertIn("has no NVIDIA 615.78.08 kernel module", stderr.getvalue())
        self.operations._run.assert_called_once_with(["systemctl", "start", "nvidia-vbios-reconcile.service"], timeout=7200)
        json_write(self.root / f"var/lib/nvidia-vbios/lifecycle/status-{fixtures.NEW}.json", dict(status, boots_normal_driver=True))
        stderr = io.StringIO()
        with patch("nvidia_vbios.lifecycle.system.Path", side_effect=lambda value: self.root / str(value).lstrip("/")), \
             patch("nvidia_vbios.lifecycle.system.checked_path"), \
             patch("nvidia_vbios.lifecycle.__main__.installed_kernels", return_value=[fixtures.OLD, fixtures.NEW]), \
             contextlib.redirect_stderr(stderr):
            self.operations.start_reconcile()
        self.assertIn("the normal entry boots the distribution driver without the override", stderr.getvalue())

    def test_actual_akmods_unit_is_restarted_synchronously(self):
        (self.root / "run/systemd/system").mkdir(parents=True)
        (self.root / "usr/lib/systemd/system").mkdir(parents=True)
        (self.root / "usr/lib/systemd/system/akmods@.service").write_text("[Unit]\n")
        self.operations._run = MagicMock()
        with patch("nvidia_vbios.lifecycle.system.Path", side_effect=lambda value: self.root / str(value).lstrip("/")):
            self.operations.coordinate_akmods(fixtures.NEW, {})
        self.operations._run.assert_called_once_with(["systemctl", "restart", f"akmods@{fixtures.NEW}.service"], timeout=3600)


if __name__ == "__main__":
    unittest.main()
