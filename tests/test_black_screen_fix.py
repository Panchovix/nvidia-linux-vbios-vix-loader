"""Per-GPU FixBlackScreenIssue stored as a preserved lifecycle registry parameter; synthetic roots, no hardware."""
import io
import json
import unittest
from unittest import mock

from nvidia_vbios import cli
from nvidia_vbios.bootstrap import CONFIG
from nvidia_vbios.lifecycle import Reconciler, blackscreen
from nvidia_vbios.lifecycle.engine import typed_parameters
from nvidia_vbios.lifecycle.security import LifecycleError

import test_bootstrap
from test_lifecycle import OLD

P2P = "pci=0000:03:00.0;RmP2PEnable=1"


class BlackScreenParameterTests(unittest.TestCase):
    def test_modes_keep_other_keys_and_scopes(self):
        parameters = {"NVreg_RegistryDwords": "RmFoo=1", blackscreen.PARAMETER: P2P}
        off = blackscreen.with_mode(parameters, "0000:06:00.0", "off")
        self.assertEqual(off["NVreg_RegistryDwords"], "RmFoo=1")
        self.assertEqual(off[blackscreen.PARAMETER], P2P + ";pci=0000:06:00.0;FixBlackScreenIssue=2")
        on = blackscreen.with_mode(off, "0000:03:00.0", "on")
        self.assertEqual(on[blackscreen.PARAMETER],
                         P2P + ";FixBlackScreenIssue=1;pci=0000:06:00.0;FixBlackScreenIssue=2")
        self.assertEqual(blackscreen.settings(on), {"0000:03:00.0": "on", "0000:06:00.0": "off"})
        self.assertEqual(parameters[blackscreen.PARAMETER], P2P)

    def test_default_drops_empty_scope_and_parameter_and_keeps_other_keys(self):
        self.assertEqual(blackscreen.with_mode(blackscreen.with_mode({}, "0000:06:00.0", "off"),
                                               "0000:06:00.0", "default"), {})
        both = blackscreen.with_mode({blackscreen.PARAMETER: "pci=0000:06:00.0;RmFoo=7"}, "0000:06:00.0", "off")
        cleared = blackscreen.with_mode(both, "0000:06:00.0", "default")
        self.assertEqual(cleared, {blackscreen.PARAMETER: "pci=0000:06:00.0;RmFoo=7"})
        self.assertEqual(blackscreen.settings(cleared), {})

    def test_invalid_modes_and_addresses_are_refused(self):
        for mode in ("2", "OFF", "", "disable"):
            with self.subTest(mode=mode), self.assertRaises(LifecycleError):
                blackscreen.with_mode({}, "0000:06:00.0", mode)
        for bdf in ("06:00.0", "0000:06:00", "0000:06:00.0;RmX=1"):
            with self.subTest(bdf=bdf), self.assertRaises(LifecycleError):
                blackscreen.with_mode({}, bdf, "off")

    def test_activation_merges_setting_into_the_vbios_scope(self):
        device = {"bdf": "0000:06:00.0", "size": 1961983, "sha256": "ab" * 32}
        parameters = blackscreen.with_mode({}, "0000:06:00.0", "off")
        typed = typed_parameters([device], "615.78.08", parameters)
        self.assertEqual(typed[blackscreen.PARAMETER], "pci=0000:06:00.0;FixBlackScreenIssue=2;"
                         "RmLinuxVbiosOverride=2;RmLinuxVbiosOverrideSize=1961983")

    def test_cli_routes_system_black_screen_fix(self):
        with mock.patch.object(blackscreen, "main", return_value=0) as route:
            self.assertEqual(cli.main(["system", "black-screen-fix", "show"]), 0)
        route.assert_called_once_with(["show"])

    def test_cli_help_lists_and_documents_the_command(self):
        with mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(cli.main(["system", "--help"]), 0)
        self.assertIn("black-screen-fix", out.getvalue())
        for argv in (["--help"], ["set", "--help"]):
            with self.subTest(argv=argv), mock.patch("sys.stdout", new_callable=io.StringIO) as out, \
                    self.assertRaises(SystemExit) as done:
                cli.main(["system", "black-screen-fix", *argv])
            self.assertEqual(done.exception.code, 0)
            self.assertIn("nvbios system black-screen-fix", out.getvalue())


class BlackScreenLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_bootstrap.BootstrapTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root, self.worker, self.ops = self.fixture.root, self.fixture.worker, self.fixture.ops
        self.ops.gpu_query = mock.Mock(side_effect=AssertionError("no GPU query allowed"))

    def config(self):
        return json.loads(self.worker.path(CONFIG).read_bytes())

    def test_enrolled_blackwell_gpu_by_address_only(self):
        self.worker.install(self.fixture.repository); self.fixture.enroll(); self.fixture.ready()
        self.worker.enable(OLD)
        device = self.config()["devices"][0]
        bdf = device["bdf"]
        self.assertEqual(device["architecture"], "blackwell-gb20x")
        with self.assertRaisesRegex(LifecycleError, "not an enrolled GPU"):
            blackscreen.update("0000:7f:00.0", "off", root=self.root, operations=self.ops)
        before = self.worker.path(CONFIG).read_bytes()
        planned = blackscreen.update(bdf, "off", root=self.root, operations=self.ops, dry_run=True)
        self.assertEqual(planned["state"], "planned")
        self.assertEqual(self.worker.path(CONFIG).read_bytes(), before)
        report = blackscreen.update(bdf, "off", root=self.root, operations=self.ops)
        self.assertEqual(report["state"], "published")
        self.assertEqual(blackscreen.settings(self.config()["parameters"]), {bdf: "off"})
        self.ops.config = self.config()
        self.assertEqual(Reconciler(self.root, self.ops).reconcile(OLD)["state"], "ready")
        self.ops.gpu_query.assert_not_called()

    def test_non_blackwell_gpu_is_refused(self):
        self.fixture.profile["devices"][-1]["architecture"] = "ada"
        self.worker.install(self.fixture.repository); self.fixture.enroll()
        bdf = self.config()["devices"][-1]["bdf"]
        with self.assertRaisesRegex(LifecycleError, "only on Blackwell"):
            blackscreen.update(bdf, "off", root=self.root, operations=self.ops)
        self.assertNotIn("parameters", self.config())


if __name__ == "__main__":
    unittest.main()
