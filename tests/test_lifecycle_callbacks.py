"""Native package callbacks defer, then select the kernel after transaction completion."""
import contextlib
import io
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock,patch
from nvidia_vbios.lifecycle import __main__ as cli
from nvidia_vbios.lifecycle.security import LifecycleError

class CallbackTests(unittest.TestCase):
 def test_deferred_callback_never_waits_for_own_parent_package_lock(self):
  ops=Mock();worker=Mock(ops=ops)
  with patch.object(cli,'Path') as paths, patch.object(cli,'load_config',return_value=SimpleNamespace(raw={'enabled':True})), patch.object(cli,'Reconciler',return_value=worker),patch.object(cli,'queue_event') as queue:
   paths.return_value.exists.return_value=True
   self.assertEqual(cli.main(['post-transaction','--defer']),0)
  queue.assert_called_once_with('changed','userspace',operations=ops)
  ops._run.assert_called_once_with(['systemctl','start','--no-block','nvidia-vbios-reconcile.service'])
  ops.start_reconcile.assert_not_called()

 def test_kernel_discovery_waits_for_parent_and_refreshes_on_lock_race(self):
  ops=Mock(assert_transaction_idle=Mock(),platform=SimpleNamespace(package_provider='pacman'))
  ops.assert_transaction_idle.side_effect=[LifecycleError('update/build lock busy'),None,None]
  worker=Mock(ops=ops)
  worker.reconcile.side_effect=[LifecycleError('update/build lock busy'),{'state':'ready'}]
  with tempfile.TemporaryDirectory() as temp,patch.object(cli,'STATE',temp),patch.object(cli,'Reconciler',return_value=worker),patch.object(cli,'installed_kernels',side_effect=[['6.10'],['6.11']]) as kernels,patch.object(cli.time,'sleep') as sleep,contextlib.redirect_stdout(io.StringIO()):
   self.assertEqual(cli.main(['reconcile']),0)
  self.assertEqual(kernels.call_count,2)
  self.assertEqual([call.args[0] for call in worker.reconcile.call_args_list],['6.10','6.11'])
  self.assertEqual([call.args[0] for call in sleep.call_args_list],[0.5,1.0])

 def test_dry_run_and_fedora_do_not_take_new_native_callback_lock(self):
  for provider,args in [('deb',['reconcile','--dry-run']),('rpm',['reconcile'])]:
   with self.subTest(provider=provider):
    ops=Mock(assert_transaction_idle=Mock(),platform=SimpleNamespace(package_provider=provider));worker=Mock(ops=ops);worker.reconcile.return_value={'state':'ready'}
    with tempfile.TemporaryDirectory() as temp,patch.object(cli,'STATE',temp),patch.object(cli,'Reconciler',return_value=worker),patch.object(cli,'installed_kernels',return_value=['6.10']),contextlib.redirect_stdout(io.StringIO()):
     self.assertEqual(cli.main(args),0)
    ops.assert_transaction_idle.assert_not_called()
