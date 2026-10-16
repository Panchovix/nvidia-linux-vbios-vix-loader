"""Native package callbacks defer, then select the kernel after transaction completion."""
import contextlib
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock,patch
from nvidia_vbios.lifecycle import __main__ as cli
from nvidia_vbios.lifecycle.security import LifecycleError, locked
sys.path.insert(0,str(Path(__file__).resolve().parent))
import test_lifecycle as fixtures

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

 def test_queue_with_busy_reconcile_lock_is_deferred_and_still_queued(self):
  case=fixtures.LifecycleTests(methodName='runTest');case.setUp();self.addCleanup(case.doCleanups)
  ready=case.worker.reconcile(fixtures.NEW);case.add_kernel(fixtures.NEXT)
  case.ops.environment['saved_entry']='normal-'+fixtures.NEXT
  state=case.root/fixtures.STATE.lstrip('/')
  with locked(state/'reconcile.lock',case.root):
   event=cli.queue_event('add',fixtures.NEXT,case.root,case.ops)
  self.assertTrue(event['deferred']);self.assertNotIn('retained_default',event)
  self.assertEqual(json.loads((state/'pending'/(fixtures.NEXT+'.json')).read_text())['action'],'add')
  # The running owner decides; the hook itself changes nothing else.
  self.assertEqual(case.ops.environment['saved_entry'],'normal-'+fixtures.NEXT)
  self.assertEqual(case.ops.builds,1);self.assertNotEqual(ready['entry'],'normal-'+fixtures.NEXT)

 def test_deferred_post_transaction_and_queue_exit_zero_without_systemctl(self):
  for args in (['post-transaction'],['post-transaction','--defer'],['queue','add','6.11']):
   with self.subTest(args=args):
    ops=Mock();worker=Mock(ops=ops);stderr=io.StringIO()
    deferred={'action':'changed','kernel':'userspace','queued':1.0,'deferred':True}
    with patch.object(cli,'Path') as paths,patch.object(cli,'load_config',return_value=SimpleNamespace(raw={'enabled':True})),patch.object(cli,'Reconciler',return_value=worker),patch.object(cli,'queue_event',return_value=deferred) as queue,contextlib.redirect_stderr(stderr),contextlib.redirect_stdout(io.StringIO()):
     paths.return_value.exists.return_value=True
     self.assertEqual(cli.main(args),0)
    queue.assert_called_once()
    self.assertIn('VBIOS_DEFERRED: reconcile running; queued',stderr.getvalue())
    ops._run.assert_not_called();ops.start_reconcile.assert_not_called()

 def test_driver_drift_result_exits_zero_and_clears_pending(self):
  ops=Mock(platform=SimpleNamespace(package_provider='rpm'));worker=Mock(ops=ops)
  drift={'state':'driver-drift','marker':'VBIOS_DRIFT','installed_driver':'615.78.08'}
  worker.reconcile.return_value=drift
  for fetched in ({'state':'failed'},{'state':'registered'}):
   with self.subTest(fetched=fetched['state']):
    final=dict(drift,source_fetch=fetched) if fetched['state']=='failed' else {'state':'ready','source_fetch':fetched}
    out=io.StringIO()
    with tempfile.TemporaryDirectory() as temp,patch.object(cli,'STATE',temp),patch.object(cli,'checked_path'),patch.object(cli,'Reconciler',return_value=worker),patch.object(cli,'installed_kernels',return_value=['6.10']),patch.object(cli,'after_drift',return_value=final) as after,contextlib.redirect_stdout(out):
     pending=Path(temp)/'pending';pending.mkdir();(pending/'6.10.json').write_text('{}')
     self.assertEqual(cli.main(['reconcile']),0)
     self.assertFalse(list(pending.glob('*.json')))
    after.assert_called_once_with(worker,'6.10',drift)
    self.assertEqual(json.loads(out.getvalue()),final)

 def test_after_drift_reconciles_again_only_after_a_registration(self):
  for state,calls in (('registered',1),('failed',0),('p2p-required',0)):
   with self.subTest(state=state):
    worker=Mock();worker.reconcile.return_value={'state':'ready'}
    with patch('nvidia_vbios.driver_update.DriverUpdate') as update:
     update.return_value.auto_source.return_value={'state':state}
     result=cli.after_drift(worker,'6.10',{'state':'driver-drift','installed_driver':'615.78.08'})
    update.assert_called_once_with(worker.root,worker.ops)
    update.return_value.auto_source.assert_called_once_with('615.78.08')
    self.assertEqual(worker.reconcile.call_count,calls)
    self.assertEqual(result['state'],'ready' if calls else 'driver-drift')
    self.assertEqual(result['source_fetch'],{'state':state})
