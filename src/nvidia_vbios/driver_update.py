"""Synchronous completion of an operator-managed NVIDIA source installation.

This does not run an installer, invoke module load/unload commands, or reboot.
The supplied source must match installed userspace; enrolled GPU identities must
be observable before any change. Missing driver/UUID recovery is a separate task.
"""
from __future__ import annotations
import argparse
import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

from .bootstrap import (Bootstrap, BootstrapError, BASE, CONFIG, STATE, ENABLED,
                        _input_path, _source_records, _fingerprint, _external, _json_bytes, _platform)
from .lifecycle.config import load_config, resume_command
from .lifecycle.engine import Reconciler
from .lifecycle import source_fetch
from .lifecycle.security import (LifecycleError, digest, hash_file, source_tree_hash,
                                 checked_path, json_write, locked, token)


FETCH_RECORD = STATE + '/source-fetch.json'


class DriverUpdate(Bootstrap):
    def auto_source(self, version, *, open_url=None):
        """After driver drift, register the exact upstream tag as the source for `version`.

        Called by the reconcile service. Returns the source-fetch record; only
        state 'registered' means a new reconcile can build the override.
        """
        with locked(self.path(STATE + '/reconcile.lock'), self.root):
            return self._auto_source_locked(version, open_url)

    def _auto_source_locked(self, version, open_url):
        config = load_config(self.path(CONFIG), self.root, require_enabled=False)
        raw, previous = config.raw, self._read(FETCH_RECORD)
        def record(state, **extra):
            value = {'schema_version': 1, 'version': version, 'state': state, 'finished': time.time(), **extra}
            json_write(self.path(FETCH_RECORD), value)
            return value
        # Every skip below happens without network access.
        if not raw['enabled'] or not raw.get('auto_source'):
            return record('off', reason='automatic source download is off for this enrollment')
        if raw.get('userspace', {}).get('provider') == 'manual':
            return record('off', reason='manual userspace')
        if raw.get('require_p2p_source') or any(s.get('p2p_preferred') for s in config.sources):
            return record('p2p-required', reason='register a reviewed P2P source with post-install')
        if not source_fetch.VERSION.fullmatch(version):
            return record('unsupported-version', reason='only three-part releases have registrable tags')
        if any(s['version'] == version for s in config.sources):
            return {'schema_version': 1, 'version': version, 'state': 'present'}
        if previous.get('version') == version:
            if previous.get('state') in ('rejected', 'rolled-back'):
                return previous
            transaction = previous.get('transaction_id')
            if (previous.get('state') == 'registered' and isinstance(transaction, str) and self._read(
                    BASE + f'/transactions/{token(transaction, "transaction")}/journal.json').get('state') == 'rolled-back'):
                # `nvbios system rollback` undid this registration; do not register it again.
                return record('rolled-back', transaction_id=transaction)
        fetch = self.path(STATE + '/fetch')
        self._mkdir(fetch, 0o700)
        for leftover in fetch.glob('.fetch-*'):
            # A service killed at its start timeout never ran the cleanup below.
            shutil.rmtree(leftover, ignore_errors=True)
        work = Path(tempfile.mkdtemp(prefix='.fetch-', dir=fetch))
        origin = {}
        try:
            if hasattr(self.ops, 'assert_transaction_idle'):
                self.ops.assert_transaction_idle(self.root)
            # Local and deterministic: read it before downloading anything.
            packaged = source_fetch.packaged_source(version, self.root)
            tree, origin = source_fetch.fetch(version, work, open_url=open_url)
            origin['cross_check'] = source_fetch.verify(tree, packaged)
            info = self.ops.inspect_source(tree)
            if (info.get('version') != version or not info.get('supported')
                    or info.get('capabilities', {}).get('already_patched')):
                raise source_fetch.Rejected(f'tag is not a supported unpatched {version} source: {info.get("reasons", [])}')
            if hash_file(self.path(CONFIG)) != config.fingerprint or self.ops.installed_version(raw) != version:
                raise source_fetch.FetchFailed('configuration or installed driver changed during the download')
            publication, entry = self._register_source_locked(config, tree, info, version, False, 'auto-source', origin=origin)
            return record('registered', transaction_id=publication['transaction_id'], snapshot=entry['path'], **origin)
        except source_fetch.Rejected as exc:
            return record('rejected', error=str(exc), **origin)
        except (LifecycleError, OSError) as exc:
            return record('failed', error=str(exc), **origin)
        finally:
            shutil.rmtree(work, ignore_errors=True)

    def _source_entry(self, config, records, info, version, p2p_preferred, origin=None):
        """Registry entry and source list for a snapshot of `records`; refuses a preference conflict."""
        destination = f'/var/lib/nvidia-vbios/sources/{version}-{_fingerprint(records)}'
        sources = [dict(s) for s in config.sources if s['path'] != destination]
        if p2p_preferred:
            for registered in sources:
                if registered['version'] == version:
                    registered['p2p_preferred'] = False
        elif any(s['version'] == version and s.get('p2p_preferred') for s in sources):
            raise BootstrapError('another source is preferred; explicitly select --p2p-preferred for the supplied reviewed P2P source')
        entry = {'version': version, 'path': destination, 'source_hashes': info['source_hashes'],
                 'tree_sha256': '0' * 64, 'p2p_preferred': bool(p2p_preferred)}
        if origin:
            entry['origin'] = origin
        return entry, [entry, *sources]

    def _register_source_locked(self, config, source, info, version, p2p_preferred, kind, origin=None, records=None):
        """Snapshot `source` and publish it as the first source for `version`.

        Caller holds reconcile.lock. Returns (publication, entry);
        `nvbios system rollback <transaction_id>` undoes the publication.
        """
        records = _source_records(source) if records is None else records
        entry, sources = self._source_entry(config, records, info, version, p2p_preferred, origin)
        copied = self._snapshot(records, lambda name: _external(source / name), entry['path'])
        if (_source_records(source) != records or
            self.ops.inspect_source(copied).get('source_hashes') != info['source_hashes']):
            raise BootstrapError('source changed during snapshot publication')
        entry['tree_sha256'] = source_tree_hash(copied, self.root)
        updated = dict(config.raw, enabled=True, sources=sources)
        if p2p_preferred:
            updated['require_p2p_source'] = True
        data = _json_bytes(updated)
        enrolled = dict(self._read(BASE + '/enrolled.json'), configuration_sha256=digest(data), version=version)
        writes = {CONFIG: (data, 0o600), BASE + '/enrolled.json': (_json_bytes(enrolled), 0o600)}
        enabled = self._read(ENABLED)
        if enabled:
            # Triggers stay on (registration from the reconcile service): keep the activation record current.
            writes[ENABLED] = (_json_bytes(dict(enabled, configuration_sha256=digest(data))), 0o600)
        return self._publish(writes, kind), entry

    def pre_install(self, *, dry_run=False):
        """Pause automatic callbacks for manual library removal, retaining READY."""
        self.status(require_installed=True)
        if self.ops.reconcile_active():
            raise BootstrapError('reconciliation is active; wait before manual driver maintenance')
        configuration = load_config(self.path(CONFIG), self.root, require_enabled=False)
        reconcile = Reconciler(self.root, self.ops)
        fleet = reconcile._effective_fleet(configuration)
        if not fleet.get('last_ready'):
            raise BootstrapError('manual maintenance requires a previous READY image')
        reconcile._fallback(configuration, fleet)
        env = self.ops.grub_environment()
        reconcile._check_option_variables(configuration, env)
        if (env.get('saved_entry') != fleet['last_ready']['entry'] or
            env.get('next_entry') or env.get('prev_saved_entry')):
            raise BootstrapError('select the existing READY default without pending GRUB transitions before maintenance')
        prior = self._read(BASE + '/driver-maintenance.json')
        provider = self._read(ENABLED).get('provider') or prior.get('provider', _platform(self.ops).hook_provider)
        report = {'schema_version': 1, 'state': 'planned' if dry_run else 'suspended',
                  'saved_entry': env['saved_entry'], 'provider': provider,
                  'gpu_settings_written': False, 'resume': resume_command(configuration.raw)}
        if dry_run:
            return report
        with locked(self.path(STATE + '/reconcile.lock'), self.root):
            if (self.ops.reconcile_active() or self.ops.grub_environment() != env or
                hash_file(self.path(CONFIG)) != configuration.fingerprint):
                raise BootstrapError('maintenance preconditions changed')
            self._disable_locked(preserve_default=True)
            json_write(self.path(BASE + '/driver-maintenance.json'), report)
        return report

    def _preflight(self, source, kernel, p2p_preferred, provider):
        self.status(require_installed=True)
        if kernel != self.ops.current_kernel():
            raise BootstrapError('post-install targets the running kernel; automatic kernel updates use lifecycle hooks')
        if self.ops.reconcile_active():
            raise BootstrapError('reconciliation is active; wait for completion and retry post-install')
        config = load_config(self.path(CONFIG), self.root, require_enabled=False)
        source = _input_path(source)
        info = self.ops.inspect_source(source)
        if not info.get('supported') or info.get('capabilities', {}).get('already_patched'):
            raise BootstrapError(f'unsupported or already VBIOS-patched source: {info.get("reasons", [])}')
        version = self.ops.installed_version(config.raw)
        if info.get('version') != version:
            raise BootstrapError('supplied source version differs from installed NVIDIA userspace')
        if config.raw.get('require_p2p_source') and not p2p_preferred:
            raise BootstrapError('this enrollment requires a reviewed P2P source; use --p2p-preferred')
        actual = self.ops.inventory()
        for device in config.devices:
            observed = actual.get(device['bdf'])
            if observed is None or any(observed.get(k) != device[k] for k in ('uuid', 'vendor', 'device')):
                raise BootstrapError(f'GPU UUID/BDF unavailable or changed at {device["bdf"]}; boot the previous READY to restore kernel-side identity before post-install (userspace compatibility is checked separately)')
            payload = self.path(device['payload_path']); checked_path(payload, self.root)
            data = payload.read_bytes()
            if len(data) != device['size'] or digest(data) != device['sha256']:
                raise BootstrapError('enrolled ROM bytes changed')
            self.ops.validate_payload(data, device)
        self.ops.prerequisites(kernel, config.raw)
        reconcile = Reconciler(self.root, self.ops)
        fleet = reconcile._effective_fleet(config)
        if not fleet.get('last_ready'):
            raise BootstrapError('post-install requires an existing READY deployment')
        reconcile._fallback(config, fleet)
        environment = self.ops.grub_environment()
        reconcile._check_option_variables(config, environment)
        if environment.get('next_entry') or environment.get('prev_saved_entry'):
            raise BootstrapError('another GRUB transition is pending')
        allowed = {fleet['last_ready']['entry'], fleet.get('normal_fallback', {}).get('entry'),
                   reconcile._normal_entry_id(kernel, config), (fleet.get('drift') or {}).get('entry')}
        if not isinstance(environment.get('saved_entry'), str) or environment['saved_entry'] not in allowed:
            raise BootstrapError('foreign or unrelated GRUB default preserved')
        previous_activation = self._read(ENABLED)
        selected_provider = (provider or previous_activation.get('provider') or
                             self._read(BASE + '/driver-maintenance.json').get('provider', _platform(self.ops).hook_provider))
        if selected_provider not in ('dnf4', 'dnf5', 'apt', 'pacman') or not self.ops.plugin_available(selected_provider):
            raise BootstrapError('native package callback provider is unavailable')
        records = _source_records(source)
        entry, _ = self._source_entry(config, records, info, version, p2p_preferred)
        return config, source, info, records, entry, fleet, environment, selected_provider

    def post_install(self, source, *, kernel=None, p2p_preferred=False, provider=None, dry_run=False):
        kernel = token(kernel or self.ops.current_kernel())
        prepared = self._preflight(source, kernel, p2p_preferred, provider)
        config, source, info, records, entry, fleet, environment, provider = prepared
        report = {'schema_version': 1, 'state': 'planned', 'kernel': kernel, 'version': info['version'],
                  'source': str(source), 'snapshot': entry['path'], 'p2p_preferred': bool(p2p_preferred),
                  'device_count': len(config.devices), 'devices_preserved': True,
                  'previous_ready': fleet['last_ready']['entry'], 'provider': provider,
                  'gpu_settings_written': False, 'reboot_performed': False}
        if dry_run:
            return report
        progress = self.path(BASE + '/post-install.json')
        suspended = False
        publication = None
        started_reconcile = False
        def record(state, **extra):
            report.update(state=state, **extra)
            json_write(progress, report)
        try:
            with locked(self.path(STATE + '/reconcile.lock'), self.root):
                if self.ops.reconcile_active():
                    raise BootstrapError('reconciliation became active; retry after completion')
                # Recheck mutable input/selection before suspending automatic work.
                if (hash_file(self.path(CONFIG)) != config.fingerprint or
                    self.ops.grub_environment() != environment or _source_records(source) != records):
                    raise BootstrapError('configuration, boot selection or source changed during preparation')
                self._disable_locked(preserve_default=True)
                suspended = True
                record('suspended')
                if fleet.get('drift'):
                    # The previous READY image loads modules built for the old
                    # driver; keep the normal entry the fail-safe selected.
                    Reconciler(self.root, self.ops)._guard_default(config, fleet)
                else:
                    # Keep the previous self-contained READY image through the build.
                    selection = self._ready_default_plan(config, {'entry': fleet['last_ready']['entry']})
                    if selection['state'] in ('ready', 'planned'):
                        self._select_ready_default_locked(selection)
                    else:
                        Reconciler(self.root, self.ops)._guard_default(config, fleet)
                publication, _ = self._register_source_locked(config, source, info, info['version'], p2p_preferred,
                                                              'post-install-source', records=records)
                record('enrolled', registration_transaction=publication['transaction_id'])
            started_reconcile = True
            result = Reconciler(self.root, self.ops).reconcile(kernel)
            if result.get('state') == 'driver-drift':
                # The build for the new driver failed: the fail-safe parked the old modules and
                # selected a normal entry with the new driver's module, if there is one.
                report['driver_drift'] = {'entry': result['entry'], 'parked': result['parked']}
            if result.get('state') != 'ready' or result.get('marker') != 'VBIOS_READY':
                raise BootstrapError('post-install reconciliation did not establish READY' +
                                     (f': {result["error"]}' if result.get('error') else ''))
            record('reconciled', entry=result['entry'])
            activation = self.enable(kernel, provider=provider)
            if not activation.get('triggers_enabled'):
                raise BootstrapError('update triggers were not restored')
            record('complete', triggers_enabled=True, activation_transaction=activation.get('transaction_id'))
            if self.path(BASE + '/driver-maintenance.json').exists():
                json_write(self.path(BASE + '/driver-maintenance.json'),
                           dict(self._read(BASE + '/driver-maintenance.json'), state='complete'))
            return report
        except Exception as exc:
            if suspended:
                recovery_errors = []
                try:
                    with locked(self.path(STATE + '/reconcile.lock'), self.root):
                        if self.ops.reconcile_active():
                            raise BootstrapError('another reconciler owns recovery; do not interrupt it')
                        if publication and not started_reconcile:
                            self._rollback_locked(publication['transaction_id'])
                        # Keep the default the reconcile left: the READY entry after a same-driver
                        # failure, what the driver-drift fail-safe selected otherwise.
                        self._disable_locked(preserve_default=True)
                except Exception as recovery:
                    recovery_errors.append(str(recovery))
                parked = (f'The new driver did not build: the old override modules are parked and the default is '
                          f'{report["driver_drift"]["entry"]}. ' if report.get('driver_drift') else '')
                record('blocked', error=str(exc), recovery_errors=recovery_errors,
                       recovery=parked + 'Fix the reported prerequisite and rerun post-install; automatic hooks remain suspended until success')
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--kernel')
    parser.add_argument('--p2p-preferred', action='store_true')
    parser.add_argument('--provider', choices=('dnf4', 'dnf5', 'apt', 'pacman'))
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        worker = DriverUpdate()
        if args.dry_run:
            result = worker.post_install(args.source, kernel=args.kernel, p2p_preferred=args.p2p_preferred,
                                         provider=args.provider, dry_run=True)
        else:
            with locked(worker.path(BASE + '/bootstrap.lock'), worker.root):
                result = worker.post_install(args.source, kernel=args.kernel, p2p_preferred=args.p2p_preferred,
                                             provider=args.provider)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (LifecycleError, OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f'POST_INSTALL_BLOCKED: {exc}', file=sys.stderr)
        return 1


def pre_install_main(argv=None):
    parser = argparse.ArgumentParser(description='Pause update callbacks during manual NVIDIA userspace maintenance; preserve READY boot')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args(argv)
    try:
        worker = DriverUpdate()
        if args.dry_run:
            result = worker.pre_install(dry_run=True)
        else:
            with locked(worker.path(BASE + '/bootstrap.lock'), worker.root):
                result = worker.pre_install()
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (LifecycleError, OSError, ValueError, KeyError, RuntimeError) as exc:
        print(f'PRE_INSTALL_BLOCKED: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
