"""Synchronous completion of an operator-managed NVIDIA source installation.

This does not run an installer, invoke module load/unload commands, or reboot.
The supplied source must match installed userspace; enrolled GPU identities must
be observable before any change. Missing driver/UUID recovery is a separate task.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from .bootstrap import (Bootstrap, BootstrapError, BASE, CONFIG, STATE, ENABLED,
                        _input_path, _source_records, _fingerprint, _external, _json_bytes, _platform)
from .lifecycle.config import load_config
from .lifecycle.engine import Reconciler
from .lifecycle.security import (LifecycleError, digest, hash_file, source_tree_hash,
                                 checked_path, json_write, locked, token)


class DriverUpdate(Bootstrap):
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
                  'gpu_settings_written': False,
                  'resume': 'nvbios system post-install --source PATH' +
                            (' --p2p-preferred' if configuration.raw.get('require_p2p_source') else '')}
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
                   reconcile._normal_entry_id(kernel, config)}
        if not isinstance(environment.get('saved_entry'), str) or environment['saved_entry'] not in allowed:
            raise BootstrapError('foreign or unrelated GRUB default preserved')
        previous_activation = self._read(ENABLED)
        selected_provider = (provider or previous_activation.get('provider') or
                             self._read(BASE + '/driver-maintenance.json').get('provider', _platform(self.ops).hook_provider))
        if selected_provider not in ('dnf4', 'dnf5', 'apt', 'pacman') or not self.ops.plugin_available(selected_provider):
            raise BootstrapError('native package callback provider is unavailable')
        records = _source_records(source)
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
        sources.insert(0, entry)
        return config, source, info, records, entry, sources, fleet, environment, selected_provider

    def post_install(self, source, *, kernel=None, p2p_preferred=False, provider=None, dry_run=False):
        kernel = token(kernel or self.ops.current_kernel())
        prepared = self._preflight(source, kernel, p2p_preferred, provider)
        config, source, info, records, entry, sources, fleet, environment, provider = prepared
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
                # Keep the previous self-contained READY image through the build.
                selection = self._ready_default_plan(config, {'entry': fleet['last_ready']['entry']})
                if selection['state'] in ('ready', 'planned'):
                    self._select_ready_default_locked(selection)
                else:
                    Reconciler(self.root, self.ops)._guard_default(config, fleet)
                copied = self._snapshot(records, lambda name: _external(source / name), entry['path'])
                if (_source_records(source) != records or
                    self.ops.inspect_source(copied).get('source_hashes') != info['source_hashes']):
                    raise BootstrapError('source changed during snapshot publication')
                entry['tree_sha256'] = source_tree_hash(copied, self.root)
                updated = dict(config.raw, enabled=True, sources=sources)
                if p2p_preferred:
                    updated['require_p2p_source'] = True
                data = _json_bytes(updated)
                enrolled = dict(self._read(BASE + '/enrolled.json'), configuration_sha256=digest(data), version=info['version'])
                publication = self._publish({CONFIG: (data, 0o600),
                    BASE + '/enrolled.json': (_json_bytes(enrolled), 0o600)}, 'post-install-source')
                record('enrolled', registration_transaction=publication['transaction_id'])
            started_reconcile = True
            result = Reconciler(self.root, self.ops).reconcile(kernel)
            if result.get('state') != 'ready' or result.get('marker') != 'VBIOS_READY':
                raise BootstrapError('post-install reconciliation did not establish READY')
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
                        # Retain the selected recovery/READY entry. A failed driver
                        # change is not permission to select a normal blank boot.
                        self._disable_locked(preserve_default=True)
                except Exception as recovery:
                    recovery_errors.append(str(recovery))
                record('blocked', error=str(exc), recovery_errors=recovery_errors,
                       recovery='Fix the reported prerequisite and rerun post-install; automatic hooks remain suspended until success')
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
