"""Portable boot publication using the shared module transaction engine.

The Fedora BLS path stays in engine.py. These adapters own generation-specific
kernel/initramfs/UKI files; normal OS boot images are never replaced.
"""
from __future__ import annotations
import fnmatch
import json
import os
from pathlib import Path
import re
import tempfile
import time
from .boot import BootAdapter, entry_identity
from .config import load_config, select_source
from .engine import (Reconciler, CONFIG, STATE, ACTIVATION_PATH, FORCE_PATH, FORCE_BYTES,
                     ACTIVATION_GENERATION, modprobe_configuration, typed_parameters)
from .security import LifecycleError, checked_path, digest, hash_file, json_write, atomic_write, token

EFI_GUID = '4a67b082-0a4c-41cf-b6c7-440b29bb8c4f'


def portable_config(raw):
    return isinstance(raw.get('boot'), dict) and raw['boot'].get('backend') in ('grub', 'systemd-boot', 'uki')


class BootOperations:
    """Normalize boot selection; delegate all source/module operations unchanged."""
    def __init__(self, base, root, raw):
        self.base = base.base if isinstance(base, BootOperations) else base
        self.root = Path(root)
        self.raw = raw
        self.boot = BootAdapter(root, raw)

    def __getattr__(self, name):
        return getattr(self.base, name)

    def _efi(self, variable):
        path = self.root / f'sys/firmware/efi/efivars/{variable}-{EFI_GUID}'
        if not path.exists():
            return ''
        checked_path(path, self.root)
        data = path.read_bytes()
        if len(data) < 4 or (len(data) - 4) % 2:
            raise LifecycleError('invalid boot-loader EFI variable')
        try:
            return data[4:].decode('utf-16-le').rstrip('\0')
        except UnicodeError as exc:
            raise LifecycleError('invalid boot-loader EFI variable text') from exc

    def grub_environment(self):
        if self.boot.backend == 'grub' or not hasattr(self.base, '_run'):
            result = self.base.grub_environment()
            if not result.get('saved_entry') and not self.raw.get('_require_explicit_default'):
                result = dict(result, saved_entry=self.raw.get('fallback_entry', ''))
            return result
        saved, once = self._efi('LoaderEntryDefault'), self._efi('LoaderEntryOneShot')
        if not saved:
            path = self.root / (self.boot.config.get('esp', self.boot.boot_root) + '/loader/loader.conf').lstrip('/')
            if path.exists():
                checked_path(path, self.root)
                values = [line.split(None, 1)[1] for line in path.read_text().splitlines()
                          if line.split() and line.split()[0] == 'default' and len(line.split(None, 1)) == 2]
                if len(values) > 1:
                    raise LifecycleError('ambiguous systemd-boot default')
                if values:
                    saved = values[0]
            if not saved or saved in ('@saved', '@current'):
                saved = self._efi('LoaderEntrySelected') or self.raw.get('fallback_entry', '')
            elif any(char in saved for char in '*?['):
                selected = self._efi('LoaderEntrySelected') or self.raw.get('fallback_entry', '')
                if not fnmatch.fnmatchcase(selected, saved):
                    raise LifecycleError('systemd-boot default pattern is not the enrolled entry')
                saved = selected
        if saved:
            entry_identity(saved, self.boot.backend)
        if once:
            entry_identity(once, self.boot.backend)
        return {'saved_entry': saved, 'next_entry': once}

    def set_default(self, entry):
        entry_identity(entry, self.boot.backend)
        if self.boot.backend == 'grub' or not hasattr(self.base, '_run'):
            return self.base.set_default(entry)
        args = ['bootctl', '--esp-path=' + self.boot.config.get('esp', self.boot.boot_root)]
        if self.boot.config.get('xbootldr'):
            args.append('--boot-path=' + self.boot.config['xbootldr'])
        self.base._run([*args, 'set-default', entry])

    def prerequisites(self, kernel, config):
        if not hasattr(self.base, '_run'):
            return self.base.prerequisites(kernel, config)
        build = self.root / f'usr/lib/modules/{token(kernel)}/build'
        checked_path(build.resolve(), self.root)
        checked_path(build.resolve() / 'Makefile', self.root)
        for directory in ('etc/modprobe.d', 'usr/lib/modprobe.d'):
            for path in (self.root / directory).glob('*.conf'):
                checked_path(path, self.root)
                for line in path.read_text().splitlines():
                    if not line.lstrip().startswith('#') and any(value in line for value in ('RmLinuxVbiosOverride=2', 'RmLinuxVbiosOverrideImage=')):
                        raise LifecycleError('global VBIOS activation conflicts with isolated boot images')
        for name in ('make', 'modinfo', 'depmod', 'mokutil'):
            checked_path(Path(self.base.command_path(name)).resolve(), self.root)
        state = self.base._text(['mokutil', '--sb-state']).lower()
        if 'secureboot enabled' in state or 'secure boot enabled' in state:
            self.base._signing_paths(kernel, config)
        elif not any(v in state for v in ('secureboot disabled', 'secure boot disabled', 'efi variables are not supported')):
            raise LifecycleError('cannot determine Secure Boot state')
        if self.boot.backend == 'grub':
            defaults = self.root / 'etc/default/grub'
            checked_path(defaults, self.root)
            if not re.search(r'^GRUB_DEFAULT=[\'\"]?saved[\'\"]?\s*$', defaults.read_text(), re.M):
                raise LifecycleError('GRUB_DEFAULT=saved is required; regenerate GRUB before enrollment')
        elif not (self.root / 'sys/firmware/efi').is_dir():
            raise LifecycleError('systemd-boot/UKI require a UEFI boot')


def operations_for(ops, root, raw):
    return BootOperations(ops, root, raw) if portable_config(raw) else ops


class PortableReconciler(Reconciler):
    def __init__(self, root=Path('/'), operations=None, config_path=CONFIG):
        super().__init__(root, operations, config_path)
        config = load_config(self.config_path, self.root, require_enabled=False)
        self.ops = operations_for(self.ops, self.root, config.raw)
        self.boot = BootAdapter(self.root, config.raw)

    def _check_option_variables(self, config, environment):
        # Portable entries contain statically resolved kernel options.
        for key in ('saved_entry', 'next_entry', 'prev_saved_entry'):
            if environment.get(key):
                entry_identity(environment[key], self.boot.backend)

    def _verify_boot_files(self, record):
        for item in record.get('boot_files', []):
            path = self.path(item['path']); self.trusted(path)
            if hash_file(path) != item['sha256']:
                raise LifecycleError('last ready boot artifact changed')

    def _normal(self, config, record=None):
        record = record or config.raw.get('normal_boot')
        if not isinstance(record, dict) or not record.get('kernel'):
            raise LifecycleError('portable enrollment requires a normal_boot snapshot')
        return self.boot.discover(record['kernel'], record['entry'])

    def _validate_normal(self, config, record):
        entry = self._normal(config, record)
        current = self.boot.fallback_record(entry)
        if any(current.get(key) != record.get(key) for key in ('entry', 'kernel', 'sha256', 'boot_files', 'options')):
            raise LifecycleError('normal recovery entry or artifacts changed')
        return entry

    def _fallback(self, config, fleet):
        normal = fleet.get('normal_fallback', config.raw.get('normal_boot'))
        last = fleet.get('last_ready')
        if last:
            self._verify_boot_files(last)
        else:
            self._validate_normal(config, normal)
        return normal

    def _normal_entry_id(self, kernel, config):
        return self.boot.discover(kernel).entry_id

    def _guard_default(self, config, fleet):
        normal = self._fallback(config, fleet)
        last = fleet.get('last_ready')
        target = last['entry'] if last else normal['entry']
        environment = self.ops.grub_environment()
        self._check_option_variables(config, environment)
        if environment.get('next_entry') or environment.get('prev_saved_entry'):
            raise LifecycleError('another boot transition is pending')
        saved = environment.get('saved_entry')
        if saved == target:
            return target
        eligible = not last and saved == config.fallback_entry
        if last:
            from .__main__ import kernel_key
            for kernel in self.boot.installed_kernels():
                try:
                    candidate = self.boot.discover(kernel)
                except LifecycleError:
                    continue
                if candidate.entry_id == saved and kernel_key(kernel) > kernel_key(last['kernel']):
                    eligible = True
        if not eligible:
            raise LifecycleError('foreign or unrelated boot default preserved')
        self.ops.set_default(target)
        if self.ops.grub_environment().get('saved_entry') != target:
            raise LifecycleError('could not retain last ready boot default')
        return target

    def _restore_normal_default_locked(self):
        config = load_config(self.config_path, self.root, require_enabled=False)
        fleet = self._effective_fleet(config); normal = fleet.get('normal_fallback', config.raw['normal_boot'])
        environment = self.ops.grub_environment(); current = environment.get('saved_entry')
        if environment.get('next_entry') or environment.get('prev_saved_entry'):
            return {'state':'preserved','reason':'pending boot transition','entry':current}
        if current not in (normal['entry'], fleet.get('last_ready',{}).get('entry')):
            return {'state':'preserved','reason':'foreign boot default','entry':current}
        self._validate_normal(config, normal)
        if current != normal['entry']:
            self.ops.set_default(normal['entry'])
        if self.ops.grub_environment().get('saved_entry') != normal['entry']:
            raise LifecycleError('normal recovery selection did not persist')
        return {'state':'normal','entry':normal['entry']}

    def plan(self, kernel, *, require_enabled=True):
        kernel = token(kernel); config = load_config(self.config_path,self.root,require_enabled=require_enabled)
        version = self.ops.installed_version(config.raw)
        source, inspection = select_source(config,version,self.ops.inspect_source,self.root)
        self._fallback(config,self._effective_fleet(config))
        entry = self.boot.discover(kernel)
        if 'nvidia.NVreg_Registry' in entry.options or 'RmLinuxVbiosOverride' in entry.options:
            raise LifecycleError('normal entry contains foreign VBIOS activation')
        payloads={};actual=self.ops.inventory()
        for device in config.devices:
            observed=actual.get(device['bdf'])
            if observed is None or any(observed.get(k)!=device[k] for k in ('uuid','vendor','device')):
                raise LifecycleError('physical GPU UUID/BDF identity unavailable or changed')
            path=self.path(device['payload_path']);self.trusted(path);data=path.read_bytes()
            if len(data)!=device['size'] or digest(data)!=device['sha256']:
                raise LifecycleError('selected ROM bytes changed')
            self.ops.validate_payload(data,device);payloads[device['bdf']]=data
        self.ops.prerequisites(kernel,config.raw)
        activation_bytes=modprobe_configuration(config.devices,version,config.raw.get('parameters'))
        normal=self.boot.fallback_record(entry)
        base_sha=digest(json.dumps(normal,sort_keys=True).encode())
        generation=digest((f'portable-boot-v1:activation-v{ACTIVATION_GENERATION}:'+kernel+version+config.fingerprint+base_sha).encode())
        managed_id=f'vbios-{kernel}-{generation[:20]}';artifacts=self.boot.plan(entry,managed_id)
        return {'kernel':kernel,'version':version,'source':source,'source_inspection':inspection,
                'configuration_sha256':config.fingerprint,'entry':artifacts.entry_id,
                'image':artifacts.initrd_path,'base_entry':str(self.path(entry.descriptor_path)),
                'base_sha256':base_sha,'generation_sha256':generation,
                'module_parameters':typed_parameters(config.devices,version,config.raw.get('parameters')),
                'activation_config_sha256':digest(activation_bytes),'activation_bytes':activation_bytes,
                'config':config,'payloads':payloads,'boot_entry':entry,'boot_plan':artifacts,
                'managed_id':managed_id,'normal_boot':normal}

    def dry_run(self,kernel):
        plan=self.plan(kernel)
        return {k:v for k,v in plan.items() if k not in ('config','payloads','activation_bytes','boot_entry','boot_plan')}

    def _shared(self,journal,target,data,fleet,*,mode=0o644,mutable=False):
        path=self.path(target);self.trusted(path,missing=True)
        expected=fleet.get('shared_boot_files',{}).get(target)
        if path.exists() and not mutable and hash_file(path) not in (expected,digest(data)):
            raise LifecycleError('unmanaged or changed boot include: '+target)
        self._stage_write(journal,path,data,mode=mode)
        journal['files'][-1]['shared_boot']=True
        json_write(self.state/'transaction.json',journal)

    def _publish_boot(self,plan,config,fleet,kernel,workspace,journal,targets):
        from . import initramfs
        journal['boot']=config.raw['boot']
        if fleet.get('last_ready',{}).get('entry')==plan['entry']:
            plan['managed_id']+='-'+digest(journal['id'].encode())[:12]
            plan['boot_plan']=self.boot.plan(plan['boot_entry'],plan['managed_id'])
            plan['entry']=plan['boot_plan'].entry_id;journal['entry']=plan['entry']
        json_write(self.state/'transaction.json',journal)
        artifacts=plan['boot_plan'];paths=[]
        for name,data in artifacts.copy_files.items():
            if name.endswith('/normal-initramfs.img'):
                continue
            path=self.path(name);self.trusted(path,missing=True)
            self._validate_existing(config,fleet,kernel,{path:data})
            self._stage_write(journal,path,data);paths.append(path)
        image=self.path(artifacts.initrd_path);self.trusted(image,missing=True)
        image.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
        fd,name=tempfile.mkstemp(prefix='.vbios-',suffix='.img',dir=image.parent);os.close(fd);temp=Path(name)
        activation=workspace/'activation.conf';force=workspace/'force.conf'
        atomic_write(activation,plan['activation_bytes']);atomic_write(force,FORCE_BYTES)
        try:
            if hasattr(self.ops,'portable_initramfs'):
                evidence=self.ops.portable_initramfs(kernel,temp,list(targets),activation_config=activation,force_config=force,config=config.raw)
                extracted=self.ops.portable_extract(temp,[*evidence,*[str(p.relative_to(self.root)) for p in targets]])
            else:
                evidence=initramfs.build(self.ops,kernel,temp,list(targets),activation_config=activation,force_config=force,config=config.raw)
                expected={**evidence,**{str(p.relative_to(self.root)):data for p,data in targets.items()}}
                extracted=initramfs.extract(self.ops,temp,list(expected),config=config.raw)
            expected={**evidence,**{str(p.relative_to(self.root)):data for p,data in targets.items()}}
            if evidence.get(ACTIVATION_PATH)!=plan['activation_bytes'] or any(extracted.get(k)!=v for k,v in expected.items()):
                raise LifecycleError('portable initramfs lacks exact activation/module/firmware/early-load bytes')
            image_bytes = temp.read_bytes()
            self._validate_existing(config, fleet, kernel, {image: image_bytes})
            self._stage_write(journal,image,image_bytes,mode=0o600,prepared_path=temp);paths.append(image)
        finally:
            temp.unlink(missing_ok=True)
        entry=self.path(artifacts.entry_path);self.trusted(entry,missing=True)
        entry.parent.mkdir(parents=True,exist_ok=True,mode=0o755)
        if self.boot.backend=='uki':
            fd,name=tempfile.mkstemp(prefix='.vbios-',suffix='.efi',dir=entry.parent);os.close(fd);temporary=Path(name)
            combined=workspace/'uki-initrd.img'
            atomic_write(combined,b''.join(self.path(p).read_bytes() for p in artifacts.supplemental_paths)+image.read_bytes())
            try:
                builder=getattr(self.ops,'portable_build_uki',None)
                if builder:
                    builder(self.path(artifacts.kernel_path),combined,temporary,cmdline=plan['boot_entry'].options,config=config.raw)
                else:
                    initramfs.build_uki(self.ops,self.path(artifacts.kernel_path),combined,temporary,cmdline=plan['boot_entry'].options,config=config.raw)
                entry_bytes = temporary.read_bytes()
                self._validate_existing(config, fleet, kernel, {entry: entry_bytes})
                self._stage_write(journal,entry,entry_bytes,mode=0o600,prepared_path=temporary)
            finally:
                temporary.unlink(missing_ok=True)
        else:
            entry_bytes = self.boot.render(plan['boot_entry'],artifacts)
            self._validate_existing(config, fleet, kernel, {entry: entry_bytes})
            self._stage_write(journal,entry,entry_bytes)
        paths.append(entry)
        shared={}
        if self.boot.backend=='grub':
            ids=[record['managed_id'] for record in fleet.get('boot_generations',{}).values() if record.get('state')!='removed']
            ids.append(plan['managed_id'])
            for name,data in self.boot.visibility_files(sorted(set(ids))).items():
                self._shared(journal,name,data,fleet,mode=0o755 if name.startswith('/etc/grub.d/') else 0o644)
                shared[name]=digest(data)
            try:self.boot.validate_visibility()
            except LifecycleError:
                if not hasattr(self.ops,'_run'):
                    raise
                existing_menu = self.path(self.boot.grub_config).read_bytes()
                if b'automatically generated by grub-mkconfig' not in existing_menu:
                    raise LifecycleError('custom GRUB config needs an explicit nvidia-vbios include; refusing regeneration')
                generated=workspace/'grub.cfg'
                self.ops._run(['grub-mkconfig','-o',generated],timeout=300)
                self.ops._run(['grub-script-check',generated])
                self._shared(journal,self.boot.grub_config,generated.read_bytes(),fleet,mutable=True)
                self.boot.validate_visibility()
        return {'paths':paths,'normal_fallback':plan['normal_boot'],
                'boot_files':[{'path':'/'+str(p.relative_to(self.root)),'sha256':hash_file(p)} for p in paths],
                'roles':artifacts.roles,'shared_boot_files':shared,
                'force_driver_sha256':digest(b''.join(evidence[k] for k in sorted(evidence)))}

    def _record_boot_publication(self,fleet,plan,publication,deployment):
        generations=fleet.setdefault('boot_generations',{})
        generations[plan['entry']]={'kernel':plan['kernel'],'managed_id':plan['managed_id'],
            'backend':self.boot.backend,'boot':self.boot.config,'files':publication['boot_files'],
            'roles':publication['roles'],'created_ns':time.time_ns(),'state':'active'}
        fleet['shared_boot_files']=dict(fleet.get('shared_boot_files',{}),**publication['shared_boot_files'])

    def _prune_removed_kernels(self):
        # Portable boot generations own kernel copies; OS package removal does not remove them.
        return []

    def _retain_boots(self,status,config):
        from .portable_retention import prune
        try:
            result=prune(self,status,config.raw.get('retain_boot_generations',3))
            status['retention']=result
        except (LifecycleError,OSError,ValueError,KeyError) as exc:
            status.setdefault('cleanup_warnings',[]).append(str(exc))
