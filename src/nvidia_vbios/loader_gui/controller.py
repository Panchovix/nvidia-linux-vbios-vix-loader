"""State of the Linux loader window: per-GPU choices, driver source, blockers, exact commands and texts. No GTK.

probe.py reads the system without a password. Load runs `nvbios system setup --progress`, Remove runs
`disable` and Details runs `status`, each through one pkexec prompt (runner.py). gui.py only draws.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import time

import nvidia_vbios
from ..driver import inspect_source
from ..bootstrap import BootstrapError
from ..families import GA100_DEVICE_IDS, architecture
from ..onboarding import payload_for
from ..payload import MAX_SIZE, PayloadError, check_loadable_payload, optional_editor
from ..system_setup import EDITOR_MARKER, RELOCATIONS
from .runner import PKEXEC, classify, sudo_text

INSTALLED = '/usr/local/bin/nvbios'
REBOOT = ['/usr/bin/systemctl', 'reboot']
LANGUAGES = (('en', 'English'), ('es', 'Español'))
SOURCE_MODES = ('keep', 'download', 'folder')
GPU_MODES = ('keep', 'new', 'own')

STRINGS = {
    'en': {
        'title': 'Linux VBIOS Vix Loader',
        'refresh': 'Refresh',
        'language': 'Language',
        'details': 'Details… (asks for the password)',
        'status': 'Status',
        'gpus': 'GPUs and VBIOS files',
        'source': 'NVIDIA driver source',
        'messages': 'Messages',
        'load': 'Load',
        'remove': 'Remove override',
        'choose': 'Choose…',
        'file_types': 'VBIOS payloads',
        'file_title': 'VBIOS payload for GPU {index}',
        'folder_title': 'NVIDIA open-gpu-kernel-modules folder',
        'file_placeholder': 'Path of the payload file',
        'folder_placeholder': 'Path of the source folder',
        'mode_keep': 'Keep the current file',
        'mode_new': 'New file',
        'mode_own': 'Own VBIOS (no override)',
        'gpu_title': '#{index} {name}',
        'gpu_line': '{bdf} · VBIOS {vbios}',
        'now_requested': 'Now: override requested at boot ({sha})',
        'now_own': 'Now: own VBIOS',
        'now_prepared': 'Now: prepared ({sha}), reboot to load it',
        'check_keep': 'Keeps the file enrolled now; it is checked again after the password.',
        'check_own': 'No override: this GPU starts with its own VBIOS.',
        'check_choose': 'Choose a payload file.',
        'check_ok': 'OK: {family}, {size} bytes, sha256 {sha}…',
        'check_serial': 'The file holds the serial number of GPU {index}: make sure it is meant for this card.',
        'refused': 'Refused: {reason}',
        'reason': '{reason}',
        'cannot_read': 'cannot read {path}: {error}',
        'too_big': 'the file is larger than 4 MiB; the loader accepts 512 B to 4 MiB',
        'portal': '{path} exists only for this session (a file portal path); choose it from its real folder',
        'not_folder': '{path} is not a folder',
        'source_keep': 'Use the source saved at the last Load ({version})',
        'source_download': 'Download open-gpu-kernel-modules {version} from GitHub (about 26 MB)',
        'note_compared': 'compared with the distribution\'s copy before use',
        'note_trusted': 'no distribution copy to compare with: trusted on GitHub\'s HTTPS',
        'source_folder': 'Use a folder:',
        'p2p': 'This folder has the P2P patches (keep them after updates)',
        'source_ok': 'OK: {version}, supported, not patched',
        'source_choose': 'Choose the folder.',
        'source_none': 'The installed driver version is unknown.',
        'source_mismatch': 'the folder has {found}, the installed driver is {version}',
        'source_patched': 'the folder is already patched; use an unpatched copy',
        'source_unsupported': 'unsupported source: {reasons}',
        'source_unavailable': 'this option is not available now',
        'row_loader': 'Loader', 'row_driver': 'NVIDIA driver', 'row_kernel': 'Kernel', 'row_secure_boot': 'Secure Boot',
        'row_boot': 'Boot', 'row_hook': 'Package hook',
        'loader_none': 'Not installed',
        'loader_installed': 'Installed (release {release}…), automatic rebuilds {state}',
        'loader_differs': 'installed release differs from this clone',
        'on': 'on', 'off': 'off', 'yes': 'yes', 'no': 'no', 'unknown': 'unknown',
        'driver_value': '{version}, {modules}, {by}',
        'driver_unknown': 'not found',
        'driver_pending': 'installed {installed}, running {loaded}: reboot pending or post-install needed',
        'modules_open': 'open kernel modules',
        'modules_proprietary': 'proprietary kernel modules',
        'modules_none': 'kernel module not loaded',
        'by_manual': 'installed with the .run installer (manual)',
        'by_package': 'installed with {provider}',
        'by_unknown': 'install type unknown',
        'kernel_headers': '{kernel} (headers installed)',
        'kernel_no_headers': '{kernel} (headers missing: install kernel-devel)',
        'kernel_older': '{kernel}; the newest installed kernel is {newest}',
        'sb_off': 'off', 'sb_on': 'on: Load from this window is not supported',
        'grub_ok': 'GRUB saved default with BLS',
        'grub_bad': 'GRUB is not set to the saved default with BLS',
        'grub_none': 'no /etc/default/grub',
        'boot_free': '{grub}, /boot free {free} MB',
        'boot_low': '{grub}, /boot free {free} MB (about {needed} MB needed)',
        'hook_ok': 'plugin installed',
        'hook_missing': 'plugin missing (libdnf5-plugin-actions)',
        'sum_running': 'A loader command is still running ({verbs}).',
        'sum_service': 'Automatic rebuild running (kernel or driver update). Wait until it finishes.',
        'sum_no_gpu': 'No NVIDIA GPU found.',
        'sum_not_installed': 'Not installed. Choose a file per GPU and press Load.',
        'sum_requested': 'Override requested at boot on GPU {gpus}.',
        'sum_removed': 'Removed. Reboot to return to the normal VBIOS.',
        'sum_prepared': 'Prepared for this kernel. Reboot to load it (or you started the normal entry).',
        'sum_not_built': 'Automatic rebuilds are on, but nothing is built for kernel {kernel} yet. Use Details.',
        'sum_old_entries': 'No override; automatic rebuilds off; older override entries stay in the boot menu.',
        'sum_none': 'No override.',
        'blk_busy': 'Wait until the current task finishes.',
        'blk_running': 'A loader command is running ({verbs}); wait until it finishes.',
        'blk_service': 'An automatic rebuild is running; wait until it finishes.',
        'blk_platform': 'Load from this window works on Fedora and the RHEL family only (this system: {distribution}); '
                        'use the command line (README).',
        'blk_secure_boot': 'Secure Boot is on: Load from this window is not supported. Use the command line with your '
                           'module signing key (README).',
        'blk_kernel': 'The running kernel {kernel} is not the newest installed one ({newest}): start {newest} first.',
        'blk_headers': 'The kernel headers for {kernel} are missing: install kernel-devel.',
        'blk_proprietary': 'The proprietary NVIDIA kernel modules are loaded; the override needs the open modules.',
        'blk_no_driver': 'No NVIDIA kernel module is loaded.',
        'blk_no_gpu': 'No NVIDIA GPU found.',
        'blk_smi': 'nvidia-smi does not answer, so the GPUs cannot be matched.',
        'blk_no_device': 'Choose a file (or keep the current one) for at least one GPU. To go back to the normal VBIOS '
                         'on every GPU, use Remove override.',
        'blk_file': 'GPU {index}: {reason}',
        'blk_source': 'Driver source: {reason}',
        'blk_userspace': 'The installed NVIDIA userspace (version or install type) is unknown.',
        'blk_plugin': 'The package hook plugin that automatic rebuilds need is missing (libdnf5-plugin-actions).',
        'blk_grub': 'Set GRUB_DEFAULT=saved and GRUB_ENABLE_BLSCFG=true in /etc/default/grub.',
        'blk_launcher': 'The loader is not installed and this window does not run from a clone with the setup '
                        'helper: start ./vbios-loader-gui from the clone.',
        'blk_flavor': 'The installed loader is a different build (internal or public) than this clone: update it '
                      'from the command line (README, "Updating").',
        'confirm_load_title': 'Load the VBIOS override?',
        'confirm_remove_title': 'Remove the override?',
        'cancel': 'Cancel',
        'cl_new': 'GPU {index} {name} ({bdf}): {path}, {family}, {size} bytes',
        'cl_keep': 'GPU {index} {name} ({bdf}): keeps its current override file',
        'cl_own': 'GPU {index} {name} ({bdf}): goes back to its own VBIOS',
        'cl_absent': 'GPU {bdf} (not in this machine now): its enrolled override is removed',
        'cl_source_keep': 'Driver source: the copy saved at the last Load ({version}).',
        'cl_source_download': 'Driver source: download {version} from GitHub ({note}).',
        'cl_source_folder': 'Driver source: {path}.',
        'cl_source_p2p': 'Driver source: {path}, with the P2P patches kept after updates.',
        'cl_steps': 'Then: check the files and the system,{install} build for kernel {kernel} (a few minutes), make '
                    'the override entry the default boot entry and turn on automatic rebuilds after kernel updates.',
        'cl_install': ' install the loader,',
        'cl_normal': 'Your normal boot entry stays in the menu and never loads the override.',
        'cl_card': 'Only the vendor and device IDs are checked: make sure each file is for that exact card.',
        'cl_password': 'Your password is asked once.',
        'risk': 'A modified VBIOS can damage hardware. If the GPU does not start, pick your normal entry in the boot '
                'menu (press Esc or hold Shift while the computer starts), then press Remove override here.',
        'confirm_remove': 'The normal entry becomes the default and automatic rebuilds stop.\n\nThe override entry '
                          'stays in the boot menu (you can still pick it by hand). The built modules stay installed; '
                          'the normal entry does not load the override. There is no uninstall.\n\nReboot to return to '
                          'the stock VBIOS. Your password is asked once.',
        'step_download': 'Downloading the NVIDIA source {version}',
        'step_prepare': 'Checking the files and the system',
        'step_preflight': 'Checking the boot setup',
        'step_disable': 'Turning off automatic rebuilds',
        'step_install': 'Installing the loader',
        'step_enroll': 'Saving the configuration and a copy of the driver source',
        'step_reconcile': 'Building for kernel {kernel}',
        'step_enable': 'Turning on automatic rebuilds',
        'phase_source': 'copying and patching the driver source',
        'phase_build': 'building the NVIDIA modules (a few minutes)',
        'phase_initramfs': 'building the boot image',
        'phase_boot-entry': 'adding the boot entry',
        'progress': 'Step {index}/{total} · {step}',
        'waiting': 'Waiting for the password…',
        'working': 'Working…',
        'running': '$ {command}',
        'step_done': '{step}: done',
        'note': 'Note: {message}',
        'close_busy': 'Wait until it finishes; closing the window would not stop it.',
        'load_done': 'Load finished for kernel {kernel}.',
        'done_new': 'GPU {bdf}: new file, {architecture}, sha256 {sha}…',
        'done_kept': 'GPU {bdf}: current file kept, {architecture}, sha256 {sha}…',
        'default_selected': 'The override entry {entry} is the default boot entry now.',
        'default_preserved': 'The default boot entry was not changed ({reason}): pick the override entry in the boot '
                             'menu.',
        'reboot_title': 'Reboot now?',
        'reboot_load': 'Reboot to load the override. Your normal boot entry stays in the boot menu and never loads '
                       'the override. If the GPU does not start, choose the normal entry in the boot menu (press Esc '
                       'or hold Shift while the computer starts), then press Remove override here.',
        'reboot_remove': 'Reboot to return to the stock VBIOS.',
        'reboot_wait': 'An automatic rebuild is running and blocks the reboot; reboot when it finishes.',
        'later': 'Later',
        'reboot_now': 'Reboot now',
        'reboot_failed': 'The reboot was refused (exit code {code}): {detail}',
        'failed_at': 'Load failed at "{step}": {message}',
        'failed': 'Load failed: {message}',
        'state_nothing': 'Nothing was changed.',
        'state_rolled_back': 'The step undid its own changes; automatic rebuilds are off and the normal entry stays '
                             'the default.',
        'state_cleaned': 'Remove ran after the failure: the normal entry is the default and automatic rebuilds are '
                         'off.',
        'cleanup_failed': 'The cleanup after the failure failed as well ({message}): the system may still start the '
                          'override by default. Press Remove override, then Details.',
        'state_unknown': 'The state is unknown: press Refresh, then Details.',
        'cancelled': 'The password dialog was closed; nothing was changed.',
        'no_agent': 'No password dialog is available (no polkit agent). Run this in a terminal instead:',
        'not_authorized': 'Not authorized. Run this in a terminal as an administrator instead:',
        'pkexec_error': 'pkexec failed: {detail}',
        'usage': 'The command was rejected (a bug in this window): {detail}',
        'crash': 'Unexpected error (exit code {code}): {detail}',
        'no_result': 'The command ended without a result.',
        'removed_normal': 'Removed: automatic rebuilds are off and the normal entry is the default again.',
        'removed_preserved': 'Removed: automatic rebuilds are off; the default boot entry was not changed ({reason}).',
        'removed_none': 'Automatic rebuilds are off; nothing was enrolled.',
        'remove_failed': 'Remove failed: {message}',
        'details_failed': 'Details failed: {message}',
        'd_installed': 'Installed: {value}',
        'd_enrolled': 'Enrolled: {value}',
        'd_ready': 'Ready for the running kernel: {value}',
        'd_triggers': 'Automatic rebuilds: {value}',
        'd_attempt': 'Last build: {state}, {finished}',
        'd_error': 'Last build error: {error}',
        'd_drift': 'The driver changed; register its source with: sudo {command}',
        'd_fetch': 'Source download: {state}',
        'd_activation': 'Loaded module parameters match the enrollment: {value}',
        'hint_lock': 'Another loader task or an automatic rebuild is running; try again in a few minutes.',
        'hint_fallback': 'Several normal boot entries match this kernel: use the command line with --fallback-entry.',
        'hint_version': 'Choose the source of the installed driver version.',
        'hint_headers': 'Install kernel-devel for the running kernel.',
        'hint_secure_boot': 'Secure Boot is on: use the command line with your module signing key (README).',
        'hint_plugin': 'Install libdnf5-plugin-actions.',
        'hint_manual': 'The install type was detected wrong; use the command line with --userspace manual.',
        'hint_grub': 'Set GRUB_DEFAULT=saved and GRUB_ENABLE_BLSCFG=true in /etc/default/grub.',
        'hint_retry': 'Internal error; try again.',
        'hint_default': 'The default boot entry is not the normal entry of this kernel: start the normal entry of the '
                        'newest kernel, then Load again.',
        'hint_pending': 'A one-time boot entry is pending (grub2-reboot): reboot once, then Load again.',
        'hint_unnamed': 'Press Refresh, then choose for every GPU whether it keeps its file.',
        'hint_migration': 'Use the command-line steps of the README once; the window works after that.',
        'hint_preserved': 'Your boot menu default was respected; make the normal entry the default, then Load again.',
        'hint_remove_first': 'Press Remove override, then Load again.',
        'hint_mixed': 'The NVIDIA userspace mixes package and .run files; reinstall the driver one way.',
        'hint_smi': 'nvidia-smi does not work: check the driver, then press Refresh.',
        'hint_identity': 'A GPU identity is unavailable (a riser or an Xid 79?): check nvidia-smi and the kernel log.',
        'hint_global': 'An older global override setting in /etc/modprobe.d must be removed first.',
    },
    'es': {
        'title': 'Linux VBIOS Vix Loader',
        'refresh': 'Actualizar',
        'language': 'Idioma',
        'details': 'Detalles… (pide la contraseña)',
        'status': 'Estado',
        'gpus': 'GPUs y archivos VBIOS',
        'source': 'Código fuente del driver NVIDIA',
        'messages': 'Mensajes',
        'load': 'Cargar',
        'remove': 'Quitar override',
        'choose': 'Elegir…',
        'file_types': 'Payloads VBIOS',
        'file_title': 'Payload VBIOS para la GPU {index}',
        'folder_title': 'Carpeta de open-gpu-kernel-modules de NVIDIA',
        'file_placeholder': 'Ruta del archivo payload',
        'folder_placeholder': 'Ruta de la carpeta del código fuente',
        'mode_keep': 'Mantener el archivo actual',
        'mode_new': 'Archivo nuevo',
        'mode_own': 'VBIOS propia (sin override)',
        'gpu_title': '#{index} {name}',
        'gpu_line': '{bdf} · VBIOS {vbios}',
        'now_requested': 'Ahora: override pedido al arrancar ({sha})',
        'now_own': 'Ahora: VBIOS propia',
        'now_prepared': 'Ahora: preparado ({sha}), reinicia para cargarlo',
        'check_keep': 'Mantiene el archivo inscrito ahora; se vuelve a revisar después de la contraseña.',
        'check_own': 'Sin override: esta GPU arranca con su propia VBIOS.',
        'check_choose': 'Elige un archivo payload.',
        'check_ok': 'Válido: {family}, {size} bytes, sha256 {sha}…',
        'check_serial': 'El archivo contiene el número de serie de la GPU {index}: asegúrate de que sea para esta '
                        'tarjeta.',
        'refused': 'Rechazado: {reason}',
        'reason': '{reason}',
        'cannot_read': 'no se puede leer {path}: {error}',
        'too_big': 'el archivo pesa más de 4 MiB; el loader acepta de 512 B a 4 MiB',
        'portal': '{path} solo existe en esta sesión (una ruta del portal de archivos); elígelo desde su carpeta real',
        'not_folder': '{path} no es una carpeta',
        'source_keep': 'Usar el código guardado en la última carga ({version})',
        'source_download': 'Descargar open-gpu-kernel-modules {version} desde GitHub (unos 26 MB)',
        'note_compared': 'se compara con la copia de la distribución antes de usarlo',
        'note_trusted': 'no hay copia de la distribución para comparar: se confía en el HTTPS de GitHub',
        'source_folder': 'Usar una carpeta:',
        'p2p': 'Esta carpeta tiene los parches P2P (mantenerlos tras las actualizaciones)',
        'source_ok': 'Válido: {version}, soportado, sin parchear',
        'source_choose': 'Elige la carpeta.',
        'source_none': 'No se conoce la versión del driver instalado.',
        'source_mismatch': 'la carpeta tiene {found} y el driver instalado es {version}',
        'source_patched': 'la carpeta ya está parcheada; usa una copia sin parchear',
        'source_unsupported': 'código fuente no soportado: {reasons}',
        'source_unavailable': 'esta opción no está disponible ahora',
        'row_loader': 'Loader', 'row_driver': 'Driver NVIDIA', 'row_kernel': 'Kernel', 'row_secure_boot': 'Secure Boot',
        'row_boot': 'Arranque', 'row_hook': 'Hook de paquetes',
        'loader_none': 'No instalado',
        'loader_installed': 'Instalado (release {release}…), recompilaciones automáticas {state}',
        'loader_differs': 'el release instalado no coincide con este clon',
        'on': 'activadas', 'off': 'desactivadas', 'yes': 'sí', 'no': 'no', 'unknown': 'desconocido',
        'driver_value': '{version}, {modules}, {by}',
        'driver_unknown': 'no encontrado',
        'driver_pending': 'instalado {installed}, en uso {loaded}: falta reiniciar o ejecutar post-install',
        'modules_open': 'módulos abiertos del kernel',
        'modules_proprietary': 'módulos propietarios del kernel',
        'modules_none': 'módulo del kernel sin cargar',
        'by_manual': 'instalado con el instalador .run (manual)',
        'by_package': 'instalado con {provider}',
        'by_unknown': 'tipo de instalación desconocido',
        'kernel_headers': '{kernel} (headers instalados)',
        'kernel_no_headers': '{kernel} (faltan los headers: instala kernel-devel)',
        'kernel_older': '{kernel}; el kernel instalado más nuevo es {newest}',
        'sb_off': 'desactivado', 'sb_on': 'activado: Cargar desde esta ventana no está soportado',
        'grub_ok': 'GRUB con entrada guardada y BLS',
        'grub_bad': 'GRUB no usa la entrada guardada con BLS',
        'grub_none': 'no existe /etc/default/grub',
        'boot_free': '{grub}, /boot libre {free} MB',
        'boot_low': '{grub}, /boot libre {free} MB (se necesitan unos {needed} MB)',
        'hook_ok': 'plugin instalado',
        'hook_missing': 'falta el plugin (libdnf5-plugin-actions)',
        'sum_running': 'Todavía se está ejecutando un comando del loader ({verbs}).',
        'sum_service': 'Recompilación automática en curso (actualización del kernel o del driver). Espera a que '
                       'termine.',
        'sum_no_gpu': 'No se encontró ninguna GPU NVIDIA.',
        'sum_not_installed': 'No instalado. Elige un archivo por GPU y pulsa Cargar.',
        'sum_requested': 'Override pedido al arrancar en la GPU {gpus}.',
        'sum_removed': 'Quitado. Reinicia para volver a la VBIOS normal.',
        'sum_prepared': 'Preparado para este kernel. Reinicia para cargarlo (o arrancaste la entrada normal).',
        'sum_not_built': 'Las recompilaciones automáticas están activadas, pero aún no hay nada compilado para el '
                         'kernel {kernel}. Usa Detalles.',
        'sum_old_entries': 'Sin override; recompilaciones automáticas desactivadas; las entradas de override '
                           'anteriores siguen en el menú de arranque.',
        'sum_none': 'Sin override.',
        'blk_busy': 'Espera a que termine la tarea en curso.',
        'blk_running': 'Se está ejecutando un comando del loader ({verbs}); espera a que termine.',
        'blk_service': 'Hay una recompilación automática en curso; espera a que termine.',
        'blk_platform': 'Cargar desde esta ventana solo funciona en Fedora y la familia RHEL (este sistema: '
                        '{distribution}); usa la línea de comandos (README).',
        'blk_secure_boot': 'Secure Boot está activado: Cargar desde esta ventana no está soportado. Usa la línea de '
                           'comandos con tu clave para firmar módulos (README).',
        'blk_kernel': 'El kernel en uso {kernel} no es el más nuevo instalado ({newest}): arranca primero {newest}.',
        'blk_headers': 'Faltan los headers del kernel {kernel}: instala kernel-devel.',
        'blk_proprietary': 'Están cargados los módulos propietarios de NVIDIA; el override necesita los módulos '
                           'abiertos.',
        'blk_no_driver': 'No hay ningún módulo NVIDIA del kernel cargado.',
        'blk_no_gpu': 'No se encontró ninguna GPU NVIDIA.',
        'blk_smi': 'nvidia-smi no responde, así que no se pueden identificar las GPUs.',
        'blk_no_device': 'Elige un archivo (o mantén el actual) para al menos una GPU. Para volver a la VBIOS normal '
                         'en todas las GPUs, usa Quitar override.',
        'blk_file': 'GPU {index}: {reason}',
        'blk_source': 'Código fuente del driver: {reason}',
        'blk_userspace': 'No se conoce el userspace NVIDIA instalado (versión o tipo de instalación).',
        'blk_plugin': 'Falta el plugin del hook de paquetes que necesitan las recompilaciones automáticas '
                      '(libdnf5-plugin-actions).',
        'blk_grub': 'Define GRUB_DEFAULT=saved y GRUB_ENABLE_BLSCFG=true en /etc/default/grub.',
        'blk_launcher': 'El loader no está instalado y esta ventana no se ejecuta desde un clon con el asistente de '
                        'instalación: abre ./vbios-loader-gui desde el clon.',
        'blk_flavor': 'El loader instalado es otra compilación (interna o pública) que este clon: actualízalo desde '
                      'la línea de comandos (README, "Actualizar").',
        'confirm_load_title': '¿Cargar la VBIOS de override?',
        'confirm_remove_title': '¿Quitar el override?',
        'cancel': 'Cancelar',
        'cl_new': 'GPU {index} {name} ({bdf}): {path}, {family}, {size} bytes',
        'cl_keep': 'GPU {index} {name} ({bdf}): mantiene su archivo de override actual',
        'cl_own': 'GPU {index} {name} ({bdf}): vuelve a su propia VBIOS',
        'cl_absent': 'GPU {bdf} (no está en este equipo ahora): se quita su override registrado',
        'cl_source_keep': 'Código fuente del driver: la copia guardada en la última carga ({version}).',
        'cl_source_download': 'Código fuente del driver: descargar {version} desde GitHub ({note}).',
        'cl_source_folder': 'Código fuente del driver: {path}.',
        'cl_source_p2p': 'Código fuente del driver: {path}, manteniendo los parches P2P tras las actualizaciones.',
        'cl_steps': 'Luego: revisar los archivos y el sistema,{install} compilar para el kernel {kernel} (unos '
                    'minutos), dejar la entrada de override como predeterminada y activar las recompilaciones '
                    'automáticas tras actualizaciones del kernel.',
        'cl_install': ' instalar el loader,',
        'cl_normal': 'Tu entrada de arranque normal sigue en el menú y nunca carga el override.',
        'cl_card': 'Solo se revisan los IDs de fabricante y dispositivo: asegúrate de que cada archivo sea para esa '
                   'tarjeta exacta.',
        'cl_password': 'La contraseña se pide una sola vez.',
        'risk': 'Una VBIOS modificada puede dañar el hardware. Si la GPU no arranca, elige tu entrada normal en el '
                'menú de arranque (pulsa Esc o mantén Shift mientras el equipo arranca) y luego pulsa Quitar '
                'override aquí.',
        'confirm_remove': 'La entrada normal queda como predeterminada y se detienen las recompilaciones '
                          'automáticas.\n\nLa entrada de override sigue en el menú de arranque (puedes elegirla a '
                          'mano). Los módulos compilados quedan instalados; la entrada normal no carga el override. '
                          'No hay desinstalación.\n\nReinicia para volver a la VBIOS de fábrica. La contraseña se pide '
                          'una sola vez.',
        'step_download': 'Descargando el código fuente de NVIDIA {version}',
        'step_prepare': 'Revisando los archivos y el sistema',
        'step_preflight': 'Revisando la configuración de arranque',
        'step_disable': 'Desactivando las recompilaciones automáticas',
        'step_install': 'Instalando el loader',
        'step_enroll': 'Guardando la configuración y una copia del código fuente del driver',
        'step_reconcile': 'Compilando para el kernel {kernel}',
        'step_enable': 'Activando las recompilaciones automáticas',
        'phase_source': 'copiando y parcheando el código fuente del driver',
        'phase_build': 'compilando los módulos NVIDIA (unos minutos)',
        'phase_initramfs': 'creando la imagen de arranque',
        'phase_boot-entry': 'agregando la entrada de arranque',
        'progress': 'Paso {index}/{total} · {step}',
        'waiting': 'Esperando la contraseña…',
        'working': 'Trabajando…',
        'running': '$ {command}',
        'step_done': '{step}: listo',
        'note': 'Nota: {message}',
        'close_busy': 'Espera a que termine; cerrar la ventana no lo detendría.',
        'load_done': 'Carga terminada para el kernel {kernel}.',
        'done_new': 'GPU {bdf}: archivo nuevo, {architecture}, sha256 {sha}…',
        'done_kept': 'GPU {bdf}: se mantuvo el archivo actual, {architecture}, sha256 {sha}…',
        'default_selected': 'La entrada de override {entry} es ahora la entrada de arranque predeterminada.',
        'default_preserved': 'La entrada de arranque predeterminada no cambió ({reason}): elige la entrada de override '
                             'en el menú de arranque.',
        'reboot_title': '¿Reiniciar ahora?',
        'reboot_load': 'Reinicia para cargar el override. Tu entrada de arranque normal sigue en el menú y nunca carga '
                       'el override. Si la GPU no arranca, elige la entrada normal en el menú de arranque (pulsa Esc '
                       'o mantén Shift mientras el equipo arranca) y luego pulsa Quitar override aquí.',
        'reboot_remove': 'Reinicia para volver a la VBIOS de fábrica.',
        'reboot_wait': 'Hay una recompilación automática en curso que bloquea el reinicio; reinicia cuando termine.',
        'later': 'Más tarde',
        'reboot_now': 'Reiniciar ahora',
        'reboot_failed': 'Se rechazó el reinicio (código de salida {code}): {detail}',
        'failed_at': 'La carga falló en "{step}": {message}',
        'failed': 'La carga falló: {message}',
        'state_nothing': 'No se cambió nada.',
        'state_rolled_back': 'El paso deshizo sus propios cambios; las recompilaciones automáticas están desactivadas '
                             'y la entrada normal sigue como predeterminada.',
        'state_cleaned': 'Tras el fallo se ejecutó Quitar override: la entrada normal es la predeterminada y las '
                         'recompilaciones automáticas están desactivadas.',
        'cleanup_failed': 'La limpieza tras el fallo también falló ({message}): el sistema podría seguir arrancando '
                          'el override por defecto. Pulsa Quitar override y luego Detalles.',
        'state_unknown': 'No se conoce el estado: pulsa Actualizar y luego Detalles.',
        'cancelled': 'Se cerró el diálogo de contraseña; no se cambió nada.',
        'no_agent': 'No hay diálogo de contraseña disponible (sin agente de polkit). Ejecuta esto en una terminal:',
        'not_authorized': 'Sin autorización. Ejecuta esto en una terminal como administrador:',
        'pkexec_error': 'pkexec falló: {detail}',
        'usage': 'Se rechazó el comando (un error de esta ventana): {detail}',
        'crash': 'Error inesperado (código de salida {code}): {detail}',
        'no_result': 'El comando terminó sin resultado.',
        'removed_normal': 'Quitado: las recompilaciones automáticas están desactivadas y la entrada normal vuelve a '
                          'ser la predeterminada.',
        'removed_preserved': 'Quitado: las recompilaciones automáticas están desactivadas; la entrada de arranque '
                             'predeterminada no cambió ({reason}).',
        'removed_none': 'Las recompilaciones automáticas están desactivadas; no había nada inscrito.',
        'remove_failed': 'Quitar override falló: {message}',
        'details_failed': 'Detalles falló: {message}',
        'd_installed': 'Instalado: {value}',
        'd_enrolled': 'Inscrito: {value}',
        'd_ready': 'Listo para el kernel en uso: {value}',
        'd_triggers': 'Recompilaciones automáticas: {value}',
        'd_attempt': 'Última compilación: {state}, {finished}',
        'd_error': 'Error de la última compilación: {error}',
        'd_drift': 'El driver cambió; registra su código fuente con: sudo {command}',
        'd_fetch': 'Descarga del código fuente: {state}',
        'd_activation': 'Los parámetros del módulo cargado coinciden con la inscripción: {value}',
        'hint_lock': 'Hay otra tarea del loader o una recompilación automática en curso; vuelve a intentarlo en unos '
                     'minutos.',
        'hint_fallback': 'Varias entradas de arranque normales coinciden con este kernel: usa la línea de comandos con '
                         '--fallback-entry.',
        'hint_version': 'Elige el código fuente de la versión del driver instalada.',
        'hint_headers': 'Instala kernel-devel para el kernel en uso.',
        'hint_secure_boot': 'Secure Boot está activado: usa la línea de comandos con tu clave para firmar módulos '
                            '(README).',
        'hint_plugin': 'Instala libdnf5-plugin-actions.',
        'hint_manual': 'Se detectó mal el tipo de instalación; usa la línea de comandos con --userspace manual.',
        'hint_grub': 'Define GRUB_DEFAULT=saved y GRUB_ENABLE_BLSCFG=true en /etc/default/grub.',
        'hint_retry': 'Error interno; vuelve a intentarlo.',
        'hint_default': 'La entrada de arranque predeterminada no es la entrada normal de este kernel: arranca la '
                        'entrada normal del kernel más nuevo y vuelve a Cargar.',
        'hint_pending': 'Hay una entrada de arranque de una sola vez pendiente (grub2-reboot): reinicia una vez y '
                        'vuelve a Cargar.',
        'hint_unnamed': 'Pulsa Actualizar y elige para cada GPU si mantiene su archivo.',
        'hint_migration': 'Usa una vez los pasos de línea de comandos del README; después la ventana funciona.',
        'hint_preserved': 'Se respetó la entrada predeterminada de tu menú de arranque; deja la entrada normal como '
                          'predeterminada y vuelve a Cargar.',
        'hint_remove_first': 'Pulsa Quitar override y vuelve a Cargar.',
        'hint_mixed': 'El userspace NVIDIA mezcla archivos de paquetes y del .run; reinstala el driver de una sola '
                      'forma.',
        'hint_smi': 'nvidia-smi no funciona: revisa el driver y pulsa Actualizar.',
        'hint_identity': 'No está disponible la identidad de una GPU (¿un riser o un Xid 79?): revisa nvidia-smi y el '
                         'log del kernel.',
        'hint_global': 'Primero hay que quitar un ajuste de override global antiguo en /etc/modprobe.d.',
    },
}

# Phrases of the loader's own errors (onboarding, bootstrap, lifecycle, setup) and what to do in this window.
HINTS = (('lock busy', 'hint_lock'), ('reconciliation service is active', 'hint_lock'),
         ('exactly one normal BLS entry', 'hint_fallback'),
         ('match the exact installed userspace version', 'hint_version'), ('kernel-devel missing', 'hint_headers'),
         ('Secure Boot enabled but', 'hint_secure_boot'), ('signing certificate is not enrolled', 'hint_secure_boot'),
         ('plugin prerequisites are unavailable', 'hint_plugin'), ('not RPM-owned', 'hint_manual'),
         ('GRUB saved default', 'hint_grub'), ('output already exists', 'hint_retry'),
         ('foreign or unrelated GRUB default', 'hint_default'), ('another GRUB transition is pending', 'hint_pending'),
         ('not named: choose keep', 'hint_unnamed'), ('depends on a migration', 'hint_migration'),
         ('kept the existing default boot entry', 'hint_preserved'),
         ('disable every enabled/active trigger', 'hint_remove_first'),
         ('manual nvidia-smi and installed libraries', 'hint_mixed'),
         ('NVIDIA-SMI/NVML GPU discovery failed', 'hint_smi'), ('identity unavailable', 'hint_identity'),
         ('global VBIOS activation must be migrated', 'hint_global'))
STEPS = ('download', 'prepare', 'preflight', 'disable', 'install', 'enroll', 'reconcile', 'enable')
# What a failed Load leaves behind, by the step that failed. After a failed enable, setup runs disable and
# reports that cleanup; without that report the state is unknown.
FAILED_STATE = {'download': 'state_nothing', 'prepare': 'state_nothing', 'preflight': 'state_nothing',
                'disable': 'state_unknown', 'install': 'state_rolled_back', 'enroll': 'state_rolled_back',
                'reconcile': 'state_rolled_back'}
# reconcile reports this when its own rollback failed: the state is then unknown.
NOT_ROLLED_BACK = 'could not be rolled back'


def language_from_env(environ=os.environ):
    """'es' when the first set of LC_ALL, LC_MESSAGES and LANG is Spanish, else 'en'."""
    value = next((environ[name] for name in ('LC_ALL', 'LC_MESSAGES', 'LANG') if environ.get(name)), '')
    return 'es' if value.lower().startswith('es') else 'en'


def find_checkout(module=nvidia_vbios.__file__):
    """The clone this window runs from, when it has the nvbios launcher and the setup helper."""
    root = Path(module).resolve().parents[2]
    return root if (root / 'nvbios').is_file() and (root / 'src/nvidia_vbios/system_setup.py').is_file() else None


def _elapsed(seconds):
    seconds = int(seconds)
    return f'{seconds // 60}:{seconds % 60:02d}'


@dataclass
class Choice:
    mode: str = 'own'               # keep, new or own
    path: str = ''
    sha256: str | None = None
    size: int = 0
    family: str | None = None
    error: tuple | None = None      # (STRINGS key, fields): rendered in the current language
    serial_of: int | None = None    # index of another GPU whose serial number the file holds


@dataclass
class Source:
    mode: str | None = None         # keep, download or folder
    path: str = ''
    p2p: bool = False
    version: str | None = None      # version.mk of the folder
    error: tuple | None = None


@dataclass
class Progress:
    steps: tuple = ()
    step: str | None = None
    index: int = 0
    total: int = 0
    phase: str | None = None
    kernel: str = ''
    started: float = 0.0


@dataclass(frozen=True)
class Finish:
    ok: bool
    lines: list
    offer_reboot: bool = False
    reboot_text: str = ''



FULL_ROM_NEEDED = ('this build checks Ada and Ampere files against the edited full ROM: choose the .rom the editor '
                   'saved, not its -loader.bin')


def check_file(data, vendor, device, editor=optional_editor):
    """The check setup's prepare makes: internal builds relocate a new Ada/Ampere file from its full ROM."""
    representation = RELOCATIONS.get(architecture(device)['family'])
    if editor() is None or representation is None or device in GA100_DEVICE_IDS:
        return check_loadable_payload(data, vendor, device)
    try:
        check_loadable_payload(data, vendor, device)
    except PayloadError:
        try:
            return payload_for(data, '<chosen file>', {'bdf': 'the selected GPU', 'vendor': vendor, 'device': device},
                               representation)[1]
        except BootstrapError as exc:
            raise PayloadError(str(exc)) from None
    raise PayloadError(FULL_ROM_NEEDED)


class Controller:
    def __init__(self, language='en', *, checkout=None, check=None, inspect=inspect_source,
                 clock=time.monotonic):
        self.language, self.text = language, STRINGS[language]
        self.checkout = Path(checkout) if checkout else None
        self.check, self.inspect, self.clock = check or check_file, inspect, clock
        self.snapshot = None
        self.choices = {}               # bdf -> Choice
        self.source = Source()
        self.busy = None                # None, refresh, load, remove, details or reboot
        self.progress = Progress()
        self.events = []                # setup's progress events of the running Load
        self.argv = None

    # -- state -------------------------------------------------------------------------------------------------
    def set_language(self, language):
        """Switch the texts; ignored while busy (the running action finishes in its language). True if changed."""
        if self.busy or language == self.language:
            return False
        self.language, self.text = language, STRINGS[language]
        return True

    def apply_snapshot(self, snapshot):
        """Take a new probe result; returns message lines. New GPUs keep their override if one was requested."""
        self.snapshot = snapshot
        if self.busy == 'refresh':
            self.busy = None
        bdfs = {gpu.bdf for gpu in snapshot.gpus}
        self.choices = {bdf: choice for bdf, choice in self.choices.items() if bdf in bdfs}
        for gpu in snapshot.gpus:
            # An enrolled GPU keeps its file by default, also when it is prepared but not booted yet.
            self.choices.setdefault(gpu.bdf, Choice('keep' if gpu.requested or gpu.enrolled else 'own'))
        if self.source.mode is None or not self.source_available(self.source.mode):
            self.source.mode = next((mode for mode in SOURCE_MODES if self.source_available(mode)), 'folder')
        if self.source.path:
            self._check_folder(self.source.path)     # the installed driver version may have changed
        return [self.text['note'].format(message=problem) for problem in snapshot.problems]

    def gpu(self, bdf):
        return next(gpu for gpu in self.snapshot.gpus if gpu.bdf == bdf)

    def set_mode(self, bdf, mode):
        if mode in GPU_MODES and not self.busy:
            self.choices[bdf].mode = mode

    def choose_file(self, bdf, path):
        """Read and check a payload as prepare will: realpath, the kernel's payload rule, sha256 for setup."""
        gpu = self.gpu(bdf)
        real = os.path.realpath(os.path.expanduser(path)) if path else ''
        self.choices[bdf] = choice = Choice('new', real)
        if not real:
            return
        if real.startswith('/run/user/'):   # FUSE/portal paths root cannot read
            choice.error = ('portal', {'path': real})
            return
        try:
            with open(real, 'rb') as stream:
                data = stream.read(MAX_SIZE + 1)
        except OSError as exc:
            choice.error = ('cannot_read', {'path': real, 'error': exc.strerror or exc})
            return
        if len(data) > MAX_SIZE:
            choice.error = ('too_big', {})
            return
        choice.sha256, choice.size = hashlib.sha256(data).hexdigest(), len(data)
        try:
            choice.family = self.check(data, gpu.vendor, gpu.device)
        except PayloadError as exc:
            choice.error = ('reason', {'reason': str(exc)})
            return
        own = gpu.serial is not None and gpu.serial.encode() in data
        choice.serial_of = None if own else next(
            (other.index for other in self.snapshot.gpus if other.bdf != bdf and other.serial
             and other.serial.encode() in data), None)

    def source_available(self, mode):
        system = self.snapshot.system
        if mode == 'keep':
            return system.saved_source
        if mode == 'download':
            return re.fullmatch(r'\d+\.\d+\.\d+', system.installed_version or '') is not None
        return mode == 'folder'

    def choose_source(self, mode, path=None):
        if self.busy or mode not in SOURCE_MODES:
            return
        self.source.mode = mode
        if path is not None:
            self._check_folder(path)

    def _check_folder(self, path):
        real = os.path.realpath(os.path.expanduser(path)) if path else ''
        self.source.path, self.source.version, self.source.error = real, None, None
        if not real:
            return
        if real.startswith('/run/user/'):
            self.source.error = ('portal', {'path': real})
            return
        if not os.path.isdir(real):
            self.source.error = ('not_folder', {'path': real})
            return
        info = self.inspect(real)
        found, installed = info.get('version'), self.snapshot.system.installed_version
        self.source.version = found
        if info.get('capabilities', {}).get('already_patched'):
            self.source.error = ('source_patched', {})
        elif not info.get('supported'):
            self.source.error = ('source_unsupported', {'reasons': '; '.join(info.get('reasons') or ['?'])})
        elif found != installed:
            self.source.error = ('source_mismatch', {'found': found, 'version': installed or '?'})

    def set_p2p(self, value):
        if not self.busy:
            self.source.p2p = bool(value)

    # -- what the window shows -----------------------------------------------------------------------------------
    def _message(self, error):
        key, fields = error
        return self.text[key].format(**fields)

    def summary(self):
        """(level, text) for the bold line at the top: level is ok, warn or error."""
        t, system = self.text, self.snapshot.system
        asked = [gpu for gpu in self.snapshot.gpus if gpu.requested]
        if system.running:
            return 'warn', t['sum_running'].format(verbs=', '.join(system.running))
        if system.service_active:
            return 'warn', t['sum_service']
        if not self.snapshot.gpus:
            return 'error', t['sum_no_gpu']
        if not system.release:
            return 'warn', t['sum_not_installed']
        if asked and system.triggers:
            names = ', '.join(str(gpu.index if gpu.index is not None else gpu.bdf) for gpu in asked)
            return 'ok', t['sum_requested'].format(gpus=names)
        if asked:
            return 'warn', t['sum_removed']
        if system.triggers:
            return 'warn', t['sum_prepared'] if system.images else t['sum_not_built'].format(kernel=system.kernel)
        return 'ok', t['sum_old_entries'] if system.old_images else t['sum_none']

    def system_rows(self):
        """(label, value, level) for the Status grid."""
        t, s = self.text, self.snapshot.system
        rows = []
        if s.release:
            value = t['loader_installed'].format(release=s.release[:8], state=t['on' if s.triggers else 'off'])
            if s.clone_matches is False:
                value += '; ' + t['loader_differs']
            rows.append((t['row_loader'], value, 'ok' if s.clone_matches is not False else 'warn'))
        else:
            rows.append((t['row_loader'], t['loader_none'], 'warn'))
        version = s.installed_version or s.loaded_version
        if version is None:
            rows.append((t['row_driver'], t['driver_unknown'], 'error'))
        elif s.installed_version and s.loaded_version and s.installed_version != s.loaded_version:
            rows.append((t['row_driver'], t['driver_pending'].format(installed=s.installed_version,
                                                                     loaded=s.loaded_version), 'error'))
        else:
            modules = t['modules_none' if s.open_modules is None else 'modules_open' if s.open_modules
                        else 'modules_proprietary']
            by = t['by_manual'] if s.userspace == 'manual' else t['by_unknown'] if s.userspace is None else \
                t['by_package'].format(provider=s.userspace)
            rows.append((t['row_driver'], t['driver_value'].format(version=version, modules=modules, by=by),
                         'ok' if s.open_modules else 'error'))
        if s.newest_kernel and s.newest_kernel != s.kernel:
            rows.append((t['row_kernel'], t['kernel_older'].format(kernel=s.kernel, newest=s.newest_kernel), 'error'))
        else:
            rows.append((t['row_kernel'], t['kernel_headers' if s.headers else 'kernel_no_headers'].format(
                kernel=s.kernel), 'ok' if s.headers else 'error'))
        rows.append((t['row_secure_boot'], t['unknown'] if s.secure_boot is None else t['sb_on' if s.secure_boot
                     else 'sb_off'], 'warn' if s.secure_boot is None else 'error' if s.secure_boot else 'ok'))
        grub = t['grub_none' if s.grub_saved is None else 'grub_ok' if s.grub_saved else 'grub_bad']
        level = 'ok' if s.grub_saved else 'error'
        if s.boot_free is None:
            rows.append((t['row_boot'], grub, level))
        else:
            low = s.boot_needed is not None and s.boot_free < s.boot_needed
            free, needed = s.boot_free // 2 ** 20, (s.boot_needed or 0) // 2 ** 20
            rows.append((t['row_boot'], t['boot_low' if low else 'boot_free'].format(grub=grub, free=free,
                         needed=needed), 'warn' if low and level == 'ok' else level))
        if s.plugin is not None:
            rows.append((t['row_hook'], t['hook_ok' if s.plugin else 'hook_missing'], 'ok' if s.plugin else 'error'))
        return rows

    def gpu_view(self, gpu):
        """Texts and state of one GPU row: title, subtitle, now, mode, path and (level, check line)."""
        t, choice = self.text, self.choices[gpu.bdf]
        index = '?' if gpu.index is None else gpu.index
        if choice.mode == 'own':
            check = 'idle', t['check_own']
        elif choice.mode == 'keep':
            check = 'idle', t['check_keep']
        elif not choice.path:
            check = 'warn', t['check_choose']
        elif choice.error:
            check = 'error', t['refused'].format(reason=self._message(choice.error))
        else:
            text = t['check_ok'].format(family=choice.family, size=choice.size, sha=choice.sha256[:16])
            if choice.serial_of is not None:
                text += ' ' + t['check_serial'].format(index=choice.serial_of)
            check = ('warn' if choice.serial_of is not None else 'ok'), text
        return dict(title=t['gpu_title'].format(index=index, name=gpu.name),
                    subtitle=t['gpu_line'].format(bdf=gpu.bdf, vbios=gpu.vbios or '?'),
                    now=(t['now_prepared'].format(sha=gpu.enrolled) if gpu.enrolled and gpu.enrolled != gpu.requested
                         else t['now_requested'].format(sha=gpu.requested) if gpu.requested else t['now_own']),
                    mode=choice.mode, path=choice.path, check=check)

    def source_view(self):
        """Labels and availability of the three source options, plus (level, check line)."""
        t, system, source = self.text, self.snapshot.system, self.source
        version = system.installed_version or '?'
        note = t['note_compared' if system.distro_source else 'note_trusted']
        labels = {'keep': t['source_keep'].format(version=version),
                  'download': f"{t['source_download'].format(version=version)}\n{note}",
                  'folder': t['source_folder']}
        error = self._source_error()
        if error:
            check = 'error', t['refused'].format(reason=error)
        elif source.mode == 'folder':
            check = 'ok', t['source_ok'].format(version=source.version)
        else:
            check = 'idle', ''
        return dict(mode=source.mode, labels=labels, path=source.path, p2p=source.p2p, check=check,
                    available={mode: self.source_available(mode) for mode in SOURCE_MODES})

    def _source_error(self):
        source, t = self.source, self.text
        if self.snapshot.system.installed_version is None:
            return t['source_none']
        if not self.source_available(source.mode):
            return t['source_unavailable']
        if source.mode != 'folder':
            return None
        if not source.path:
            return t['source_choose']
        return self._message(source.error) if source.error else None

    # -- what Load needs ------------------------------------------------------------------------------------------
    def launcher(self):
        """(nvbios, clone for --repository or None): the installed runtime once it has the setup helper."""
        system = self.snapshot.system
        if system.release and system.release_has_setup:
            return INSTALLED, None
        if self.checkout:
            return str(self.checkout / 'nvbios'), str(self.checkout)
        return None, None

    def load_blockers(self):
        """Why Load is disabled now; empty when it is enabled."""
        if self.snapshot is None:
            return [self.text['blk_busy']]
        t, s = self.text, self.snapshot.system
        found = []
        if self.busy:
            found.append(t['blk_busy'])
        if s.running:
            found.append(t['blk_running'].format(verbs=', '.join(s.running)))
        if s.service_active:
            found.append(t['blk_service'])
        if s.family not in ('fedora', 'rhel'):
            found.append(t['blk_platform'].format(distribution=s.distribution or '?'))
        if s.secure_boot:
            found.append(t['blk_secure_boot'])
        if s.newest_kernel and s.newest_kernel != s.kernel:
            found.append(t['blk_kernel'].format(kernel=s.kernel, newest=s.newest_kernel))
        if not s.headers:
            found.append(t['blk_headers'].format(kernel=s.kernel))
        if not self.snapshot.gpus:
            found.append(t['blk_no_gpu'])
        elif s.open_modules is None:
            found.append(t['blk_no_driver'])
        elif not s.open_modules:
            found.append(t['blk_proprietary'])
        elif not s.smi:
            found.append(t['blk_smi'])
        if s.installed_version is None or s.userspace is None:
            found.append(t['blk_userspace'])
        if s.plugin is False:
            found.append(t['blk_plugin'])
        if s.family in ('fedora', 'rhel') and not s.grub_saved:
            found.append(t['blk_grub'])
        launcher, repository = self.launcher()
        if launcher is None:
            found.append(t['blk_launcher'])
        elif repository and s.release and \
                s.release_internal != (Path(repository) / 'src' / EDITOR_MARKER).is_file():
            found.append(t['blk_flavor'])
        chosen = [self.choices[gpu.bdf] for gpu in self.snapshot.gpus if self.choices[gpu.bdf].mode != 'own']
        if self.snapshot.gpus and not chosen:
            found.append(t['blk_no_device'])
        for gpu in self.snapshot.gpus:
            choice = self.choices[gpu.bdf]
            if choice.mode == 'new' and (choice.error or not choice.sha256):
                found.append(t['blk_file'].format(index='?' if gpu.index is None else gpu.index,
                                                  reason=self.gpu_view(gpu)['check'][1]))
        error = self._source_error()
        if error:
            found.append(t['blk_source'].format(reason=error))
        return found

    def can_load(self):
        return self.snapshot is not None and not self.load_blockers()

    def _quiet(self):
        s = self.snapshot.system if self.snapshot else None
        return s is not None and not self.busy and not s.running and not s.service_active

    def can_remove(self):
        return self._quiet() and self.snapshot.system.release is not None

    def can_details(self):
        return self.snapshot is not None and not self.busy and self.snapshot.system.release is not None

    def can_reboot(self):
        return self._quiet()

    def load_argv(self):
        """The exact pkexec command of the setup contract; absolute real paths only."""
        system = self.snapshot.system
        launcher, repository = self.launcher()
        argv = [*PKEXEC, launcher, 'system', 'setup', '--progress']
        if repository:
            argv += ['--repository', repository]
        argv += ['--kernel', system.kernel, '--userspace', system.userspace]
        for gpu in self.snapshot.gpus:
            choice = self.choices[gpu.bdf]
            if choice.mode == 'new':
                argv += ['--device', gpu.bdf, choice.path, choice.sha256]
            elif choice.mode == 'keep':
                argv += ['--keep', gpu.bdf]
            elif gpu.requested or gpu.enrolled:
                argv += ['--remove', gpu.bdf]
        for bdf in self.snapshot.enrolled_absent:
            argv += ['--remove', bdf]
        if self.source.mode == 'keep':
            argv.append('--keep-source')
        elif self.source.mode == 'download':
            argv += ['--download-source', system.installed_version]
        else:
            argv += ['--driver-source', self.source.path] + (['--p2p-preferred'] if self.source.p2p else [])
        return argv

    def remove_argv(self):
        return [*PKEXEC, INSTALLED, 'system', 'disable']

    def details_argv(self):
        return [*PKEXEC, INSTALLED, 'system', 'status']

    def reboot_argv(self):
        return list(REBOOT)

    def recheck(self):
        """Read every chosen file again: it may have changed since it was checked."""
        for gpu in self.snapshot.gpus:
            choice = self.choices[gpu.bdf]
            if choice.mode == 'new' and choice.path:
                self.choose_file(gpu.bdf, choice.path)

    def confirm_load(self):
        """The question asked before Load, after a fresh check of the files; None when Load is not possible."""
        self.recheck()
        if not self.can_load():
            return None
        t, system = self.text, self.snapshot.system
        parts = []
        for gpu in self.snapshot.gpus:
            choice, index = self.choices[gpu.bdf], '?' if gpu.index is None else gpu.index
            fields = dict(index=index, name=gpu.name, bdf=gpu.bdf)
            if choice.mode == 'new':
                parts.append(t['cl_new'].format(path=choice.path, family=choice.family, size=choice.size, **fields))
            elif choice.mode == 'keep':
                parts.append(t['cl_keep'].format(**fields))
            elif gpu.requested or gpu.enrolled:
                parts.append(t['cl_own'].format(**fields))
        parts += [t['cl_absent'].format(bdf=bdf) for bdf in self.snapshot.enrolled_absent]
        lines = ['\n'.join(parts)]
        version = system.installed_version
        if self.source.mode == 'keep':
            lines.append(t['cl_source_keep'].format(version=version))
        elif self.source.mode == 'download':
            note = t['note_compared' if system.distro_source else 'note_trusted']
            lines.append(t['cl_source_download'].format(version=version, note=note))
        else:
            lines.append(t['cl_source_p2p' if self.source.p2p else 'cl_source_folder'].format(path=self.source.path))
        install = t['cl_install'] if self.launcher()[1] else ''
        lines += [t['cl_steps'].format(install=install, kernel=system.kernel), t['cl_normal'], t['cl_card'],
                  t['cl_password'], t['risk']]
        return '\n\n'.join(lines)

    def confirm_remove(self):
        return self.text['confirm_remove']

    # -- a running action ------------------------------------------------------------------------------------------
    def begin(self, action):
        """Mark busy and return (argv, message lines) for load, remove, details or reboot."""
        argv = {'load': self.load_argv, 'remove': self.remove_argv, 'details': self.details_argv,
                'reboot': self.reboot_argv}[action]()
        self.busy, self.argv, self.events = action, argv, []
        self.progress = Progress(kernel=self.snapshot.system.kernel, started=self.clock())
        return argv, [self.text['running'].format(command=' '.join(argv))]

    def _step_text(self, step):
        key = 'step_' + str(step)
        version = self.snapshot.system.installed_version or '?'
        return self.text[key].format(version=version, kernel=self.progress.kernel) if key in self.text else str(step)

    def on_line(self, line):
        """One stdout line of the running command; returns message lines. Only Load streams events."""
        if self.busy != 'load':
            return []
        try:
            event = json.loads(line)
        except ValueError:
            return [line] if line.strip() else []
        if not isinstance(event, dict):
            return [line]
        self.events.append(event)
        kind, progress = event.get('event'), self.progress
        if kind == 'start':
            progress.steps = tuple(event.get('steps') or ())
            progress.total = len(progress.steps)
            progress.kernel = event.get('kernel') or progress.kernel
        elif kind == 'step':
            step = event.get('step')
            # The position in the announced step list, whatever base `index` uses.
            progress.index = progress.steps.index(step) + 1 if step in progress.steps else int(event.get('index', 0))
            progress.total = progress.total or int(event.get('total', 0))
            progress.step, progress.phase = step, None
            return [self.text['progress'].format(index=progress.index, total=progress.total,
                                                 step=self._step_text(step))]
        elif kind == 'phase':
            progress.phase = event.get('phase')
            return ['  ' + self._phase_text()]
        elif kind == 'result':
            return [self.text['step_done'].format(step=self._step_text(event.get('step')))]
        return []

    def _phase_text(self):
        phase = self.progress.phase
        return self.text.get(f'phase_{phase}', str(phase))

    def progress_text(self):
        """The line beside the spinner: step, phase and elapsed time."""
        if not self.busy or self.busy == 'refresh':
            return ''
        progress, t = self.progress, self.text
        elapsed = _elapsed(self.clock() - progress.started)
        if self.busy != 'load':
            return f"{t['working']} {elapsed}"
        if progress.step is None:
            return f"{t['waiting']} {elapsed}"
        text = t['progress'].format(index=progress.index, total=progress.total, step=self._step_text(progress.step))
        if progress.phase:
            text += ': ' + self._phase_text()
        return f'{text} · {elapsed}'

    def progress_fraction(self):
        progress = self.progress
        return max(progress.index - 1, 0) / progress.total if self.busy == 'load' and progress.total else 0.0

    def _hinted(self, message):
        hint = next((self.text[key] for phrase, key in HINTS if phrase in message), None)
        return f'{message} {hint}' if hint else message

    def finish(self, outcome):
        """The action ended (runner.Outcome); returns a Finish with message lines and the reboot offer."""
        action, self.busy = self.busy, None
        t = self.text
        kind, detail = classify(outcome)
        if action == 'reboot':
            if outcome.returncode == 0:
                return Finish(True, [])
            return Finish(False, [t['reboot_failed'].format(code=outcome.returncode,
                                                           detail=outcome.stderr.strip() or '?')])
        if kind == 'cancelled':
            return Finish(False, [t['cancelled']])
        if kind in ('no-agent', 'not-authorized'):
            return Finish(False, [t['no_agent' if kind == 'no-agent' else 'not_authorized'], sudo_text(self.argv)])
        if kind == 'pkexec-error':
            return Finish(False, [t['pkexec_error'].format(detail=detail or '?')])
        if kind == 'usage':
            return Finish(False, [t['usage'].format(detail=detail)])
        if action == 'load':
            return self._finish_load(kind, detail, outcome)
        result = None
        if kind == 'ok':
            try:
                result = json.loads('\n'.join(outcome.stdout))
            except ValueError:
                kind, detail = 'crash', t['no_result']
        if kind != 'ok':
            message = self._hinted(detail) if kind == 'blocked' else \
                t['crash'].format(code=outcome.returncode, detail=detail or '?')
            key = 'remove_failed' if action == 'remove' else 'details_failed'
            return Finish(False, [t[key].format(message=message)])
        if action == 'details':
            return Finish(True, self._details(result))
        restoration = result.get('default_restoration')
        if not restoration:
            line = t['removed_none']
        elif restoration.get('state') == 'normal':
            line = t['removed_normal']
        else:
            line = t['removed_preserved'].format(reason=restoration.get('reason') or '?')
        return Finish(True, [line], True, t['reboot_remove'])

    def _finish_load(self, kind, detail, outcome):
        t = self.text
        events = {event.get('event'): event for event in self.events}
        done, failed = events.get('done'), events.get('failed')
        if kind == 'ok' and done:
            lines = [t['load_done'].format(kernel=done.get('kernel') or self.progress.kernel)]
            for device in done.get('devices') or []:
                lines.append(t['done_kept' if device.get('kept') else 'done_new'].format(
                    bdf=device.get('bdf'), architecture=device.get('architecture'), sha=str(device.get('sha256'))[:16]))
            if done.get('default') not in ('selected', 'ready'):
                # setup reports this as a failure; an older helper may not.
                lines.append(t['default_preserved'].format(reason=done.get('default_reason') or '?'))
                return Finish(False, lines)
            lines.append(t['default_selected'].format(entry=done.get('entry')))
            return Finish(True, lines, True, t['reboot_load'])
        if kind == 'ok':
            return Finish(False, [t['no_result'], t['state_unknown']])
        if kind == 'blocked' or failed:
            step, message = (failed.get('step'), failed.get('message') or detail) if failed else (None, detail)
            prefix, _, rest = detail.partition(': ')
            if step is None and prefix in STEPS:
                step, message = prefix, rest
            lines = [t['failed_at'].format(step=self._step_text(step), message=self._hinted(message)) if step
                     else t['failed'].format(message=self._hinted(message))]
            cleanup = (failed or {}).get('cleanup') or {}
            if cleanup.get('ran') and cleanup.get('ok') is not True:
                lines.append(t['cleanup_failed'].format(message=cleanup.get('message') or '?'))
            elif cleanup.get('ran'):
                lines.append(t['state_cleaned'])
            elif NOT_ROLLED_BACK in message:
                lines.append(t['state_unknown'])
            else:
                lines.append(t[FAILED_STATE.get(step, 'state_unknown')])
            return Finish(False, lines)
        return Finish(False, [t['crash'].format(code=outcome.returncode, detail=detail or '?'), t['state_unknown']])

    def _details(self, status):
        t = self.text

        def answer(value):
            return t['yes'] if value is True else t['no'] if value is False else t['unknown']
        lines = [t['d_installed'].format(value=answer(status.get('installed'))),
                 t['d_enrolled'].format(value=answer(status.get('enrolled'))),
                 t['d_ready'].format(value=answer(status.get('ready'))),
                 t['d_triggers'].format(value=answer(status.get('triggers_enabled')))]
        attempt = status.get('last_attempt') or {}
        if attempt.get('state'):
            finished = attempt.get('finished')
            when = time.strftime('%Y-%m-%d %H:%M', time.localtime(finished)) if isinstance(finished, (int, float)) \
                else '?'
            lines.append(t['d_attempt'].format(state=attempt['state'], finished=when))
            if attempt.get('error'):
                lines.append(t['d_error'].format(error=self._hinted(str(attempt['error']))))
        drift = status.get('driver_drift') or {}
        if drift.get('resume'):
            lines.append(t['d_drift'].format(command=drift['resume']))
        fetch = status.get('source_fetch') or {}
        if fetch.get('state'):
            lines.append(t['d_fetch'].format(state=fetch['state']))
        runtime = status.get('runtime') or {}
        lines.append(t['d_activation'].format(value=answer(runtime.get('activation_matches'))))
        return lines
