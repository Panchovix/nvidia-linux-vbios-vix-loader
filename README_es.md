# NVIDIA Linux VBIOS Vix Loader

[English](README.md) | Español

Carga una VBIOS modificada para cada GPU NVIDIA al arrancar Linux, **en memoria**: nunca escribe en el chip
flash de la tarjeta. Parchea los módulos abiertos del kernel de NVIDIA para que el firmware GSP arranque con
tu VBIOS, los compila en una entrada de arranque aparte, los recompila automáticamente tras actualizaciones del kernel y
mantiene tu entrada normal como respaldo.

Gracias a **@pantsoftime** ([overclock.net](https://www.overclock.net)): este proyecto se basa en su parche
original `vbios_override`, y sin él nada de esto habría sido posible.

Para modificar la VBIOS, usa [NVIDIA VBIOS Vix Editor](https://github.com/Panchovix/nvidia-vbios-vix-editor).
Este repositorio solo la carga.

> **Advertencia.** Una VBIOS modificada puede subir potencia, frecuencias y voltajes más allá de los límites de
> diseño de la tarjeta. Puedes dañar el hardware. Guarda una copia de tu ROM original y úsalo bajo tu propio riesgo.

## Estado

| Plataforma | Estado |
| --- | --- |
| Fedora 43, GRUB/BLS, dracut, DNF5, módulos abiertos NVIDIA 615.x instalados con el instalador `.run` | **Soportado**: usado en hardware real |
| Fedora con drivers de akmods/RPM Fusion, familia RHEL, Debian/Ubuntu, Arch/CachyOS/EndeavourOS, systemd-boot, UKI, Secure Boot | **Experimental**: solo pruebas sintéticas y en contenedores |
| rpm-ostree, módulos de kernel propietarios de NVIDIA, drivers anteriores a 615 | No soportado |

Probado funcionando en: RTX PRO 6000 Blackwell Max-Q, RTX PRO 6000 Blackwell Workstation Edition, GeForce RTX
5090, 5080, 5070 Ti, 5070 y 5060 Ti. Los payloads de Ada de más de 512 KiB se rechazan.

## Qué necesitas

- Un driver NVIDIA 615.x funcionando con los módulos **abiertos**; `nvidia-smi` debe listar tus GPUs.
- El código fuente sin parchear de los módulos abiertos para la versión instalada **exacta**, por ejemplo:
  `git clone --depth 1 --branch 615.78.08 https://github.com/NVIDIA/open-gpu-kernel-modules`
- Python 3.11 o superior, los headers del kernel en uso (`kernel-devel` en Fedora), `make`, `dracut`,
  `grub2-editenv` y `mokutil`. Con DNF5, también `libdnf5-plugin-actions`.
- GRUB con `GRUB_DEFAULT=saved` y `GRUB_ENABLE_BLSCFG=true` (lo normal en Fedora).
- Secure Boot desactivado, o tu propia clave para firmar módulos: pasa `--signing-key` y `--signing-certificate` a `prepare`.
- Un **payload** de VBIOS por GPU: una imagen de una sola cadena para esa tarjeta exacta. Los volcados de ROM
  completos con dos bancos se rechazan. Con la herramienta de línea de comandos de Vix Editor:
  `./nvbios-<versión>-linux-x86_64 normalize editada.rom gpu0.bin`.

## Instalación

Ejecuta esto desde un clon de este repositorio.

1. Lista las GPUs. Anota el índice de cada una (el mismo de `nvidia-smi`) y asócialo a su propio payload.

   ```sh
   sudo ./nvbios system devices
   ```

2. Prepara un perfil, con un `--device` por GPU. Usa `--userspace manual` si instalaste el driver con `.run`;
   omítelo con drivers empaquetados. Este paso solo escribe el directorio de salida.

   ```sh
   sudo ./nvbios system prepare \
     --device 0 /ruta/a/gpu0.bin \
     --device 1 /ruta/a/gpu1.bin \
     --driver-source /ruta/a/open-gpu-kernel-modules \
     --userspace manual --output "$PWD/gpu-profile"
   ```

   También puedes elegir una GPU por UUID o dirección PCI (`--device 0000:03:00.0 ...`).

3. Instala la herramienta e inscribe el perfil. `--dry-run` muestra qué cambiaría.

   ```sh
   sudo ./nvbios system install --repository "$PWD"
   sudo /usr/local/bin/nvbios system enroll --profile "$PWD/gpu-profile/profile.json"
   ```

4. Compila los módulos y la entrada de arranque, que queda como predeterminada, y activa las recompilaciones
   automáticas tras actualizaciones. La compilación tarda unos minutos.

   ```sh
   sudo /usr/local/bin/nvbios system reconcile --kernel "$(uname -r)"
   sudo /usr/local/bin/nvbios system enable --kernel "$(uname -r)"
   sudo /usr/local/bin/nvbios system status
   ```

5. Reinicia. Tu entrada normal sigue en el menú de arranque. Tras reiniciar, `sudo nvbios system status`
   compara el módulo y los parámetros cargados con los preparados.

## Actualizaciones del kernel y del driver

- **Kernel**: automático. El hook de paquetes y un temporizador de reintento recompilan los módulos y la
  entrada de arranque para el kernel nuevo.
- **Driver** (instalación `.run`): ejecuta `sudo nvbios system pre-install` antes de quitar el driver anterior,
  instala el nuevo y registra el código fuente sin parchear de la nueva versión:

  ```sh
  sudo nvbios system post-install --source /ruta/a/open-gpu-kernel-modules-NUEVO
  ```

  Compila y selecciona la nueva entrada de arranque y reanuda las actualizaciones automáticas. Reinicia al terminar.

## Si algo sale mal

- Elige tu entrada **normal** en el menú de arranque; no carga ningún override.
- `sudo nvbios system disable` detiene las recompilaciones automáticas y vuelve a dejar la entrada normal como
  predeterminada.
- `sudo nvbios system rollback ID_TRANSACCION` deshace un paso de install, enroll o enable; esos comandos
  muestran el ID.

## Desinstalar (Fedora)

Todavía no hay un comando para desinstalar. Tras una actualización del kernel, los módulos que compila esta
herramienta pueden ser los **únicos** módulos NVIDIA de ese kernel, y la entrada normal también puede cargarlos.
Primero restaura módulos normales:

1. `sudo nvbios system disable`.
2. Para cada kernel que conserves, instala módulos NVIDIA normales de la misma versión del driver: vuelve a
   ejecutar el instalador `.run` de NVIDIA para ese kernel (`--kernel-name=KERNEL`), o deja que akmods/DKMS los
   recompile con drivers empaquetados. Luego reconstruye su initramfs normal con `sudo dracut -f --kver KERNEL`.
3. Mueve temporalmente `/usr/lib/modules/*/updates/vbios-override` a otro lugar (por ejemplo
   `/var/backups/vbios-override`), ejecuta `sudo depmod -a KERNEL` para cada kernel, reinicia en la entrada normal
   y comprueba que `nvidia-smi` funcione.
4. Solo entonces borra la copia de respaldo y:
   - `/usr/local/bin/nvbios`, `/usr/libexec/nvidia-vbios` y `/usr/local/lib/nvidia-vbios-tools`
   - `/etc/nvidia-vbios` y `/var/lib/nvidia-vbios`
   - `/usr/lib/systemd/system/nvidia-vbios-reconcile.{service,path,timer}`, y luego `sudo systemctl daemon-reload`
   - `/usr/lib/kernel/install.d/99-nvidia-vbios.install` y `/etc/dnf/libdnf5-plugins/actions.d/nvidia-vbios.actions`
   - los archivos de arranque administrados `/boot/loader/entries/vbios-*.conf` y `/boot/initramfs-*-vbios-*.img`
   - `/usr/lib/firmware/nvidia/*/vbios-override`

Si `nvidia-smi` falla en el paso 3, devuelve el directorio a su lugar, ejecuta otra vez `depmod -a KERNEL` y
corrige primero el paso 2.

## Tests

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

Los tests usan solo archivos sintéticos; nunca tocan una GPU, `/boot` ni el sistema instalado.

## Licencia

MIT. Ver [LICENSE](LICENSE) y [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
