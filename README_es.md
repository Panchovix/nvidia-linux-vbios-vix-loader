# NVIDIA Linux VBIOS Vix Loader

[English](README.md) | Español

Carga una VBIOS modificada para cada GPU NVIDIA al arrancar Linux, **en memoria**: nunca escribe en el chip
flash de la tarjeta. Parchea los módulos abiertos del kernel de NVIDIA para que el firmware GSP arranque con
tu VBIOS, los compila en una entrada de arranque aparte, los recompila automáticamente tras actualizaciones del kernel y
mantiene tu entrada normal como respaldo.

Gracias a **@pantsoftime** ([overclock.net](https://www.overclock.net)): este proyecto se basa en su parche
original `vbios_override`, y sin él nada de esto habría sido posible.

Para modificar la VBIOS, usa [NVIDIA VBIOS Vix Editor](https://github.com/Panchovix/nvidia-vbios-vix-editor).
Este repositorio solo la carga. En Windows, usa
[NVIDIA Windows VBIOS Vix Loader](https://github.com/Panchovix/nvidia-windows-vbios-vix-loader).

Este proyecto no está afiliado a NVIDIA ni cuenta con su respaldo. NVIDIA y GeForce son marcas registradas
de NVIDIA Corporation.

> **Advertencia.** Una VBIOS modificada puede subir potencia, frecuencias y voltajes más allá de los límites de
> diseño de la tarjeta. Puedes dañar el hardware. Guarda una copia de tu ROM original y úsalo bajo tu propio riesgo.

## Estado

| Plataforma | Estado |
| --- | --- |
| Fedora 43, GRUB/BLS, dracut, DNF5, módulos abiertos NVIDIA 615.x instalados con el instalador `.run` | **Soportado**: usado en hardware real |
| Familia RHEL, Debian/Ubuntu, Arch/CachyOS/EndeavourOS, systemd-boot, UKI, Secure Boot (todos con el driver `.run`) | **Experimental**: solo pruebas sintéticas y en contenedores |
| Drivers NVIDIA de un gestor de paquetes (RPM Fusion, repositorios de NVIDIA, apt, pacman), módulos abiertos 615+ | **Experimental**: solo pruebas sintéticas |
| rpm-ostree, módulos de kernel propietarios de NVIDIA, drivers anteriores a 615 | No soportado |

Tras una actualización del driver con un gestor de paquetes, el loader descarga una vez el tag correspondiente de
github.com/NVIDIA/open-gpu-kernel-modules, lo compara con la copia del código de la distribución cuando reconoce el
formato del paquete y recompila. Los repositorios de NVIDIA y Arch instalan el árbol completo, que se compara entero.
RPM Fusion y Ubuntu instalan solo kernel-open, así que los Makefile de nivel superior y `src/` del tag se confían solo
por el TLS de GitHub (`cross_check: kernel-open-only` en `nvbios system status`).
Sin red, con un perfil P2P o ante cualquier diferencia, aparta sus módulos y selecciona la entrada normal más nueva
cuyo módulo NVIDIA propio (de la distribución) se compiló para la nueva versión y cuya imagen de arranque no carga otra
versión de NVIDIA; arranca sin override. Si no hay ninguna, la entrada anterior sigue como predeterminada.
`nvbios system status` muestra el comando post-install.
`--no-auto-source` (en `prepare`) desactiva la descarga.

Probado funcionando en: RTX PRO 6000 Blackwell Max-Q, RTX PRO 6000 Blackwell Workstation Edition, GeForce RTX
5090, 5080, 5070 Ti, 5070, 5060 Ti y RTX 2000 Ada.

El firmware GSP de Ada carga como máximo 512 KiB, contados desde la imagen legacy del payload, así que los payloads
de Ada hay que reubicarlos con Vix Editor:

- RTX 2000 Ada (probada): `nvbios normalize editada.rom gpu0.bin --representation ada-relocated-v1` (0.1.5 o superior).
- **Experimental, sin probar en hardware**: otras GPUs Ada de escritorio y workstation con
  `--representation ada-relocated-v2` (0.1.6 o superior). Funciona offline con imágenes de RTX 4090, 4080 (SUPER),
  4070 Ti SUPER, 4070 (SUPER), 4060 Ti, 4060 y RTX 6000/5000/4500/4000 Ada; lo que no verifica se rechaza.
  Si la pruebas, abre un issue con el resultado.
- Las imágenes Ada de laptop probadas se rechazan: cuatro no caben y la de la RTX 4090 Laptop no trae imagen UEFI.

Ampere GA102–GA107 tiene el mismo **límite conocido de 512 KiB del GSP**, contado
desde la imagen legacy seleccionada hasta el final del payload. El loader rechaza
las imágenes demasiado grandes durante la preparación e inscripción, evitando
que el firmware vuelva silenciosamente a la VBIOS de fábrica. Una ROM Ampere
normalizada sin más supera ese límite. **Experimental, sin probar en hardware**:
`nvbios normalize editada.rom gpu0.bin --representation ampere-relocated-v1` (Vix Editor 0.1.9
o posterior)
quita la imagen UEFI y los bytes posteriores a la última imagen de datos, con lo que
quedan entre unos 443 y 506 KiB desde la imagen legacy en las imágenes examinadas (el
archivo conserva un prefijo de ~37 KiB que no se envía); lo que no verifica se rechaza.
Si la pruebas, abre un issue con el resultado. GA100 usa otro firmware y queda fuera
de esta auditoría de capacidad.

## Varias GPUs

Selecciona **de 1 a 32 GPUs**, repitiendo `--device INDICE PAYLOAD` para cada una.
Durante la preparación, los índices se resuelven a UUID y dirección PCI; las
asignaciones y los hashes completos se verifican individualmente. La configuración
queda dentro del initramfs, sin añadir cada GPU a la línea de comandos del kernel.

El módulo parcheado admite **4094 bytes por parámetro de registro**. Una configuración
típica de 17 GPUs ocupa 1733 bytes para los nombres de firmware; con 32 GPUs, 3263
bytes. Los ajustes de registro adicionales conservados cuentan dentro del mismo
límite. Si se excede, se rechaza la configuración antes de publicarla. Es necesario
recompilar mediante el loader actualizado: el módulo antiguo, limitado a 1024
bytes, no admite los valores ampliados. Hay pruebas offline para más de ocho GPUs;
todavía no se ha verificado un arranque real con 17 o 32 GPUs.

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
  Para Ada y Ampere, agrega el `--representation` indicado más arriba (`ada-relocated-v1`, `ada-relocated-v2` o
  `ampere-relocated-v1`); sin él, el payload supera el límite de 512 KiB del GSP y se rechaza.

## Instalación

Ejecuta esto desde un clon de este repositorio.

1. Lista las GPUs. Anota el índice de cada una (el mismo de `nvidia-smi`) y asócialo a su propio payload.

   ```sh
   sudo ./nvbios system devices
   ```

2. Prepara un perfil, con un `--device` por GPU (`--userspace manual` para el driver instalado con `.run`; `rpm`,
   `deb` o `pacman` para un driver de gestor de paquetes). Este paso solo escribe el directorio de salida.

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

## Actualizar una instalación existente del loader

Después de actualizar este checkout, reemplaza el runtime instalado y recompila
para el kernel en ejecución usando las fuentes del driver NVIDIA **actualmente
instalado**:

```sh
sudo nvbios system pre-install
sudo nvbios system install --repository "$PWD"
sudo nvbios system post-install --source /ruta/a/las/fuentes-actuales
```

Conserva `--p2p-preferred` en `post-install` si tu perfil existente exige fuentes
P2P. Esta secuencia actualiza el loader y prepara una imagen de arranque nueva;
no reinstala las bibliotecas NVIDIA ni recarga los módulos activos. Espera a que
termine `post-install` y luego reinicia. Descargar el repositorio por sí solo no
amplía el límite del runtime o módulo que ya tenías instalado.

## Actualizaciones del kernel y del driver

- **Kernel**: automático. El hook de paquetes y un temporizador de reintento recompilan los módulos y la
  entrada de arranque para el kernel nuevo.
- **Driver** (instalación `.run`): ejecuta `sudo nvbios system pre-install` antes de quitar el driver anterior,
  instala el nuevo y registra el código fuente sin parchear de la nueva versión:

  ```sh
  sudo nvbios system post-install --source /ruta/a/open-gpu-kernel-modules-NUEVO
  ```

  Compila y selecciona la nueva entrada de arranque y reanuda las actualizaciones automáticas. Reinicia al terminar.

  Ejecuta `post-install` **antes de reiniciar**. Mientras tanto, los módulos compilados para el driver anterior tienen
  prioridad en todas las entradas de arranque, incluida la normal, y el driver NVIDIA no arrancará. Si ya
  reiniciaste, ejecuta `post-install` desde ese arranque; funciona aunque `nvidia-smi` falle.
- **Driver** (gestor de paquetes, experimental): no hay que ejecutar nada. El hook de paquetes descarga el código
  fuente correspondiente y recompila durante la actualización (ver Estado). Revisa `sudo nvbios system status`
  antes de reiniciar: si no pudo recompilar, queda como predeterminada una entrada normal con el módulo nuevo de la
  distribución (o la anterior, si no hay ninguna) y `status` muestra el comando `post-install`.

## Si algo sale mal

- Elige tu entrada **normal** en el menú de arranque; no carga ningún override. Igual usa los módulos que compiló
  esta herramienta, así que no sirve tras una actualización del driver sin `post-install` (ver arriba).
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
   ejecutar el instalador `.run` de NVIDIA para ese kernel (`--kernel-name=KERNEL`). Luego reconstruye su
   initramfs normal con `sudo dracut -f --kver KERNEL`.
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
