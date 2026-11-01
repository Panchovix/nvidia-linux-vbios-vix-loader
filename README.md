# NVIDIA Linux VBIOS Vix Loader

English | [Español](README_es.md)

Loads a modified VBIOS for each NVIDIA GPU at boot on Linux, **in memory**: the card's flash chip is never
written. It patches the NVIDIA open kernel modules so the GSP firmware starts with your VBIOS image, builds
them in a separate boot entry, rebuilds them automatically after kernel updates, and keeps your normal boot
entry as a fallback.

Works with NVIDIA 615.x (R615) drivers. It may stop working in a future driver if NVIDIA decides to change or
remove the override, so after every driver update run `nvbios system status` and check an edited value (for
example the power limits in `nvidia-smi -q -d POWER`).

Thanks to **@pantsoftime** ([overclock.net](https://www.overclock.net)), whose original `vbios_override` patch
this project is built on. Without it, none of this would have been possible.

To modify the VBIOS, use [NVIDIA VBIOS Vix Editor](https://github.com/Panchovix/nvidia-vbios-vix-editor).
This repository only loads it. On Windows, use
[NVIDIA Windows VBIOS Vix Loader](https://github.com/Panchovix/nvidia-windows-vbios-vix-loader).

This project is not affiliated with or endorsed by NVIDIA. NVIDIA and GeForce are trademarks of NVIDIA
Corporation.

> **Warning.** A modified VBIOS can raise power, clocks and voltages beyond the card's design limits. You can
> damage hardware. Keep a copy of your original ROM and use this at your own risk.

## Status

| Platform | State |
| --- | --- |
| Fedora 43, GRUB/BLS, dracut, DNF5, NVIDIA 615.x open kernel modules installed with the `.run` installer | **Supported**: used on real hardware |
| RHEL family, Debian/Ubuntu, Arch/CachyOS/EndeavourOS, systemd-boot, UKI, Secure Boot (all with the `.run` driver) | **Experimental**: users report it working on Ubuntu, Kubuntu, Debian, CachyOS and Arch Linux; the maintainer only uses Fedora |
| NVIDIA drivers from a package manager (RPM Fusion, NVIDIA repos, apt, pacman), open kernel modules 615+ | **Experimental**: synthetic tests only |
| rpm-ostree, proprietary NVIDIA kernel modules, drivers older than 615 | Not supported |

After a package-manager driver upgrade the loader downloads the matching tag from github.com/NVIDIA/open-gpu-kernel-modules
once, compares it with the distribution's own copy of the source when it recognises the package layout, and rebuilds.
NVIDIA's repositories and Arch install the whole tree, which is compared whole. RPM Fusion and Ubuntu install only
kernel-open, so the tag's top-level Makefiles and `src/` are trusted on GitHub's TLS alone
(`cross_check: kernel-open-only` in `nvbios system status`).
Offline, with a P2P profile, or on any mismatch, it moves its modules aside and selects the newest normal entry whose
own NVIDIA module (from the distribution) was built for the new version, and whose boot image does not load another
NVIDIA build; it boots without the override. If there is none, the previous entry stays the default.
`nvbios system status` shows the post-install command.
`--no-auto-source` (on `prepare`) turns off the download.

Tested working on: RTX PRO 6000 Blackwell Max-Q, RTX PRO 6000 Blackwell Workstation Edition, GeForce RTX 5090,
5080, 5070 Ti, 5070, 5060 Ti and RTX 2000 Ada. It works on Turing, Ampere, Ada and Blackwell GPUs, desktops and
laptops alike, except Ada laptop GPUs (see below).

Ada GSP firmware loads at most 512 KiB, counted from the payload's legacy image, so Ada payloads must be relocated
with Vix Editor:

- RTX 2000 Ada (tested): `nvbios normalize edited.rom gpu0.bin --representation ada-relocated-v1` (0.1.5 or newer).
- Other desktop and workstation Ada GPUs, with
  `--representation ada-relocated-v2` (0.1.6 or newer). It works offline on images of the RTX 4090, 4080 (SUPER),
  4070 Ti SUPER, 4070 (SUPER), 4060 Ti, 4060 and RTX 6000/5000/4500/4000 Ada; anything that does not verify is refused.
- The laptop Ada images tested are refused: four do not fit, and the RTX 4090 Laptop image has no UEFI image.

Ampere GA102–GA107 has the same known **512 KiB GSP load limit**, counted from the
selected legacy image to the end of the payload. The loader rejects oversized
images during preparation and enrollment, rather than letting firmware silently
use the stock VBIOS. Plain normalized Ampere ROMs exceed it. Use
`nvbios normalize edited.rom gpu0.bin --representation ampere-relocated-v1`
(Vix Editor 0.1.9 or newer) drops the UEFI image and the bytes after the last data image, which
leaves about 443–506 KiB from the legacy image on the images examined (the file keeps
a ~37 KiB prefix that is not sent); anything that does not verify is refused.
GA100 uses different firmware
and is outside this capacity audit.

**Turing (TU102, TU104, TU106, TU116, TU117).** The patched
module accepts these chips, and their GSP firmware (`gsp_tu10x.bin`) has the same override receiver and
512 KiB limit (found by static analysis of 615.78.08). A single-bank Turing payload sends
250-355 KB from the legacy image (the file keeps a prefix of up to ~162 KiB that is not sent) and needs no
relocation: `nvbios normalize edited.rom gpu0.bin`. Vix Editor 0.1.18 or newer also saves
`<name>-loader-e0end.bin` (`--representation turing-e0-end-v1`), a variant to try when the first file loads
but the edit does not apply. If GSP refuses an image, the card runs its stock VBIOS. If an edit does not apply, the
[Turing tester guide](https://github.com/Panchovix/nvidia-vbios-vix-editor/blob/main/docs/turing.md) shows how to check it: load your unmodified ROM first, then a power-limit edit, and compare
`nvidia-smi -q -d POWER` before and after and the `vbios_override` line of `journalctl -k -b`.

## Multiple GPUs

Select **1–32 GPUs**, repeating `--device INDEX PAYLOAD` for each one. Indices are
resolved to UUID and PCI address during preparation; assignments and full payload
hashes are checked separately. The configuration is stored in the initramfs,
without adding every GPU to the kernel command line.

The patched module accepts **4094 bytes per registry parameter**. A typical
17-GPU configuration uses 1733 bytes for firmware filenames; 32 GPUs use 3263
bytes. Preserved extra registry settings count toward the same budget. Oversized
configurations fail before publication. Rebuild through the updated loader: an
old module with the original 1024-byte limit cannot load the expanded values.
Support above eight GPUs has offline tests; a 17- or 32-GPU hardware boot has not
yet been verified.

## What you need

- A working NVIDIA 615.x (R615) driver with the **open** kernel modules; `nvidia-smi` must list your GPUs.
- The unpatched source of the open kernel modules for the **exact** installed version, for example:
  `git clone --depth 1 --branch 615.78.08 https://github.com/NVIDIA/open-gpu-kernel-modules`
- Python 3.11 or newer, the headers for the running kernel (`kernel-devel` on Fedora), `make`, `dracut`,
  `grub2-editenv` and `mokutil`. With DNF5, also `libdnf5-plugin-actions`.
- GRUB with `GRUB_DEFAULT=saved` and `GRUB_ENABLE_BLSCFG=true` (Fedora's defaults).
- Secure Boot off, or your own module signing key: pass `--signing-key` and `--signing-certificate` to `prepare`.
- One VBIOS **payload** per GPU: a single-chain image for that exact card. Full ROM dumps that contain two
  banks are refused. With Vix Editor's command-line tool: `./nvbios-<version>-linux-x86_64 normalize edited.rom gpu0.bin`.
  For Ada and Ampere, add the `--representation` given above (`ada-relocated-v1`, `ada-relocated-v2` or
  `ampere-relocated-v1`); without it the payload exceeds the 512 KiB GSP limit and is refused. Vix Editor
  0.1.11 or newer also saves this payload as `<name>-loader.bin` next to an edited Ada or Ampere copy.
  Turing needs no `--representation` (see above).

## Window

On Fedora and RHEL-family systems the loader also has a window, as an alternative to the steps under
[Install](#install). It needs GTK 4.10 or newer and PyGObject (`sudo dnf install python3-gobject gtk4`).

```sh
./vbios-loader-gui
```

Run it from a clone, **without** `sudo`. It shows the driver, kernel, Secure Boot and boot setup it detected and
one row per GPU. For each GPU choose **New file** (the `.rom` or `<name>-loader.bin` the editor saved, checked as
soon as you pick it), **Keep the current file** or **Own VBIOS (no override)**. Choose where the NVIDIA source comes from (the copy saved
at the last Load, a download of the installed version, or a folder; mark P2P sources), then press **Load**. It asks
for your password once and runs `nvbios system setup`, which does steps 2-4 below, with live progress. Then reboot;
your normal boot entry stays in the menu and never loads the override. **Remove override** runs `nvbios system
disable`. Menu > **Details** shows `nvbios system status`.

Tested on Fedora 43 with eight GPUs: two new files (an RTX PRO 4000 Blackwell SFF and an RTX 2000 Ada, both
raised to a 106 W power limit) and six kept; after the reboot both reported the new limit.

The window refuses to start as root. Without a graphical password agent (for example over SSH) it prints the
`sudo` command instead. Secure Boot with your own signing key, other distributions and driver updates with the
`.run` installer still use the command-line steps.

## Install

Run these from a clone of this repository.

1. List the GPUs. Note each GPU's index (as in `nvidia-smi`) and match it to its own payload.

   ```sh
   sudo ./nvbios system devices
   ```

2. Prepare a profile, with one `--device` per GPU (`--userspace manual` for the `.run` driver; `rpm`, `deb` or
   `pacman` for a package-manager driver). This step only writes the output directory.

   ```sh
   sudo ./nvbios system prepare \
     --device 0 /path/to/gpu0.bin \
     --device 1 /path/to/gpu1.bin \
     --driver-source /path/to/open-gpu-kernel-modules \
     --userspace manual --output "$PWD/gpu-profile"
   ```

   A device can also be selected by GPU UUID or PCI address (`--device 0000:03:00.0 ...`).

3. Install the tool and enroll the profile. `--dry-run` shows what would change.

   ```sh
   sudo ./nvbios system install --repository "$PWD"
   sudo /usr/local/bin/nvbios system enroll --profile "$PWD/gpu-profile/profile.json"
   ```

4. Build the modules and the boot entry, which becomes the default, then turn on automatic rebuilds after
   updates. Building takes a few minutes.

   ```sh
   sudo /usr/local/bin/nvbios system reconcile --kernel "$(uname -r)"
   sudo /usr/local/bin/nvbios system enable --kernel "$(uname -r)"
   sudo /usr/local/bin/nvbios system status
   ```

5. Reboot. Your normal entry stays in the boot menu. After the reboot, `sudo nvbios system status` compares the
   loaded module and parameters with the prepared ones.

## Updating an existing loader installation

After updating this checkout, replace the installed runtime and rebuild for the
running kernel using the source for your **currently installed** NVIDIA driver:

```sh
sudo nvbios system pre-install
sudo nvbios system install --repository "$PWD"
sudo nvbios system post-install --source /path/to/current-open-kernel-modules
```

Keep `--p2p-preferred` on `post-install` if your existing profile requires a P2P
source. This sequence updates the loader and builds a new boot image; it does not
reinstall NVIDIA userspace or reload active GPU modules. Wait for `post-install`
to complete, then reboot. An older installed runtime or module does not gain the
expanded GPU count merely by downloading this repository.

## Kernel and driver updates

- **Kernel updates** are handled automatically: the package hook and a retry timer rebuild the modules and the
  boot entry for the new kernel.
- **Driver updates** (`.run` installs): run `sudo nvbios system pre-install` before removing the old driver,
  install the new driver, then register the matching unpatched source of the new version:

  ```sh
  sudo nvbios system post-install --source /path/to/open-gpu-kernel-modules-NEW
  ```

  It builds and selects the new boot entry and resumes automatic updates. Reboot when it finishes.

  Run `post-install` **before rebooting**. Until then the modules built for the previous driver take priority in
  every boot entry, including the normal one, so the NVIDIA driver will not start. If you already rebooted, run
  `post-install` from that boot; it works even while `nvidia-smi` fails.
- **Driver updates** (package manager, experimental): nothing to run. The package hook downloads the matching
  source and rebuilds during the upgrade (see Status). Check `sudo nvbios system status` before rebooting: if it
  could not rebuild, a normal entry with the distribution's new module is the default (or the previous entry, if
  there is none) and `status` shows the `post-install` command.

## If something goes wrong

- Choose your **normal** entry in the boot menu (press Esc or hold Shift while the computer starts); it does not
  load any override. It still uses the modules this tool built, so it does not help after a driver update without
  `post-install` (see above).
- `sudo nvbios system disable` stops automatic rebuilds and restores the normal entry as default.
- To remove the loader completely, see [Uninstall](#uninstall).
- If `nvidia-smi` stops listing a GPU after you boot an override, the NVIDIA driver most likely could not use that
  GPU's override (`sudo dmesg | grep NVRM` shows the error). The loader then refuses to load ("NVIDIA driver did not
  initialize GPU ..."). Reboot and choose the **normal** entry (without "VBIOS override" in its name), then pick
  another file or **Own VBIOS (no override)** for that GPU and press **Load**. **Remove override** and a reboot also
  work.
- `sudo nvbios system rollback TRANSACTION_ID` undoes one install, enroll or enable step; the IDs are printed
  by those commands.

## Uninstall

Run it from an up-to-date clone of this repository: an installed `/usr/local/bin/nvbios` has the command only when it
was installed from this version or a later one.

```sh
sudo ./nvbios system uninstall --dry-run
sudo ./nvbios system uninstall
```

The command is new and has only been tested on synthetic systems so far. Run `--dry-run` first, and if anything in
its output looks wrong, open an issue with that output before running it for real.

`--dry-run` lists what would be removed and changes nothing. Uninstall works on every distribution and boot setup this
tool supports, and it needs neither the GPU nor a working NVIDIA driver, so it also works after the driver was removed
or replaced. In order, it:

1. Removes the package, kernel and systemd hooks, so nothing builds the override again.
2. With GRUB, makes a normal entry the default, preferring kernels that keep an NVIDIA driver: on Fedora the entry of
   the override's kernel, elsewhere the newest kernel's (the menu's top entry, which follows later kernels). With
   systemd-boot, clears the override default. A default you chose yourself, such as another system, stays.
3. Removes the override boot entries and their images.
4. Removes the modules it built, runs `depmod`, and rebuilds a kernel's normal initramfs if it contains them. A normal
   UKI that contains them is left to the tool that made it, unless that is mkinitcpio: uninstall names the command
   (such as `kernel-install add KERNEL /usr/lib/modules/KERNEL/vmlinuz`) and finishes when run again.
5. Removes the VBIOS files it gave the driver, its state (`/etc/nvidia-vbios/lifecycle.json` and
   `/var/lib/nvidia-vbios`) and, last, `nvbios` itself.

On GRUB systems other than Fedora, `GRUB_DEFAULT=saved` stays in `/etc/default/grub`. If you set it only for the
loader, set `GRUB_DEFAULT=0` again and run `sudo update-grub` (or `sudo grub-mkconfig -o /boot/grub/grub.cfg`) and
`sudo grub-set-default 0`.

It deletes only the loader's own files; anything else it finds is listed under `kept`. On a boot or EFI partition
shared with another system that also uses the loader, that system's entries and images are kept as well. The enrolled
payloads in `/var/lib/nvidia-vbios/roms` are deleted too, so copy that folder first if you need them. Your signing
keys and your Secure Boot key (MOK) are not touched. If it stops halfway, it says why and keeps what it needs to
finish: fix that and run it again. Running it twice is harmless. Reboot when it is done, before suspending or using
CUDA.

The modules this tool builds can be the **only** NVIDIA kernel modules of a kernel, for example a kernel installed
after a `.run` driver. Uninstall then stops before changing anything and names that kernel. Install the driver's own
module for it and run uninstall again:

- `.run` driver: `sudo sh NVIDIA-Linux-x86_64-VERSION.run --kernel-module-only --kernel-name=KERNEL`, with the
  version of the installed driver.
- Package-manager driver: reinstall its kernel module package, or rebuild the module with
  `sudo akmods --force --kernels KERNEL`. DKMS can refuse to install over the loader's module: use
  `sudo dkms install --force NAME/VERSION -k KERNEL`, with the name and version `dkms status` lists, or run uninstall
  with `--allow-missing-module` and then `sudo dkms autoinstall -k KERNEL`.

`--allow-missing-module` removes them anyway; that kernel then starts without the NVIDIA driver until you install one.

### If the computer no longer starts

- GRUB: open the boot menu (press Esc or hold Shift while the computer starts), select the normal entry (without
  "VBIOS override" in its name), press `e`, add `module_blacklist=nvidia,nvidia_drm,nvidia_modeset,nvidia_uvm,nvidia_peermem`
  at the end of the `linux` line and start it with Ctrl+X or F10. With systemd-boot, select the normal entry, press
  `e`, add the same text and press Enter. NVIDIA stays off for that boot only. Then run the uninstall from a clone.
- Recovery mode works too: first run `mount -o remount,rw /` and, if `/boot` or the EFI partition is separate,
  `mount -a`. The clone must already be on the computer, or turn on networking in the recovery menu to download it.
- From a live USB (the only way with a signed UKI, whose command line cannot be edited): mount the installed system on
  `/mnt`, with `/boot` and the EFI partition at their usual places below it, copy this repository (a clone or the
  extracted ZIP from GitHub) to `/mnt/opt/vix-loader`, then run:

  ```sh
  for d in dev proc sys run; do sudo mount --rbind /$d /mnt/$d; done
  sudo chroot /mnt /usr/bin/python3 /opt/vix-loader/nvbios system uninstall
  ```

### Manual removal

Only if the command cannot run at all. As root:

1. `systemctl disable --now nvidia-vbios-reconcile.path nvidia-vbios-reconcile.timer` (in a chroot, without `--now`).
   Delete whichever of these exist, then run `systemctl daemon-reload`:
   `/usr/lib/systemd/system/nvidia-vbios-reconcile.{service,path,timer}`,
   `/usr/lib/kernel/install.d/99-nvidia-vbios.install`, `/etc/kernel/postinst.d/zz-nvidia-vbios`,
   `/etc/kernel/postrm.d/zz-nvidia-vbios`, `/etc/apt/apt.conf.d/99-nvidia-vbios`,
   `/etc/pacman.d/hooks/99-nvidia-vbios.hook`, `/etc/dnf/libdnf5-plugins/actions.d/nvidia-vbios.actions` and
   `/etc/dnf/plugins/post-transaction-actions.d/nvidia-vbios.action`.
2. Make a normal entry the default: `grub2-set-default 0` (Fedora), `grub-set-default 0` (other GRUB systems) or
   `bootctl set-default ""` (systemd-boot).
3. Delete the override boot files. On Fedora: `/boot/loader/entries/vbios-*.conf` and `/boot/initramfs-*-vbios-*.img`.
   Elsewhere: `/etc/grub.d/41_nvidia_vbios`, `/boot/grub/nvidia-vbios-entries`, and on `/boot` or the EFI partition
   the `nvidia-vbios` folder and the `vbios-*` files in `loader/entries` or `EFI/Linux` (if another system on the
   computer also uses the loader, only the `vbios-*` folders and files of this system's kernels). With GRUB, then
   delete `/boot/grub/nvidia-vbios.cfg` and run `update-grub` (or `grub-mkconfig -o /boot/grub/grub.cfg`). With a
   hand-written `grub.cfg`, run neither: delete its line `source $prefix/nvidia-vbios.cfg`, then
   `/boot/grub/nvidia-vbios.cfg`.
4. Move each `/usr/lib/modules/KERNEL/updates/vbios-override` to a backup folder of its own (for example
   `/var/backups/vbios-override-KERNEL`), and `/usr/lib/modules/.vbios-*` too. Run `depmod -a KERNEL` for every
   installed kernel and check that `modinfo -k KERNEL -F filename nvidia` prints a module (if not, see above, or move
   that kernel's folder back and run `depmod -a KERNEL` again).
5. Rebuild the normal initramfs: `dracut -f --kver KERNEL`, `update-initramfs -u -k all` or `mkinitcpio -P`.
6. Delete `/usr/lib/firmware/nvidia/*/vbios-override`, `/usr/local/bin/nvbios`, `/usr/libexec/nvidia-vbios`,
   `/usr/local/lib/nvidia-vbios-tools`, `/etc/nvidia-vbios` and `/var/lib/nvidia-vbios`. First move out any key you
   keep in `/etc/nvidia-vbios`, and copy `/var/lib/nvidia-vbios/roms` if you want the payloads. Reboot, check that
   `nvidia-smi` works, then delete the module backups.

## Tests

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

The tests use synthetic files only; they never touch a GPU, `/boot` or the installed system.

## License

Copyright (C) 2026 panchovix. GNU General Public License v3.0 or later (`GPL-3.0-or-later`), see
[LICENSE](LICENSE): you can use, study, change and share it, and changed versions you share must stay under
the same license.

The kernel module patches (`patches/*.patch`) and `src/nvidia_vbios/driver/_payload.py` derive from NVIDIA's
open kernel modules and stay under the MIT license, so a patched module can still be built and shared with the
Linux kernel (GPLv2). See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md). Earlier versions were released under
the MIT license.
