# NVIDIA Linux VBIOS Vix Loader

English | [Español](README_es.md)

Loads a modified VBIOS for each NVIDIA GPU at boot on Linux, **in memory**: the card's flash chip is never
written. It patches the NVIDIA open kernel modules so the GSP firmware starts with your VBIOS image, builds
them in a separate boot entry, rebuilds them automatically after kernel updates, and keeps your normal boot
entry as a fallback.

Thanks to **@pantsoftime** ([overclock.net](https://www.overclock.net)), whose original `vbios_override` patch
this project is built on. Without it, none of this would have been possible.

To modify the VBIOS, use [NVIDIA VBIOS Vix Editor](https://github.com/Panchovix/nvidia-vbios-vix-editor).
This repository only loads it.

> **Warning.** A modified VBIOS can raise power, clocks and voltages beyond the card's design limits. You can
> damage hardware. Keep a copy of your original ROM and use this at your own risk.

## Status

| Platform | State |
| --- | --- |
| Fedora 43, GRUB/BLS, dracut, DNF5, NVIDIA 615.x open kernel modules installed with the `.run` installer | **Supported**: used on real hardware |
| RHEL family, Debian/Ubuntu, Arch/CachyOS/EndeavourOS, systemd-boot, UKI, Secure Boot (all with the `.run` driver) | **Experimental**: synthetic and container tests only |
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
5080, 5070 Ti, 5070, 5060 Ti and RTX 2000 Ada.

Ada GSP firmware loads at most 512 KiB, counted from the payload's legacy image, so Ada payloads must be relocated
with Vix Editor:

- RTX 2000 Ada (tested): `nvbios normalize edited.rom gpu0.bin --representation ada-relocated-v1` (0.1.5 or newer).
- **Experimental, not tested on hardware**: other desktop and workstation Ada GPUs with
  `--representation ada-relocated-v2` (0.1.6 or newer). It works offline on images of the RTX 4090, 4080 (SUPER),
  4070 Ti SUPER, 4070 (SUPER), 4060 Ti, 4060 and RTX 6000/5000/4500/4000 Ada; anything that does not verify is refused.
  If you try it, please open an issue with the result.
- The laptop Ada images tested are refused: four do not fit, and the RTX 4090 Laptop image has no UEFI image.

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

- A working NVIDIA 615.x driver with the **open** kernel modules; `nvidia-smi` must list your GPUs.
- The unpatched source of the open kernel modules for the **exact** installed version, for example:
  `git clone --depth 1 --branch 615.78.08 https://github.com/NVIDIA/open-gpu-kernel-modules`
- Python 3.11 or newer, the headers for the running kernel (`kernel-devel` on Fedora), `make`, `dracut`,
  `grub2-editenv` and `mokutil`. With DNF5, also `libdnf5-plugin-actions`.
- GRUB with `GRUB_DEFAULT=saved` and `GRUB_ENABLE_BLSCFG=true` (Fedora's defaults).
- Secure Boot off, or your own module signing key: pass `--signing-key` and `--signing-certificate` to `prepare`.
- One VBIOS **payload** per GPU: a single-chain image for that exact card. Full ROM dumps that contain two
  banks are refused. With Vix Editor's command-line tool: `./nvbios-<version>-linux-x86_64 normalize edited.rom gpu0.bin`.

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

- Choose your **normal** entry in the boot menu; it does not load any override. It still uses the modules this tool
  built, so it does not help after a driver update without `post-install` (see above).
- `sudo nvbios system disable` stops automatic rebuilds and restores the normal entry as default.
- `sudo nvbios system rollback TRANSACTION_ID` undoes one install, enroll or enable step; the IDs are printed
  by those commands.

## Uninstall (Fedora)

There is no uninstall command yet. After a kernel update, the modules this tool builds can be the **only** NVIDIA
kernel modules for that kernel, and the normal boot entry may load them too. Restore normal modules first:

1. `sudo nvbios system disable`.
2. For every kernel you keep, install normal NVIDIA modules of the same driver version: re-run the NVIDIA `.run`
   installer for that kernel (`--kernel-name=KERNEL`). Then
   rebuild its normal initramfs with `sudo dracut -f --kver KERNEL`.
3. Temporarily move `/usr/lib/modules/*/updates/vbios-override` aside (for example to `/var/backups/vbios-override`),
   run `sudo depmod -a KERNEL` for each kernel, reboot into the normal entry and check that `nvidia-smi` works.
4. Only then remove the backup and:
   - `/usr/local/bin/nvbios`, `/usr/libexec/nvidia-vbios` and `/usr/local/lib/nvidia-vbios-tools`
   - `/etc/nvidia-vbios` and `/var/lib/nvidia-vbios`
   - `/usr/lib/systemd/system/nvidia-vbios-reconcile.{service,path,timer}`, then `sudo systemctl daemon-reload`
   - `/usr/lib/kernel/install.d/99-nvidia-vbios.install` and `/etc/dnf/libdnf5-plugins/actions.d/nvidia-vbios.actions`
   - the managed boot files `/boot/loader/entries/vbios-*.conf` and `/boot/initramfs-*-vbios-*.img`
   - `/usr/lib/firmware/nvidia/*/vbios-override`

If `nvidia-smi` fails in step 3, move the directory back, run `depmod -a KERNEL` again and fix step 2 first.

## Tests

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
```

The tests use synthetic files only; they never touch a GPU, `/boot` or the installed system.

## License

MIT. See [LICENSE](LICENSE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
