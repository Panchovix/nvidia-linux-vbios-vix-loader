"""Reviewed C payloads. Loader derived from NVIDIA open modules 615.71.09 (MIT)."""

PARSER_HEADER = r'''/* SPDX-License-Identifier: MIT */
#ifndef VBIOS_OVERRIDE_IMAGE_H
#define VBIOS_OVERRIDE_IMAGE_H

#include "nvtypes.h"

#define NV_VBIOS_OVERRIDE_MODE_KEY    "RmLinuxVbiosOverride"
#define NV_VBIOS_OVERRIDE_SIZE_KEY    "RmLinuxVbiosOverrideSize"
#define NV_VBIOS_OVERRIDE_IMAGE_KEY   "RmLinuxVbiosOverrideImage"
#define NV_VBIOS_OVERRIDE_DISABLE_KEY "RmLinuxVbiosOverrideDisable"
#define NV_VBIOS_OVERRIDE_MAX_SIZE    (4U * 1024U * 1024U)

/* Pure, bounded parser, also compiled by the userspace regression harness.
 * pciId is the PCI configuration dword: device in bits 31:16, vendor in 15:0.
 * A full dump must contain exactly one legacy image, for this physical GPU.
 */
static inline NvBool
kgspVbiosOverrideFindLegacy(const NvU8 *image, NvU32 size,
                          NvU32 pciId, NvU32 *offset)
{
    NvU32 off, found = 0, selected = 0;

    if (image == 0 || offset == 0 || size < 0x200 ||
        size > NV_VBIOS_OVERRIDE_MAX_SIZE)
        return NV_FALSE;

    for (off = 0; off <= size - 0x200; off += 0x200)
    {
        NvU32 pcir, relative, length, id, j;
        NvU8 checksum = 0;

        if (image[off] != 0x55 || image[off + 1] != 0xAA)
            continue;
        relative = image[off + 0x18] | ((NvU32)image[off + 0x19] << 8);
        if (relative > size - off - 0x18)
            continue;
        pcir = off + relative;
        if (image[pcir] != 'P' || image[pcir + 1] != 'C' ||
            image[pcir + 2] != 'I' || image[pcir + 3] != 'R' ||
            image[pcir + 0x14] != 0)
            continue;

        id = image[pcir + 4] | ((NvU32)image[pcir + 5] << 8) |
             ((NvU32)image[pcir + 6] << 16) | ((NvU32)image[pcir + 7] << 24);
        length = (image[pcir + 0x10] | ((NvU32)image[pcir + 0x11] << 8)) * 512U;
        if (id != pciId || length == 0 || length > size - off ||
            relative > length || length - relative < 0x18)
            return NV_FALSE;
        for (j = 0; j < length; j++)
            checksum = (NvU8)(checksum + image[off + j]);
        if (checksum != 0 || ++found != 1)
            return NV_FALSE;
        selected = off;
    }
    if (found != 1)
        return NV_FALSE;
    *offset = selected;
    return NV_TRUE;
}

#endif
'''

HELPERS = r'''static void
_kgspVbiosOverrideFree(KernelGsp *pKernelGsp)
{
    if (pKernelGsp->pVbiosOverrideDescriptor != NULL)
    {
        memdescFree(pKernelGsp->pVbiosOverrideDescriptor);
        memdescDestroy(pKernelGsp->pVbiosOverrideDescriptor);
        pKernelGsp->pVbiosOverrideDescriptor = NULL;
    }
    pKernelGsp->vbiosOverrideSize = 0;
}

static void
_kgspVbiosOverridePrepare(OBJGPU *pGpu, KernelGsp *pKernelGsp, NvU64 memdescFlags)
{
    NvU32 mode = 0, disabled = 0, size = 0, actualSize, skip = 0;
    NvU8 *image = NULL;
    NvU64 allocSize;
    NvP64 va = NvP64_NULL, priv = NvP64_NULL;
    NV_STATUS status = NV_OK;
    const char *stage = "chip-scope";

    _kgspVbiosOverrideFree(pKernelGsp);
    if ((osReadRegistryDword(NULL, NV_VBIOS_OVERRIDE_DISABLE_KEY, &disabled) == NV_OK) && disabled)
        return;
    if (osReadRegistryDword(pGpu, NV_VBIOS_OVERRIDE_MODE_KEY, &mode) != NV_OK || mode == 0)
        return;
    // Explicit chip scope: no Hopper, datacenter Blackwell, or future chips.
    if (!(IsGA100(pGpu) || IsGA102(pGpu) || IsGA103(pGpu) || IsGA104(pGpu) ||
          IsGA106(pGpu) || IsGA107(pGpu) || IsAD102(pGpu) ||
          IsAD103(pGpu) || IsAD104(pGpu) || IsAD106(pGpu) ||
          IsAD107(pGpu) || IsGB202(pGpu) || IsGB203(pGpu) ||
          IsGB205(pGpu) || IsGB206(pGpu) || IsGB207(pGpu)))
    {
        status = NV_ERR_NOT_SUPPORTED;
        goto done;
    }
    stage = "request-size";
    if (mode != 2 ||
        osReadRegistryDword(pGpu, NV_VBIOS_OVERRIDE_SIZE_KEY, &size) != NV_OK ||
        size < 0x200 || size > NV_VBIOS_OVERRIDE_MAX_SIZE)
    {
        status = NV_ERR_INVALID_ARGUMENT;
        goto done;
    }

    stage = "image-allocation";
    image = portMemAllocNonPaged(size);
    if (image == NULL)
    {
        status = NV_ERR_NO_MEMORY;
        goto done;
    }
    stage = "registry-image";
    actualSize = size;
    status = osReadRegistryBinary(pGpu, NV_VBIOS_OVERRIDE_IMAGE_KEY, image, &actualSize);
    if (status != NV_OK)
        goto done;
    stage = "image-validation";
    if (actualSize != size ||
        !kgspVbiosOverrideFindLegacy(image, size, pGpu->idInfo.PCIDeviceID, &skip))
    {
        status = NV_ERR_INVALID_DATA;
        goto done;
    }

    allocSize = NV_ALIGN_UP64((NvU64)(size - skip), RM_PAGE_SIZE);
    stage = "descriptor-create";
    status = memdescCreate(&pKernelGsp->pVbiosOverrideDescriptor, pGpu,
                           allocSize, RM_PAGE_SIZE, NV_TRUE, ADDR_SYSMEM,
                           NV_MEMORY_UNCACHED, memdescFlags);
    if (status != NV_OK)
    {
        pKernelGsp->pVbiosOverrideDescriptor = NULL;
        goto done;
    }
    stage = "descriptor-allocation";
    memdescTagAlloc(status, NV_FB_ALLOC_RM_INTERNAL_OWNER_BOOTLOADER_ARGS,
                    pKernelGsp->pVbiosOverrideDescriptor);
    if (status != NV_OK)
    {
        memdescDestroy(pKernelGsp->pVbiosOverrideDescriptor);
        pKernelGsp->pVbiosOverrideDescriptor = NULL;
        goto done;
    }
    stage = "descriptor-contiguity";
    if (!memdescCheckContiguity(pKernelGsp->pVbiosOverrideDescriptor, AT_GPU))
    {
        status = NV_ERR_MEMORY_ERROR;
        goto done;
    }
    stage = "descriptor-map";
    status = memdescMap(pKernelGsp->pVbiosOverrideDescriptor, 0, allocSize,
                        NV_TRUE, NV_PROTECT_READ_WRITE, &va, &priv);
    if (status != NV_OK)
        goto done;
    portMemSet(NvP64_VALUE(va), 0, allocSize);
    portMemCopy(NvP64_VALUE(va), allocSize, image + skip, size - skip);
    memdescUnmap(pKernelGsp->pVbiosOverrideDescriptor, NV_TRUE, va, priv);
    pKernelGsp->vbiosOverrideSize = size - skip;
    // Emit to the OS log even when release NV_PRINTF strings/routes are disabled.
    // This confirms host staging only, never firmware acceptance.
    portDbgPrintf(
        "NVRM: vbios_override: GPU %04x:%02x:%02x selected: %u bytes from offset 0x%x staged for GSP\n",
        gpuGetDomain(pGpu), gpuGetBus(pGpu), gpuGetDevice(pGpu), size - skip, skip);

done:
    portMemFree(image);
    if (status != NV_OK)
    {
        _kgspVbiosOverrideFree(pKernelGsp);
        portDbgPrintf(
            "NVRM: vbios_override: GPU %04x:%02x:%02x rejected override at %s (0x%x); using stock VBIOS\n",
            gpuGetDomain(pGpu), gpuGetBus(pGpu), gpuGetDevice(pGpu), stage, status);
    }
}
'''

LOADER_LICENSE = r'''/*
 * SPDX-FileCopyrightText: Copyright (c) 2000-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

'''

LOADER_FUNCTIONS = r'''static NV_STATUS
nv_parse_binary_registry_token(const char *param_name, char *token,
                               char **key_name, char **path)
{
    if ((key_name == NULL) || (path == NULL))
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Extract key name before first '='; reject if missing or empty
    if (((*key_name = strsep(&token, "=")) == NULL) || !strlen(*key_name))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: %s contains malformed token: missing key name\n",
                  param_name);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Extract file path after first '='; reject if missing or empty
    if (((*path = strsep(&token, "=")) == NULL) || !strlen(*path))
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: %s contains malformed token for key \"%s\": missing path\n",
                  param_name, *key_name);
        return NV_ERR_INVALID_ARGUMENT;
    }

    // Reject tokens with more than one '=' (e.g. "key=path=extra")
    if (strsep(&token, "=") != NULL)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: %s contains malformed token for key \"%s\": too many '=' separators\n",
                  param_name, *key_name);
        return NV_ERR_INVALID_ARGUMENT;
    }

    return NV_OK;
}

static NV_STATUS
nv_write_binary_registry_file(nvidia_stack_t *sp, nv_state_t *nv,
                              const char *key_name, const char *relative_path,
                              const char *param_name)
{
    int fw_status;
    char *firmware_path = NULL;
    NV_STATUS status;
    size_t firmware_path_len;
    const struct firmware *fw = NULL;
    nv_linux_state_t *nvl;

    if ((nv == NULL) || (key_name == NULL) ||
        (relative_path == NULL) || (param_name == NULL))
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    nvl = NV_GET_NVL_FROM_NV_STATE(nv);

    firmware_path_len = strlen(NV_BINARY_REGISTRY_FIRMWARE_DIR) +
                        strlen(relative_path) + 1;

    status = os_alloc_mem((void **)&firmware_path, firmware_path_len);
    if (status != NV_OK)
    {
        return status;
    }

    snprintf(firmware_path, firmware_path_len, "%s%s",
             NV_BINARY_REGISTRY_FIRMWARE_DIR, relative_path);

    fw_status = request_firmware(&fw, firmware_path, nvl->dev);
    if (fw_status != 0)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: %s key \"%s\" failed to load firmware file \"%s\" (rc=%d)\n",
                  param_name, key_name, firmware_path, fw_status);
        status = NV_ERR_OBJECT_NOT_FOUND;
        goto done;
    }

    if (fw->size > NV_U32_MAX)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: %s key \"%s\" firmware file \"%s\" too large (%zu bytes)\n",
                  param_name, key_name, firmware_path, fw->size);
        status = NV_ERR_INVALID_DATA;
        goto done;
    }

    status = rm_write_registry_binary(sp, nv, key_name,
                                      (NvU8 *)fw->data, (NvU32)fw->size);
    if (status != NV_OK)
    {
        nv_printf(NV_DBG_ERRORS,
                  "NVRM: %s key \"%s\" failed to write registry binary (status=0x%x)\n",
                  param_name, key_name, status);
    }

done:
    if (fw != NULL)
    {
        release_firmware(fw);
    }

    os_free_mem(firmware_path);
    return status;
}

NV_STATUS nv_parse_per_device_binary_option_string(nvidia_stack_t *sp,
                                                   nv_state_t *current_nv)
{
    NV_STATUS status = NV_OK;
    char *option_string = NULL;
    char *ptr, *token;
    char *name, *value;
    NvU32 domain, bus, slot, func;
    nv_state_t *nv = NULL;

    if (current_nv == NULL)
    {
        return NV_ERR_INVALID_ARGUMENT;
    }

    if (NVreg_RegistryBinaryFilePerDevice == NULL)
    {
        return NV_OK;
    }

    option_string = rm_remove_spaces(NVreg_RegistryBinaryFilePerDevice);
    if (option_string == NULL)
    {
        return NV_ERR_GENERIC;
    }

    ptr = option_string;

    while ((token = strsep(&ptr, ";")) != NULL)
    {
        if (!strlen(token))
        {
            continue;
        }

        status = nv_parse_binary_registry_token("NVreg_RegistryBinaryFilePerDevice",
                                                token, &name, &value);
        if (status != NV_OK)
        {
            break;
        }

        if (strcmp(name, NV_REG_PCI_DEVICE_BDF) == 0)
        {
            status = pci_str_to_bdf(value, &domain, &bus, &slot, &func);

            if (status != NV_OK)
            {
                nv = NULL;
                status = NV_OK;
                continue;
            }

            if ((current_nv->pci_info.domain == domain) &&
                (current_nv->pci_info.bus == bus) &&
                (current_nv->pci_info.slot == slot) &&
                (current_nv->pci_info.function == func))
            {
                nv = current_nv;
            }
            else
            {
                nv = NULL;
            }
            continue;
        }

        if (nv == NULL)
        {
            continue;
        }

        status = nv_write_binary_registry_file(sp, nv, name,
                                               value, "NVreg_RegistryBinaryFilePerDevice");
        if (status != NV_OK)
        {
            break;
        }
    }

    os_free_mem(option_string);
    return status;
}
'''

CACHED_ARGUMENTS_ABI = r'''typedef struct NV_ABI_STABLE MESSAGE_QUEUE_INIT_ARGUMENTS
{
#define MESSAGE_QUEUE_INIT_FLAG_ENCRYPTION          0x01
    NvU64 flags;

    NvU64 sharedMemPhysAddr;
    NvU64 cmdQueueOffset;
    NvU64 statQueueOffset;
    NvU32 queueElementHdrSize;
    NvU32 queueElementSizeMin;
    NvU32 queueElementSizeMax;
    NvU32 queueHeaderAlign;
    NvU32 queueElementAlign;
    NvU32 pageTableEntryCount;
    NvU8  reserved[8];
} MESSAGE_QUEUE_INIT_ARGUMENTS;

typedef struct NV_ABI_STABLE GSP_SR_INIT_ARGUMENTS
{
    NvU32 oldLevel;
    NvU32 flags;
    NvU8  reserved[8];
} GSP_SR_INIT_ARGUMENTS;

/*!
 * (Cached) GSP fw RM initialization arguments.
 */
typedef struct NV_ABI_STABLE GSP_ARGUMENTS_CACHED
{
#define GSP_ARGUMENTS_MAGIC_VALUE (' ' << 24 | 'P' << 16 | 'S' << 8 | 'G')
    NvU32                             magic;
    NvU16                             size;
    NvU8                              reserved[2];

#define GSP_ARGUMENTS_FLAG_IN_PM_TRANSITION          0x01
#define GSP_ARGUMENTS_FLAG_STACK_IN_DMEM             0x02
#define GSP_ARGUMENTS_FLAG_RECOVERY_MARGIN_PRESENT   0x04
#define GSP_ARGUMENTS_FLAG_SCAN_RECOVERY_MARGIN      0x08
    NvU64                             flags;

    MESSAGE_QUEUE_INIT_ARGUMENTS      messageQueueInitArguments;

    GSP_SR_INIT_ARGUMENTS             srInitArguments;

    NvU8                              reserved2[4];
    NvU32                             gpuInstance;

    struct
    {
        NvU64                         pa;
        NvU64                         size;
    } profilerArgs;

    struct
    {
        NvU64                         pa;
        NvU64                         size;
    } sysmemHeapArgs;

    struct
    {
        NvU64                         pa;
        NvU64                         size;
    } rmStateMonitorBufferArgs;

    struct
    {
        NvU64                         radix3;
        NvU64                         size;
    } bindataArgs;

    struct
    {
        NvU64                         pa;
        NvU64                         size;
    } vbiosOverrideArgs;

    //
    // Other data can be added here, so long as the whole structure is <=4kb
    //
} GSP_ARGUMENTS_CACHED;'''
