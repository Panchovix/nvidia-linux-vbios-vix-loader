"""Shared limits for the loader and its patched kernel module."""

# The reviewed open NVIDIA module sources support at most 32 GPU instances.
MAX_GPUS = 32
# Reserve one byte for the trailing newline and one for NUL in a 4 KiB
# sysfs parameter buffer, so status can compare the complete loaded value.
REGISTRY_STRING_MAX_BYTES = 4094
