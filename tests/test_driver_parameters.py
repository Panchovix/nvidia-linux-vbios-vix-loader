"""Execute the emitted aggregate registry parameter callbacks without a module."""
import ctypes
import errno
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
import nvidia_vbios.driver as driver
from nvidia_vbios.limits import REGISTRY_STRING_MAX_BYTES

KEYS = ('__NV_REGISTRY_DWORDS', '__NV_REGISTRY_DWORDS_PER_DEVICE',
        '__NV_REGISTRY_BINARY_FILE_PER_DEVICE')
NAMES = ('NVreg_RegistryDwords', 'NVreg_RegistryDwordsPerDevice',
         'NVreg_RegistryBinaryFilePerDevice')

STUBS = r'''
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#define PAGE_SIZE 4096
struct kernel_param;
struct kernel_param_ops {
    unsigned int flags;
    int (*set)(const char *, const struct kernel_param *);
    int (*get)(char *, const struct kernel_param *);
    void (*free)(void *);
};
struct kernel_param {
    const char *name;
    const struct kernel_param_ops *ops;
    void *arg;
    unsigned int permission;
};
static int scnprintf(char *buffer, size_t size, const char *format, ...) {
    va_list args;
    int result;
    va_start(args, format);
    result = vsnprintf(buffer, size, format, args);
    va_end(args);
    return result < 0 ? result : (result >= (int)size ? (int)size - 1 : result);
}
#define module_param_cb(name, ops, arg, perm) \
    static const struct kernel_param param_##name = {#name, ops, arg, perm}
#define __MODULE_PARM_TYPE(name, type) \
    static const char type_##name[] __attribute__((used)) = #name ":" type
#define __NV_REG_VAR(regkey) NVreg_##regkey
#define __NV_REGISTRY_DWORDS RegistryDwords
#define __NV_REGISTRY_DWORDS_PER_DEVICE RegistryDwordsPerDevice
#define __NV_REGISTRY_BINARY_FILE_PER_DEVICE RegistryBinaryFilePerDevice
'''
WRAPPERS = r'''
static const struct kernel_param *parameters[] = {
    &param_NVreg_RegistryDwords,
    &param_NVreg_RegistryDwordsPerDevice,
    &param_NVreg_RegistryBinaryFilePerDevice,
};
void reset(void) {
    unsigned int i;
    for (i = 0; i < sizeof(parameters) / sizeof(parameters[0]); i++) {
        struct nv_vbios_registry_string_parameter *state = parameters[i]->arg;
        *state->value = NULL;
        memset(state->storage, 0, sizeof(state->storage));
    }
}
int set_value(unsigned int i, const char *value) {
    return parameters[i]->ops->set(value, parameters[i]);
}
int get_value(unsigned int i, char *buffer) {
    return parameters[i]->ops->get(buffer, parameters[i]);
}
const char *raw_value(unsigned int i) {
    const struct nv_vbios_registry_string_parameter *state = parameters[i]->arg;
    return *state->value;
}
const char *parameter_name(unsigned int i) { return parameters[i]->name; }
unsigned int permission(unsigned int i) { return parameters[i]->permission; }
int has_free(unsigned int i) { return parameters[i]->ops->free != NULL; }
'''


class RegistryParameterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('cc'):
            raise unittest.SkipTest('C compiler required')
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        path = Path(cls.temp.name)
        contents = {driver.REG_H: '\n'.join(
            f'NV_DEFINE_REG_STRING_ENTRY({key}, NULL);' for key in KEYS),
            driver.OS_REG: '#include "nv-reg.h"\n'}
        driver._patch_registry_parameters(contents)
        payload = contents[driver.OS_REG].removesuffix('#include "nv-reg.h"\n')
        source = path / 'parameters.c'
        source.write_text(STUBS + payload + contents[driver.REG_H] + WRAPPERS)
        subprocess.run(['cc', '-shared', '-fPIC', '-std=c11', '-Wall', '-Wextra',
                        '-Werror', str(source), '-o', str(path / 'parameters.so')],
                       check=True, capture_output=True)
        cls.lib = ctypes.CDLL(str(path / 'parameters.so'))
        cls.lib.set_value.argtypes = [ctypes.c_uint, ctypes.c_char_p]
        cls.lib.get_value.argtypes = [ctypes.c_uint, ctypes.c_void_p]
        cls.lib.raw_value.argtypes = [ctypes.c_uint]
        cls.lib.raw_value.restype = ctypes.c_char_p
        cls.lib.parameter_name.argtypes = [ctypes.c_uint]
        cls.lib.parameter_name.restype = ctypes.c_char_p
        cls.lib.permission.argtypes = [ctypes.c_uint]
        cls.lib.has_free.argtypes = [ctypes.c_uint]

    def setUp(self):
        self.lib.reset()

    def test_exact_parameter_names_read_only_and_static_lifetime(self):
        for index, name in enumerate(NAMES):
            with self.subTest(parameter=name):
                self.assertEqual(self.lib.parameter_name(index).decode(), name)
                self.assertEqual(self.lib.permission(index), 0o444)
                self.assertFalse(self.lib.has_free(index))
                self.assertIsNone(self.lib.raw_value(index))
                self.assertEqual(self.lib.set_value(index, b''), 0)
                self.assertEqual(self.lib.raw_value(index), b'')

    def test_old_limit_and_maximum_round_trip_with_sysfs_guards(self):
        self.assertEqual(REGISTRY_STRING_MAX_BYTES, 4094)
        for index, name in enumerate(NAMES):
            for length in (1, 1024, 1025, REGISTRY_STRING_MAX_BYTES):
                with self.subTest(parameter=name, length=length):
                    value = b'x' * length
                    self.assertEqual(self.lib.set_value(index, value), 0)
                    self.assertEqual(self.lib.raw_value(index), value)
                    output = ctypes.create_string_buffer(4098)
                    ctypes.memset(output, 0xA5, len(output))
                    count = self.lib.get_value(index, ctypes.byref(output, 1))
                    self.assertEqual(count, length + 1)
                    self.assertEqual(output.raw[1:count + 1], value + b'\n')
                    self.assertEqual(output.raw[count + 1], 0)
                    self.assertEqual(output.raw[0], 0xA5)
                    self.assertEqual(output.raw[-1], 0xA5)

    def test_rejections_preserve_previous_pointer_contents_and_other_parameters(self):
        for index in range(3):
            value = f'pci=0000:{index + 1:02x}:00.0;Example=2'.encode()
            self.assertEqual(self.lib.set_value(index, value), 0)
        before = [self.lib.raw_value(index) for index in range(3)]
        for index in range(3):
            with self.subTest(parameter=NAMES[index]):
                self.assertEqual(self.lib.set_value(index, None), -errno.EINVAL)
                for length in (REGISTRY_STRING_MAX_BYTES + 1, 16384):
                    self.assertEqual(self.lib.set_value(index, b'z' * length), -errno.ENOSPC)
                    self.assertEqual([self.lib.raw_value(i) for i in range(3)], before)
                self.assertEqual(self.lib.set_value(index, b'replacement=3'), 0)
                self.assertEqual(self.lib.raw_value(index), b'replacement=3')
                self.assertEqual(self.lib.set_value(index, before[index]), 0)

    def test_null_rejection_does_not_turn_omitted_into_empty(self):
        for index in range(3):
            self.assertEqual(self.lib.set_value(index, None), -errno.EINVAL)
            self.assertIsNone(self.lib.raw_value(index))
            self.assertEqual(self.lib.set_value(index, b'z' * (REGISTRY_STRING_MAX_BYTES + 1)), -errno.ENOSPC)
            self.assertIsNone(self.lib.raw_value(index))
            self.assertEqual(self.lib.set_value(index, b''), 0)
            output = ctypes.create_string_buffer(4096)
            self.assertEqual(self.lib.get_value(index, output), 1)
            self.assertEqual(output.value, b'\n')


if __name__ == '__main__':
    unittest.main()
