"""The runtime VFE layout store sync of the loader (lifecycle.vfe_layouts) on a synthetic root: without the editor
extension, as in the open loader, it reads, writes and removes nothing."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from nvidia_vbios.lifecycle import vfe_layouts
from nvidia_vbios.lifecycle.security import atomic_write

EMPTY = {'written': [], 'removed': [], 'warnings': []}


class OpenLoaderLayoutStoreTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.store = self.root / vfe_layouts.STORE.lstrip('/')
        atomic_write(self.root / vfe_layouts.ROMS.lstrip('/') / ('a' * 64 + '.bin'), b'REVIEWED ROM payload')

    def test_without_the_editor_nothing_is_written_or_removed(self):
        with mock.patch('nvidia_vbios.payload.optional_editor', return_value=None):
            self.assertEqual(vfe_layouts.sync(self.root), EMPTY)
            self.assertFalse(self.store.exists())
            atomic_write(self.store / ('b' * 64 + '.json'), b'{}', 0o644)
            self.assertEqual(vfe_layouts.sync(self.root), EMPTY)
        self.assertEqual([path.name for path in self.store.iterdir()], ['b' * 64 + '.json'])

    def test_a_payload_without_hooks_gets_no_layout(self):
        """With or without the editor: a stored payload that is not an image with hooks creates no store."""
        self.assertEqual(vfe_layouts.sync(self.root), EMPTY)
        self.assertFalse(self.store.exists())


if __name__ == '__main__':
    unittest.main()
