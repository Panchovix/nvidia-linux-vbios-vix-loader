"""Opt-in GTK smoke test of the Linux loader window; needs a dedicated display, for example Broadway.

VBIOS_LOADER_GUI_SMOKE=1; optional VBIOS_LOADER_GUI_SCREENSHOTS=DIR saves shot-en.png and shot-es.png there.
Broadway without a browser draws new frames only with GDK_DEBUG=no-vsync, which the screenshots wait for.
The probe and the runner are fakes: nothing runs pkexec, reads the GPUs or changes the system.
"""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

from test_loader_gui import GPU0, KERNEL, VERSION, make_checkout, snapshot
from test_payload import PRO_6000, legacy_image

EVENTS = [{'event': 'start', 'protocol': 1, 'kernel': KERNEL,
           'steps': ['download', 'prepare', 'preflight', 'install', 'enroll', 'reconcile', 'enable']},
          *({'event': 'step', 'step': step, 'index': index, 'total': 7}
            for index, step in enumerate(('download', 'prepare', 'preflight', 'install', 'enroll'), 1)),
          {'event': 'step', 'step': 'reconcile', 'index': 6, 'total': 7},
          {'event': 'phase', 'step': 'reconcile', 'phase': 'build'},
          {'event': 'step', 'step': 'enable', 'index': 7, 'total': 7},
          {'event': 'done', 'ok': True, 'kernel': KERNEL, 'entry': f'vbios-{KERNEL}-0123456789abcdef0123',
           'default': 'selected', 'default_reason': None,
           'devices': [{'bdf': GPU0.bdf, 'sha256': 'ab' * 32, 'architecture': 'blackwell-gb20x', 'kept': False}]}]


@unittest.skipUnless(os.environ.get('VBIOS_LOADER_GUI_SMOKE') == '1', 'opt-in GTK display smoke test')
class LoaderWindowSmokeTests(unittest.TestCase):
    def test_load_progress_reboot_offer_language_and_close(self):
        import gi
        gi.require_version('Gtk', '4.0')
        from gi.repository import Gio, GLib, Gtk
        from nvidia_vbios.loader_gui import gui, runner
        from nvidia_vbios.loader_gui.controller import Controller
        app = Gtk.Application(application_id='io.github.panchovix.VixLoader.Smoke',
                              flags=Gio.ApplicationFlags.NON_UNIQUE)
        self.assertTrue(app.register(None))
        context = GLib.MainContext.default()
        seen, asked, commands = set(), [], []

        def until(condition):
            deadline = time.monotonic() + 15
            while not condition():
                for _ in range(200):          # bounded: a spinning spinner keeps the context busy
                    if not context.pending():
                        break
                    context.iteration(False)
                seen.add(window.progress_label.get_text())
                if time.monotonic() >= deadline:
                    self.fail('GTK operation did not complete')
                time.sleep(.01)

        def ask(message, detail, buttons, answered):
            asked.append(message)
            # Confirm Load with its last button; answer the reboot offer with Later.
            GLib.idle_add(lambda: answered(len(buttons) - 1 if len(asked) == 1 else 0) and False)

        def stream(argv, on_line):
            commands.append(argv)
            for event in EVENTS:
                time.sleep(.2)
                on_line(json.dumps(event))
            state['snapshot'] = snapshot(release='cd' * 32, release_has_setup=True, triggers=True,
                                         images=(f'initramfs-{KERNEL}-vbios-0123456789abcdef0123.img',))
            return runner.Outcome(0, tuple(json.dumps(event) for event in EVENTS), '')

        def save(name):
            directory = os.environ.get('VBIOS_LOADER_GUI_SCREENSHOTS')
            if not directory:
                return
            clock = window.get_frame_clock()
            drawn = clock.get_frame_counter()
            window.queue_draw()
            until(lambda: clock.get_frame_counter() > drawn + 1)
            picture = Gtk.Snapshot()
            Gtk.WidgetPaintable.new(window).snapshot(picture, window.get_width(), window.get_height())
            texture = window.get_renderer().render_texture(picture.to_node(), None)
            self.assertTrue(texture.save_to_png(str(Path(directory) / name)))

        with tempfile.TemporaryDirectory() as directory:
            state = {'snapshot': snapshot()}
            payload = Path(directory) / 'gpu0-loader.bin'
            payload.write_bytes(legacy_image(PRO_6000))
            controller = Controller('en', checkout=make_checkout(directory),
                                    inspect=lambda path: {'version': VERSION, 'supported': True, 'capabilities': {}})
            gui.install_css()
            window = gui.Window(app, controller, read_system=lambda: state['snapshot'], stream=stream, ask=ask)
            try:
                window.present()
                until(lambda: controller.snapshot is not None and controller.busy is None)
                self.assertFalse(window.load_button.get_sensitive())
                window.on_file(GPU0.bdf, str(payload))
                self.assertTrue(window.load_button.get_sensitive())
                window.load()
                until(lambda: len(asked) == 2 and controller.busy is None)
                self.assertEqual(asked, ['Load the VBIOS override?', 'Reboot now?'])
                self.assertEqual(commands[0][2:6],
                                 [str(controller.checkout / 'nvbios'), 'system', 'setup', '--progress'])
                steps = {text.split(' · ')[0] for text in seen if text.startswith('Step ')}
                self.assertGreaterEqual(len(steps), 3)                 # the loop kept drawing while it ran
                buffer = window.messages
                log = buffer.get_text(buffer.get_start_iter(), buffer.get_end_iter(), False)
                self.assertIn(f'Load finished for kernel {KERNEL}.', log)
                self.assertEqual(window.summary.get_text(), 'Prepared for this kernel. Reboot to load it (or you '
                                                            'started the normal entry).')
                save('shot-en.png')
                window.language_action.activate(GLib.Variant('s', 'es'))
                until(lambda: window.load_button.get_label() == 'Cargar')
                self.assertTrue(window.summary.get_text().startswith('Preparado para este kernel.'))
                save('shot-es.png')
                window.close()
                until(lambda: not window.get_visible())
            finally:
                window.destroy()


if __name__ == '__main__':
    unittest.main()
