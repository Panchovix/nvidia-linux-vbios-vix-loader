"""The loader window (GTK 4, no libadwaita): widgets only; state, checks, commands and texts are in controller.py.

The probe and every pkexec command run in a worker thread; results come back through GLib.idle_add.
VBIOS_LOADER_GUI_SMOKE=1 opens the window, switches to the other language and closes it after a few seconds.
"""
from __future__ import annotations
import os
import threading

import gi
gi.require_version('Gdk', '4.0')
gi.require_version('Gtk', '4.0')
from gi.repository import Gdk, Gio, GLib, Gtk, Pango

from .. import __version__
from . import probe, runner
from .controller import GPU_MODES, LANGUAGES, SOURCE_MODES, Controller, find_checkout, language_from_env

APP_ID = 'io.github.panchovix.VixLoader'
SMOKE_ENV = 'VBIOS_LOADER_GUI_SMOKE'
SMOKE_SECONDS = 8
LEVELS = ('ok', 'warn', 'error')
ICONS = {'ok': 'emblem-ok-symbolic', 'warn': 'dialog-warning-symbolic', 'error': 'dialog-error-symbolic'}
# Worker results go ahead of redraws, so a busy spinner never delays them.
RESULT = GLib.PRIORITY_DEFAULT
CSS = '.vl-ok { color: @success_color; } .vl-warn { color: @warning_color; } .vl-error { color: @error_color; }'


def install_css():
    provider = Gtk.CssProvider()
    if hasattr(provider, 'load_from_string'):        # GTK 4.12
        provider.load_from_string(CSS)
    else:
        provider.load_from_data(CSS, -1)
    Gtk.StyleContext.add_provider_for_display(Gdk.Display.get_default(), provider,
                                              Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION)


def set_level(widget, level):
    for name in LEVELS:
        widget.remove_css_class('vl-' + name)
    if level in LEVELS:
        widget.add_css_class('vl-' + level)


def frame(title, child):
    label = Gtk.Label(label=title)
    label.add_css_class('heading')
    child.set_margin_top(6)
    child.set_margin_bottom(8)
    child.set_margin_start(8)
    child.set_margin_end(8)
    return Gtk.Frame(label_widget=label, child=child)


class Window(Gtk.ApplicationWindow):
    def __init__(self, app, controller, *, read_system=None, stream=runner.stream, ask=None):
        super().__init__(application=app, default_width=900, default_height=900)
        self.c = controller
        self.read_system = read_system or (lambda: probe.snapshot(checkout=controller.checkout))
        self.stream = stream
        self.ask = ask or self.alert
        self.reboot_text = None          # offered after the refresh that follows Load or Remove
        self.filling = False             # set while widgets are updated from the controller
        self.rows = {}
        self.messages = Gtk.TextBuffer()
        self.end = self.messages.create_mark(None, self.messages.get_end_iter(), False)
        header = Gtk.HeaderBar()
        self.refresh_button = Gtk.Button(icon_name='view-refresh-symbolic')
        self.refresh_button.connect('clicked', lambda *_: self.refresh())
        header.pack_start(self.refresh_button)
        self.menu_button = Gtk.MenuButton(icon_name='open-menu-symbolic')
        header.pack_end(self.menu_button)
        self.set_titlebar(header)
        self.language_action = Gio.SimpleAction.new_stateful('language', GLib.VariantType.new('s'),
                                                             GLib.Variant('s', controller.language))
        self.language_action.connect('change-state', self.on_language)
        self.details_action = Gio.SimpleAction.new('details', None)
        self.details_action.connect('activate', lambda *_: self.start('details'))
        for action in (self.language_action, self.details_action):
            self.add_action(action)
        self.connect('close-request', self.on_close)
        self.build()
        timer = GLib.timeout_add_seconds(1, self.tick)
        self.connect('destroy', lambda *_: GLib.source_remove(timer))
        self.refresh()

    # -- widgets --------------------------------------------------------------------------------------------------
    def build(self):
        """Create the content in the controller's language (again after a language change)."""
        t = self.c.text
        self.set_title(f"{t['title']} {__version__}")
        self.refresh_button.set_tooltip_text(t['refresh'])
        menu, languages = Gio.Menu(), Gio.Menu()
        for code, name in LANGUAGES:
            languages.append(name, f'win.language::{code}')
        menu.append_section(t['language'], languages)
        menu.append(t['details'], 'win.details')
        self.menu_button.set_menu_model(menu)

        content = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10, margin_top=10, margin_bottom=10,
                          margin_start=12, margin_end=12)
        status = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.summary = Gtk.Label(xalign=0, wrap=True)
        self.summary.add_css_class('heading')
        self.grid = Gtk.Grid(column_spacing=10, row_spacing=3)
        status.append(self.summary)
        status.append(self.grid)
        content.append(frame(t['status'], status))

        self.gpu_list = Gtk.ListBox(selection_mode=Gtk.SelectionMode.NONE)
        content.append(frame(t['gpus'], Gtk.ScrolledWindow(child=self.gpu_list, propagate_natural_height=True,
                                                           max_content_height=330, min_content_height=150,
                                                           vexpand=True)))

        source = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.source_buttons, group = {}, None
        for mode in SOURCE_MODES:
            button = Gtk.CheckButton(group=group)
            group = group or button
            button.connect('toggled', self.on_source_mode, mode)
            self.source_buttons[mode] = button
        folder = Gtk.Box(spacing=6)
        self.folder_entry = Gtk.Entry(hexpand=True, placeholder_text=t['folder_placeholder'])
        self.folder_entry.connect('activate', lambda entry: self.on_folder(entry.get_text()))
        self.on_leave(self.folder_entry, lambda: self.on_folder(self.folder_entry.get_text()))
        self.folder_button = Gtk.Button(label=t['choose'])
        self.folder_button.connect('clicked', lambda *_: self.pick_folder())
        self.p2p = Gtk.CheckButton(label=t['p2p'], margin_start=24)
        self.p2p.connect('toggled', self.on_p2p)
        self.source_check = Gtk.Label(xalign=0, wrap=True)
        for widget in (self.source_buttons['folder'], self.folder_entry, self.folder_button):
            folder.append(widget)
        for widget in (self.source_buttons['keep'], self.source_buttons['download'], folder, self.p2p,
                       self.source_check):
            source.append(widget)
        content.append(frame(t['source'], source))

        actions = Gtk.Box(spacing=8)
        self.spinner = Gtk.Spinner()
        self.progress_label = Gtk.Label(xalign=0, hexpand=True, ellipsize=Pango.EllipsizeMode.MIDDLE)
        self.progress_bar = Gtk.ProgressBar(valign=Gtk.Align.CENTER, width_request=140)
        self.remove_button = Gtk.Button(label=t['remove'])
        self.remove_button.connect('clicked', lambda *_: self.remove())
        self.load_button = Gtk.Button(label=t['load'])
        self.load_button.add_css_class('suggested-action')
        self.load_button.connect('clicked', lambda *_: self.load())
        for widget in (self.spinner, self.progress_label, self.progress_bar, self.remove_button, self.load_button):
            actions.append(widget)
        content.append(actions)
        self.blockers = Gtk.Label(xalign=0, wrap=True)
        self.blockers.add_css_class('dim-label')
        content.append(self.blockers)

        view = Gtk.TextView(buffer=self.messages, editable=False, cursor_visible=False,
                            wrap_mode=Gtk.WrapMode.WORD_CHAR, left_margin=4, right_margin=4)
        self.message_view = view
        content.append(frame(t['messages'], Gtk.ScrolledWindow(child=view, vexpand=True, min_content_height=110)))
        # Scrolls as a whole on short screens; the GPU list and the messages also scroll on their own.
        self.set_child(Gtk.ScrolledWindow(child=content, hscrollbar_policy=Gtk.PolicyType.NEVER))
        self.fill_gpus()

    def on_leave(self, entry, callback):
        """Check a typed or pasted path when the entry loses focus, as on Enter."""
        focus = Gtk.EventControllerFocus()
        focus.connect('leave', lambda *_: callback())
        entry.add_controller(focus)

    def fill_gpus(self):
        """One row per GPU: name, what is loaded now, the choice, the file and its check line."""
        t = self.c.text
        while (row := self.gpu_list.get_first_child()) is not None:   # ListBox has no remove-all call before GTK 4.12
            self.gpu_list.remove(row)
        self.rows = {}
        for gpu in self.c.snapshot.gpus if self.c.snapshot else ():
            view = self.c.gpu_view(gpu)
            grid = Gtk.Grid(column_spacing=8, row_spacing=3, margin_top=6, margin_bottom=6, margin_start=4,
                            margin_end=4)
            title = Gtk.Label(label=view['title'], xalign=0, hexpand=True)
            title.add_css_class('heading')
            subtitle = Gtk.Label(label=view['subtitle'], xalign=0)
            subtitle.add_css_class('dim-label')
            mode = Gtk.DropDown.new_from_strings([t['mode_' + name] for name in GPU_MODES])
            mode.set_selected(GPU_MODES.index(view['mode']))
            mode.connect('notify::selected', self.on_mode, gpu.bdf)
            entry = Gtk.Entry(text=view['path'], hexpand=True, placeholder_text=t['file_placeholder'])
            entry.connect('activate', lambda entry, bdf=gpu.bdf: self.on_file(bdf, entry.get_text()))
            self.on_leave(entry, lambda entry=entry, bdf=gpu.bdf: self.on_file(bdf, entry.get_text(), typed=True))
            choose = Gtk.Button(label=t['choose'])
            choose.connect('clicked', lambda *_, gpu=gpu: self.pick_file(gpu))
            check = Gtk.Label(xalign=0, wrap=True)
            grid.attach(title, 0, 0, 2, 1)
            grid.attach(Gtk.Label(label=view['now'], xalign=1), 2, 0, 2, 1)
            grid.attach(subtitle, 0, 1, 4, 1)
            grid.attach(mode, 0, 2, 1, 1)
            grid.attach(entry, 1, 2, 2, 1)
            grid.attach(choose, 3, 2, 1, 1)
            grid.attach(check, 0, 3, 4, 1)
            self.gpu_list.append(grid)
            self.rows[gpu.bdf] = dict(mode=mode, entry=entry, choose=choose, check=check)

    def update(self):
        """Bring every widget in line with the controller."""
        c, t = self.c, self.c.text
        idle = not c.busy
        self.filling = True
        try:
            self.refresh_button.set_sensitive(idle)
            self.details_action.set_enabled(c.can_details())
            child = self.grid.get_first_child()
            while child:
                self.grid.remove(child)
                child = self.grid.get_first_child()
            if c.snapshot is None:
                self.summary.set_text(t['working'])
            else:
                level, text = c.summary()
                self.summary.set_text(text)
                set_level(self.summary, level)
                for row, (label, value, level) in enumerate(c.system_rows()):
                    name = Gtk.Label(label=label, xalign=0)
                    name.add_css_class('dim-label')
                    icon = Gtk.Image(icon_name=ICONS[level])
                    set_level(icon, level)
                    self.grid.attach(name, 0, row, 1, 1)
                    self.grid.attach(icon, 1, row, 1, 1)
                    self.grid.attach(Gtk.Label(label=value, xalign=0, wrap=True), 2, row, 1, 1)
                for gpu in c.snapshot.gpus:
                    view, row = c.gpu_view(gpu), self.rows.get(gpu.bdf)
                    if row is None:
                        continue
                    row['mode'].set_selected(GPU_MODES.index(view['mode']))
                    row['mode'].set_sensitive(idle)
                    for name in ('entry', 'choose'):
                        row[name].set_sensitive(idle and view['mode'] == 'new')
                    level, text = view['check']
                    row['check'].set_text(text)
                    set_level(row['check'], level)
                source = c.source_view()
                for mode, button in self.source_buttons.items():
                    button.set_label(source['labels'][mode])
                    button.set_sensitive(idle and source['available'][mode])
                    button.set_active(mode == source['mode'])
                folder = idle and source['mode'] == 'folder'
                for widget in (self.folder_entry, self.folder_button, self.p2p):
                    widget.set_sensitive(folder)
                self.p2p.set_active(source['p2p'])
                if self.folder_entry.get_text() != source['path'] and not self.folder_entry.has_focus():
                    self.folder_entry.set_text(source['path'])
                level, text = source['check']
                self.source_check.set_text(text)
                self.source_check.set_visible(bool(text))
                set_level(self.source_check, level)
            self.load_button.set_sensitive(c.can_load())
            self.remove_button.set_sensitive(c.can_remove())
            blockers = c.load_blockers() if c.snapshot is not None and idle else []
            self.blockers.set_text('\n'.join('• ' + text for text in blockers))
            self.blockers.set_visible(bool(blockers))
            self.tick()
        finally:
            self.filling = False

    def tick(self):
        """Spinner, progress line and bar; also every second for the elapsed time."""
        self.spinner.set_spinning(bool(self.c.busy))
        self.progress_label.set_text(self.c.progress_text())
        self.progress_bar.set_visible(self.c.busy == 'load')
        self.progress_bar.set_fraction(self.c.progress_fraction())
        return True

    def log(self, lines):
        if lines:
            self.messages.insert(self.messages.get_end_iter(), '\n'.join(lines) + '\n')
            self.message_view.scroll_mark_onscreen(self.end)

    def alert(self, message, detail, buttons, answered):
        """Gtk.AlertDialog with buttons; answered(index), 0 when dismissed."""
        dialog = Gtk.AlertDialog(message=message, detail=detail, buttons=buttons, cancel_button=0,
                                 default_button=len(buttons) - 1, modal=True)

        def done(dialog, result):
            try:
                index = dialog.choose_finish(result)
            except GLib.Error:
                index = 0
            answered(index)
        dialog.choose(self, None, done)

    # -- choices --------------------------------------------------------------------------------------------------
    def on_mode(self, dropdown, _spec, bdf):
        if self.filling:
            return
        mode = GPU_MODES[dropdown.get_selected()]
        self.c.set_mode(bdf, mode)
        path = self.rows[bdf]['entry'].get_text()
        if mode == 'new' and path and path != self.c.choices[bdf].path:
            self.c.choose_file(bdf, path)
        self.update()

    def on_file(self, bdf, path, typed=False):
        choice = self.c.choices.get(bdf)
        # Leaving the entry checks only a changed path; Enter and the file dialog always read the file again.
        if self.c.busy or choice is None or (typed and choice.mode == 'new' and path == choice.path):
            return
        self.c.choose_file(bdf, path)
        self.rows[bdf]['entry'].set_text(self.c.choices[bdf].path)
        self.update()

    def pick_file(self, gpu):
        t = self.c.text
        payloads = Gtk.FileFilter(name=t['file_types'])
        for pattern in ('*.bin', '*.rom'):
            payloads.add_pattern(pattern)
        filters = Gio.ListStore.new(Gtk.FileFilter)
        filters.append(payloads)
        dialog = Gtk.FileDialog(title=t['file_title'].format(index='?' if gpu.index is None else gpu.index),
                                filters=filters, default_filter=payloads, modal=True)
        dialog.open(self, None, lambda dialog, result: self.picked(dialog.open_finish, result,
                                                                  lambda path: self.on_file(gpu.bdf, path)))

    def pick_folder(self):
        dialog = Gtk.FileDialog(title=self.c.text['folder_title'], modal=True)
        dialog.select_folder(self, None, lambda dialog, result: self.picked(dialog.select_folder_finish, result,
                                                                           self.on_folder))

    def picked(self, finish, result, use):
        try:
            chosen = finish(result)
        except GLib.Error:      # dismissed
            return
        path = chosen.get_path() if chosen else None
        if path:
            use(path)

    def on_source_mode(self, button, mode):
        if not self.filling and button.get_active():
            self.c.choose_source(mode)
            self.update()

    def on_folder(self, path):
        if not self.c.busy and self.c.source.mode == 'folder' and path != self.c.source.path:
            self.c.choose_source('folder', path)
            self.update()

    def on_p2p(self, button):
        if not self.filling:
            self.c.set_p2p(button.get_active())
            self.update()

    def on_language(self, action, value):
        if self.c.set_language(value.get_string()):
            action.set_state(value)
            self.build()
            self.update()

    # -- actions --------------------------------------------------------------------------------------------------
    def work(self, function, done):
        def target():
            try:
                result = function()
            except Exception as exc:  # shown in Messages; the window must survive anything
                result = exc
            GLib.idle_add(done, result, priority=RESULT)
        threading.Thread(target=target, daemon=True).start()

    def refresh(self):
        if self.c.busy:
            return
        self.c.busy = 'refresh'
        self.update()
        self.work(self.read_system, self.refreshed)

    def refreshed(self, snapshot):
        if isinstance(snapshot, Exception):
            self.c.busy = None
            self.log([self.c.text['note'].format(message=f'{type(snapshot).__name__}: {snapshot}')])
        else:
            self.log(self.c.apply_snapshot(snapshot))
            self.fill_gpus()
        self.update()
        if self.reboot_text and self.c.snapshot is not None:
            text, self.reboot_text = self.reboot_text, None
            self.offer_reboot(text)
        return False

    def load(self):
        question = self.c.confirm_load()       # reads the files again: they may have changed
        self.update()
        if question:
            t = self.c.text
            self.ask(t['confirm_load_title'], question, [t['cancel'], t['load']],
                     lambda answer: answer == 1 and self.start('load'))

    def remove(self):
        if self.c.can_remove():
            t = self.c.text
            self.ask(t['confirm_remove_title'], self.c.confirm_remove(), [t['cancel'], t['remove']],
                     lambda answer: answer == 1 and self.start('remove'))

    def offer_reboot(self, text):
        t = self.c.text
        if self.c.can_reboot():
            self.ask(t['reboot_title'], text, [t['later'], t['reboot_now']],
                     lambda answer: answer == 1 and self.c.can_reboot() and self.start('reboot'))
        else:
            self.ask(t['reboot_title'], f"{text}\n\n{t['reboot_wait']}", [t['later']], lambda answer: None)

    def start(self, action):
        if self.c.busy or self.c.snapshot is None:
            return
        argv, lines = self.c.begin(action)
        self.log(lines)
        self.update()

        def target():
            try:
                outcome = self.stream(argv, lambda line: GLib.idle_add(self.on_line, line, priority=RESULT))
            except Exception as exc:  # reported like a crashed command
                outcome = runner.Outcome(-1, (), f'{type(exc).__name__}: {exc}')
            GLib.idle_add(self.finished, outcome, priority=RESULT)
        threading.Thread(target=target, daemon=True).start()

    def on_line(self, line):
        self.log(self.c.on_line(line))
        self.tick()
        return False

    def finished(self, outcome):
        result = self.c.finish(outcome)
        self.log(result.lines)
        self.reboot_text = result.reboot_text if result.offer_reboot else None
        self.update()
        self.refresh()
        return False

    def on_close(self, _window):
        if self.c.busy not in (None, 'refresh'):      # a pkexec command keeps running without the window
            self.log([self.c.text['close_busy']])
            return True
        return False


def run(args):
    controller = Controller(args.lang or language_from_env(), checkout=find_checkout())
    app = Gtk.Application(application_id=APP_ID, flags=Gio.ApplicationFlags.NON_UNIQUE)

    def activate(app):
        install_css()
        window = Window(app, controller)
        window.present()
        if os.environ.get(SMOKE_ENV) == '1':
            other = next(code for code, _ in LANGUAGES if code != controller.language)
            GLib.timeout_add_seconds(3, lambda: window.language_action.activate(GLib.Variant('s', other)) or False)
            GLib.timeout_add_seconds(SMOKE_SECONDS, lambda: app.quit() or False)
    app.connect('activate', activate)
    return app.run([])
