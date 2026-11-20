//! The terminal widget: draws a [`Terminal`] and turns keyboard and mouse
//! input into bytes for the remote side.

use std::time::{Duration, Instant};

use egui::{
    Color32, CornerRadius, Event, FontId, Id, Modal, PointerButton, Pos2, Rect, Response, RichText,
    Sense, Stroke, StrokeKind, Ui, Vec2, pos2, vec2,
};
use rooste_core::RightClickAction;
use rooste_terminal::input::{self, MouseAction, MouseButton};
use rooste_terminal::{CursorShape, MouseReport, Rgb, Screen, SelectionKind, Terminal};

use crate::keys::{Action, KeyTranslator};

const MULTI_CLICK: Duration = Duration::from_millis(400);
const COPIED_BANNER_DURATION: Duration = Duration::from_millis(1400);
const DRAG_SCROLL_INTERVAL: Duration = Duration::from_millis(50);

/// What the widget wants the session to do after a frame.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ViewOutput {
    /// Bytes for the remote side, in order.
    pub send: Vec<u8>,
    /// The grid size changed to (columns, rows).
    pub resize: Option<(u16, u16)>,
    /// User chose "Find…" from the terminal context menu.
    pub open_find: bool,
}

/// Gap between the terminal text and the edges of its area.
const PADDING: f32 = 6.0;
/// Room for the scrollbar at the terminal's right edge.
const SCROLLBAR_WIDTH: f32 = 12.0;
const SCROLLBAR_THUMB_WIDTH: f32 = 6.0;
const SCROLLBAR_MIN_THUMB: f32 = 24.0;
/// Lines of scrollback per mouse wheel notch.
const WHEEL_LINES: f32 = 3.0;
/// Key in egui's data: some terminal is waiting to take the keyboard focus.
const FOCUS_PENDING: &str = "rooste-terminal-focus-pending";

/// Tell the terminals drawn next whether one of them is waiting to take the
/// keyboard focus, so the others leave it alone.
pub fn set_focus_pending(ctx: &egui::Context, pending: bool) {
    ctx.data_mut(|d| d.insert_temp(Id::unique(FOCUS_PENDING), pending));
}
const MIN_FONT_SIZE: f32 = 6.0;
const MAX_FONT_SIZE: f32 = 72.0;

/// Per-terminal widget state.
#[derive(Debug)]
pub struct TerminalView {
    pub font_size: f32,
    /// This tab's zoom, multiplying `font_size` (1.0 = 100%).
    pub zoom: f32,
    /// What right-clicking inside the terminal does.
    pub right_click_action: RightClickAction,
    /// Copy the selection to the clipboard when the mouse button is released.
    pub copy_on_select: bool,
    /// On Windows/Linux, let plain `Ctrl+V` paste directly.
    pub ctrl_v_paste: bool,
    keys: KeyTranslator,
    /// Fractional wheel lines not yet scrolled.
    scroll_accum: f32,
    clicks: u8,
    last_click: Option<Instant>,
    /// Mouse button currently held while reporting to the application.
    reported_button: Option<MouseButton>,
    selecting: bool,
    /// Last auto-scroll tick while dragging selection past the viewport edge.
    drag_scroll_at: Option<Instant>,
    /// Brief "Copied" toast shown in the top-right corner of the terminal.
    copied_banner: Option<(String, Instant)>,
    /// Pending text inside the dedicated "Multi-line Paste…" preview modal.
    pub multiline_paste: Option<String>,
    /// While dragging the scrollbar: where the thumb was grabbed, from its top.
    scrollbar_grab: Option<f32>,
    /// Take keyboard focus as soon as possible, e.g. when its tab is clicked.
    pub focus_requested: bool,
    /// Whether the terminal had keyboard focus when last shown.
    pub has_focus: bool,
}

impl Default for TerminalView {
    fn default() -> Self {
        Self {
            font_size: 14.0,
            zoom: 1.0,
            right_click_action: RightClickAction::ContextMenu,
            copy_on_select: false,
            ctrl_v_paste: true,
            keys: KeyTranslator::default(),
            scroll_accum: 0.0,
            clicks: 0,
            last_click: None,
            reported_button: None,
            selecting: false,
            drag_scroll_at: None,
            copied_banner: None,
            multiline_paste: None,
            scrollbar_grab: None,
            focus_requested: false,
            has_focus: false,
        }
    }
}

/// Cell geometry in points.
#[derive(Debug, Clone, Copy)]
struct Metrics {
    cell: Vec2,
    origin: Pos2,
}

impl Metrics {
    /// The visible cell under `pos`, and whether `pos` is on its right half.
    fn cell_at(&self, pos: Pos2, cols: usize, rows: usize) -> (usize, usize, bool) {
        let rel = pos - self.origin;
        let x = (rel.x / self.cell.x).max(0.0);
        let y = (rel.y / self.cell.y).max(0.0);
        let col = (x as usize).min(cols.saturating_sub(1));
        let row = (y as usize).min(rows.saturating_sub(1));
        (col, row, x.fract() >= 0.5)
    }
}

fn color(rgb: Rgb) -> Color32 {
    Color32::from_rgb(rgb.r, rgb.g, rgb.b)
}

impl TerminalView {
    fn font(&self) -> FontId {
        FontId::monospace((self.font_size * self.zoom).clamp(MIN_FONT_SIZE, MAX_FONT_SIZE))
    }

    /// Make the text 10% larger.
    pub fn zoom_in(&mut self) {
        self.zoom = (self.zoom * 1.1).min(MAX_FONT_SIZE / self.font_size);
    }

    /// Make the text 10% smaller.
    pub fn zoom_out(&mut self) {
        self.zoom = (self.zoom / 1.1).max(MIN_FONT_SIZE / self.font_size);
    }

    pub fn reset_zoom(&mut self) {
        self.zoom = 1.0;
    }

    /// Lay out, handle input and paint. Call once per frame.
    pub fn show(&mut self, ui: &mut Ui, term: &mut Terminal) -> ViewOutput {
        let mut out = ViewOutput::default();
        let font = self.font();
        let cell = ui
            .ctx()
            .fonts_mut(|f| vec2(f.glyph_width(&font, 'M'), f.row_height(&font)));
        let available = ui.available_size().max(cell + vec2(2.0, 2.0) * PADDING);
        // The text keeps a small gap from the edges; the background fills them.
        let grid = available - vec2(2.0, 2.0) * PADDING - vec2(SCROLLBAR_WIDTH, 0.0);

        let cols = ((grid.x / cell.x).floor() as u16).max(1);
        let rows = ((grid.y / cell.y).floor() as u16).max(1);
        if term.size() != (cols, rows) {
            let ppp = ui.ctx().pixels_per_point();
            term.resize(cols, rows, (cell.x * ppp) as u16, (cell.y * ppp) as u16);
            out.resize = Some((cols, rows));
        }

        // A fixed id, so the keyboard focus stays when widgets above the
        // terminal (find bar, status lines) come and go.
        let (rect, _) = ui.allocate_exact_size(available, Sense::hover());
        let (text_rect, bar_rect) = rect.split_left_right_at_x(rect.right() - SCROLLBAR_WIDTH);
        let response = ui.interact(
            text_rect,
            ui.make_persistent_id("terminal"),
            Sense::click_and_drag(),
        );
        let bar = ui.interact(
            bar_rect,
            ui.make_persistent_id("scrollbar"),
            Sense::click_and_drag(),
        );
        bar.widget_info(|| egui::WidgetInfo::labeled(egui::Role::ScrollBar, true, "Scrollback"));
        let response = response.on_hover_cursor(egui::CursorIcon::Text);
        response.widget_info(|| egui::WidgetInfo::labeled(egui::Role::Terminal, true, "Terminal"));
        let id = response.id;
        // Take keyboard focus when clicked, and whenever nothing else has it
        // (e.g. after a dialog closes) unless another terminal is about to
        // take it (e.g. a tab just switched to); otherwise the first terminal
        // drawn would grab it for a moment.
        // A click elsewhere may be giving another widget focus this frame
        // (egui applies it at the end of the frame), and while a button is
        // held the focus is about to go somewhere, so don't take it then.
        let pending = ui
            .data(|d| d.get_temp::<bool>(Id::unique(FOCUS_PENDING)))
            .unwrap_or(false);
        let nothing_focused = ui.memory(|m| m.focused().is_none())
            && !pending
            && !ui.input(|i| {
                i.pointer.any_pressed() || i.pointer.any_released() || i.pointer.any_down()
            });
        if nothing_focused || self.focus_requested || response.clicked() || response.drag_started()
        {
            ui.memory_mut(|m| m.request_focus(id));
        }
        ui.memory_mut(|m| {
            m.set_focus_lock_filter(
                id,
                egui::EventFilter {
                    tab: true,
                    horizontal_arrows: true,
                    vertical_arrows: true,
                    escape: true,
                },
            )
        });
        let metrics = Metrics {
            cell,
            origin: rect.min + vec2(PADDING, PADDING),
        };

        if response.has_focus() && self.multiline_paste.is_none() {
            self.handle_keyboard(ui, term, &mut out);
        }
        let hovered = response.hovered() || bar.hovered();
        if self.multiline_paste.is_none() {
            self.handle_mouse(ui, term, &response, hovered, metrics, &mut out);
        }

        // Mode A: right-click context menu (when not captured by remote app mouse reporting).
        let shift_held = ui.input(|i| i.modifiers.shift);
        let app_mouse_reporting = term.mouse_mode().report != MouseReport::None && !shift_held;
        if self.right_click_action == RightClickAction::ContextMenu && !app_mouse_reporting {
            self.context_menu(&response, term, &mut out);
        }

        let thumb = self.scrollbar(term, &bar);

        if self.has_focus != response.has_focus() {
            // The tab bar, drawn before the terminal, shows which tab has
            // the focus; draw again so it doesn't lag a frame behind.
            ui.ctx().request_repaint();
        }
        self.has_focus = response.has_focus();
        // Ask until it has the focus: a click that opened this tab (e.g. on a
        // menu) can take the focus away again in the next frame.
        if self.has_focus {
            self.focus_requested = false;
        }
        self.paint(ui, rect, metrics, &term.screen(), self.has_focus);
        self.paint_copied_banner(ui, text_rect);
        if let Some(thumb) = thumb {
            let widgets = &ui.visuals().widgets;
            let fill = if bar.dragged() || bar.is_pointer_button_down_on() {
                widgets.active.bg_fill
            } else if bar.hovered() {
                widgets.hovered.bg_fill
            } else {
                widgets.inactive.bg_fill
            };
            ui.painter_at(rect).rect_filled(thumb, 3.0, fill);
        }
        self.show_multiline_paste_modal(ui.ctx(), id, term, &mut out);
        out
    }

    pub fn flash_copied_banner(&mut self, text: &str) {
        let lines = text.lines().count().max(1);
        let label = if lines > 1 {
            format!("Copied {lines} lines")
        } else {
            "Copied".to_owned()
        };
        self.copied_banner = Some((label, Instant::now()));
    }

    fn copy_selection(&mut self, ctx: &egui::Context, term: &mut Terminal, clear: bool) {
        if let Some(text) = term.selection_text()
            && !text.is_empty()
        {
            ctx.copy_text(text.clone());
            self.flash_copied_banner(&text);
        }
        if clear {
            term.clear_selection();
        }
    }

    fn paste_text(term: &mut Terminal, out: &mut ViewOutput, text: &str) {
        if text.is_empty() {
            return;
        }
        term.scroll_to_bottom();
        out.send
            .extend(input::encode_paste(text, term.bracketed_paste()));
    }

    fn context_menu(&mut self, response: &Response, term: &mut Terminal, out: &mut ViewOutput) {
        let has_sel = term.selection_text().is_some();
        let copy_hint = if cfg!(target_os = "macos") {
            "Cmd+C"
        } else if has_sel {
            "Ctrl+C"
        } else {
            "Ctrl+Shift+C"
        };
        let paste_hint = if cfg!(target_os = "macos") {
            "Cmd+V"
        } else if self.ctrl_v_paste {
            "Ctrl+V"
        } else {
            "Ctrl+Shift+V"
        };
        let select_all_hint = if cfg!(target_os = "macos") {
            "Cmd+A"
        } else {
            "Ctrl+Shift+A"
        };
        let find_hint = if cfg!(target_os = "macos") {
            "Cmd+Shift+F"
        } else {
            "Ctrl+Shift+F"
        };

        response.context_menu(|ui| {
            if ui
                .add_enabled(has_sel, egui::Button::new("Copy").shortcut_text(copy_hint))
                .clicked()
            {
                self.copy_selection(ui.ctx(), term, true);
                ui.close();
            }
            if ui
                .add(egui::Button::new("Paste").shortcut_text(paste_hint))
                .clicked()
            {
                if let Some(text) = read_clipboard() {
                    Self::paste_text(term, out, &text);
                }
                ui.close();
            }
            if ui.button("Multi-line Paste…").clicked() {
                self.multiline_paste = Some(read_clipboard().unwrap_or_default());
                ui.close();
            }
            ui.separator();
            if ui
                .add(egui::Button::new("Select All").shortcut_text(select_all_hint))
                .clicked()
            {
                term.select_all();
                ui.close();
            }
            if ui
                .add(egui::Button::new("Find…").shortcut_text(find_hint))
                .clicked()
            {
                out.open_find = true;
                ui.close();
            }
            if ui.button("Clear Scrollback").clicked() {
                term.clear_scrollback();
                ui.close();
            }
        });
    }

    fn show_multiline_paste_modal(
        &mut self,
        ctx: &egui::Context,
        terminal_id: Id,
        term: &mut Terminal,
        out: &mut ViewOutput,
    ) {
        let Some(mut text) = self.multiline_paste.take() else {
            return;
        };
        let mut keep_open = true;
        let modal_resp = Modal::new(Id::unique(("multiline-paste", terminal_id)))
            .frame(crate::theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                ui.set_min_width(480.0);
                ui.set_max_width(580.0);
                ui.heading("Multi-line Paste");
                let line_count = if text.is_empty() {
                    0
                } else {
                    text.lines().count().max(1)
                };
                ui.label(
                    RichText::new(format!(
                        "Review or edit before sending to the terminal ({line_count} line(s), {} char(s)).",
                        text.chars().count()
                    ))
                    .small()
                    .weak(),
                );
                ui.add_space(8.0);
                egui::ScrollArea::vertical()
                    .id_salt(("multiline-paste-scroll", terminal_id))
                    .max_height(240.0)
                    .show(ui, |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut text)
                                .font(egui::TextStyle::Monospace)
                                .desired_rows(8)
                                .desired_width(f32::INFINITY),
                        );
                    });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        keep_open = false;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let non_empty = !text.is_empty();
                        if ui
                            .add_enabled_ui(non_empty, |ui| {
                                crate::theme::primary_button(ui, "Paste")
                            })
                            .inner
                            .clicked()
                        {
                            Self::paste_text(term, out, &text);
                            keep_open = false;
                            self.focus_requested = true;
                        }
                        if ui
                            .add_enabled(non_empty, egui::Button::new("Paste as Single Line"))
                            .on_hover_text("Join all lines with spaces before sending")
                            .clicked()
                        {
                            let single = collapse_to_single_line(&text);
                            Self::paste_text(term, out, &single);
                            keep_open = false;
                            self.focus_requested = true;
                        }
                    });
                });
            });
        if modal_resp.should_close() {
            keep_open = false;
            self.focus_requested = true;
        }
        if keep_open {
            self.multiline_paste = Some(text);
        }
    }

    fn paint_copied_banner(&mut self, ui: &Ui, text_rect: Rect) {
        let Some((ref text, shown_at)) = self.copied_banner else {
            return;
        };
        let elapsed = shown_at.elapsed();
        if elapsed >= COPIED_BANNER_DURATION {
            self.copied_banner = None;
            return;
        }
        ui.ctx()
            .request_repaint_after(COPIED_BANNER_DURATION.saturating_sub(elapsed));

        let galley = ui.painter().layout_no_wrap(
            text.clone(),
            FontId::proportional(12.0),
            crate::theme::NORDIC_SNOW,
        );
        let pad = vec2(10.0, 4.0);
        let size = galley.size() + pad * 2.0;
        let top_right = pos2(text_rect.right() - 10.0, text_rect.top() + 10.0);
        let pill = Rect::from_min_size(pos2(top_right.x - size.x, top_right.y), size);
        let painter = ui.painter_at(text_rect);
        painter.rect_filled(
            pill,
            CornerRadius::same(4),
            Color32::from_rgba_unmultiplied(15, 23, 42, 225),
        );
        painter.rect_stroke(
            pill,
            CornerRadius::same(4),
            Stroke::new(1.0, crate::theme::TERMINAL_CYAN),
            StrokeKind::Inside,
        );
        painter.galley(pill.min + pad, galley, crate::theme::NORDIC_SNOW);
    }

    fn handle_keyboard(&mut self, ui: &Ui, term: &mut Terminal, out: &mut ViewOutput) {
        let (events, modifiers) = ui.input(|i| (i.events.clone(), i.modifiers));
        for event in &events {
            let has_selection = term.selection_text().is_some();
            match self.keys.translate(
                event,
                modifiers,
                term.input_mode(),
                has_selection,
                self.ctrl_v_paste,
            ) {
                Some(Action::Send(bytes)) => {
                    term.clear_selection();
                    term.scroll_to_bottom();
                    out.send.extend_from_slice(&bytes);
                }
                Some(Action::Copy) => {
                    self.copy_selection(ui.ctx(), term, true);
                }
                Some(Action::Paste(text)) => {
                    Self::paste_text(term, out, &text);
                }
                Some(Action::PasteFromClipboard) => {
                    if let Some(text) = read_clipboard() {
                        Self::paste_text(term, out, &text);
                    }
                }
                Some(Action::SelectAll) => {
                    term.select_all();
                }
                None => {}
            }
        }
    }

    fn handle_mouse(
        &mut self,
        ui: &Ui,
        term: &mut Terminal,
        response: &Response,
        hovered: bool,
        metrics: Metrics,
        out: &mut ViewOutput,
    ) {
        let (cols, rows) = term.size();
        let (cols, rows) = (usize::from(cols), usize::from(rows));
        let (events, modifiers) = ui.input(|i| (i.events.clone(), i.modifiers));
        let mods = input::Modifiers {
            shift: modifiers.shift,
            alt: modifiers.alt,
            ctrl: modifiers.ctrl,
        };
        let mode = term.mouse_mode();
        // Shift overrides application mouse reporting so text can always be
        // selected, as in xterm.
        let reporting = mode.report != MouseReport::None && !modifiers.shift;

        for event in &events {
            match event {
                Event::PointerButton {
                    pos,
                    button,
                    pressed,
                    ..
                } if response.rect.contains(*pos) || self.selecting || !pressed => {
                    let (col, row, right) = metrics.cell_at(*pos, cols, rows);
                    let button = match button {
                        PointerButton::Primary => MouseButton::Left,
                        PointerButton::Middle => MouseButton::Middle,
                        PointerButton::Secondary => MouseButton::Right,
                        _ => continue,
                    };
                    if reporting && response.rect.contains(*pos) {
                        let action = if *pressed {
                            self.reported_button = Some(button);
                            MouseAction::Press
                        } else {
                            self.reported_button = None;
                            MouseAction::Release
                        };
                        out.send.extend(
                            input::encode_mouse(Some(button), action, col, row, mods, mode)
                                .unwrap_or_default(),
                        );
                        continue;
                    }
                    match (button, pressed) {
                        (MouseButton::Left, true) => {
                            let now = Instant::now();
                            let repeat = self
                                .last_click
                                .is_some_and(|t| now.duration_since(t) < MULTI_CLICK);
                            self.clicks = if repeat { self.clicks % 3 + 1 } else { 1 };
                            self.last_click = Some(now);
                            let kind = match self.clicks {
                                2 => SelectionKind::Word,
                                3 => SelectionKind::Line,
                                _ if modifiers.alt => SelectionKind::Block,
                                _ => SelectionKind::Simple,
                            };
                            term.select_start(col, row, right, kind);
                            self.selecting = true;
                        }
                        (MouseButton::Left, false) => {
                            self.selecting = false;
                            self.drag_scroll_at = None;
                            // Copy on select when enabled (default off; auto-enabled in Classic PuTTY mode).
                            match term.selection_text() {
                                Some(_) if self.copy_on_select => {
                                    self.copy_selection(ui.ctx(), term, false);
                                }
                                Some(_) => {}
                                None => term.clear_selection(),
                            }
                        }
                        // Right-click follows the configured mode (ContextMenu is handled via `response.context_menu`).
                        (MouseButton::Right, true) => match self.right_click_action {
                            RightClickAction::ContextMenu => {}
                            RightClickAction::SmartCopyPaste => {
                                if term.selection_text().is_some() {
                                    self.copy_selection(ui.ctx(), term, true);
                                } else if let Some(text) = read_clipboard() {
                                    Self::paste_text(term, out, &text);
                                }
                            }
                            RightClickAction::Paste => {
                                if let Some(text) = read_clipboard() {
                                    Self::paste_text(term, out, &text);
                                }
                            }
                        },
                        // Middle-click pastes directly.
                        (MouseButton::Middle, true) => {
                            if let Some(text) = read_clipboard() {
                                Self::paste_text(term, out, &text);
                            }
                        }
                        _ => {}
                    }
                }
                Event::PointerMoved(pos) => {
                    let (col, row, right) = metrics.cell_at(*pos, cols, rows);
                    if self.selecting {
                        term.select_update(col, row, right);
                    } else if reporting
                        && response.rect.contains(*pos)
                        && let Some(bytes) = input::encode_mouse(
                            self.reported_button,
                            MouseAction::Motion,
                            col,
                            row,
                            mods,
                            mode,
                        )
                    {
                        out.send.extend(bytes);
                    }
                }
                // Ctrl + wheel zooms instead of scrolling.
                Event::MouseWheel {
                    delta, modifiers, ..
                } if hovered && modifiers.command => {
                    if delta.y > 0.0 {
                        self.zoom_in();
                    } else if delta.y < 0.0 {
                        self.zoom_out();
                    }
                }
                Event::MouseWheel { unit, delta, .. } if hovered => {
                    // Programs with mouse reporting get one event per notch.
                    let notch = if reporting { 1.0 } else { WHEEL_LINES };
                    let lines = match unit {
                        egui::MouseWheelUnit::Line => delta.y * notch,
                        egui::MouseWheelUnit::Page => delta.y * rows as f32,
                        egui::MouseWheelUnit::Point => delta.y / metrics.cell.y,
                    };
                    self.scroll_accum += lines;
                    let whole = self.scroll_accum.trunc();
                    self.scroll_accum -= whole;
                    let whole = whole as i32;
                    if whole == 0 {
                        continue;
                    }
                    let pos = response.hover_pos().unwrap_or(metrics.origin);
                    let (col, row, _) = metrics.cell_at(pos, cols, rows);
                    let wheel = if whole > 0 {
                        MouseButton::WheelUp
                    } else {
                        MouseButton::WheelDown
                    };
                    for _ in 0..whole.unsigned_abs() {
                        if reporting {
                            out.send.extend(
                                input::encode_mouse(
                                    Some(wheel),
                                    MouseAction::Press,
                                    col,
                                    row,
                                    mods,
                                    mode,
                                )
                                .unwrap_or_default(),
                            );
                        } else if term.alternate_scroll() {
                            let key = if whole > 0 {
                                input::Key::Up
                            } else {
                                input::Key::Down
                            };
                            out.send.extend(input::encode(
                                key,
                                input::Modifiers::NONE,
                                term.input_mode(),
                            ));
                        }
                    }
                    if !reporting && !term.alt_screen() {
                        term.scroll(whole);
                    }
                }
                _ => {}
            }
        }

        // Auto-scroll scrollback when dragging a selection past the top or bottom edge.
        if self.selecting
            && !term.alt_screen()
            && let Some(pos) = ui.input(|i| i.pointer.latest_pos())
        {
            let grid_bottom = metrics.origin.y + rows as f32 * metrics.cell.y;
            let scroll_dir = if pos.y < metrics.origin.y {
                1
            } else if pos.y > grid_bottom {
                -1
            } else {
                0
            };
            if scroll_dir != 0 {
                let due = self
                    .drag_scroll_at
                    .is_none_or(|t| t.elapsed() >= DRAG_SCROLL_INTERVAL);
                if due {
                    term.scroll(scroll_dir);
                    let (col, row, right) = metrics.cell_at(pos, cols, rows);
                    term.select_update(col, row, right);
                    self.drag_scroll_at = Some(Instant::now());
                }
                ui.ctx().request_repaint_after(DRAG_SCROLL_INTERVAL);
            } else {
                self.drag_scroll_at = None;
            }
        }
    }

    /// Follow the mouse on the scrollbar. Returns the thumb to draw, if there
    /// is history to scroll through.
    fn scrollbar(&mut self, term: &mut Terminal, bar: &Response) -> Option<Rect> {
        let history = term.history_size();
        if history == 0 || term.alt_screen() {
            self.scrollbar_grab = None;
            return None;
        }
        let track = bar.rect.shrink2(vec2(0.0, 2.0));
        let rows = usize::from(term.size().1);
        let height = (track.height() * rows as f32 / (history + rows) as f32)
            .clamp(SCROLLBAR_MIN_THUMB.min(track.height()), track.height());
        let travel = track.height() - height;
        let top_for = |offset: usize| track.top() + travel * (1.0 - offset as f32 / history as f32);

        match bar.interact_pointer_pos() {
            Some(pos) if travel > 0.0 => {
                let top = top_for(term.display_offset());
                let grab = *self.scrollbar_grab.get_or_insert_with(|| {
                    // On the thumb it stays under the pointer; on the track
                    // it jumps there.
                    if (top..=top + height).contains(&pos.y) {
                        pos.y - top
                    } else {
                        height / 2.0
                    }
                });
                let along = ((pos.y - grab - track.top()) / travel).clamp(0.0, 1.0);
                let target = ((1.0 - along) * history as f32).round() as i32;
                term.scroll(target - term.display_offset() as i32);
                self.focus_requested = true;
            }
            _ => self.scrollbar_grab = None,
        }
        let x = bar.rect.center().x - SCROLLBAR_THUMB_WIDTH / 2.0;
        Some(Rect::from_min_size(
            pos2(x, top_for(term.display_offset())),
            vec2(SCROLLBAR_THUMB_WIDTH, height),
        ))
    }

    fn paint(&self, ui: &Ui, rect: Rect, metrics: Metrics, screen: &Screen, focused: bool) {
        let painter = ui.painter_at(rect);
        let font = self.font();
        let cell = metrics.cell;
        painter.rect_filled(rect, CornerRadius::ZERO, color(screen.background));

        for row in 0..screen.rows {
            let cells = screen.row(row);
            let y = metrics.origin.y + row as f32 * cell.y;

            // Backgrounds, merged into runs of equal color.
            let mut col = 0;
            while col < cells.len() {
                let bg = cells[col].bg;
                let start = col;
                while col < cells.len() && cells[col].bg == bg {
                    col += 1;
                }
                if bg != screen.background {
                    let min = pos2(metrics.origin.x + start as f32 * cell.x, y);
                    let size = vec2((col - start) as f32 * cell.x, cell.y);
                    painter.rect_filled(Rect::from_min_size(min, size), 0.0, color(bg));
                }
            }

            // Text: ASCII runs with the same style share one galley; other
            // characters are placed cell by cell so wide glyphs line up.
            let mut col = 0;
            while col < cells.len() {
                let c = cells[col];
                if c.spacer || c.ch == ' ' {
                    col += 1;
                    continue;
                }
                let x = metrics.origin.x + col as f32 * cell.x;
                let cell_rect = Rect::from_min_size(pos2(x, y), cell);
                if crate::box_drawing::draw(&painter, cell_rect, c.ch, color(c.fg)) {
                    col += 1;
                    continue;
                }
                let mut text = String::from(c.ch);
                let mut end = col + 1;
                if c.ch.is_ascii() {
                    while end < cells.len() {
                        let n = cells[end];
                        let same = n.ch.is_ascii()
                            && n.fg == c.fg
                            && n.italic == c.italic
                            && n.underline == c.underline
                            && n.strikeout == c.strikeout;
                        if !same {
                            break;
                        }
                        text.push(n.ch);
                        end += 1;
                    }
                }
                let fg = color(c.fg);
                let mut format = egui::TextFormat::simple(font.clone(), fg);
                format.italics = c.italic;
                let mut job = egui::text::LayoutJob::single_section(text, format);
                job.wrap.max_width = f32::INFINITY;
                let galley = ui.ctx().fonts_mut(|f| f.layout_job(job));
                painter.galley(pos2(x, y), galley, fg);

                let width = (end - col + usize::from(c.wide)) as f32 * cell.x;
                if c.underline {
                    let uy = y + cell.y - 1.5;
                    painter.line_segment([pos2(x, uy), pos2(x + width, uy)], Stroke::new(1.0, fg));
                }
                if c.strikeout {
                    let sy = y + cell.y * 0.55;
                    painter.line_segment([pos2(x, sy), pos2(x + width, sy)], Stroke::new(1.0, fg));
                }
                col = end;
            }
        }

        if let Some((col, row)) = screen.cursor
            && let Some(&c) = screen.row(row).get(col)
        {
            let width = if c.wide { 2.0 } else { 1.0 } * cell.x;
            let min = pos2(
                metrics.origin.x + col as f32 * cell.x,
                metrics.origin.y + row as f32 * cell.y,
            );
            let cursor_rect = Rect::from_min_size(min, vec2(width, cell.y));
            let cursor_color = color(screen.cursor_color);
            match (screen.cursor_shape, focused) {
                (_, false) => {
                    painter.rect_stroke(
                        cursor_rect.shrink(0.5),
                        0.0,
                        Stroke::new(1.0, cursor_color),
                        StrokeKind::Inside,
                    );
                }
                (CursorShape::Block, true) => {
                    painter.rect_filled(cursor_rect, 0.0, cursor_color);
                    if c.ch != ' ' {
                        painter.text(min, egui::Align2::LEFT_TOP, c.ch, font.clone(), color(c.bg));
                    }
                }
                (CursorShape::Underline, true) => {
                    let bar = Rect::from_min_max(
                        pos2(cursor_rect.min.x, cursor_rect.max.y - 2.0),
                        cursor_rect.max,
                    );
                    painter.rect_filled(bar, 0.0, cursor_color);
                }
                (CursorShape::Beam, true) => {
                    let bar = Rect::from_min_size(cursor_rect.min, vec2(2.0, cell.y));
                    painter.rect_filled(bar, 0.0, cursor_color);
                }
            }
        }
    }
}

fn collapse_to_single_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

pub(crate) fn read_clipboard() -> Option<String> {
    arboard::Clipboard::new()
        .and_then(|mut c| c.get_text())
        .ok()
        .filter(|t| !t.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cell_hit_testing() {
        let m = Metrics {
            cell: vec2(10.0, 20.0),
            origin: pos2(100.0, 50.0),
        };
        assert_eq!(m.cell_at(pos2(100.0, 50.0), 80, 24), (0, 0, false));
        assert_eq!(m.cell_at(pos2(126.0, 95.0), 80, 24), (2, 2, true));
        // Clamped to the grid.
        assert_eq!(m.cell_at(pos2(5000.0, 5000.0), 80, 24), (79, 23, false));
        assert_eq!(m.cell_at(pos2(0.0, 0.0), 80, 24), (0, 0, false));
    }
}
