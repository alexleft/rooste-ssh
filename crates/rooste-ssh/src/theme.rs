//! Applying settings to the UI and terminals.

use rooste_core::{Settings, Theme};
use rooste_terminal::Palette;

use crate::terminal_view::TerminalView;

/// Brand VI Kit color tokens (`docs/rooster-term-vi-kit/VI_GUIDELINES.md`).
pub const MIDNIGHT_SLATE: egui::Color32 = egui::Color32::from_rgb(18, 22, 31);
pub const ROOST_CHARCOAL: egui::Color32 = egui::Color32::from_rgb(28, 34, 48);
pub const CREST_AMBER: egui::Color32 = egui::Color32::from_rgb(255, 107, 53);
pub const DAWN_GOLD: egui::Color32 = egui::Color32::from_rgb(255, 184, 0);
pub const TERMINAL_CYAN: egui::Color32 = egui::Color32::from_rgb(56, 189, 248);
pub const NORDIC_SNOW: egui::Color32 = egui::Color32::from_rgb(244, 246, 249);

pub fn palette(theme: Theme) -> Palette {
    match theme {
        Theme::Dark => Palette::default(),
        Theme::Light => Palette::light(),
    }
}

pub fn visuals(theme: Theme) -> egui::Visuals {
    match theme {
        Theme::Dark => {
            let mut v = egui::Visuals::dark();
            v.panel_fill = ROOST_CHARCOAL;
            v.window_fill = ROOST_CHARCOAL;
            v.extreme_bg_color = MIDNIGHT_SLATE;
            v.hyperlink_color = TERMINAL_CYAN;
            v.override_text_color = Some(NORDIC_SNOW);
            v
        }
        Theme::Light => {
            let mut v = egui::Visuals::light();
            v.panel_fill = NORDIC_SNOW;
            v.window_fill = NORDIC_SNOW;
            v
        }
    }
}

/// Width of text fields in forms, including any "Browse…" button.
pub const FIELD_WIDTH: f32 = 320.0;
/// Space inside text fields around the text.
pub const FIELD_MARGIN: egui::Margin = egui::Margin::symmetric(6, 4);
/// Column and row gaps in form grids.
pub const FORM_SPACING: [f32; 2] = [16.0, 10.0];

/// Roomier spacing than egui's compact defaults.
pub fn spacing(style: &mut egui::Style) {
    let s = &mut style.spacing;
    s.item_spacing = egui::vec2(8.0, 6.0);
    s.button_padding = egui::vec2(8.0, 4.0);
    s.interact_size.y = 24.0;
    s.menu_margin = egui::Margin::same(8);
    s.window_margin = egui::Margin::same(12);
    s.menu_spacing = 4.0;
}

/// `add` with buttons in white on `fills` (normal, hovered, pressed).
fn colored_buttons<R>(
    ui: &mut egui::Ui,
    fills: [egui::Color32; 3],
    add: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    ui.scope(|ui| {
        let widgets = &mut ui.visuals_mut().widgets;
        let states = [
            &mut widgets.inactive,
            &mut widgets.hovered,
            &mut widgets.active,
        ];
        for (state, fill) in states.into_iter().zip(fills) {
            state.weak_bg_fill = fill;
            state.bg_fill = fill;
            state.bg_stroke = egui::Stroke::NONE;
            state.fg_stroke.color = egui::Color32::WHITE;
        }
        add(ui)
    })
    .inner
}

/// `add` with buttons styled as a dialog's main action (Crest Amber `#FF6B35`).
pub fn primary<R>(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui) -> R) -> R {
    use egui::Color32;
    let fills = [
        CREST_AMBER,
        Color32::from_rgb(255, 128, 79),
        Color32::from_rgb(224, 88, 38),
    ];
    colored_buttons(ui, fills, add)
}

/// A dialog's main action.
pub fn primary_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    primary(ui, |ui| ui.button(text))
}

/// A dialog's main action when it destroys something.
pub fn danger_button(ui: &mut egui::Ui, text: &str) -> egui::Response {
    use egui::Color32;
    let fills = [
        Color32::from_rgb(190, 40, 40),
        Color32::from_rgb(212, 56, 56),
        Color32::from_rgb(160, 30, 30),
    ];
    colored_buttons(ui, fills, |ui| ui.button(text))
}

/// The frame of side panels (sessions, files).
pub fn side_panel_frame(ctx: &egui::Context) -> egui::Frame {
    egui::Frame::side_top_panel(&ctx.global_style()).inner_margin(10)
}

/// The frame of modal dialogs.
pub fn dialog_frame(ctx: &egui::Context) -> egui::Frame {
    egui::Frame::popup(&ctx.global_style()).inner_margin(20)
}

pub fn apply_to_view(view: &mut TerminalView, settings: &Settings) {
    view.font_size = settings.font_size.clamp(6.0, 48.0);
    view.copy_on_select = settings.copy_on_select;
}

/// The folder last chosen with "Download to…", if any.
pub fn recent_download_dir(settings: &Settings) -> Option<std::path::PathBuf> {
    let dir = settings.last_download_to.trim();
    (!dir.is_empty()).then(|| rooste_core::expand_tilde(dir))
}

/// Where SFTP downloads are saved.
pub fn download_dir(settings: &Settings) -> std::path::PathBuf {
    if settings.download_dir.trim().is_empty() {
        crate::files::default_download_dir()
    } else {
        rooste_core::expand_tilde(settings.download_dir.trim())
    }
}
