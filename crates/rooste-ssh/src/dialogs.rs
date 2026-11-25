//! Modal dialogs. Each returns what the user decided; the app applies it.

use std::path::PathBuf;

use egui::{Id, Modal, Ui};
use rooste_core::{
    FlowControl, Language, Parity, Profile, Protocol, RightClickAction, SerialSettings, Settings,
    Theme, Tunnel, TunnelKind,
};
use rooste_protocols::ssh::UnknownHostKey;

use crate::i18n::{self, tr, tr_fmt};
use crate::picker::{PickId, PickKind, Picker, path_row};
use crate::session::PromptKind;

/// Outcome of a dialog for one frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision<T> {
    Pending,
    Cancel,
    Accept(T),
}

fn labeled(
    ui: &mut Ui,
    label: &str,
    add: impl FnOnce(&mut Ui) -> egui::Response,
) -> egui::Response {
    let label = ui.label(label);
    let response = add(ui).labelled_by(label.id);
    ui.end_row();
    response
}

fn text(ui: &mut Ui, label: &str, value: &mut String) -> egui::Response {
    labeled(ui, label, |ui| {
        ui.add(
            egui::TextEdit::singleline(value)
                .margin(crate::theme::FIELD_MARGIN)
                .desired_width(crate::theme::FIELD_WIDTH),
        )
    })
}

/// A dialog's bottom row, below a separator and aligned right. `add` adds
/// the buttons from right to left.
pub fn footer(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    // As wide as the content above, so the dialog doesn't stretch.
    let width = ui.min_rect().width().max(240.0);
    ui.add_space(12.0);
    ui.allocate_ui(egui::vec2(width, 0.0), |ui| {
        ui.set_width(width);
        ui.separator();
    });
    ui.add_space(4.0);
    let size = egui::vec2(width, ui.spacing().interact_size.y);
    ui.allocate_ui_with_layout(size, egui::Layout::right_to_left(egui::Align::Center), add);
}

/// Checkboxes stacked in one grid cell, closer together than grid rows.
fn checkboxes(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    ui.label("");
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 4.0;
        add(ui);
    });
    ui.end_row();
}

/// Cancel and the main action, which `accept_button` draws.
fn buttons_with(
    ui: &mut Ui,
    accept: &str,
    accept_button: fn(&mut Ui, &str) -> egui::Response,
) -> (bool, bool) {
    let mut result = (false, false);
    footer(ui, |ui| {
        result.1 = ui.button(tr("Cancel")).clicked();
        result.0 = accept_button(ui, accept).clicked();
    });
    result
}

fn buttons(ui: &mut Ui, accept: &str) -> (bool, bool) {
    buttons_with(ui, accept, crate::theme::primary_button)
}

/// Editing a profile, with string fields for parsing on save.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileEditor {
    pub profile: Profile,
    pub port: String,
    pub key_file: String,
    pub tags: String,
    pub proxy_jump: String,
    /// New password to store; empty keeps the stored one.
    pub password: String,
    pub is_new: bool,
    pub error: Option<String>,
}

impl ProfileEditor {
    pub fn new(profile: Profile, is_new: bool) -> Self {
        Self {
            port: profile.port.map(|p| p.to_string()).unwrap_or_default(),
            key_file: profile
                .key_file
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            tags: profile.tags.join(", "),
            proxy_jump: profile.proxy_jump.clone().unwrap_or_default(),
            password: String::new(),
            profile,
            is_new,
            error: None,
        }
    }

    /// Validate the fields into a profile.
    pub fn finish(&self) -> Result<Profile, String> {
        let mut profile = self.profile.clone();
        profile.host = profile.host.trim().to_owned();
        profile.name = profile.name.trim().to_owned();
        profile.tmux_session_name = profile.tmux_session_name.trim().to_owned();
        profile.folder = profile
            .folder
            .split('/')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("/");
        if profile.host.is_empty() {
            return Err(if profile.protocol == Protocol::Serial {
                tr("Enter a serial port, such as COM3 or /dev/ttyUSB0.").into()
            } else {
                tr("Enter a host name.").into()
            });
        }
        profile.port = match self.port.trim() {
            "" => None,
            port => Some(
                port.parse::<u16>()
                    .ok()
                    .filter(|&p| p != 0)
                    .ok_or_else(|| tr("Port must be a number between 1 and 65535."))?,
            ),
        };
        let trimmed = |s: &str| (!s.trim().is_empty()).then(|| s.trim().to_owned());
        profile.key_file = trimmed(&self.key_file).map(PathBuf::from);
        profile.proxy_jump = trimmed(&self.proxy_jump);
        for tunnel in &profile.tunnels {
            tunnel.validate().map_err(|e| {
                let desc = tunnel.describe();
                let err = e.to_string();
                tr_fmt("Tunnel {desc}: {err}", &[("desc", &desc), ("err", &err)])
            })?;
        }
        profile.tags = self
            .tags
            .split(',')
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_owned)
            .collect();
        Ok(profile)
    }

    pub fn show(
        &mut self,
        ctx: &egui::Context,
        folders: &[String],
        ports: &[String],
        scripts: &[String],
        managed_keys: &[crate::vault_ui::ManagedKeySummary],
        picker: &mut Picker,
    ) -> Decision<(Profile, String)> {
        let mut decision = Decision::Pending;
        let title = if self.is_new {
            tr("New session")
        } else {
            tr("Edit session")
        };
        Modal::new(Id::unique("profile-editor"))
            .frame(crate::theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                ui.heading(title);
                ui.add_space(10.0);
                // Leave room for the heading and buttons in small windows.
                let max_height = (ctx.content_rect().height() - 180.0).max(200.0);
                egui::ScrollArea::vertical()
                    .max_height(max_height)
                    .show(ui, |ui| {
                        egui::Grid::new("profile-fields")
                            .num_columns(2)
                            .spacing(crate::theme::FORM_SPACING)
                            .show(ui, |ui| {
                                let p = &mut self.profile;
                                text(ui, tr("Name"), &mut p.name);
                                labeled(ui, tr("Folder"), |ui| {
                                    let size = egui::vec2(
                                        crate::theme::FIELD_WIDTH,
                                        ui.spacing().interact_size.y,
                                    );
                                    let layout = egui::Layout::right_to_left(egui::Align::Center);
                                    ui.allocate_ui_with_layout(size, layout, |ui| {
                                        if !folders.is_empty() {
                                            ui.menu_button("⏷", |ui| {
                                                for folder in folders {
                                                    if ui.button(folder).clicked() {
                                                        p.folder = folder.clone();
                                                        ui.close();
                                                    }
                                                }
                                            });
                                        }
                                        ui.add(
                                            egui::TextEdit::singleline(&mut p.folder)
                                                .margin(crate::theme::FIELD_MARGIN)
                                                .hint_text(tr("e.g. Work/Production"))
                                                .desired_width(f32::INFINITY),
                                        )
                                    })
                                    .inner
                                });
                                labeled(ui, tr("Protocol"), |ui| {
                                    egui::ComboBox::from_id_salt("protocol")
                                        .selected_text(protocol_name(p.protocol))
                                        .show_ui(ui, |ui| {
                                            for protocol in Protocol::ALL {
                                                ui.selectable_value(
                                                    &mut p.protocol,
                                                    protocol,
                                                    protocol_name(protocol),
                                                );
                                            }
                                        })
                                        .response
                                });
                                if p.protocol == Protocol::Serial {
                                    serial_fields(ui, &mut p.host, &mut p.serial, ports);
                                } else {
                                    text(ui, tr("Host"), &mut p.host);
                                    let default_port = p
                                        .protocol
                                        .default_port()
                                        .map(|d| d.to_string())
                                        .unwrap_or_default();
                                    labeled(ui, tr("Port"), |ui| {
                                        ui.add(
                                            egui::TextEdit::singleline(&mut self.port)
                                                .margin(crate::theme::FIELD_MARGIN)
                                                .hint_text(default_port)
                                                .desired_width(80.0),
                                        )
                                    });
                                }
                                if p.protocol == Protocol::Ssh {
                                    text(ui, tr("User"), &mut p.user);
                                    if !managed_keys.is_empty() || p.key_sha256.is_some() {
                                        labeled(ui, tr("Vault key"), |ui| {
                                            let selected_label = match &p.key_sha256 {
                                                None => tr("(None — use key file / agent)").to_owned(),
                                                Some(sha) => managed_keys
                                                    .iter()
                                                    .find(|k| &k.sha256 == sha)
                                                    .map(|k| {
                                                        format!(
                                                            "{} ({})",
                                                            k.label,
                                                            &k.sha256[..8.min(k.sha256.len())]
                                                        )
                                                    })
                                                    .unwrap_or_else(|| {
                                                        let prefix = &sha[..8.min(sha.len())];
                                                        tr_fmt(
                                                            "Missing key ({sha})",
                                                            &[("sha", prefix)],
                                                        )
                                                    }),
                                            };
                                            egui::ComboBox::from_id_salt("profile_vault_key_combo")
                                                .width(crate::theme::FIELD_WIDTH)
                                                .selected_text(selected_label)
                                                .show_ui(ui, |ui| {
                                                    ui.selectable_value(
                                                        &mut p.key_sha256,
                                                        None,
                                                        tr("(None — use key file / agent)"),
                                                    );
                                                    for key in managed_keys {
                                                        let text = format!(
                                                            "{} ({})",
                                                            key.label,
                                                            &key.sha256[..8.min(key.sha256.len())]
                                                        );
                                                        ui.selectable_value(
                                                            &mut p.key_sha256,
                                                            Some(key.sha256.clone()),
                                                            text,
                                                        );
                                                    }
                                                })
                                                .response
                                        });
                                    }
                                    path_row(
                                        ui,
                                        tr("Key file"),
                                        &mut self.key_file,
                                        picker,
                                        PickId::ProfileKeyFile,
                                        PickKind::OpenFile,
                                    );
                                    checkboxes(ui, |ui| {
                                        ui.checkbox(&mut p.use_agent, tr("Use SSH agent"));
                                        ui.checkbox(
                                            &mut p.allow_legacy,
                                            tr("Allow legacy algorithms"),
                                        )
                                        .on_hover_text(tr(
                                            "Offer outdated SHA-1 and CBC algorithms for old devices",
                                        ));
                                        ui.checkbox(
                                            &mut p.save_password,
                                            tr("Save password (encrypted vault)"),
                                        );
                                    });
                                    if p.save_password {
                                        labeled(ui, tr("Password"), |ui| {
                                            ui.add(
                                                egui::TextEdit::singleline(&mut self.password)
                                                    .margin(crate::theme::FIELD_MARGIN)
                                                    .password(true)
                                                    .hint_text(tr("unchanged"))
                                                    .desired_width(crate::theme::FIELD_WIDTH),
                                            )
                                        });
                                    }

                                    text(ui, tr("Jump host"), &mut self.proxy_jump);
                                    checkboxes(ui, |ui| {
                                        ui.checkbox(&mut p.forward_agent, tr("Forward SSH agent"));
                                        ui.checkbox(&mut p.forward_x11, tr("Forward X11"))
                                            .on_hover_text(tr(
                                                "Show the server's graphical programs here. Needs a local X server (on Windows e.g. VcXsrv).",
                                            ));
                                        ui.checkbox(
                                            &mut p.tmux_auto_attach,
                                            tr("Attach to tmux (-CC) on connect"),
                                        )
                                        .on_hover_text(tr(
                                            "Run `tmux -CC new-session -A -s <session>` automatically so remote tmux windows and splits open as native tabs and panes.",
                                        ));
                                    });
                                    if p.tmux_auto_attach {
                                        labeled(ui, tr("tmux session"), |ui| {
                                            ui.add(
                                                egui::TextEdit::singleline(
                                                    &mut p.tmux_session_name,
                                                )
                                                .margin(crate::theme::FIELD_MARGIN)
                                                .hint_text("main")
                                                .desired_width(crate::theme::FIELD_WIDTH),
                                            )
                                        });
                                    }
                                }
                                labeled(ui, tr("Run on connect"), |ui| {
                                    let shown = if p.on_connect_script.is_empty() {
                                        tr("Nothing").to_owned()
                                    } else {
                                        p.on_connect_script.clone()
                                    };
                                    egui::ComboBox::from_id_salt("on-connect-script")
                                        .selected_text(shown)
                                        .show_ui(ui, |ui| {
                                            ui.selectable_value(
                                                &mut p.on_connect_script,
                                                String::new(),
                                                tr("Nothing"),
                                            );
                                            for name in scripts {
                                                ui.selectable_value(
                                                    &mut p.on_connect_script,
                                                    name.clone(),
                                                    name,
                                                );
                                            }
                                        })
                                        .response
                                        .on_hover_text(tr(
                                            "A script from the scripts folder to run each time this session connects",
                                        ))
                                });
                                text(ui, tr("Tags"), &mut self.tags);
                                labeled(ui, tr("Notes"), |ui| {
                                    ui.add(
                                        egui::TextEdit::multiline(&mut p.notes)
                                            .margin(crate::theme::FIELD_MARGIN)
                                            .desired_rows(2)
                                            .desired_width(crate::theme::FIELD_WIDTH),
                                    )
                                });
                            });
                        if self.profile.protocol == Protocol::Ssh {
                            tunnels_ui(ui, &mut self.profile.tunnels);
                        }
                    });
                if let Some(error) = &self.error {
                    ui.colored_label(ui.visuals().error_fg_color, error);
                }
                let (save, cancel) = buttons(ui, tr("Save"));
                if save {
                    match self.finish() {
                        Ok(profile) => {
                            decision = Decision::Accept((profile, self.password.clone()))
                        }
                        Err(e) => self.error = Some(e),
                    }
                }
                if cancel {
                    decision = Decision::Cancel;
                }
            });
        decision
    }
}

fn serial_fields(ui: &mut Ui, port: &mut String, serial: &mut SerialSettings, ports: &[String]) {
    labeled(ui, tr("Serial port"), |ui| {
        ui.horizontal(|ui| {
            let response = ui.add(
                egui::TextEdit::singleline(port)
                    .margin(crate::theme::FIELD_MARGIN)
                    .hint_text(if cfg!(windows) {
                        "COM3"
                    } else {
                        "/dev/ttyUSB0"
                    })
                    .desired_width(270.0),
            );
            ui.menu_button("⏷", |ui| {
                if ports.is_empty() {
                    ui.weak(tr("No serial ports found"));
                }
                for name in ports {
                    if ui.button(name).clicked() {
                        *port = name.clone();
                        ui.close();
                    }
                }
            });
            response
        })
        .inner
    });
    labeled(ui, tr("Speed (baud)"), |ui| {
        egui::ComboBox::from_id_salt("baud")
            .selected_text(serial.baud.to_string())
            .show_ui(ui, |ui| {
                for rate in SerialSettings::BAUD_RATES {
                    ui.selectable_value(&mut serial.baud, rate, rate.to_string());
                }
            })
            .response
    });
    labeled(ui, tr("Data bits"), |ui| {
        ui.horizontal(|ui| {
            for bits in 5..=8u8 {
                ui.selectable_value(&mut serial.data_bits, bits, bits.to_string());
            }
        })
        .response
    });
    labeled(ui, tr("Parity"), |ui| {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut serial.parity, Parity::None, tr("None"));
            ui.selectable_value(&mut serial.parity, Parity::Odd, tr("Odd"));
            ui.selectable_value(&mut serial.parity, Parity::Even, tr("Even"));
        })
        .response
    });
    labeled(ui, tr("Stop bits"), |ui| {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut serial.stop_bits, 1, "1");
            ui.selectable_value(&mut serial.stop_bits, 2, "2");
        })
        .response
    });
    labeled(ui, tr("Flow control"), |ui| {
        ui.horizontal(|ui| {
            ui.selectable_value(&mut serial.flow_control, FlowControl::None, tr("None"));
            ui.selectable_value(&mut serial.flow_control, FlowControl::XonXoff, "XON/XOFF");
            ui.selectable_value(&mut serial.flow_control, FlowControl::RtsCts, "RTS/CTS");
        })
        .response
    });
}

fn tunnels_ui(ui: &mut Ui, tunnels: &mut Vec<Tunnel>) {
    ui.add_space(6.0);
    ui.label(egui::RichText::new(tr("Port forwarding")).strong());
    let mut remove = None;
    for (i, tunnel) in tunnels.iter_mut().enumerate() {
        ui.horizontal(|ui| {
            egui::ComboBox::from_id_salt(("tunnel-kind", i))
                .width(80.0)
                .selected_text(match tunnel.kind {
                    TunnelKind::Local => tr("Local"),
                    TunnelKind::Remote => tr("Remote"),
                    TunnelKind::Dynamic => "SOCKS",
                })
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut tunnel.kind, TunnelKind::Local, tr("Local"));
                    ui.selectable_value(&mut tunnel.kind, TunnelKind::Remote, tr("Remote"));
                    ui.selectable_value(&mut tunnel.kind, TunnelKind::Dynamic, "SOCKS");
                });
            ui.add(
                egui::TextEdit::singleline(&mut tunnel.listen)
                    .margin(crate::theme::FIELD_MARGIN)
                    .hint_text(tr("listen port"))
                    .desired_width(110.0),
            )
            .widget_info(|| egui::WidgetInfo::labeled(egui::Role::TextInput, true, tr("Listen")));
            if tunnel.kind != TunnelKind::Dynamic {
                ui.label("->");
                ui.add(
                    egui::TextEdit::singleline(&mut tunnel.target)
                        .margin(crate::theme::FIELD_MARGIN)
                        .hint_text("host:port")
                        .desired_width(150.0),
                )
                .widget_info(|| {
                    egui::WidgetInfo::labeled(egui::Role::TextInput, true, tr("Target"))
                });
            }
            if ui
                .small_button("×")
                .on_hover_text(tr("Remove tunnel"))
                .clicked()
            {
                remove = Some(i);
            }
        });
    }
    if let Some(i) = remove {
        tunnels.remove(i);
    }
    if ui.button(tr("Add tunnel")).clicked() {
        tunnels.push(Tunnel::default());
    }
}

pub fn protocol_name(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Ssh => "SSH",
        Protocol::Serial => tr("Serial"),
        Protocol::Telnet => "Telnet",
        Protocol::Raw => tr("Raw TCP"),
    }
}

/// Editing application settings.
#[derive(Debug, Clone, PartialEq)]
pub struct SettingsEditor {
    pub settings: Settings,
}

impl SettingsEditor {
    pub fn show(&mut self, ctx: &egui::Context, picker: &mut Picker) -> Decision<Settings> {
        let mut decision = Decision::Pending;
        Modal::new(Id::unique("settings"))
            .frame(crate::theme::dialog_frame(ctx))
            .show(ctx, |ui| {
                ui.heading(tr("Settings"));
                ui.add_space(10.0);
                let s = &mut self.settings;
                egui::Grid::new("settings-fields")
                    .num_columns(2)
                    .spacing(crate::theme::FORM_SPACING)
                    .show(ui, |ui| {
                        labeled(ui, tr("Font size"), |ui| {
                            ui.add(egui::Slider::new(&mut s.font_size, 8.0..=32.0).step_by(1.0))
                        });
                        labeled(ui, tr("Scrollback lines"), |ui| {
                            ui.add(
                                egui::DragValue::new(&mut s.scrollback_lines)
                                    .range(100..=200_000)
                                    .speed(100),
                            )
                        });
                        labeled(ui, tr("Theme"), |ui| {
                            ui.horizontal(|ui| {
                                ui.selectable_value(&mut s.theme, Theme::Dark, tr("Dark"));
                                ui.selectable_value(&mut s.theme, Theme::Light, tr("Light"));
                            })
                            .response
                        });
                        labeled(ui, tr("Language"), |ui| {
                            egui::ComboBox::from_id_salt("settings-language")
                                .width(crate::theme::FIELD_WIDTH)
                                .selected_text(i18n::language_label(s.language))
                                .show_ui(ui, |ui| {
                                    for lang in Language::ALL {
                                        ui.selectable_value(
                                            &mut s.language,
                                            lang,
                                            i18n::language_label(lang),
                                        );
                                    }
                                })
                                .response
                        });
                        text(ui, tr("Default user"), &mut s.default_user);
                        path_row(
                            ui,
                            tr("Download folder"),
                            &mut s.download_dir,
                            picker,
                            PickId::DownloadDir,
                            PickKind::Folder,
                        );
                        path_row(
                            ui,
                            tr("Log sessions to"),
                            &mut s.log_dir,
                            picker,
                            PickId::LogDir,
                            PickKind::Folder,
                        )
                        .on_hover_text(tr(
                            "Every session's output is saved as text in this folder. Leave empty to log only when you start it from a tab.",
                        ));
                        labeled(ui, tr("Right-click & clipboard"), |ui| {
                            ui.vertical(|ui| {
                                let prev = s.right_click_action;
                                ui.radio_value(
                                    &mut s.right_click_action,
                                    RightClickAction::ContextMenu,
                                    tr("Context menu (Copy, Paste, Multi-line Paste…)"),
                                );
                                ui.radio_value(
                                    &mut s.right_click_action,
                                    RightClickAction::SmartCopyPaste,
                                    tr("Smart (Copy if selected, otherwise Paste)"),
                                );
                                ui.radio_value(
                                    &mut s.right_click_action,
                                    RightClickAction::Paste,
                                    tr("Classic PuTTY (Paste directly + Copy on select)"),
                                );
                                // Selecting Classic PuTTY mode automatically enables copy-on-select.
                                if s.right_click_action == RightClickAction::Paste
                                    && prev != RightClickAction::Paste
                                {
                                    s.copy_on_select = true;
                                }
                                ui.add_space(4.0);
                                ui.checkbox(&mut s.copy_on_select, tr("Copy text when selected"));
                                ui.checkbox(
                                    &mut s.ctrl_v_paste,
                                    tr("Paste with Ctrl+V (Windows / Linux)"),
                                )
                                .on_hover_text(tr(
                                    "When unchecked, Ctrl+V sends raw ^V to the terminal; Ctrl+Shift+V and Shift+Insert still paste.",
                                ));
                            })
                            .response
                        });
                        checkboxes(ui, |ui| {
                            ui.checkbox(
                                &mut s.confirm_close,
                                tr("Ask before closing a connected tab"),
                            );
                            ui.checkbox(
                                &mut s.auto_reconnect,
                                tr("Reconnect automatically when a connection drops"),
                            );
                            ui.checkbox(&mut s.check_updates, tr("Check for updates at startup"));
                        });
                    });
                let (save, cancel) = buttons(ui, tr("Save"));
                if save {
                    decision = Decision::Accept(self.settings.clone());
                }
                if cancel {
                    decision = Decision::Cancel;
                }
            });
        decision
    }
}

/// Ask for a password or key passphrase.
pub fn prompt(
    ctx: &egui::Context,
    kind: &PromptKind,
    retry: bool,
    input: &mut String,
) -> Decision<String> {
    let mut decision = Decision::Pending;
    Modal::new(Id::unique("secret-prompt"))
        .frame(crate::theme::dialog_frame(ctx))
        .show(ctx, |ui| {
            let (heading, label, hidden) = match kind {
                PromptKind::Password { user, host } => (
                    tr("Password").to_owned(),
                    tr_fmt(
                        "Password for {user}@{host}",
                        &[("user", user), ("host", host)],
                    ),
                    true,
                ),
                PromptKind::Passphrase { key_file } => {
                    let key = key_file.display().to_string();
                    (
                        tr("Key passphrase").to_owned(),
                        tr_fmt("Passphrase for key {key}", &[("key", &key)]),
                        true,
                    )
                }
                PromptKind::Interactive {
                    user,
                    host,
                    name,
                    prompt,
                    echo,
                    ..
                } => {
                    let heading = if name.trim().is_empty() {
                        tr_fmt("Log in to {user}@{host}", &[("user", user), ("host", host)])
                    } else {
                        name.trim().to_owned()
                    };
                    (heading, prompt.trim_end_matches(':').to_owned(), !echo)
                }
                PromptKind::Script {
                    script,
                    question,
                    hidden,
                } => (
                    tr_fmt("Script {script}", &[("script", script)]),
                    question.clone(),
                    *hidden,
                ),
            };
            ui.heading(heading);
            if let PromptKind::Interactive { instructions, .. } = kind
                && !instructions.trim().is_empty()
            {
                ui.label(instructions.trim());
            }
            if retry {
                ui.colored_label(
                    ui.visuals().error_fg_color,
                    tr("Not accepted, please try again."),
                );
            }
            let label = ui.label(label);
            let response = ui
                .add(
                    egui::TextEdit::singleline(input)
                        .margin(crate::theme::FIELD_MARGIN)
                        .password(hidden)
                        .desired_width(280.0),
                )
                .labelled_by(label.id);
            if !response.has_focus() && !response.lost_focus() {
                response.request_focus();
            }
            let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            let accept = match kind {
                PromptKind::Script { .. } => tr("OK"),
                _ => tr("Log in"),
            };
            let (ok, cancel) = buttons(ui, accept);
            if ok || enter {
                decision = Decision::Accept(std::mem::take(input));
            } else if cancel {
                decision = Decision::Cancel;
            }
        });
    decision
}

/// Ask whether to trust an unknown host key.
pub fn host_key(ctx: &egui::Context, key: &UnknownHostKey) -> Decision<()> {
    let mut decision = Decision::Pending;
    Modal::new(Id::unique("host-key"))
        .frame(crate::theme::dialog_frame(ctx))
        .show(ctx, |ui| {
            ui.set_max_width(460.0);
            ui.heading(tr("Unknown host"));
            let host = if key.port == 22 {
                key.host.clone()
            } else {
                format!("{}:{}", key.host, key.port)
            };
            ui.label(tr_fmt(
                "The authenticity of host {host} can't be established. Check that this fingerprint matches the server before trusting it.",
                &[("host", &host)],
            ));
            ui.add_space(6.0);
            ui.label(tr_fmt(
                "{algorithm} key fingerprint:",
                &[("algorithm", &key.algorithm)],
            ));
            ui.monospace(&key.fingerprint);
            let (trust, cancel) = buttons(ui, tr("Trust and connect"));
            if trust {
                decision = Decision::Accept(());
            } else if cancel {
                decision = Decision::Cancel;
            }
        });
    decision
}

/// A yes/cancel question.
pub fn confirm(
    ctx: &egui::Context,
    id: &str,
    title: &str,
    text: &str,
    accept: &str,
) -> Decision<()> {
    let mut decision = Decision::Pending;
    Modal::new(Id::unique(id))
        .frame(crate::theme::dialog_frame(ctx))
        .show(ctx, |ui| {
            ui.set_max_width(420.0);
            ui.heading(title);
            ui.label(text);
            let (yes, cancel) = buttons_with(ui, accept, crate::theme::danger_button);
            if yes {
                decision = Decision::Accept(());
            } else if cancel {
                decision = Decision::Cancel;
            }
        });
    decision
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn editor_validation_and_parsing() {
        let mut editor = ProfileEditor::new(Profile::default(), true);
        assert_eq!(editor.finish().unwrap_err(), "Enter a host name.");
        editor.profile.host = " db.example.com ".into();
        editor.profile.folder = " Work / / Prod ".into();
        editor.port = "70000".into();
        assert!(editor.finish().unwrap_err().starts_with("Port"));
        editor.port = "2200".into();
        editor.tags = "db, prod,, ".into();
        editor.key_file = " ~/.ssh/id ".into();
        editor.proxy_jump = "".into();
        let p = editor.finish().unwrap();
        assert_eq!(p.host, "db.example.com");
        assert_eq!(p.folder, "Work/Prod");
        assert_eq!(p.port, Some(2200));
        assert_eq!(p.tags, ["db", "prod"]);
        assert_eq!(p.key_file, Some(PathBuf::from("~/.ssh/id")));
        assert_eq!(p.proxy_jump, None);
    }

    #[test]
    fn editor_round_trips_existing_profile() {
        let profile = Profile {
            host: "h".into(),
            port: Some(2222),
            tags: vec!["a".into(), "b".into()],
            proxy_jump: Some("jump".into()),
            key_file: Some("/k".into()),
            ..Profile::default()
        };
        let editor = ProfileEditor::new(profile.clone(), false);
        assert_eq!(editor.finish().unwrap(), profile);
    }
}
