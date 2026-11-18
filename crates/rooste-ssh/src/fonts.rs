//! Fallback fonts from the operating system for characters egui's bundled
//! fonts lack (CJK, many symbols). Only the first available font of each
//! group is loaded, since CJK fonts are large.

#[cfg(target_os = "macos")]
use std::path::PathBuf;
use std::sync::Arc;

use egui::epaint::text::{Fonts, LayoutJob, TextOptions};
use egui::{Color32, FontData, FontDefinitions, FontFamily, FontId, FontTweak};

#[derive(Clone, Copy)]
enum GroupKind {
    Plain,
    Cjk,
}

struct FontGroup {
    kind: GroupKind,
    paths: &'static [&'static str],
}

/// Groups of candidate paths, most preferred first within each group.
#[cfg(windows)]
const GROUPS: &[FontGroup] = &[
    // Monospace with broad symbol coverage.
    FontGroup {
        kind: GroupKind::Plain,
        paths: &[
            r"C:\Windows\Fonts\consola.ttf",
            r"C:\Windows\Fonts\cour.ttf",
        ],
    },
    // CJK: prefer Microsoft YaHei (complete GB18030 coverage & clean UI metrics)
    // before Japanese Yu Gothic. Vertical baseline alignment is computed
    // dynamically against egui's bundled primary fonts below.
    FontGroup {
        kind: GroupKind::Cjk,
        paths: &[
            r"C:\Windows\Fonts\msyh.ttc",
            r"C:\Windows\Fonts\simhei.ttf",
            r"C:\Windows\Fonts\YuGothM.ttc",
            r"C:\Windows\Fonts\msgothic.ttc",
            r"C:\Windows\Fonts\malgun.ttf",
        ],
    },
    // Symbols.
    FontGroup {
        kind: GroupKind::Plain,
        paths: &[r"C:\Windows\Fonts\seguisym.ttf"],
    },
];

#[cfg(target_os = "macos")]
const GROUPS: &[FontGroup] = &[
    FontGroup {
        kind: GroupKind::Plain,
        paths: &["/System/Library/Fonts/Menlo.ttc"],
    },
    FontGroup {
        kind: GroupKind::Cjk,
        paths: &[
            "/System/Library/Fonts/PingFang.ttc",
            "/System/Library/Fonts/Hiragino Sans GB.ttc",
            "/System/Library/Fonts/STHeiti Medium.ttc",
            "/System/Library/Fonts/STHeiti Light.ttc",
        ],
    },
];

#[cfg(all(not(windows), not(target_os = "macos")))]
const GROUPS: &[FontGroup] = &[
    FontGroup {
        kind: GroupKind::Plain,
        paths: &[
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/dejavu/DejaVuSansMono.ttf",
            "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        ],
    },
    FontGroup {
        kind: GroupKind::Cjk,
        paths: &[
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
            "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
            "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        ],
    },
    FontGroup {
        kind: GroupKind::Plain,
        paths: &[
            "/usr/share/fonts/truetype/noto/NotoSansSymbols2-Regular.ttf",
            "/usr/share/fonts/noto/NotoSansSymbols2-Regular.ttf",
        ],
    },
];

/// On macOS 15+, PingFang moved into the system MobileAsset Font7 directory.
#[cfg(target_os = "macos")]
fn find_macos_asset_pingfang() -> Option<PathBuf> {
    let root = PathBuf::from("/System/Library/AssetsV2/com_apple_MobileAsset_Font7");
    let entries = std::fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let candidate = entry.path().join("AssetData/PingFang.ttc");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn load_first_in_group(group: &FontGroup) -> Option<(String, Vec<u8>)> {
    #[cfg(target_os = "macos")]
    if matches!(group.kind, GroupKind::Cjk)
        && let Some(pingfang) = find_macos_asset_pingfang()
        && let Ok(bytes) = std::fs::read(&pingfang)
    {
        return Some((pingfang.display().to_string(), bytes));
    }
    group.paths.iter().find_map(|path| {
        std::fs::read(path)
            .ok()
            .map(|bytes| ((*path).to_owned(), bytes))
    })
}

/// Measure how far `epaint` shifts `fallback_data`'s baseline relative to the
/// primary font of `family` (due to differing `ascent` / `line_gap` metrics),
/// and return the exact `FontTweak::y_offset_factor` that aligns their baselines.
fn calibrate_baseline_y_offset_factor(
    base_fonts: &FontDefinitions,
    family: FontFamily,
    fallback_data: &FontData,
    sample_char: char,
) -> f32 {
    let Some(primary_name) = base_fonts
        .families
        .get(&family)
        .and_then(|list| list.first())
        .cloned()
    else {
        return 0.0;
    };
    let Some(primary_data) = base_fonts.font_data.get(&primary_name).cloned() else {
        return 0.0;
    };

    const PROBE_KEY: &str = "__probe_fallback";
    const PROBE_SIZE: f32 = 100.0;

    let mut probe = FontDefinitions::empty();
    probe.font_data.insert(primary_name.clone(), primary_data);
    probe
        .font_data
        .insert(PROBE_KEY.to_owned(), Arc::new(fallback_data.clone()));
    probe
        .families
        .insert(family.clone(), vec![primary_name, PROBE_KEY.to_owned()]);

    let mut engine = Fonts::new(TextOptions::default(), probe);
    let galley = engine.layout_uncached(
        1.0,
        Arc::new(LayoutJob::simple_singleline(
            format!("A{sample_char}"),
            FontId::new(PROBE_SIZE, family),
            Color32::WHITE,
        )),
    );
    let Some(row) = galley.rows.first() else {
        return 0.0;
    };
    if row.glyphs.len() < 2 {
        return 0.0;
    }
    let latin_baseline = row.glyphs[0].pos.y;
    let fallback_baseline = row.glyphs[1].pos.y;
    ((latin_baseline - fallback_baseline) / PROBE_SIZE).clamp(-0.5, 0.5)
}

/// Font definitions with the first available font of each group appended
/// as a fallback to both families. Also returns the paths that were used.
pub fn with_system_fallbacks(mut fonts: FontDefinitions) -> (FontDefinitions, Vec<String>) {
    let mut used = Vec::new();
    for group in GROUPS {
        let Some((path, bytes)) = load_first_in_group(group) else {
            continue;
        };
        let base_data = FontData::from_owned(bytes);
        match group.kind {
            GroupKind::Plain => {
                let name = format!("system:{path}");
                fonts.font_data.insert(name.clone(), Arc::new(base_data));
                for family in [FontFamily::Monospace, FontFamily::Proportional] {
                    fonts.families.entry(family).or_default().push(name.clone());
                }
            }
            GroupKind::Cjk => {
                // Share the underlying `Blob` Arc across both families, but
                // calibrate each family's vertical baseline tweak separately
                // against its own primary font (`Ubuntu-Light` vs `Hack`) and
                // disable legacy TrueType bytecode hinting so adjacent CJK
                // characters never bounce vertically at small UI sizes.
                for (suffix, family) in [
                    ("mono", FontFamily::Monospace),
                    ("prop", FontFamily::Proportional),
                ] {
                    let y_offset_factor = calibrate_baseline_y_offset_factor(
                        &fonts,
                        family.clone(),
                        &base_data,
                        '汉',
                    );
                    let tuned = base_data.clone().tweak(FontTweak {
                        y_offset_factor,
                        hinting: Some(false),
                        ..FontTweak::default()
                    });
                    let name = format!("system:{path}:{suffix}");
                    fonts.font_data.insert(name.clone(), Arc::new(tuned));
                    fonts.families.entry(family).or_default().push(name);
                }
            }
        }
        used.push(path);
    }
    (fonts, used)
}

/// Install system fallbacks into an egui context.
pub fn install(ctx: &egui::Context) {
    let (fonts, _) = with_system_fallbacks(FontDefinitions::default());
    ctx.set_fonts(fonts);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallbacks_come_after_bundled_fonts() {
        let defaults = FontDefinitions::default();
        let bundled = defaults.families[&FontFamily::Monospace].clone();
        let (fonts, used) = with_system_fallbacks(defaults);
        let mono = &fonts.families[&FontFamily::Monospace];
        assert_eq!(&mono[..bundled.len()], &bundled[..]);
        assert_eq!(mono.len(), bundled.len() + used.len());
        assert!(used.len() <= GROUPS.len());
    }

    #[test]
    fn cjk_fallback_aligns_baseline_with_latin() {
        let (fonts, used) = with_system_fallbacks(FontDefinitions::default());
        if !used.iter().any(|p| {
            p.contains("PingFang")
                || p.contains("Hiragino")
                || p.contains("msyh")
                || p.contains("NotoSansCJK")
        }) {
            return;
        }
        let mut engine = Fonts::new(TextOptions::default(), fonts);
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            let galley = engine.layout_uncached(
                1.0,
                Arc::new(LayoutJob::simple_singleline(
                    "oneplus(手机平台)".to_owned(),
                    FontId::new(14.0, family),
                    Color32::WHITE,
                )),
            );
            let row = &galley.rows[0];
            let paren = row.glyphs.iter().find(|g| g.chr == '(').unwrap();
            let cjk = row.glyphs.iter().find(|g| g.chr == '手').unwrap();
            let paren_mid = paren.pos.y + paren.uv_rect.offset.y + paren.uv_rect.size.y * 0.5;
            let cjk_mid = cjk.pos.y + cjk.uv_rect.offset.y + cjk.uv_rect.size.y * 0.5;
            assert!(
                (paren_mid - cjk_mid).abs() <= 2.0,
                "CJK center {cjk_mid} drifted from Latin '(' center {paren_mid}"
            );
        }
    }
}
