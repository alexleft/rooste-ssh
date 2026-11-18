//! Fallback fonts from the operating system for characters egui's bundled
//! fonts lack (CJK, many symbols). Only the first available font of each
//! group is loaded, since CJK fonts are large.

use std::sync::Arc;

use egui::{FontData, FontDefinitions, FontFamily, FontTweak};

struct FontCandidate {
    path: &'static str,
    y_offset_factor: f32,
    disable_hinting: bool,
}

impl FontCandidate {
    const fn plain(path: &'static str) -> Self {
        Self {
            path,
            y_offset_factor: 0.0,
            disable_hinting: false,
        }
    }

    const fn cjk(path: &'static str, y_offset_factor: f32) -> Self {
        Self {
            path,
            y_offset_factor,
            disable_hinting: true,
        }
    }
}

/// Groups of candidate paths, most preferred first within each group.
#[cfg(windows)]
const GROUPS: &[&[FontCandidate]] = &[
    // Monospace with broad symbol coverage.
    &[
        FontCandidate::plain(r"C:\Windows\Fonts\consola.ttf"),
        FontCandidate::plain(r"C:\Windows\Fonts\cour.ttf"),
    ],
    // CJK: prefer Microsoft YaHei (complete GB18030 coverage & zero abnormal
    // lineGap so glyphs align cleanly with egui's Latin baseline) before
    // Japanese Yu Gothic (which has a large vertical lineGap and uneven
    // Simplified Chinese glyph metrics). Disable legacy GDI bytecode hinting
    // on CJK fallbacks so vello_cpu rasterizes uniform baselines at small sizes.
    &[
        FontCandidate::cjk(r"C:\Windows\Fonts\msyh.ttc", -0.02),
        FontCandidate::cjk(r"C:\Windows\Fonts\simhei.ttf", 0.0),
        FontCandidate::cjk(r"C:\Windows\Fonts\YuGothM.ttc", 0.14),
        FontCandidate::cjk(r"C:\Windows\Fonts\msgothic.ttc", 0.0),
        FontCandidate::cjk(r"C:\Windows\Fonts\malgun.ttf", 0.0),
    ],
    // Symbols.
    &[FontCandidate::plain(r"C:\Windows\Fonts\seguisym.ttf")],
];

#[cfg(target_os = "macos")]
const GROUPS: &[&[FontCandidate]] = &[
    &[FontCandidate::plain("/System/Library/Fonts/Menlo.ttc")],
    &[
        FontCandidate::cjk("/System/Library/Fonts/PingFang.ttc", 0.0),
        FontCandidate::cjk("/System/Library/Fonts/Hiragino Sans GB.ttc", 0.0),
        FontCandidate::cjk("/System/Library/Fonts/STHeiti Medium.ttc", 0.0),
        FontCandidate::cjk("/System/Library/Fonts/STHeiti Light.ttc", 0.0),
    ],
];

#[cfg(all(not(windows), not(target_os = "macos")))]
const GROUPS: &[&[FontCandidate]] = &[
    &[
        FontCandidate::plain("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"),
        FontCandidate::plain("/usr/share/fonts/dejavu/DejaVuSansMono.ttf"),
        FontCandidate::plain("/usr/share/fonts/TTF/DejaVuSansMono.ttf"),
    ],
    &[
        FontCandidate::cjk(
            "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
            0.0,
        ),
        FontCandidate::cjk("/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc", 0.0),
        FontCandidate::cjk(
            "/usr/share/fonts/google-noto-cjk/NotoSansCJK-Regular.ttc",
            0.0,
        ),
        FontCandidate::cjk(
            "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
            0.0,
        ),
        FontCandidate::cjk("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc", 0.0),
    ],
    &[
        FontCandidate::plain("/usr/share/fonts/truetype/noto/NotoSansSymbols2-Regular.ttf"),
        FontCandidate::plain("/usr/share/fonts/noto/NotoSansSymbols2-Regular.ttf"),
    ],
];

/// Font definitions with the first available font of each group appended
/// as a fallback to both families. Also returns the paths that were used.
pub fn with_system_fallbacks(mut fonts: FontDefinitions) -> (FontDefinitions, Vec<String>) {
    let mut used = Vec::new();
    for group in GROUPS {
        let Some((candidate, bytes)) = group.iter().find_map(|candidate| {
            std::fs::read(candidate.path)
                .ok()
                .map(|bytes| (candidate, bytes))
        }) else {
            continue;
        };
        let name = format!("system:{}", candidate.path);
        let mut data = FontData::from_owned(bytes);
        if candidate.disable_hinting || candidate.y_offset_factor != 0.0 {
            data = data.tweak(FontTweak {
                y_offset_factor: candidate.y_offset_factor,
                hinting: if candidate.disable_hinting {
                    Some(false)
                } else {
                    None
                },
                ..FontTweak::default()
            });
        }
        fonts.font_data.insert(name.clone(), Arc::new(data));
        for family in [FontFamily::Monospace, FontFamily::Proportional] {
            fonts.families.entry(family).or_default().push(name.clone());
        }
        used.push(candidate.path.to_owned());
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
}
