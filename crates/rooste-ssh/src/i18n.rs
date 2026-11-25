//! UI internationalization: system-locale auto-detection with English fallback,
//! explicit language overrides, and embedded JSON translation catalogs.

use std::collections::HashMap;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, Ordering};

use rooste_core::Language;

/// Concrete UI locale backed by an embedded translation catalog (or English).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Locale {
    En = 0,
    ZhCn = 1,
    ZhTw = 2,
    Ja = 3,
    Ko = 4,
    De = 5,
    Fr = 6,
    Es = 7,
    Ru = 8,
    PtBr = 9,
}

impl Locale {
    pub const ALL: [Self; 10] = [
        Self::En,
        Self::ZhCn,
        Self::ZhTw,
        Self::Ja,
        Self::Ko,
        Self::De,
        Self::Fr,
        Self::Es,
        Self::Ru,
        Self::PtBr,
    ];

    fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::ZhCn,
            2 => Self::ZhTw,
            3 => Self::Ja,
            4 => Self::Ko,
            5 => Self::De,
            6 => Self::Fr,
            7 => Self::Es,
            8 => Self::Ru,
            9 => Self::PtBr,
            _ => Self::En,
        }
    }

    /// BCP-47 tag identifying this locale.
    pub const fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::ZhCn => "zh-CN",
            Self::ZhTw => "zh-TW",
            Self::Ja => "ja",
            Self::Ko => "ko",
            Self::De => "de",
            Self::Fr => "fr",
            Self::Es => "es",
            Self::Ru => "ru",
            Self::PtBr => "pt-BR",
        }
    }

    /// Display name of this locale in its own script.
    pub const fn native_name(self) -> &'static str {
        match self {
            Self::En => "English",
            Self::ZhCn => "简体中文",
            Self::ZhTw => "繁體中文",
            Self::Ja => "日本語",
            Self::Ko => "한국어",
            Self::De => "Deutsch",
            Self::Fr => "Français",
            Self::Es => "Español",
            Self::Ru => "Русский",
            Self::PtBr => "Português (Brasil)",
        }
    }
}

static ACTIVE_LOCALE: AtomicU8 = AtomicU8::new(Locale::En as u8);

type Catalog = HashMap<&'static str, &'static str>;

fn load_catalog(raw: &'static str) -> Catalog {
    let parsed: HashMap<String, String> =
        serde_json::from_str(raw).expect("valid embedded locale JSON");
    parsed
        .into_iter()
        .map(|(k, v)| {
            let k: &'static str = Box::leak(k.into_boxed_str());
            let v: &'static str = Box::leak(v.into_boxed_str());
            (k, v)
        })
        .collect()
}

fn catalog(locale: Locale) -> Option<&'static Catalog> {
    static ZH_CN: OnceLock<Catalog> = OnceLock::new();
    static ZH_TW: OnceLock<Catalog> = OnceLock::new();
    static JA: OnceLock<Catalog> = OnceLock::new();
    static KO: OnceLock<Catalog> = OnceLock::new();
    static DE: OnceLock<Catalog> = OnceLock::new();
    static FR: OnceLock<Catalog> = OnceLock::new();
    static ES: OnceLock<Catalog> = OnceLock::new();
    static RU: OnceLock<Catalog> = OnceLock::new();
    static PT_BR: OnceLock<Catalog> = OnceLock::new();

    match locale {
        Locale::En => None,
        Locale::ZhCn => Some(ZH_CN.get_or_init(|| load_catalog(include_str!("../assets/locales/zh-CN.json")))),
        Locale::ZhTw => Some(ZH_TW.get_or_init(|| load_catalog(include_str!("../assets/locales/zh-TW.json")))),
        Locale::Ja => Some(JA.get_or_init(|| load_catalog(include_str!("../assets/locales/ja.json")))),
        Locale::Ko => Some(KO.get_or_init(|| load_catalog(include_str!("../assets/locales/ko.json")))),
        Locale::De => Some(DE.get_or_init(|| load_catalog(include_str!("../assets/locales/de.json")))),
        Locale::Fr => Some(FR.get_or_init(|| load_catalog(include_str!("../assets/locales/fr.json")))),
        Locale::Es => Some(ES.get_or_init(|| load_catalog(include_str!("../assets/locales/es.json")))),
        Locale::Ru => Some(RU.get_or_init(|| load_catalog(include_str!("../assets/locales/ru.json")))),
        Locale::PtBr => Some(PT_BR.get_or_init(|| load_catalog(include_str!("../assets/locales/pt-BR.json")))),
    }
}

/// Human-readable label for a [`Language`] setting in the UI language selector.
pub fn language_label(lang: Language) -> &'static str {
    match lang {
        Language::Auto => tr("Auto (System)"),
        Language::En => Locale::En.native_name(),
        Language::ZhCn => Locale::ZhCn.native_name(),
        Language::ZhTw => Locale::ZhTw.native_name(),
        Language::Ja => Locale::Ja.native_name(),
        Language::Ko => Locale::Ko.native_name(),
        Language::De => Locale::De.native_name(),
        Language::Fr => Locale::Fr.native_name(),
        Language::Es => Locale::Es.native_name(),
        Language::Ru => Locale::Ru.native_name(),
        Language::PtBr => Locale::PtBr.native_name(),
    }
}

/// Parse a BCP-47 or POSIX locale tag (e.g. `"zh_CN.UTF-8"`, `"zh-Hant-TW"`, `"pt-BR"`)
/// into a supported [`Locale`], returning `None` if unrecognized or unsupported.
pub fn parse_locale_tag(tag: &str) -> Option<Locale> {
    let trimmed = tag.trim();
    if trimmed.is_empty() {
        return None;
    }
    let without_encoding = trimmed.split('.').next().unwrap_or(trimmed);
    let without_modifier = without_encoding.split('@').next().unwrap_or(without_encoding);
    let normalized = without_modifier.to_ascii_lowercase().replace('_', "-");
    if normalized.is_empty() || normalized == "c" || normalized == "posix" {
        return None;
    }
    let mut parts = normalized.split('-').filter(|s| !s.is_empty());
    let primary = parts.next()?;
    match primary {
        "en" => Some(Locale::En),
        "zh" => {
            let is_traditional = parts.any(|sub| matches!(sub, "hant" | "tw" | "hk" | "mo"));
            Some(if is_traditional {
                Locale::ZhTw
            } else {
                Locale::ZhCn
            })
        }
        "ja" => Some(Locale::Ja),
        "ko" => Some(Locale::Ko),
        "de" => Some(Locale::De),
        "fr" => Some(Locale::Fr),
        "es" => Some(Locale::Es),
        "ru" => Some(Locale::Ru),
        "pt" => Some(Locale::PtBr),
        _ => None,
    }
}

/// Pick the first supported [`Locale`] from an ordered list of preferred locale tags,
/// falling back to [`Locale::En`] when none can be matched.
pub fn detect_from_tags<'a>(tags: impl IntoIterator<Item = &'a str>) -> Locale {
    tags.into_iter()
        .find_map(parse_locale_tag)
        .unwrap_or(Locale::En)
}

/// Detect the operating system UI locale, falling back to [`Locale::En`] when
/// the OS locale is unavailable or not among the supported languages.
pub fn detect_system_locale() -> Locale {
    sys_locale::get_locales()
        .find_map(|tag| parse_locale_tag(&tag))
        .unwrap_or(Locale::En)
}

/// Resolve a configured [`Language`] preference into a concrete [`Locale`].
pub fn resolve(lang: Language) -> Locale {
    match lang {
        Language::Auto => detect_system_locale(),
        Language::En => Locale::En,
        Language::ZhCn => Locale::ZhCn,
        Language::ZhTw => Locale::ZhTw,
        Language::Ja => Locale::Ja,
        Language::Ko => Locale::Ko,
        Language::De => Locale::De,
        Language::Fr => Locale::Fr,
        Language::Es => Locale::Es,
        Language::Ru => Locale::Ru,
        Language::PtBr => Locale::PtBr,
    }
}

/// Apply a [`Language`] setting as the active UI locale and return the resolved [`Locale`].
pub fn set_language(lang: Language) -> Locale {
    let locale = resolve(lang);
    set_locale(locale);
    locale
}

/// Directly set the active UI [`Locale`].
pub fn set_locale(locale: Locale) {
    ACTIVE_LOCALE.store(locale as u8, Ordering::Relaxed);
}

/// Return the currently active UI [`Locale`].
pub fn current_locale() -> Locale {
    Locale::from_u8(ACTIVE_LOCALE.load(Ordering::Relaxed))
}

/// Translate a static English UI string for the active UI locale.
pub fn tr(en: &'static str) -> &'static str {
    tr_for(current_locale(), en)
}

/// Translate a static English UI string for an explicit [`Locale`].
pub fn tr_for(locale: Locale, en: &'static str) -> &'static str {
    catalog(locale)
        .and_then(|map| map.get(en).copied())
        .filter(|s| !s.is_empty())
        .unwrap_or(en)
}

/// Translate a template containing `{name}` placeholders for the active UI locale.
pub fn tr_fmt(en: &'static str, args: &[(&str, &str)]) -> String {
    tr_fmt_for(current_locale(), en, args)
}

/// Translate a template containing `{name}` placeholders for an explicit [`Locale`].
pub fn tr_fmt_for(locale: Locale, en: &'static str, args: &[(&str, &str)]) -> String {
    let template = tr_for(locale, en);
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find('{') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        if let Some(end) = after.find('}') {
            let name = &after[..end];
            if let Some((_, val)) = args.iter().find(|(k, _)| *k == name) {
                out.push_str(val);
            } else {
                out.push('{');
                out.push_str(name);
                out.push('}');
            }
            rest = &after[end + 1..];
        } else {
            out.push_str(&rest[start..]);
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::*;

    #[test]
    fn parse_locale_tags() {
        assert_eq!(parse_locale_tag("en"), Some(Locale::En));
        assert_eq!(parse_locale_tag("en-US"), Some(Locale::En));
        assert_eq!(parse_locale_tag("en_GB.UTF-8"), Some(Locale::En));
        assert_eq!(parse_locale_tag("zh-CN"), Some(Locale::ZhCn));
        assert_eq!(parse_locale_tag("zh_CN.UTF-8"), Some(Locale::ZhCn));
        assert_eq!(parse_locale_tag("zh-Hans-CN"), Some(Locale::ZhCn));
        assert_eq!(parse_locale_tag("zh-SG"), Some(Locale::ZhCn));
        assert_eq!(parse_locale_tag("zh-TW"), Some(Locale::ZhTw));
        assert_eq!(parse_locale_tag("zh-HK"), Some(Locale::ZhTw));
        assert_eq!(parse_locale_tag("zh-MO"), Some(Locale::ZhTw));
        assert_eq!(parse_locale_tag("zh-Hant"), Some(Locale::ZhTw));
        assert_eq!(parse_locale_tag("ja-JP"), Some(Locale::Ja));
        assert_eq!(parse_locale_tag("ko_KR"), Some(Locale::Ko));
        assert_eq!(parse_locale_tag("de-DE@euro"), Some(Locale::De));
        assert_eq!(parse_locale_tag("fr-FR"), Some(Locale::Fr));
        assert_eq!(parse_locale_tag("es-419"), Some(Locale::Es));
        assert_eq!(parse_locale_tag("ru-RU"), Some(Locale::Ru));
        assert_eq!(parse_locale_tag("pt-BR"), Some(Locale::PtBr));
        assert_eq!(parse_locale_tag("pt-PT"), Some(Locale::PtBr));
        assert_eq!(parse_locale_tag("C"), None);
        assert_eq!(parse_locale_tag("POSIX"), None);
        assert_eq!(parse_locale_tag(""), None);
        assert_eq!(parse_locale_tag("xx-Unknown"), None);
    }

    #[test]
    fn detect_falls_back_to_english() {
        assert_eq!(detect_from_tags([]), Locale::En);
        assert_eq!(detect_from_tags(["C", "POSIX", "sw-KE"]), Locale::En);
        assert_eq!(detect_from_tags(["sw-KE", "ja-JP", "en-US"]), Locale::Ja);
        assert_eq!(detect_from_tags(["zh-TW", "en-US"]), Locale::ZhTw);
    }

    #[test]
    fn tr_fmt_substitutes_placeholders() {
        assert_eq!(
            tr_fmt_for(
                Locale::En,
                "Delete the saved session \"{name}\"?",
                &[("name", "prod {1}")],
            ),
            "Delete the saved session \"prod {1}\"?"
        );
        assert_eq!(
            tr_fmt_for(
                Locale::ZhCn,
                "Delete the saved session \"{name}\"?",
                &[("name", "prod")],
            ),
            "删除已保存的会话“prod”？"
        );
    }

    #[test]
    fn language_labels_and_resolve() {
        assert_eq!(resolve(Language::ZhCn), Locale::ZhCn);
        assert_eq!(resolve(Language::Ja), Locale::Ja);
        assert_eq!(language_label(Language::ZhCn), "简体中文");
        assert_eq!(language_label(Language::En), "English");
        assert_eq!(tr_for(Locale::ZhCn, "Language"), "语言");
    }

    fn placeholders(s: &str) -> BTreeSet<String> {
        let mut set = BTreeSet::new();
        let mut rest = s;
        while let Some(start) = rest.find('{') {
            let after = &rest[start + 1..];
            if let Some(end) = after.find('}') {
                set.insert(after[..end].to_owned());
                rest = &after[end + 1..];
            } else {
                break;
            }
        }
        set
    }

    #[test]
    fn all_locales_parse_and_share_identical_keys() {
        let mut reference: Option<(Locale, BTreeSet<&'static str>)> = None;
        for &locale in &Locale::ALL {
            let Some(map) = catalog(locale) else {
                continue;
            };
            assert!(
                !map.is_empty(),
                "locale {} catalog must not be empty",
                locale.code()
            );
            let mut keys = BTreeSet::new();
            for (&k, &v) in map {
                assert!(
                    !v.trim().is_empty(),
                    "empty translation for {k:?} in {}",
                    locale.code()
                );
                assert_eq!(
                    placeholders(k),
                    placeholders(v),
                    "mismatched placeholders for {k:?} in {}",
                    locale.code()
                );
                keys.insert(k);
            }
            match &reference {
                None => reference = Some((locale, keys)),
                Some((ref_locale, ref_keys)) => {
                    let missing: Vec<_> = ref_keys.difference(&keys).copied().collect();
                    let extra: Vec<_> = keys.difference(ref_keys).copied().collect();
                    assert!(
                        missing.is_empty() && extra.is_empty(),
                        "locale {} key mismatch vs {}: missing={missing:?}, extra={extra:?}",
                        locale.code(),
                        ref_locale.code(),
                    );
                }
            }
        }
    }

    fn extract_tr_keys(src: &str) -> Vec<String> {
        let non_test = src.split("#[cfg(test)]").next().unwrap_or(src);
        let bytes = non_test.as_bytes();
        let mut keys = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            let matched = if bytes[i..].starts_with(b"tr_fmt(") {
                if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
                    false
                } else {
                    i += "tr_fmt(".len();
                    true
                }
            } else if bytes[i..].starts_with(b"tr(") {
                if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_') {
                    false
                } else {
                    i += "tr(".len();
                    true
                }
            } else {
                false
            };
            if !matched {
                i += 1;
                continue;
            }
            while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                i += 1;
            }
            if i < bytes.len() && bytes[i] == b'"' {
                i += 1;
                let mut lit = String::new();
                while i < bytes.len() {
                    let b = bytes[i];
                    if b == b'\\' && i + 1 < bytes.len() {
                        i += 1;
                        match bytes[i] {
                            b'n' => lit.push('\n'),
                            b'r' => lit.push('\r'),
                            b't' => lit.push('\t'),
                            b'\\' => lit.push('\\'),
                            b'"' => lit.push('"'),
                            other => lit.push(other as char),
                        }
                        i += 1;
                    } else if b == b'"' {
                        i += 1;
                        break;
                    } else {
                        let ch = non_test[i..].chars().next().unwrap();
                        lit.push(ch);
                        i += ch.len_utf8();
                    }
                }
                keys.push(lit);
            }
        }
        keys
    }

    #[test]
    fn all_source_tr_calls_exist_in_catalog() {
        let src_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut used_keys = BTreeSet::new();
        for entry in std::fs::read_dir(&src_dir).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                for k in extract_tr_keys(&text) {
                    used_keys.insert(k);
                }
            }
        }
        assert!(!used_keys.is_empty(), "expected extracted i18n keys");
        for &locale in &Locale::ALL {
            let Some(map) = catalog(locale) else {
                continue;
            };
            for key in &used_keys {
                assert!(
                    map.contains_key(key.as_str()),
                    "missing key {key:?} in locale {}",
                    locale.code()
                );
            }
        }
    }
}
