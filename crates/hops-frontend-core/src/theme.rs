//! UI-agnostic theming for hops front-ends.
//!
//! A named RGB palette with semantic roles, mirroring Slint's built-in `Palette`
//! taxonomy (background/surface/foreground/accent/…) so ONE schema drives both the
//! Ratatui TUI (maps to `ratatui::Color`) and the Slint GUI (maps to `ThemeColors`,
//! feeding its token-driven design system) — Rust is the single source of truth;
//! neither front-end hardcodes palette literals. Theme is a UI-LOCAL preference
//! (persisted per front-end), never sent over IPC.
//!
//! Anyone can add their own theme: drop a `.toml` file in
//! `~/.config/lan-mouse/themes/` (see [`load_user_themes`] for the schema) and it
//! shows up in both front-ends' theme picker, right alongside the built-ins —
//! that's the whole extension surface, no code changes required.

use std::path::PathBuf;

use serde::Deserialize;

/// A 24-bit color. Front-ends map this to their own color type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

const fn rgb(r: u8, g: u8, b: u8) -> Rgb {
    Rgb(r, g, b)
}

/// A named palette with semantic roles (not raw color names) so a front-end
/// styles by meaning and any theme drops in. Field names match the Slint GUI's
/// `ThemeColors` struct 1:1 — and the on-disk TOML schema — so the same names
/// mean the same thing everywhere a theme is authored or consumed.
#[derive(Clone, Debug, PartialEq)]
pub struct Theme {
    pub name: String,
    /// window background
    pub background: Rgb,
    /// panel / list background — one step up from `background` (tonal elevation)
    pub surface: Rgb,
    /// card / control / hover background — one step up from `surface`
    pub surface_raised: Rgb,
    /// primary text
    pub foreground: Rgb,
    /// de-emphasized text / borders / hints
    pub muted: Rgb,
    /// brand accent (positions, key hints, fingerprints, the one accent)
    pub accent: Rgb,
    /// text/icons drawn on top of an accent-filled surface
    pub on_accent: Rgb,
    /// selected-row tint
    pub selection: Rgb,
    /// hairlines / separators
    pub border: Rgb,
    /// connected / enabled / healthy
    pub success: Rgb,
    /// warnings / in-flight
    pub warn: Rgb,
    /// offline / disabled / errors
    pub error: Rgb,
}

/// Built-in themes — clean dark default first, then curated popular schemes and
/// a light option. Selection cycles through [`all_themes`].
pub fn builtins() -> Vec<Theme> {
    vec![
        Theme {
            name: "grabbr dark".into(),
            background: rgb(0x0f, 0x0f, 0x13),
            surface: rgb(0x1a, 0x1b, 0x22),
            surface_raised: rgb(0x26, 0x27, 0x2f),
            foreground: rgb(0xe8, 0xe8, 0xea),
            muted: rgb(0x8e, 0x8e, 0x99),
            accent: rgb(0x57, 0x9b, 0xff),
            on_accent: rgb(0x0f, 0x10, 0x16),
            selection: rgb(0x1d, 0x27, 0x40),
            border: rgb(0x34, 0x34, 0x3f),
            success: rgb(0x44, 0xc4, 0x68),
            warn: rgb(0xe7, 0xb8, 0x4b),
            error: rgb(0xf2, 0x5d, 0x5d),
        },
        Theme {
            name: "catppuccin".into(),
            background: rgb(0x1e, 0x1e, 0x2e),
            surface: rgb(0x28, 0x28, 0x39),
            surface_raised: rgb(0x31, 0x32, 0x44),
            foreground: rgb(0xcd, 0xd6, 0xf4),
            muted: rgb(0x93, 0x99, 0xb2),
            accent: rgb(0x89, 0xb4, 0xfa),
            on_accent: rgb(0x1e, 0x1e, 0x2e),
            selection: rgb(0x2a, 0x2a, 0x45),
            border: rgb(0x45, 0x47, 0x5a),
            success: rgb(0xa6, 0xe3, 0xa1),
            warn: rgb(0xf9, 0xe2, 0xaf),
            error: rgb(0xf3, 0x8b, 0xa8),
        },
        Theme {
            name: "nord".into(),
            background: rgb(0x2e, 0x34, 0x40),
            surface: rgb(0x3b, 0x42, 0x52),
            surface_raised: rgb(0x43, 0x4c, 0x5e),
            foreground: rgb(0xd8, 0xde, 0xe9),
            muted: rgb(0x9a, 0xa3, 0xb5),
            accent: rgb(0x88, 0xc0, 0xd0),
            on_accent: rgb(0x2e, 0x34, 0x40),
            selection: rgb(0x3a, 0x4a, 0x5a),
            border: rgb(0x4c, 0x56, 0x6a),
            success: rgb(0xa3, 0xbe, 0x8c),
            warn: rgb(0xeb, 0xcb, 0x8b),
            error: rgb(0xbf, 0x61, 0x6a),
        },
        Theme {
            name: "tokyo night".into(),
            background: rgb(0x1a, 0x1b, 0x26),
            surface: rgb(0x20, 0x21, 0x2e),
            surface_raised: rgb(0x29, 0x2e, 0x42),
            foreground: rgb(0xc0, 0xca, 0xf5),
            muted: rgb(0x88, 0x91, 0xc4),
            accent: rgb(0x7a, 0xa2, 0xf7),
            on_accent: rgb(0x1a, 0x1b, 0x26),
            selection: rgb(0x28, 0x34, 0x57),
            border: rgb(0x34, 0x3a, 0x52),
            success: rgb(0x9e, 0xce, 0x6a),
            warn: rgb(0xe0, 0xaf, 0x68),
            error: rgb(0xf7, 0x76, 0x8e),
        },
        Theme {
            name: "gruvbox".into(),
            background: rgb(0x28, 0x28, 0x28),
            surface: rgb(0x32, 0x30, 0x2f),
            surface_raised: rgb(0x3c, 0x38, 0x36),
            foreground: rgb(0xeb, 0xdb, 0xb2),
            muted: rgb(0xa8, 0x99, 0x84),
            accent: rgb(0x83, 0xa5, 0x98),
            on_accent: rgb(0x28, 0x28, 0x28),
            selection: rgb(0x45, 0x40, 0x3a),
            border: rgb(0x50, 0x49, 0x45),
            success: rgb(0xb8, 0xbb, 0x26),
            warn: rgb(0xfa, 0xbd, 0x2f),
            error: rgb(0xfb, 0x49, 0x34),
        },
        Theme {
            name: "light".into(),
            background: rgb(0xfa, 0xfa, 0xfa),
            surface: rgb(0xf0, 0xf0, 0xf2),
            surface_raised: rgb(0xff, 0xff, 0xff),
            foreground: rgb(0x1b, 0x1b, 0x1b),
            muted: rgb(0x6b, 0x6b, 0x6b),
            accent: rgb(0x00, 0x66, 0xcc),
            on_accent: rgb(0xff, 0xff, 0xff),
            selection: rgb(0xdc, 0xe8, 0xf8),
            border: rgb(0xe0, 0xe0, 0xe4),
            success: rgb(0x1d, 0x8a, 0x34),
            warn: rgb(0xb8, 0x6b, 0x00),
            error: rgb(0xcc, 0x2f, 0x2f),
        },
    ]
}

/// The default theme (first built-in).
pub fn default_theme() -> Theme {
    builtins().into_iter().next().expect("at least one builtin")
}

/// Every theme available to pick from: built-ins, then any valid user theme
/// found in `~/.config/lan-mouse/themes/*.toml`. This — not [`builtins`] — is
/// the list a front-end's theme picker/cycle should show; both front-ends
/// index into it the same way, so the merged order is the shared contract.
pub fn all_themes() -> Vec<Theme> {
    let mut themes = builtins();
    themes.extend(load_user_themes());
    themes
}

/// Find a theme by name within `themes`, falling back to the first entry (or
/// the built-in default if `themes` is empty).
pub fn by_name(themes: &[Theme], name: &str) -> Theme {
    themes
        .iter()
        .find(|t| t.name == name)
        .cloned()
        .or_else(|| themes.first().cloned())
        .unwrap_or_else(default_theme)
}

/// Position of a theme in `themes` by name, or 0 if not found. Both front-ends
/// call this against the SAME `themes` list (from [`all_themes`]) so an index
/// means the same palette on both sides.
pub fn index_of(themes: &[Theme], name: &str) -> usize {
    themes.iter().position(|t| t.name == name).unwrap_or(0)
}

fn config_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut p = PathBuf::from(home);
    p.push(".config/lan-mouse");
    Some(p)
}

fn themes_dir() -> Option<PathBuf> {
    let mut p = config_dir()?;
    p.push("themes");
    Some(p)
}

/// On-disk theme schema — every field is a `"#rrggbb"` hex string. A user theme
/// file must define every field (no partial/inherited themes in v1); a file
/// that fails to parse is skipped with a `log::warn!`, not a hard error, so one
/// broken theme file never breaks the front-end.
///
/// Example — save as `~/.config/lan-mouse/themes/my-theme.toml`:
/// ```toml
/// name = "my theme"
/// background = "#101014"
/// surface = "#181820"
/// surface_raised = "#20202a"
/// foreground = "#eaeaea"
/// muted = "#888888"
/// accent = "#ff6b35"
/// on_accent = "#101014"
/// selection = "#2a2010"
/// border = "#303030"
/// success = "#4caf50"
/// warn = "#ffb300"
/// error = "#f44336"
/// ```
#[derive(Deserialize)]
struct ThemeToml {
    name: String,
    background: String,
    surface: String,
    surface_raised: String,
    foreground: String,
    muted: String,
    accent: String,
    on_accent: String,
    selection: String,
    border: String,
    success: String,
    warn: String,
    error: String,
}

/// Parse `"#rrggbb"` or `"rrggbb"` into an [`Rgb`].
fn parse_hex(s: &str) -> Option<Rgb> {
    let s = s.trim().strip_prefix('#').unwrap_or(s.trim());
    if s.len() != 6 {
        return None;
    }
    let r = u8::from_str_radix(s.get(0..2)?, 16).ok()?;
    let g = u8::from_str_radix(s.get(2..4)?, 16).ok()?;
    let b = u8::from_str_radix(s.get(4..6)?, 16).ok()?;
    Some(Rgb(r, g, b))
}

impl TryFrom<ThemeToml> for Theme {
    type Error = &'static str;

    fn try_from(t: ThemeToml) -> Result<Self, Self::Error> {
        Ok(Theme {
            name: t.name,
            background: parse_hex(&t.background).ok_or("background")?,
            surface: parse_hex(&t.surface).ok_or("surface")?,
            surface_raised: parse_hex(&t.surface_raised).ok_or("surface_raised")?,
            foreground: parse_hex(&t.foreground).ok_or("foreground")?,
            muted: parse_hex(&t.muted).ok_or("muted")?,
            accent: parse_hex(&t.accent).ok_or("accent")?,
            on_accent: parse_hex(&t.on_accent).ok_or("on_accent")?,
            selection: parse_hex(&t.selection).ok_or("selection")?,
            border: parse_hex(&t.border).ok_or("border")?,
            success: parse_hex(&t.success).ok_or("success")?,
            warn: parse_hex(&t.warn).ok_or("warn")?,
            error: parse_hex(&t.error).ok_or("error")?,
        })
    }
}

/// Load every valid `*.toml` theme in `~/.config/lan-mouse/themes/`. Also
/// creates the directory (empty) if missing, and drops a `README.md` there
/// documenting the schema — so the directory is discoverable even before
/// anyone has authored a theme. Best-effort throughout: a missing `$HOME`,
/// an unreadable directory, or a malformed file never panics a front-end.
pub fn load_user_themes() -> Vec<Theme> {
    let Some(dir) = themes_dir() else {
        return Vec::new();
    };
    if !dir.exists() {
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("README.md"), THEMES_README);
    }
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Vec::new();
    };
    entries
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "toml"))
        .filter_map(|e| {
            let path = e.path();
            let raw = std::fs::read_to_string(&path).ok()?;
            match toml_edit::de::from_str::<ThemeToml>(&raw).map_err(|e| e.to_string()).and_then(|t| {
                Theme::try_from(t).map_err(|field| format!("invalid color in `{field}`"))
            }) {
                Ok(theme) => Some(theme),
                Err(e) => {
                    log::warn!("{}: skipping theme file: {e}", path.display());
                    None
                }
            }
        })
        .collect()
}

const THEMES_README: &str = r##"# hops themes

Drop a `.toml` file in this directory to add a theme to BOTH front-ends'
picker (the GUI's swatch footer and the TUI's `t` cycle) — no code, no
rebuild, just a file.

Every field is required and must be a `"#rrggbb"` hex color:

```toml
name = "my theme"
background = "#101014"      # window background
surface = "#181820"         # panel / list background (one step up from background)
surface_raised = "#20202a"  # card / control / hover background (one step up from surface)
foreground = "#eaeaea"      # primary text
muted = "#888888"           # secondary text / hints / hairlines' text
accent = "#ff6b35"          # the one accent — positions, key hints, the active theme swatch
on_accent = "#101014"       # text/icons drawn on top of an accent-filled surface
selection = "#2a2010"       # selected-row tint
border = "#303030"          # hairlines / separators
success = "#4caf50"         # connected / enabled / healthy
warn = "#ffb300"            # warnings / in-flight
error = "#f44336"           # offline / disabled / errors
```

A file that fails to parse is skipped (logged, not fatal) — the rest of your
themes and the built-ins still load.
"##;

fn pref_path() -> Option<PathBuf> {
    let mut p = config_dir()?;
    p.push("tui-theme");
    Some(p)
}

/// The persisted theme name, if any (UI-local; lives next to config.toml).
pub fn load_name() -> Option<String> {
    let s = std::fs::read_to_string(pref_path()?).ok()?;
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// Persist the chosen theme name (best-effort).
pub fn save_name(name: &str) {
    if let Some(p) = pref_path() {
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(p, name);
    }
}
