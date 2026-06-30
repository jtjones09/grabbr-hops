//! UI-agnostic theming for grabbr-hop front-ends.
//!
//! A small, named RGB palette with semantic roles. The Ratatui TUI maps it to
//! `ratatui` colors; the Slint GUI (later) maps the same palette to its own —
//! so both front-ends share one theme system. Theme is a UI-LOCAL preference
//! (persisted per front-end), never sent over IPC.

use std::path::PathBuf;

/// A 24-bit color. Front-ends map this to their own color type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

const fn rgb(r: u8, g: u8, b: u8) -> Rgb {
    Rgb(r, g, b)
}

/// A named palette with semantic roles (not raw color names) so a front-end
/// styles by meaning and any theme drops in.
#[derive(Clone, Debug)]
pub struct Theme {
    pub name: &'static str,
    /// window background
    pub bg: Rgb,
    /// primary text
    pub fg: Rgb,
    /// de-emphasized text / borders / hints
    pub muted: Rgb,
    /// brand accent (positions, key hints, fingerprints)
    pub accent: Rgb,
    /// connected / enabled / healthy
    pub success: Rgb,
    /// warnings / in-flight
    pub warn: Rgb,
    /// offline / disabled / errors
    pub error: Rgb,
    /// selected-row background
    pub highlight_bg: Rgb,
    /// selected-row foreground
    pub highlight_fg: Rgb,
}

/// Built-in themes — clean dark default first, then curated popular schemes and
/// a light option. Selection cycles through this list.
pub fn builtins() -> Vec<Theme> {
    vec![
        Theme {
            name: "grabbr dark",
            bg: rgb(0x12, 0x12, 0x16),
            fg: rgb(0xe8, 0xe8, 0xea),
            muted: rgb(0x8e, 0x8e, 0x99),
            accent: rgb(0x57, 0x9b, 0xff),
            success: rgb(0x44, 0xc4, 0x68),
            warn: rgb(0xe7, 0xb8, 0x4b),
            error: rgb(0xf2, 0x5d, 0x5d),
            highlight_bg: rgb(0x57, 0x9b, 0xff),
            highlight_fg: rgb(0x10, 0x12, 0x18),
        },
        Theme {
            name: "catppuccin",
            bg: rgb(0x1e, 0x1e, 0x2e),
            fg: rgb(0xcd, 0xd6, 0xf4),
            muted: rgb(0x93, 0x99, 0xb2),
            accent: rgb(0x89, 0xb4, 0xfa),
            success: rgb(0xa6, 0xe3, 0xa1),
            warn: rgb(0xf9, 0xe2, 0xaf),
            error: rgb(0xf3, 0x8b, 0xa8),
            highlight_bg: rgb(0x89, 0xb4, 0xfa),
            highlight_fg: rgb(0x1e, 0x1e, 0x2e),
        },
        Theme {
            name: "nord",
            bg: rgb(0x2e, 0x34, 0x40),
            fg: rgb(0xd8, 0xde, 0xe9),
            muted: rgb(0x9a, 0xa3, 0xb5),
            accent: rgb(0x88, 0xc0, 0xd0),
            success: rgb(0xa3, 0xbe, 0x8c),
            warn: rgb(0xeb, 0xcb, 0x8b),
            error: rgb(0xbf, 0x61, 0x6a),
            highlight_bg: rgb(0x88, 0xc0, 0xd0),
            highlight_fg: rgb(0x2e, 0x34, 0x40),
        },
        Theme {
            name: "tokyo night",
            bg: rgb(0x1a, 0x1b, 0x26),
            fg: rgb(0xc0, 0xca, 0xf5),
            muted: rgb(0x88, 0x91, 0xc4),
            accent: rgb(0x7a, 0xa2, 0xf7),
            success: rgb(0x9e, 0xce, 0x6a),
            warn: rgb(0xe0, 0xaf, 0x68),
            error: rgb(0xf7, 0x76, 0x8e),
            highlight_bg: rgb(0x7a, 0xa2, 0xf7),
            highlight_fg: rgb(0x1a, 0x1b, 0x26),
        },
        Theme {
            name: "gruvbox",
            bg: rgb(0x28, 0x28, 0x28),
            fg: rgb(0xeb, 0xdb, 0xb2),
            muted: rgb(0xa8, 0x99, 0x84),
            accent: rgb(0x83, 0xa5, 0x98),
            success: rgb(0xb8, 0xbb, 0x26),
            warn: rgb(0xfa, 0xbd, 0x2f),
            error: rgb(0xfb, 0x49, 0x34),
            highlight_bg: rgb(0x83, 0xa5, 0x98),
            highlight_fg: rgb(0x28, 0x28, 0x28),
        },
        Theme {
            name: "light",
            bg: rgb(0xfa, 0xfa, 0xfa),
            fg: rgb(0x1b, 0x1b, 0x1b),
            muted: rgb(0x6b, 0x6b, 0x6b),
            accent: rgb(0x00, 0x66, 0xcc),
            success: rgb(0x1d, 0x8a, 0x34),
            warn: rgb(0xb8, 0x6b, 0x00),
            error: rgb(0xcc, 0x2f, 0x2f),
            highlight_bg: rgb(0x00, 0x66, 0xcc),
            highlight_fg: rgb(0xfa, 0xfa, 0xfa),
        },
    ]
}

/// The default theme (first built-in).
pub fn default_theme() -> Theme {
    builtins().into_iter().next().expect("at least one builtin")
}

/// Find a built-in by name, falling back to the default.
pub fn by_name(name: &str) -> Theme {
    builtins()
        .into_iter()
        .find(|t| t.name == name)
        .unwrap_or_else(default_theme)
}

/// Position of a built-in in [`builtins`] (0-based), or 0 if unknown. The Slint
/// GUI uses this to select the matching palette from its own token table, so the
/// `builtins()` order is the shared contract between the two front-ends.
pub fn index_of(name: &str) -> usize {
    builtins().iter().position(|t| t.name == name).unwrap_or(0)
}

fn pref_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    let mut p = PathBuf::from(home);
    p.push(".config/lan-mouse/tui-theme");
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
