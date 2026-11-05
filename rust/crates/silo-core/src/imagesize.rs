//! `internal/imagesize`: the client-selectable image size contract (`image_size` and the per-slot
//! width parameters) and the mapping from a size to a cached artwork variant.

use crate::artworkkey::{self, ORIGINAL_VARIANT};
use silo_gocompat::strings::{to_lower, trim_space};

/// `QueryParam`.
pub const QUERY_PARAM: &str = "image_size";

/// `Size`. Named sizes are the lowercase words; a target width is `width:<px>`; `Unset` is empty.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Size(pub String);

pub const UNSET: &str = "";
pub const SMALL: &str = "small";
pub const MEDIUM: &str = "medium";
pub const LARGE: &str = "large";
pub const ORIGINAL: &str = "original";

/// `All`, narrowest first.
pub const ALL: [&str; 4] = [SMALL, MEDIUM, LARGE, ORIGINAL];

const WIDTH_PREFIX: &str = "width:";

impl Size {
    pub fn named(name: &str) -> Self {
        Size(name.to_owned())
    }

    pub fn is_unset(&self) -> bool {
        self.0.is_empty()
    }

    /// `Width(px)`.
    pub fn width(px: i64) -> Self {
        Size(format!("{WIDTH_PREFIX}{px}"))
    }

    /// `TargetWidth`.
    pub fn target_width(&self) -> Option<i64> {
        let raw = self.0.strip_prefix(WIDTH_PREFIX)?;
        let px = go_atoi(raw)?;
        (px > 0).then_some(px)
    }
}

/// `Parse`. The error text matches Go's `%q`-formatted message only for printable input, so
/// callers that echo it should use [`parse_error_message`].
pub fn parse(raw: &str) -> Result<Size, String> {
    let lowered = to_lower(trim_space(raw));
    match lowered.as_str() {
        UNSET | SMALL | MEDIUM | LARGE | ORIGINAL => Ok(Size(lowered)),
        _ => Err(parse_error_message(raw)),
    }
}

/// The message Go's `Parse` returns for an unknown value.
pub fn parse_error_message(raw: &str) -> String {
    format!(
        "imagesize: unknown {QUERY_PARAM} {} (want small, medium, large, or original)",
        silo_gocompat::strconv::quote(raw)
    )
}

/// `Variant`.
pub fn variant(image_type: &str, size: &Size) -> String {
    if let Some(px) = size.target_width() {
        return variant_for_width(image_type, px);
    }
    let widths = artworkkey::variant_widths(image_type);
    match size.0.as_str() {
        ORIGINAL => ORIGINAL_VARIANT.to_owned(),
        SMALL => widths
            .last()
            .map_or_else(|| ORIGINAL_VARIANT.to_owned(), |w| width_variant(*w)),
        LARGE => widths
            .first()
            .map_or_else(|| ORIGINAL_VARIANT.to_owned(), |w| width_variant(*w)),
        _ => medium_variant(image_type),
    }
}

const MEDIUM_BACKDROP_WIDTH: i64 = 1920;
const MEDIUM_DEFAULT_WIDTH: i64 = 500;

fn medium_variant(image_type: &str) -> String {
    if silo_gocompat::strings::equal_fold(trim_space(image_type), artworkkey::IMAGE_BACKDROP) {
        width_variant(MEDIUM_BACKDROP_WIDTH)
    } else {
        width_variant(MEDIUM_DEFAULT_WIDTH)
    }
}

pub const PLUGIN_VARIANT_CARD: &str = "card";
pub const PLUGIN_VARIANT_FEATURED: &str = "featured";
pub const PLUGIN_VARIANT_LARGE: &str = "large";
pub const PLUGIN_VARIANT_FULL: &str = "full";
pub const PLUGIN_VARIANT_ORIGINAL: &str = ORIGINAL_VARIANT;

/// `PluginVariant`.
pub fn plugin_variant(size: &Size) -> &'static str {
    if let Some(px) = size.target_width() {
        return plugin_variant_for_width(px);
    }
    match size.0.as_str() {
        SMALL => PLUGIN_VARIANT_CARD,
        LARGE => PLUGIN_VARIANT_LARGE,
        ORIGINAL => PLUGIN_VARIANT_ORIGINAL,
        _ => PLUGIN_VARIANT_FEATURED,
    }
}

/// `NextLower`.
pub fn next_lower(image_type: &str, variant: &str) -> Option<String> {
    let width = variant_width_px(variant)?;
    artworkkey::variant_widths(image_type)
        .iter()
        .find(|c| **c < width)
        .map(|c| width_variant(*c))
}

fn width_variant(width: i64) -> String {
    format!("w{width}")
}

/// `VariantWidthPx`.
pub fn variant_width_px(variant: &str) -> Option<i64> {
    let variant = trim_space(variant);
    let rest = variant.strip_prefix('w')?;
    let width = go_atoi(rest)?;
    (width > 0).then_some(width)
}

/// `strconv.Atoi` on a 64-bit platform: optional sign, ASCII digits, no overflow.
fn go_atoi(s: &str) -> Option<i64> {
    let digits = s.strip_prefix(['+', '-']).unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<i64>().ok()
}

/// `Slot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    Poster,
    Backdrop,
    Logo,
    Still,
    Photo,
}

/// `Slots`.
pub const SLOTS: [Slot; 5] = [
    Slot::Poster,
    Slot::Backdrop,
    Slot::Logo,
    Slot::Still,
    Slot::Photo,
];

impl Slot {
    /// `Name`.
    pub fn name(self) -> &'static str {
        match self {
            Slot::Poster => artworkkey::IMAGE_POSTER,
            Slot::Backdrop => artworkkey::IMAGE_BACKDROP,
            Slot::Logo => artworkkey::IMAGE_LOGO,
            Slot::Still => artworkkey::IMAGE_STILL,
            Slot::Photo => "photo",
        }
    }
}

/// `MaxTargetWidth`.
pub const MAX_TARGET_WIDTH: i64 = 7680;

/// `Widths`: per-slot target widths; zero means no preference.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Widths {
    pub poster: i64,
    pub backdrop: i64,
    pub logo: i64,
    pub still: i64,
    pub photo: i64,
}

impl Widths {
    pub fn is_zero(&self) -> bool {
        *self == Widths::default()
    }

    fn of(&self, slot: Slot) -> i64 {
        match slot {
            Slot::Poster => self.poster,
            Slot::Backdrop => self.backdrop,
            Slot::Logo => self.logo,
            Slot::Still => self.still,
            Slot::Photo => self.photo,
        }
    }

    /// `Encode`.
    pub fn encode(&self) -> String {
        SLOTS
            .iter()
            .filter_map(|slot| {
                let px = self.of(*slot);
                (px > 0).then(|| format!("{}={px}", slot.name()))
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// `Request`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub size: Size,
    pub widths: Widths,
}

impl Request {
    /// `For`.
    pub fn for_slot(&self, slot: Slot) -> Size {
        let px = self.widths.of(slot);
        if px > 0 {
            Size::width(px)
        } else {
            self.size.clone()
        }
    }
}

fn variant_for_width(image_type: &str, px: i64) -> String {
    artworkkey::variant_widths(image_type)
        .iter()
        .rev()
        .find(|w| **w >= px)
        .map_or_else(|| ORIGINAL_VARIANT.to_owned(), |w| width_variant(*w))
}

fn plugin_variant_for_width(px: i64) -> &'static str {
    match px {
        _ if px <= 300 => PLUGIN_VARIANT_CARD,
        _ if px <= 500 => PLUGIN_VARIANT_FEATURED,
        _ if px <= 1280 => PLUGIN_VARIANT_LARGE,
        _ => PLUGIN_VARIANT_ORIGINAL,
    }
}

/// `PhotoPluginVariant`.
pub fn photo_plugin_variant(size: &Size) -> &'static str {
    if size.is_unset() {
        return PLUGIN_VARIANT_LARGE;
    }
    if let Some(px) = size.target_width()
        && plugin_variant_for_width(px) != PLUGIN_VARIANT_ORIGINAL
    {
        return PLUGIN_VARIANT_LARGE;
    }
    plugin_variant(size)
}
