//! `internal/artworkkey`: the object-key naming contract for cached artwork. Stored keys reference
//! existing objects, so the layout is frozen.

use silo_gocompat::path;
use silo_gocompat::strings::{to_lower, trim_space};

pub const ORIGINAL_VARIANT: &str = "original";
pub const LOCAL_PREFIX: &str = "local/";
pub const NFO_PREFIX: &str = "nfo/";
/// `LadderVersion`, compared with the stored `backfilled_version`.
pub const LADDER_VERSION: i64 = 3;

pub const IMAGE_POSTER: &str = "poster";
pub const IMAGE_BACKDROP: &str = "backdrop";
pub const IMAGE_STILL: &str = "still";
pub const IMAGE_LOGO: &str = "logo";
pub const IMAGE_PROFILE: &str = "profile";
pub const IMAGE_BANNER: &str = "banner";
pub const IMAGE_THUMB: &str = "thumb";
pub const IMAGE_CLEAR_ART: &str = "clearart";
pub const IMAGE_DISC: &str = "disc";

/// `IsLocal`.
pub fn is_local(object_path: &str) -> bool {
    object_path.starts_with(LOCAL_PREFIX) || object_path.starts_with(NFO_PREFIX)
}

/// `ImageTypeOf`.
pub fn image_type_of(object_path: &str, fallback: &str) -> String {
    let dir = directory(object_path);
    if dir.is_empty() {
        return fallback.to_owned();
    }
    let segment = path::base(&dir);
    match segment {
        IMAGE_POSTER | IMAGE_BACKDROP | IMAGE_STILL | IMAGE_LOGO | IMAGE_PROFILE | IMAGE_BANNER
        | IMAGE_THUMB | IMAGE_CLEAR_ART | IMAGE_DISC => segment.to_owned(),
        _ => fallback.to_owned(),
    }
}

/// `Build`.
pub fn build(base_path: &str, variant: &str, revision: &str, ext: &str) -> String {
    let base_path = trim_space(base_path).trim_end_matches('/');
    let variant = trim_space(variant);
    let revision = trim_space(revision);
    if base_path.is_empty() || variant.is_empty() {
        return String::new();
    }
    let ext = if ext.is_empty() {
        ".webp".to_owned()
    } else if !ext.starts_with('.') {
        format!(".{ext}")
    } else {
        ext.to_owned()
    };
    if revision.is_empty() {
        format!("{base_path}/{variant}{ext}")
    } else {
        format!("{base_path}/{variant}.{revision}{ext}")
    }
}

/// `Original`.
pub fn original(base_path: &str, revision: &str, ext: &str) -> String {
    build(base_path, ORIGINAL_VARIANT, revision, ext)
}

/// `Variant`: rewrites an original key to another variant, keeping any revision and extension.
pub fn variant(original_path: &str, variant: &str) -> String {
    if original_path.is_empty() || variant.is_empty() || variant == ORIGINAL_VARIANT {
        return original_path.to_owned();
    }
    let dir = path::dir(original_path);
    let base = path::base(original_path);
    let prefix = format!("{ORIGINAL_VARIANT}.");
    if dir == "." || !base.starts_with(&prefix) {
        return original_path.to_owned();
    }
    format!(
        "{}/{variant}{}",
        dir.trim_end_matches('/'),
        &base[ORIGINAL_VARIANT.len()..]
    )
}

/// `Directory`, with a trailing slash.
pub fn directory(object_path: &str) -> String {
    let object_path = trim_space(object_path);
    if object_path.is_empty() || object_path.contains("://") {
        return String::new();
    }
    let dir = path::dir(object_path);
    if dir == "." || dir == "/" {
        return String::new();
    }
    format!("{}/", dir.trim_end_matches('/'))
}

/// `Revision`: empty for a legacy key.
pub fn revision(object_path: &str) -> String {
    let name = path::base(trim_space(object_path));
    let ext = path::ext(name);
    let stem = name.strip_suffix(ext).unwrap_or(name);
    match stem.find('.') {
        Some(dot) if dot != stem.len() - 1 => stem[dot + 1..].to_owned(),
        _ => String::new(),
    }
}

/// `OriginalOf`.
pub fn original_of(object_path: &str) -> String {
    let dir = directory(object_path);
    if dir.is_empty() {
        return object_path.to_owned();
    }
    let base = path::base(object_path);
    let ext = path::ext(base);
    let stem = &base[..base.len() - ext.len()];
    match stem.find('.') {
        None => object_path.to_owned(),
        Some(dot) => format!("{dir}{ORIGINAL_VARIANT}{}{ext}", &stem[dot..]),
    }
}

/// `VariantWidths`, widest first.
pub fn variant_widths(image_type: &str) -> &'static [i64] {
    match to_lower(trim_space(image_type)).as_str() {
        IMAGE_BACKDROP => &[2560, 1920, 1280, 300],
        IMAGE_STILL | IMAGE_THUMB => &[1280, 500, 300],
        IMAGE_LOGO => &[1280, 500],
        IMAGE_BANNER | IMAGE_CLEAR_ART => &[1000, 500],
        IMAGE_PROFILE => &[500, 300],
        _ => &[1000, 500, 300],
    }
}

/// `VariantNames`.
pub fn variant_names(image_type: &str) -> Vec<String> {
    let mut names = vec![ORIGINAL_VARIANT.to_owned()];
    names.extend(variant_widths(image_type).iter().map(|w| format!("w{w}")));
    names
}

/// `ObjectKeys`.
pub fn object_keys(original_path: &str, image_type: &str) -> Vec<String> {
    if original_path.is_empty() || original_path.contains("://") {
        return Vec::new();
    }
    variant_names(image_type)
        .iter()
        .map(|name| variant(original_path, name))
        .collect()
}

/// `imagecache.normalizeImageLanguage`.
pub fn normalize_image_language(language: &str) -> String {
    let language = to_lower(trim_space(language));
    let mut out = String::with_capacity(language.len());
    for c in language.chars() {
        match c {
            'a'..='z' | '0'..='9' | '-' | '_' => out.push(c),
            _ => out.push('_'),
        }
    }
    out.trim_matches('_').to_owned()
}

/// `imagecache.buildBasePath`. `image_type` is what `imageTypeName` returned.
#[allow(clippy::too_many_arguments)]
pub fn build_base_path(
    provider_id: &str,
    content_type: &str,
    content_id: &str,
    language: &str,
    season: Option<i64>,
    episode: Option<i64>,
    discriminator: &str,
    image_type: &str,
) -> String {
    let mut base = format!("{provider_id}/{content_type}/{content_id}");
    let language = normalize_image_language(language);
    if !language.is_empty() {
        base = format!("{base}/localizations/{language}");
    }
    if let Some(season) = season {
        base = format!("{base}/seasons/{season}");
        if let Some(episode) = episode {
            base = format!("{base}/episodes/{episode}");
        }
    }
    let discriminator = trim_space(discriminator);
    if !discriminator.is_empty() {
        base = format!("{base}/{discriminator}");
    }
    format!("{base}/{image_type}")
}
