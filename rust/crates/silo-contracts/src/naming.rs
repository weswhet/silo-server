//! Port of `internal/naming/subtitle.go`: what a sidecar subtitle's file name says about the track.

use silo_gocompat::filepath;
use silo_gocompat::strings::{equal_fold, to_lower, trim_space};

use crate::lang::registered_tag;

/// `naming.SubtitleTags`.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SubtitleTags {
    pub language: String,
    pub forced: bool,
    pub hearing_impaired: bool,
}

/// `naming.SubtitleSuffix`: the part of a sidecar's name after the video's name, when the sidecar
/// belongs to that video. Its name must equal the video's, ignoring case, or continue with a dot.
pub fn subtitle_suffix<'a>(video_base: &str, subtitle_base: &'a str) -> Option<&'a str> {
    // Case folding can change a name's byte length, so compare the whole name before each dot.
    let bytes = subtitle_base.as_bytes();
    for i in 0..=bytes.len() {
        if i < bytes.len() && bytes[i] != b'.' {
            continue;
        }
        if equal_fold(&subtitle_base[..i], video_base) {
            return Some(&subtitle_base[i..]);
        }
    }
    None
}

/// `naming.SidecarSubtitleTags`.
pub fn sidecar_subtitle_tags(video_path: &str, subtitle_path: &str) -> Option<SubtitleTags> {
    let video_base = filepath::base(video_path);
    let subtitle_base = filepath::base(subtitle_path);
    let video_name = video_base
        .strip_suffix(filepath::ext(video_base))
        .unwrap_or(video_base);
    let subtitle_name = subtitle_base
        .strip_suffix(filepath::ext(subtitle_base))
        .unwrap_or(subtitle_base);
    let suffix = subtitle_suffix(video_name, subtitle_name)?;
    Some(parse_subtitle_suffix(suffix))
}

/// `naming.ParseSubtitleSuffix`: reads the dot-separated words of a suffix such as `.en.sdh`.
pub fn parse_subtitle_suffix(suffix: &str) -> SubtitleTags {
    let mut tags = SubtitleTags::default();
    let mut three_letter_only = String::new();
    let mut hi_words = 0;
    for word in suffix.split('.') {
        match to_lower(trim_space(word)).as_str() {
            "" => continue,
            "forced" => tags.forced = true,
            "sdh" | "cc" => tags.hearing_impaired = true,
            "hi" => hi_words += 1,
            _ => {
                let tag = registered_tag(word);
                if tag.is_empty() {
                } else if has_two_letter_code(word, &tag) {
                    if tags.language.is_empty() {
                        tags.language = tag;
                    }
                } else if three_letter_only.is_empty() {
                    three_letter_only = tag;
                }
            }
        }
    }
    if tags.language.is_empty() && hi_words > 0 {
        tags.language = "hi".to_string();
        hi_words -= 1;
    }
    if tags.language.is_empty() {
        tags.language = three_letter_only;
    }
    if hi_words > 0 {
        tags.hearing_impaired = true;
    }
    tags
}

fn has_two_letter_code(word: &str, tag: &str) -> bool {
    let primary = tag.split('-').next().unwrap_or_default();
    let normalized = trim_space(word).replace('_', "-");
    let written = normalized.split('-').next().unwrap_or_default();
    primary.len() == 2 || written.len() == 2
}
