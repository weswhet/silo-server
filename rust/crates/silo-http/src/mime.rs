//! Port of `mime.TypeByExtension` and `mime.AddExtensionType`, including the Unix loaders.
//!
//! `setExtensionType` parses with `mime.ParseMediaType`. System files and the server's own calls use
//! plain `type/subtype` values, sometimes with a charset, so this keeps only that much of the parser.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use silo_gocompat::strings::{fields, to_lower};

/// `builtinTypesLower` from Go 1.26.7.
const BUILTIN: &[(&str, &str)] = &[
    (".ai", "application/postscript"),
    (".apk", "application/vnd.android.package-archive"),
    (".apng", "image/apng"),
    (".avif", "image/avif"),
    (".bin", "application/octet-stream"),
    (".bmp", "image/bmp"),
    (".com", "application/octet-stream"),
    (".css", "text/css; charset=utf-8"),
    (".csv", "text/csv; charset=utf-8"),
    (".doc", "application/msword"),
    (
        ".docx",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ),
    (".ehtml", "text/html; charset=utf-8"),
    (".eml", "message/rfc822"),
    (".eps", "application/postscript"),
    (".exe", "application/octet-stream"),
    (".flac", "audio/flac"),
    (".gif", "image/gif"),
    (".gz", "application/gzip"),
    (".htm", "text/html; charset=utf-8"),
    (".html", "text/html; charset=utf-8"),
    (".ico", "image/vnd.microsoft.icon"),
    (".ics", "text/calendar; charset=utf-8"),
    (".jfif", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".jpg", "image/jpeg"),
    (".js", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".m4a", "audio/mp4"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".mp3", "audio/mpeg"),
    (".mp4", "video/mp4"),
    (".oga", "audio/ogg"),
    (".ogg", "audio/ogg"),
    (".ogv", "video/ogg"),
    (".opus", "audio/ogg"),
    (".pdf", "application/pdf"),
    (".pjp", "image/jpeg"),
    (".pjpeg", "image/jpeg"),
    (".png", "image/png"),
    (".ppt", "application/vnd.ms-powerpoint"),
    (
        ".pptx",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ),
    (".ps", "application/postscript"),
    (".rdf", "application/rdf+xml"),
    (".rtf", "application/rtf"),
    (".shtml", "text/html; charset=utf-8"),
    (".svg", "image/svg+xml"),
    (".text", "text/plain; charset=utf-8"),
    (".tif", "image/tiff"),
    (".tiff", "image/tiff"),
    (".txt", "text/plain; charset=utf-8"),
    (".vtt", "text/vtt; charset=utf-8"),
    (".wasm", "application/wasm"),
    (".wav", "audio/wav"),
    (".webm", "audio/webm"),
    (".webp", "image/webp"),
    (".xbl", "text/xml; charset=utf-8"),
    (".xbm", "image/x-xbitmap"),
    (".xht", "application/xhtml+xml"),
    (".xhtml", "application/xhtml+xml"),
    (".xls", "application/vnd.ms-excel"),
    (
        ".xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ),
    (".xml", "text/xml; charset=utf-8"),
    (".xsl", "text/xml; charset=utf-8"),
    (".zip", "application/zip"),
];

#[derive(Default)]
struct Tables {
    exact: HashMap<String, String>,
    lower: HashMap<String, String>,
}

fn tables() -> &'static RwLock<Tables> {
    static TABLES: OnceLock<RwLock<Tables>> = OnceLock::new();
    TABLES.get_or_init(|| {
        let mut t = Tables::default();
        for (ext, ty) in BUILTIN {
            t.exact.insert((*ext).to_owned(), (*ty).to_owned());
            t.lower.insert((*ext).to_owned(), (*ty).to_owned());
        }
        init_unix(&mut t);
        RwLock::new(t)
    })
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// `setExtensionType`. `false` is the error return, for a media type that does not parse.
fn set_extension_type(t: &mut Tables, extension: &str, mime_type: &str) -> bool {
    let base = mime_type.split(';').next().unwrap_or("").trim();
    let Some((major, minor)) = base.split_once('/') else {
        return false;
    };
    if !is_token(major) || !is_token(minor) {
        return false;
    }
    let mut value = mime_type.to_owned();
    if mime_type.starts_with("text/") && !mime_type.contains("charset=") {
        value = format!("{}; charset=utf-8", to_lower(base));
    }
    t.exact.insert(extension.to_owned(), value.clone());
    t.lower.insert(to_lower(extension), value);
    true
}

fn load_globs(t: &mut Tables, filename: &str) -> bool {
    let Ok(text) = std::fs::read(filename) else {
        return false;
    };
    for line in String::from_utf8_lossy(&text).lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() < 3 || f[0].is_empty() || f[2].len() < 3 {
            continue;
        }
        if f[0].starts_with('#') || !f[2].starts_with("*.") {
            continue;
        }
        let extension = &f[2][1..];
        if extension.contains(['?', '*', '[']) || t.exact.contains_key(extension) {
            continue;
        }
        set_extension_type(t, extension, f[1]);
    }
    true
}

fn load_types_file(t: &mut Tables, filename: &str) {
    let Ok(text) = std::fs::read(filename) else {
        return;
    };
    for line in String::from_utf8_lossy(&text).lines() {
        let f = fields(line);
        if f.len() <= 1 || f[0].starts_with('#') {
            continue;
        }
        for ext in &f[1..] {
            if ext.starts_with('#') {
                break;
            }
            set_extension_type(t, &format!(".{ext}"), f[0]);
        }
    }
}

fn init_unix(t: &mut Tables) {
    for filename in ["/usr/local/share/mime/globs2", "/usr/share/mime/globs2"] {
        if load_globs(t, filename) {
            return;
        }
    }
    for filename in [
        "/etc/mime.types",
        "/etc/apache2/mime.types",
        "/etc/apache/mime.types",
        "/etc/httpd/conf/mime.types",
    ] {
        load_types_file(t, filename);
    }
}

/// `mime.TypeByExtension`: case-sensitive first, then case-insensitive. Empty when unknown.
pub fn type_by_extension(ext: &str) -> String {
    let t = tables()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(v) = t.exact.get(ext) {
        return v.clone();
    }
    t.lower.get(&to_lower(ext)).cloned().unwrap_or_default()
}

/// `mime.AddExtensionType`. `false` when `mime_type` does not parse or `ext` has no leading dot.
pub fn add_extension_type(ext: &str, mime_type: &str) -> bool {
    if !ext.starts_with('.') {
        return false;
    }
    let mut t = tables()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set_extension_type(&mut t, ext, mime_type)
}
