//! `internal/blobstore`: this module adds only [`media_type`]. Key validation and the identity
//! and presign strings are already ported in `silo_core::blobstore` (`validate_key`,
//! `local_identity`, `s3_identity`, `presign_get_url`, …) — re-export or depend on those rather
//! than re-porting `key.go`; this module does not redefine them.
//!
//! Not ported: the `Store` trait (`store.go`), the filesystem backend (`filesystem.go`, the
//! largest file in the package), the S3 backend (`s3.go`, needs `s3client`, also not ported),
//! `Matches` (`matches.go`, needs a working backend to call `Get` against), `bucketapi.go`,
//! `fence.go`, and `open.go`'s backend-selection/config wiring. `internal/s3client` is not ported
//! at all in this session (see the crate's top-level doc).

/// `blobstore.MediaType`: the content type for a stored artwork key, by extension.
pub fn media_type(key: &str) -> &'static str {
    let ext = key
        .rsplit_once('/')
        .map_or(key, |(_, name)| name)
        .rsplit_once('.')
        .map_or("", |(_, ext)| ext);
    match ext.to_ascii_lowercase().as_str() {
        "webp" => "image/webp",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "avif" => "image/avif",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::media_type;

    // path.Ext in Go returns the suffix from the last '.' in the FINAL path element, so a dotted
    // directory component must not leak an extension (e.g. "a.dir/b" has no extension).
    #[test]
    fn matches_go_path_ext_semantics() {
        assert_eq!(media_type("poster.jpg"), "image/jpeg");
        assert_eq!(media_type("poster.JPG"), "image/jpeg");
        assert_eq!(media_type("a/b/poster.webp"), "image/webp");
        assert_eq!(media_type("a.dir/b"), "application/octet-stream");
        assert_eq!(media_type("noext"), "application/octet-stream");
        assert_eq!(media_type("x.PNG"), "image/png");
    }
}
