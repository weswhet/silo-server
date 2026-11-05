//! `handlers/ebook_read_state.go` and `PGEbookReaderProgressStore`.
use std::time::SystemTime;

use silo_pg::AnyInt;
use silo_store::catalog::access::AccessFilter;

use super::super::auth::ApiError;
use super::super::chain::Stack;
use super::super::settings::api;

const GET: &str = r#"
		SELECT user_id, profile_id, content_id, file_id, location, progress, updated_at
		FROM ebook_reader_progress
		WHERE user_id = $1 AND profile_id = $2 AND content_id = $3"#;

const DELETE: &str = r#"
		DELETE FROM ebook_reader_progress
		WHERE user_id = $1 AND profile_id = $2 AND content_id = $3"#;

const UPSERT: &str = r#"
		INSERT INTO ebook_reader_progress
			(user_id, profile_id, content_id, file_id, location, progress, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id, profile_id, content_id) DO UPDATE SET
			file_id = EXCLUDED.file_id,
			location = EXCLUDED.location,
			progress = CASE
				WHEN ebook_reader_progress.progress >= 0.9 AND EXCLUDED.progress < 0.9
				THEN ebook_reader_progress.progress
				ELSE EXCLUDED.progress
			END,
			updated_at = EXCLUDED.updated_at"#;

pub(super) async fn set_ebook_read_state(
    s: &Stack,
    user: i64,
    profile: &str,
    content: &str,
    read: bool,
    filter: &AccessFilter,
    quality: &str,
) -> Result<(), ApiError> {
    let failed = |_| api(500, "internal_error", "Failed to update watched state");
    if !read {
        s.pool
            .execute(DELETE, &[&AnyInt(user), &profile, &content])
            .await
            .map_err(failed)?;
        return Ok(());
    }
    let now = SystemTime::now();
    let existing = s
        .pool
        .query(GET, &[&AnyInt(user), &profile, &content])
        .await
        .map_err(failed)?;
    let (file, location) = if let Some(row) = existing.first() {
        (
            row.get::<_, AnyInt>("file_id").0,
            row.get::<_, String>("location"),
        )
    } else {
        let files = s
            .pool
            .query(super::GET_FILES, &[&content])
            .await
            .map_err(failed)?;
        let mut first = None;
        for file in files {
            let folder: i32 = file.get("media_folder_id");
            let resolution = file
                .get::<_, Option<String>>("resolution")
                .unwrap_or_default();
            if filter
                .allowed
                .as_ref()
                .is_some_and(|ids| !ids.contains(&folder))
                || filter.disabled.contains(&folder)
                || !quality_allowed(&resolution, quality)
            {
                continue;
            }
            let base = file
                .get::<_, Option<String>>("base_type")
                .unwrap_or_default();
            if !silo_gocompat::strings::equal_fold(&base, "ebook") {
                continue;
            }
            let path: String = file.get("file_path");
            let container = file
                .get::<_, Option<String>>("container")
                .unwrap_or_default();
            let format = reader_format(&path, &container);
            if format.is_empty() {
                continue;
            }
            let id = file.get::<_, AnyInt>("id").0;
            if format == "epub" {
                first = Some(id);
                break;
            }
            first.get_or_insert(id);
        }
        (
            first.ok_or_else(|| api(404, "not_found", "Item not found"))?,
            String::new(),
        )
    };
    s.pool
        .execute(
            UPSERT,
            &[
                &AnyInt(user),
                &profile,
                &content,
                &AnyInt(file),
                &location,
                &1.0_f64,
                &now,
            ],
        )
        .await
        .map_err(failed)?;
    Ok(())
}

fn reader_format(path: &str, container: &str) -> String {
    if silo_gocompat::strings::to_lower(path).ends_with(".fb2.zip") {
        return "fbz".to_owned();
    }
    let filename = path.rsplit('/').next().unwrap_or_default();
    let extension = filename.rsplit_once('.').map_or("", |(_, ext)| ext);
    let format = normalize_format(extension);
    if format.is_empty() {
        normalize_format(container)
    } else {
        format
    }
}

fn normalize_format(value: &str) -> String {
    let value = silo_gocompat::strings::to_lower(silo_gocompat::strings::trim_space(value));
    let value = value.strip_prefix('.').unwrap_or(&value);
    match value {
        "epub" | "pdf" | "mobi" | "azw" | "azw3" | "cbz" | "cbr" | "fb2" | "fbz" => {
            value.to_owned()
        }
        _ => String::new(),
    }
}

fn quality_allowed(file: &str, ceiling: &str) -> bool {
    let normalized = silo_gate::mw::viewer::normalize_playback_quality(ceiling);
    let max = match normalized.as_str() {
        "1080p" => 3,
        "2160p" => 4,
        _ => return true,
    };
    let rank =
        match silo_gocompat::strings::to_upper(silo_gocompat::strings::trim_space(file)).as_str() {
            "480P" => 1,
            "720P" => 2,
            "1080P" => 3,
            "2160P" => 4,
            "4320P" => 5,
            _ => 0,
        };
    rank <= max
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_format_prefers_supported_extension_and_falls_back_to_container() {
        for (path, container, expected) in [
            ("book.FB2.ZIP", "zip", "fbz"),
            ("book.EPUB", "pdf", "epub"),
            ("book.unknown", " .EPUB ", "epub"),
            ("folder.epub/book", "zip", ""),
            ("book.zip", "zip", ""),
        ] {
            assert_eq!(reader_format(path, container), expected);
        }
    }

    #[test]
    fn reader_file_quality_obeys_normalized_ceiling() {
        for (file, ceiling, expected) in [
            ("2160p", "standard", false),
            ("1080p", "480p", true),
            ("4320p", "4k", false),
            ("2160p", " UHD ", true),
            ("unknown", "1080p", true),
            ("4320p", "any", true),
        ] {
            assert_eq!(quality_allowed(file, ceiling), expected);
        }
    }
}
