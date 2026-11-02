//! The read half of `internal/catalog/folder_repo.go`.

use std::collections::HashMap;
use std::time::SystemTime;

use silo_pg::{Error, Pool, Row};

/// `folderColumns`.
const FOLDER_COLUMNS: &str = "id, type, name, enabled, metadata_language, auto_translate_metadata, chapter_thumbnails_enabled, intro_detection_enabled, trickplay_enabled, realtime_monitoring, trailer_kinds, poster_path, last_scanned_at,
	scan_warning_code, scan_warning_message, scan_warning_at, allow_empty_cleanup_once, sort_order";

/// `models.MediaFolder`.
#[derive(Clone, Debug, Default)]
pub struct Folder {
    pub id: i32,
    pub kind: String,
    pub name: String,
    pub enabled: bool,
    pub metadata_language: String,
    pub auto_translate_metadata: bool,
    pub chapter_thumbnails_enabled: bool,
    pub intro_detection_enabled: bool,
    pub trickplay_enabled: bool,
    pub realtime_monitoring: bool,
    pub trailer_kinds: Vec<String>,
    pub poster_path: String,
    pub last_scanned_at: Option<SystemTime>,
    pub scan_warning_code: Option<String>,
    pub scan_warning_message: Option<String>,
    pub scan_warning_at: Option<SystemTime>,
    pub sort_order: i32,
    pub paths: Vec<String>,
}

/// `ErrFolderNotFound` or a failed read.
#[derive(Debug)]
pub enum FolderError {
    NotFound,
    Db(String),
}

impl From<Error> for FolderError {
    fn from(e: Error) -> Self {
        FolderError::Db(e.to_string())
    }
}

fn scan(row: &Row) -> Result<Folder, FolderError> {
    let driver = |e: silo_pg::DriverError| FolderError::Db(e.to_string());
    Ok(Folder {
        id: row.try_get::<_, silo_pg::AnyInt>(0).map_err(driver)?.0 as i32,
        kind: row.try_get(1).map_err(driver)?,
        name: row.try_get(2).map_err(driver)?,
        enabled: row.try_get(3).map_err(driver)?,
        metadata_language: row.try_get(4).map_err(driver)?,
        auto_translate_metadata: row.try_get(5).map_err(driver)?,
        chapter_thumbnails_enabled: row.try_get(6).map_err(driver)?,
        intro_detection_enabled: row.try_get(7).map_err(driver)?,
        trickplay_enabled: row.try_get(8).map_err(driver)?,
        realtime_monitoring: row.try_get(9).map_err(driver)?,
        trailer_kinds: row
            .try_get::<_, Option<Vec<String>>>(10)
            .map_err(driver)?
            .unwrap_or_default(),
        poster_path: row.try_get(11).map_err(driver)?,
        last_scanned_at: row.try_get(12).map_err(driver)?,
        scan_warning_code: row.try_get(13).map_err(driver)?,
        scan_warning_message: row.try_get(14).map_err(driver)?,
        scan_warning_at: row.try_get(15).map_err(driver)?,
        sort_order: row.try_get(17).map_err(driver)?,
        paths: Vec::new(),
    })
}

/// `loadPaths`.
async fn load_paths(pool: &Pool, folders: &mut [Folder]) -> Result<(), FolderError> {
    if folders.is_empty() {
        return Ok(());
    }
    let ids: Vec<i32> = folders.iter().map(|f| f.id).collect();
    let rows = pool
        .query(
            "SELECT media_folder_id, path FROM media_folder_paths WHERE media_folder_id = ANY($1) ORDER BY id ASC",
            &[&ids],
        )
        .await?;
    let index: HashMap<i32, usize> = folders.iter().enumerate().map(|(i, f)| (f.id, i)).collect();
    for row in rows {
        let id = row
            .try_get::<_, silo_pg::AnyInt>(0)
            .map_err(|e| FolderError::Db(e.to_string()))?
            .0 as i32;
        let path: String = row.try_get(1).map_err(|e| FolderError::Db(e.to_string()))?;
        if let Some(&i) = index.get(&id) {
            folders[i].paths.push(path);
        }
    }
    Ok(())
}

async fn listed(
    pool: &Pool,
    sql: &str,
    params: silo_pg::Params<'_>,
) -> Result<Vec<Folder>, FolderError> {
    let rows = pool.query(sql, params).await?;
    let mut folders = rows.iter().map(scan).collect::<Result<Vec<_>, _>>()?;
    load_paths(pool, &mut folders).await?;
    Ok(folders)
}

/// `FolderRepository.List`.
pub async fn list(pool: &Pool) -> Result<Vec<Folder>, FolderError> {
    let sql = format!("SELECT {FOLDER_COLUMNS} FROM media_folders ORDER BY sort_order ASC, id ASC");
    listed(pool, &sql, &[]).await
}

/// `FolderRepository.GetEnabled`.
pub async fn get_enabled(pool: &Pool) -> Result<Vec<Folder>, FolderError> {
    let sql = format!(
        "SELECT {FOLDER_COLUMNS} FROM media_folders WHERE enabled = true ORDER BY sort_order ASC, id ASC"
    );
    listed(pool, &sql, &[]).await
}

/// `FolderRepository.ListByIDs`.
pub async fn list_by_ids(pool: &Pool, ids: &[i64]) -> Result<Vec<Folder>, FolderError> {
    let ids = ids.to_vec();
    let sql = format!(
        "SELECT {FOLDER_COLUMNS} FROM media_folders WHERE id = ANY($1) AND enabled = true ORDER BY sort_order ASC, id ASC"
    );
    listed(pool, &sql, &[&ids]).await
}

/// `FolderRepository.GetByID`.
pub async fn get_by_id(pool: &Pool, id: i64) -> Result<Folder, FolderError> {
    let sql = format!("SELECT {FOLDER_COLUMNS} FROM media_folders WHERE id = $1");
    let rows = pool.query(&sql, &[&id]).await?;
    let Some(row) = rows.first() else {
        return Err(FolderError::NotFound);
    };
    let mut folders = vec![scan(row)?];
    load_paths(pool, &mut folders).await?;
    Ok(folders.remove(0))
}
