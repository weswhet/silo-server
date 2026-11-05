//! Device-scoped download subscription reads from `apiv2/download_subscriptions.go`.
use std::sync::Arc;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::problem::Problem;
use silo_api_v2::wire::{Instant, paginated};
use silo_gate::mw::auth::get_profile_id;
use silo_gocompat::json::marshal;
use silo_gocompat::time::{GoTime, RFC3339_NANO, parse};
use silo_http::chi::Mux;
use silo_http::{Request, handler_fn};
use silo_pg::{AnyInt, Row};

use super::chain::{Stack, V2Class, problem_type, write_problem, write_v2_json};
use super::personal::{internal, user_of, viewer_digest};
use crate::rows::{NativeRow, Surface::ApiV2};

const LIST: &str = "/api/v2/downloads/subscriptions";
const GET: &str = "/api/v2/downloads/subscriptions/{id}";
pub const ROWS: &[NativeRow] = &[
    NativeRow::new(ApiV2, "GET", LIST),
    NativeRow::new(ApiV2, "GET", GET),
];

const LIST_SQL: &str = "SELECT id, user_id, profile_id, device_id, series_id, mode,
\tseason_numbers, target_season, delete_watched, max_storage_bytes, active, created_at, updated_at, quality FROM download_subscriptions
 WHERE user_id=$1 AND profile_id=$2 AND device_id=$3
 AND ($4::timestamptz IS NULL OR (created_at,id)<($4,$5))
 ORDER BY created_at DESC,id DESC LIMIT $6";
const GET_SQL: &str = "SELECT id, user_id, profile_id, device_id, series_id, mode,
\tseason_numbers, target_season, delete_watched, max_storage_bytes, active, created_at, updated_at, quality FROM download_subscriptions
\t\tWHERE id = $1 AND user_id = $2 AND profile_id = $3 AND device_id = $4";

// Declaration order, nil slices, raw quality, and Go time encoding are part of the ETag.
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
struct Subscription {
    #[serde(rename = "ID")]
    id: String,
    #[serde(rename = "UserID")]
    user_id: i64,
    #[serde(rename = "ProfileID")]
    profile_id: String,
    #[serde(rename = "DeviceID")]
    device_id: String,
    #[serde(rename = "SeriesID")]
    series_id: String,
    mode: String,
    season_numbers: Option<Vec<i32>>,
    target_season: Option<i32>,
    delete_watched: bool,
    max_storage_bytes: i64,
    quality: String,
    active: bool,
    created_at: GoTime,
    updated_at: GoTime,
}

impl Subscription {
    fn scan(row: &Row) -> Result<Self, silo_pg::Error> {
        let seasons: Option<Vec<i32>> = row.try_get(6)?;
        Ok(Self {
            id: row.try_get(0)?,
            user_id: row.try_get::<_, AnyInt>(1)?.0,
            profile_id: row.try_get(2)?,
            device_id: row.try_get(3)?,
            series_id: row.try_get(4)?,
            mode: row.try_get(5)?,
            season_numbers: seasons.filter(|s| !s.is_empty()),
            target_season: row.try_get(7)?,
            delete_watched: row.try_get(8)?,
            max_storage_bytes: row.try_get(9)?,
            active: row.try_get(10)?,
            created_at: GoTime::from_system_time(row.try_get::<_, SystemTime>(11)?).to_utc(),
            updated_at: GoTime::from_system_time(row.try_get::<_, SystemTime>(12)?).to_utc(),
            quality: row.try_get(13)?,
        })
    }

    fn etag(&self) -> Result<String, Problem> {
        let json = marshal(self).map_err(|_| internal())?;
        Ok(format!("\"{:x}\"", Sha256::digest(json)))
    }

    fn into_wire(self) -> Result<DownloadSubscription, Problem> {
        let etag = self.etag()?;
        Ok(DownloadSubscription {
            id: self.id,
            series_id: self.series_id,
            mode: self.mode,
            season_numbers: self.season_numbers.unwrap_or_default(),
            target_season: self.target_season,
            delete_watched: self.delete_watched,
            max_storage_bytes: self.max_storage_bytes,
            quality: if self.quality.is_empty() {
                "original".to_owned()
            } else {
                self.quality
            },
            active: self.active,
            created_at: instant(self.created_at.to_system_time()),
            updated_at: instant(self.updated_at.to_system_time()),
            etag,
        })
    }
}

#[derive(Serialize)]
struct DownloadSubscription {
    id: String,
    series_id: String,
    mode: String,
    season_numbers: Vec<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_season: Option<i32>,
    delete_watched: bool,
    max_storage_bytes: i64,
    quality: String,
    active: bool,
    created_at: Instant,
    updated_at: Instant,
    etag: String,
}

#[derive(Serialize, Deserialize)]
struct RegistryPosition {
    #[serde(rename = "CreatedAt")]
    created_at: String,
    #[serde(rename = "ID")]
    id: String,
}

fn instant(t: SystemTime) -> Instant {
    Instant::new(time::OffsetDateTime::from(t))
}

async fn list(
    s: &Stack,
    r: &Request,
) -> Result<silo_api_v2::wire::Collection<DownloadSubscription>, Problem> {
    let (user, profile) = (user_of(r), get_profile_id(r));
    let device = String::from_utf8_lossy(r.header.get("X-Silo-Device-Id")).into_owned();
    let (query, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    let param = |key: &str| {
        query
            .get(key)
            .and_then(|v| v.first())
            .map(String::as_str)
            .unwrap_or("")
    };
    let limit = param("limit").parse::<i64>().unwrap_or(50);
    let scope = CursorScope {
        operation_id: "listDownloadSubscriptions".to_owned(),
        security: format!("{user}/{profile}/{}", viewer_digest(r)),
        filter: device.to_owned(),
        sort: "-created_at,-id".to_owned(),
        tiebreaker: "id".to_owned(),
    };
    let (mut at, mut id): (Option<SystemTime>, String) = (None, String::new());
    if !param("cursor").is_empty() {
        let pos: RegistryPosition = s.cursors.decode(&scope, param("cursor"))?;
        at = Some(
            parse(RFC3339_NANO, &pos.created_at)
                .map_err(|_| {
                    Problem::new(
                        problem_type("invalid_cursor"),
                        "The cursor is malformed, tampered with, or belongs to a different query.",
                    )
                })?
                .to_system_time(),
        );
        id = pos.id;
    }
    let rows = s
        .pool
        .query(
            LIST_SQL,
            &[
                &AnyInt(user),
                &profile,
                &device,
                &at,
                &id,
                &AnyInt(limit + 1),
            ],
        )
        .await
        .map_err(|_| internal())?;
    let mut rows = rows
        .iter()
        .map(Subscription::scan)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| internal())?;
    let mut next = String::new();
    if rows.len() as i64 > limit {
        rows.truncate(limit as usize);
        if let Some(last) = rows.last() {
            next = s
                .cursors
                .encode(
                    &scope,
                    &RegistryPosition {
                        created_at: last.created_at.format(RFC3339_NANO),
                        id: last.id.clone(),
                    },
                )
                .map_err(|_| internal())?;
        }
    }
    let items = rows
        .into_iter()
        .map(Subscription::into_wire)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(paginated(items, next))
}

async fn get(s: &Stack, r: &Request) -> Result<DownloadSubscription, Problem> {
    let rows = s
        .pool
        .query(
            GET_SQL,
            &[
                &r.url_param("id"),
                &AnyInt(user_of(r)),
                &get_profile_id(r),
                &String::from_utf8_lossy(r.header.get("X-Silo-Device-Id")).into_owned(),
            ],
        )
        .await
        .map_err(|_| internal())?;
    let row = rows
        .first()
        .ok_or_else(|| Problem::new(problem_type("not_found"), "Download not found."))?;
    Subscription::scan(row).map_err(|_| internal())?.into_wire()
}

pub fn mount(stack: &Arc<Stack>, _api: &Mux, v2: &Mux) {
    for path in [LIST, GET] {
        let s = stack.clone();
        v2.get(
            path,
            stack.v2(
                path,
                V2Class::ProfileScoped,
                handler_fn(move |w, r| {
                    let s = s.clone();
                    Box::pin(async move {
                        if path == LIST {
                            match list(&s, r).await {
                                Ok(out) => {
                                    w.header().set("Cache-Control", "private, no-cache");
                                    write_v2_json(w, &out).await
                                }
                                Err(p) => write_problem(w, r, p).await,
                            }
                        } else {
                            match get(&s, r).await {
                                Ok(out) => {
                                    w.header().set("Cache-Control", "private, no-cache");
                                    w.header().set("ETag", &out.etag);
                                    write_v2_json(w, &out).await
                                }
                                Err(p) => write_problem(w, r, p).await,
                            }
                        }
                    })
                }),
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn downloads_etag_go_json_encoding() {
        let mut sub = Subscription {
            id: "<&>\u{2028}\u{2029}".to_owned(),
            user_id: 7,
            profile_id: "p".to_owned(),
            device_id: "d".to_owned(),
            series_id: "s".to_owned(),
            mode: "all".to_owned(),
            season_numbers: None,
            target_season: None,
            delete_watched: true,
            max_storage_bytes: 123,
            quality: String::new(),
            active: false,
            created_at: parse(RFC3339_NANO, "2026-01-02T03:04:05.123456789Z").unwrap(),
            updated_at: parse(RFC3339_NANO, "2026-01-02T03:04:06Z").unwrap(),
        };
        let expected = r#"{"ID":"\u003c\u0026\u003e\u2028\u2029","UserID":7,"ProfileID":"p","DeviceID":"d","SeriesID":"s","Mode":"all","SeasonNumbers":null,"TargetSeason":null,"DeleteWatched":true,"MaxStorageBytes":123,"Quality":"","Active":false,"CreatedAt":"2026-01-02T03:04:05.123456789Z","UpdatedAt":"2026-01-02T03:04:06Z"}"#;
        assert_eq!(marshal(&sub).unwrap(), expected.as_bytes());
        assert_eq!(
            sub.etag().unwrap(),
            format!("\"{:x}\"", Sha256::digest(expected.as_bytes()))
        );
        sub.season_numbers = Some(vec![1, 3]);
        sub.target_season = Some(3);
        let expected = expected
            .replace("\"SeasonNumbers\":null", "\"SeasonNumbers\":[1,3]")
            .replace("\"TargetSeason\":null", "\"TargetSeason\":3");
        assert_eq!(marshal(&sub).unwrap(), expected.as_bytes());
    }
}
