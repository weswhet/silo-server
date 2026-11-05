//! Native admin playback observations, ported from `handlers/playback_sessions.go`.
use super::super::chain::{Stack, write_problem, write_v2_json};
use serde::Serialize;
use silo_api_v2::cursor::CursorScope;
use silo_api_v2::problem::{Problem, internal_error, validation_failed};
use silo_api_v2::wire::{Instant, paginated};
use silo_gate::mw::auth::{get_claims, get_profile_id};
use silo_gocompat::strings::{equal_fold, fields, to_lower, to_upper, trim_space};
use silo_http::{Request, ResponseWriter};
use silo_pg::{AnyInt, Pool, Row, ToSql};
use std::collections::HashMap;
use std::time::SystemTime;

#[derive(Serialize)]
struct AdminPlaybackSession {
    session_id: String,
    user_id: String,
    username: String,
    profile_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    profile_name: String,
    media_file_id: String,
    requested_media_file_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    content_id: String,
    media_title: String,
    media_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    episode_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    season_number: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    episode_number: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    poster_url: String,
    play_method: String,
    reporting_node: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    node_display_name: String,
    file_duration: Option<i64>,
    started_at: Instant,
    updated_at: Instant,
    position_seconds: f64,
    is_paused: bool,
    has_playback_control: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_ip: String,
    stream_location: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_build: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_channel: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_label_full: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    client_user_agent: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    device_platform: String,
    audio_track_index: i64,
    transcode_audio: bool,
    stream_bitrate_kbps: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    target_resolution: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    target_video_codec: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    target_audio_codec: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_audio_channels: Option<i64>,
    target_bitrate_kbps: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    transcode_hw_accel: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    tone_map_mode: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    output_container: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    output_protocol: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source_container: String,
    source_bitrate_kbps: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    source_video_codec: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source_video_resolution: String,
    #[serde(skip_serializing_if = "is_zero")]
    source_video_height: i64,
    #[serde(skip_serializing_if = "String::is_empty")]
    source_audio_codec: String,
    source_audio_channels: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    source_audio_language: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source_audio_title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    source_audio_layout: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    requested_video_codec: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    requested_video_resolution: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    video_decision: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    audio_decision: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    effective_play_method: String,
    #[serde(skip_serializing_if = "is_false")]
    is_jellyfin_client: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    routing_network_provider: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    routing_workload: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    routing_execution: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    routing_execution_node_id: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    routing_execution_node_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    routing_egress: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    routing_egress_node_id: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    routing_egress_node_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle_seq: Option<i64>,
}
fn is_false(v: &bool) -> bool {
    !*v
}
fn is_zero(v: &i64) -> bool {
    *v == 0
}

const LIFECYCLE_ONLY_SESSIONS: &str = r#"
	SELECT (jsonb_populate_record(NULL::playback_sessions_sync, lc.start_facts || jsonb_build_object(
		'reporting_node', '',
		'updated_at', a.updated_at,
		'last_sync_at', a.updated_at,
		'is_paused', lc.state = 'paused',
		'position_seconds', COALESCE((a.last_sample->>'position')::double precision, (lc.start_facts->>'position_seconds')::double precision, 0)))).*
	FROM playback_session_lifecycle lc
	JOIN playback_v3_attempts a ON a.session_id = lc.session_id AND a.stopped_at IS NULL AND a.expires_at > NOW()
	WHERE lc.state <> 'stopped' AND lc.start_facts <> '{}'::jsonb
	  AND NOT EXISTS (SELECT 1 FROM playback_sessions_sync live WHERE live.session_id = lc.session_id::text)"#;

fn session_sql(user_id: i64, summary: bool) -> String {
    let total_column = if summary { "count(*) OVER ()" } else { "0" };
    let paused_column = "CASE WHEN lc.state IN ('playing', 'paused') THEN lc.state = 'paused' ELSE COALESCE(s.is_paused, FALSE) END";
    let source =
        format!("(SELECT * FROM playback_sessions_sync UNION ALL {LIFECYCLE_ONLY_SESSIONS})");
    let lifecycle_columns = "lc.seq";
    let lifecycle_join =
        " LEFT JOIN playback_session_lifecycle lc ON lc.session_id::text = s.session_id";
    let mut sql = [r#"
		SELECT "#,total_column,r#",
			s.session_id,
			s.user_id,
			COALESCE(u.username, ''),
			COALESCE(s.profile_id, ''),
			s.media_file_id,
			COALESCE(s.requested_media_file_id, s.media_file_id, 0),
			COALESCE(mf.episode_id, mf.content_id, ''),
			COALESCE(mi.title, ''),
			COALESCE(mi.type, ''),
			COALESCE(series_mi.title, ''),
			COALESCE(e.title, ''),
			e.season_number,
			e.episode_number,
			COALESCE(CASE WHEN e.series_id IS NOT NULL THEN series_mi.poster_path ELSE mi.poster_path END, ''),
			s.play_method,
			s.reporting_node,
			COALESCE(remote_node.name, ''),
			mf.duration,
			s.started_at,
			s.updated_at,
			COALESCE(s.position_seconds, 0),
			"#,paused_column,r#",
			COALESCE(s.has_websocket, FALSE),
			COALESCE(HOST(s.client_ip), ''),
			COALESCE(s.client_name, ''),
			COALESCE(s.client_version, ''),
			COALESCE(s.client_build, ''),
			COALESCE(s.client_channel, ''),
			COALESCE(s.client_user_agent, ''),
			COALESCE(s.audio_track_index, 0),
			COALESCE(s.transcode_audio, FALSE),
			s.stream_bitrate_kbps,
			COALESCE(s.transcode_node_url, ''),
			COALESCE(s.target_resolution, ''),
			COALESCE(s.target_video_codec, ''),
			COALESCE(s.target_audio_codec, ''),
			s.target_audio_channels,
			s.target_bitrate_kbps,
			COALESCE(s.transcode_hw_accel, ''),
			COALESCE(s.tone_map_mode, ''),
			COALESCE(mf.container, ''),
			mf.bitrate,
			COALESCE(mf.codec_video, ''),
			COALESCE(mf.resolution, ''),
			CASE WHEN mf.video_tracks->0->>'height' ~ '^[0-9]{1,5}$' THEN (mf.video_tracks->0->>'height')::int ELSE 0 END,
			COALESCE(mf.codec_audio, ''),
			mf.audio_channels,
			COALESCE(mf.audio_tracks::text, '[]'),
			COALESCE(requested_mf.codec_video, ''),
			COALESCE(requested_mf.resolution, ''),
			COALESCE(s.compat_origin, FALSE),
			COALESCE(s.routing_workload, ''),
			COALESCE(s.routing_execution, ''),
			s.routing_execution_node_id,
			COALESCE(execution_node.name, ''),
			COALESCE(s.routing_egress, ''),
			s.routing_egress_node_id,
			COALESCE(egress_node.name, ''),
			s.routing_network_provider,
			COALESCE(s.output_container, ''),
			COALESCE(s.output_protocol, ''),
			COALESCE(s.stream_location, ''),
			COALESCE(s.device_id, ''),
			COALESCE(s.device_platform, ''),
			"#,lifecycle_columns,r#"
		 FROM "#,&source,r#" s
		 LEFT JOIN users u ON u.id = s.user_id
		 LEFT JOIN media_files mf ON mf.id = s.media_file_id
		 LEFT JOIN media_files requested_mf ON requested_mf.id = COALESCE(s.requested_media_file_id, s.media_file_id)
		 LEFT JOIN media_items mi ON mi.content_id = mf.content_id
		 LEFT JOIN episodes e ON e.content_id = mf.episode_id
		 LEFT JOIN media_items series_mi ON series_mi.content_id = e.series_id
		 LEFT JOIN stream_nodes remote_node ON remote_node.url = s.transcode_node_url
		 LEFT JOIN stream_nodes execution_node ON execution_node.id = s.routing_execution_node_id
		 LEFT JOIN stream_nodes egress_node ON egress_node.id = s.routing_egress_node_id"#,lifecycle_join].concat();
    let mut predicates = Vec::new();
    let mut count = 0;
    if user_id > 0 {
        count += 1;
        predicates.push(format!("s.user_id = ${count}"));
    }
    predicates.push("lc.state IS DISTINCT FROM 'stopped'".into());
    if !summary {
        count += 1;
        predicates.push(format!("s.session_id > ${count}"));
    }
    sql.push_str(" WHERE ");
    sql.push_str(&predicates.join(" AND "));
    sql.push_str(if summary {
        " ORDER BY s.started_at DESC, s.session_id ASC"
    } else {
        " ORDER BY s.session_id ASC"
    });
    count += 1;
    sql.push_str(&format!(" LIMIT ${count}"));
    sql
}

fn integer(row: &Row, index: usize) -> Result<i64, silo_pg::DriverError> {
    Ok(row.try_get::<_, AnyInt>(index)?.0)
}
fn optional_integer(row: &Row, index: usize) -> Result<Option<i64>, silo_pg::DriverError> {
    Ok(row.try_get::<_, Option<AnyInt>>(index)?.map(|n| n.0))
}
fn instant(row: &Row, index: usize) -> Result<Instant, silo_pg::DriverError> {
    Ok(Instant::new(row.try_get::<_, SystemTime>(index)?.into()))
}
fn scan(row: &Row) -> Result<AdminPlaybackSession, silo_pg::DriverError> {
    Ok(AdminPlaybackSession {
        session_id: row.try_get(1)?,
        user_id: integer(row, 2)?.to_string(),
        username: row.try_get(3)?,
        profile_id: row.try_get(4)?,
        profile_name: Default::default(),
        media_file_id: integer(row, 5)?.to_string(),
        requested_media_file_id: integer(row, 6)?.to_string(),
        content_id: row.try_get(7)?,
        media_title: row.try_get(8)?,
        media_type: row.try_get(9)?,
        series_name: row.try_get(10)?,
        episode_name: row.try_get(11)?,
        season_number: optional_integer(row, 12)?,
        episode_number: optional_integer(row, 13)?,
        poster_url: Default::default(),
        play_method: row.try_get(15)?,
        reporting_node: row.try_get(16)?,
        node_display_name: row.try_get(17)?,
        file_duration: optional_integer(row, 18)?,
        started_at: instant(row, 19)?,
        updated_at: instant(row, 20)?,
        position_seconds: row.try_get(21)?,
        is_paused: row.try_get(22)?,
        has_playback_control: row.try_get(23)?,
        client_ip: row.try_get(24)?,
        stream_location: row.try_get(62)?,
        client_name: row.try_get(25)?,
        client_version: row.try_get(26)?,
        client_build: row.try_get(27)?,
        client_channel: row.try_get(28)?,
        client_label: Default::default(),
        client_label_full: Default::default(),
        client_user_agent: row.try_get(29)?,
        device_id: row.try_get(63)?,
        device_platform: row.try_get(64)?,
        audio_track_index: integer(row, 30)?,
        transcode_audio: row.try_get(31)?,
        stream_bitrate_kbps: optional_integer(row, 32)?,
        target_resolution: row.try_get(34)?,
        target_video_codec: row.try_get(35)?,
        target_audio_codec: row.try_get(36)?,
        target_audio_channels: optional_integer(row, 37)?,
        target_bitrate_kbps: optional_integer(row, 38)?,
        transcode_hw_accel: row.try_get(39)?,
        tone_map_mode: row.try_get(40)?,
        output_container: row.try_get(60)?,
        output_protocol: row.try_get(61)?,
        source_container: row.try_get(41)?,
        source_bitrate_kbps: optional_integer(row, 42)?,
        source_video_codec: row.try_get(43)?,
        source_video_resolution: row.try_get(44)?,
        source_video_height: integer(row, 45)?,
        source_audio_codec: row.try_get(46)?,
        source_audio_channels: optional_integer(row, 47)?,
        source_audio_language: Default::default(),
        source_audio_title: Default::default(),
        source_audio_layout: Default::default(),
        requested_video_codec: row.try_get(49)?,
        requested_video_resolution: row.try_get(50)?,
        video_decision: Default::default(),
        audio_decision: Default::default(),
        effective_play_method: Default::default(),
        is_jellyfin_client: Default::default(),
        routing_network_provider: row.try_get(59)?,
        routing_workload: row.try_get(52)?,
        routing_execution: row.try_get(53)?,
        routing_execution_node_id: optional_integer(row, 54)?.map(|v| v.to_string()),
        routing_execution_node_name: row.try_get(55)?,
        routing_egress: row.try_get(56)?,
        routing_egress_node_id: optional_integer(row, 57)?.map(|v| v.to_string()),
        routing_egress_node_name: row.try_get(58)?,
        lifecycle_seq: optional_integer(row, 65)?,
    })
}
const POSTER_COLUMN: usize = 14;
const AUDIO_TRACKS_COLUMN: usize = 48;
const TRANSCODE_NODE_COLUMN: usize = 33;
const COMPAT_ORIGIN_COLUMN: usize = 51;

fn query(r: &Request, name: &str) -> String {
    let (q, _) = silo_gocompat::url::parse_query(&String::from_utf8_lossy(&r.url.raw_query));
    q.get(name)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}
fn internal_problem() -> Problem {
    Problem::new(internal_error(), "An unexpected error occurred.")
}
fn account_filter(r: &Request) -> Option<i64> {
    let value = query(r, "user_id");
    if value.is_empty() {
        Some(0)
    } else {
        value.parse().ok().filter(|v| *v > 0)
    }
}
pub(super) async fn list(stack: &Stack, w: &mut dyn ResponseWriter, r: &Request) {
    let Some(user_id) = account_filter(r) else {
        return write_problem(
            w,
            r,
            Problem::new(validation_failed(), "Invalid playback account filter."),
        )
        .await;
    };
    let Some(claims) = get_claims(r) else {
        return;
    };
    let limit = query(r, "limit").parse::<i64>().unwrap_or(50);
    let scope = CursorScope {
        operation_id: "listAdminPlaybackSessions".into(),
        security: format!("{}/{}", claims.user_id, get_profile_id(r)),
        filter: if user_id > 0 {
            format!("{limit}/{user_id}")
        } else {
            limit.to_string()
        },
        sort: "session_id".into(),
        tiebreaker: "session_id".into(),
    };
    let cursor = query(r, "cursor");
    let after: String = if cursor.is_empty() {
        String::new()
    } else {
        match stack.cursors.decode(&scope, &cursor) {
            Ok(value) => value,
            Err(p) => return write_problem(w, r, p).await,
        }
    };
    let (mut items, _) = match load(stack, user_id, &after, limit, false).await {
        Ok(value) => value,
        Err(_) => return write_problem(w, r, internal_problem()).await,
    };
    let mut next = String::new();
    if items.len() > limit as usize {
        items.truncate(limit as usize);
        match stack.cursors.encode(
            &scope,
            &items.last().expect("validated positive limit").session_id,
        ) {
            Ok(value) => next = value,
            Err(p) => return write_problem(w, r, p).await,
        }
    }
    write_v2_json(w, &paginated(items, next)).await;
}
#[derive(Serialize)]
struct SummaryItem {
    user_id: String,
    media_title: String,
    media_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    series_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    episode_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    season_number: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    episode_number: Option<i64>,
    is_paused: bool,
}
#[derive(Serialize)]
struct Summary {
    count: i64,
    items: Vec<SummaryItem>,
}
pub(super) async fn summary(stack: &Stack, w: &mut dyn ResponseWriter, r: &Request) {
    let Some(user_id) = account_filter(r) else {
        return write_problem(
            w,
            r,
            Problem::new(validation_failed(), "Invalid playback account filter."),
        )
        .await;
    };
    let limit = query(r, "limit").parse::<i64>().unwrap_or(20);
    let (rows, count) = match load(stack, user_id, "", limit, true).await {
        Ok(value) => value,
        Err(_) => return write_problem(w, r, internal_problem()).await,
    };
    let items = rows
        .into_iter()
        .map(|row| SummaryItem {
            user_id: row.user_id,
            media_title: row.media_title,
            media_type: row.media_type,
            series_name: row.series_name,
            episode_name: row.episode_name,
            season_number: row.season_number,
            episode_number: row.episode_number,
            is_paused: row.is_paused,
        })
        .collect();
    write_v2_json(w, &Summary { count, items }).await;
}
async fn load(
    stack: &Stack,
    user_id: i64,
    after: &str,
    limit: i64,
    summary: bool,
) -> Result<(Vec<AdminPlaybackSession>, i64), String> {
    let sql = session_sql(user_id, summary);
    // Go ints bind to the source's integer columns and Postgres's int8 LIMIT parameter.
    let account = AnyInt(user_id);
    let take = AnyInt(if summary { limit } else { limit + 1 });
    let mut args: Vec<&(dyn ToSql + Sync)> = Vec::new();
    if user_id > 0 {
        args.push(&account);
    }
    if !summary {
        args.push(&after);
    }
    args.push(&take);
    let rows = stack
        .pool
        .query(&sql, &args)
        .await
        .map_err(|e| e.to_string())?;
    let mut items = Vec::with_capacity(rows.len());
    let mut total = 0;
    for row in rows {
        total = integer(&row, 0).map_err(|e| e.to_string())?;
        let mut item = scan(&row).map_err(|e| e.to_string())?;
        if !summary {
            item.poster_url = poster_url(
                stack,
                row.try_get(POSTER_COLUMN).map_err(|e| e.to_string())?,
            )
            .await;
        }
        let audio_tracks: &str = row
            .try_get(AUDIO_TRACKS_COLUMN)
            .map_err(|e| e.to_string())?;
        let node_url: &str = row
            .try_get(TRANSCODE_NODE_COLUMN)
            .map_err(|e| e.to_string())?;
        let compat_origin: bool = row
            .try_get(COMPAT_ORIGIN_COLUMN)
            .map_err(|e| e.to_string())?;
        enrich(&mut item, audio_tracks, node_url, compat_origin);
        items.push(item);
    }
    if !summary {
        populate_profile_names(&stack.pool, &mut items).await;
    }
    Ok((items, total))
}
async fn populate_profile_names(pool: &Pool, sessions: &mut [AdminPlaybackSession]) {
    let mut by_user = HashMap::<String, HashMap<String, String>>::new();
    for session in sessions.iter() {
        if trim_space(&session.profile_id).is_empty() || by_user.contains_key(&session.user_id) {
            continue;
        }
        let user_id = session
            .user_id
            .parse::<i64>()
            .expect("database numeric user ID");
        let Ok(profiles) = silo_store::userstore::profiles::list_profiles_full(pool, user_id).await
        else {
            continue;
        };
        let names = profiles
            .into_iter()
            .filter_map(|p| {
                let name = trim_space(&p.name);
                (!name.is_empty()).then(|| (p.id, name.to_owned()))
            })
            .collect();
        by_user.insert(session.user_id.clone(), names);
    }
    for session in sessions {
        session.profile_name = by_user
            .get(&session.user_id)
            .and_then(|names| names.get(&session.profile_id))
            .cloned()
            .unwrap_or_default();
    }
}
#[derive(Default)]
struct AudioTrack {
    title: String,
    embedded_title: String,
    language: String,
    codec: String,
    layout: String,
    channels: i64,
    default: bool,
}
// PostgreSQL jsonb emits object keys by byte length, then byte order. Preserve that
// order when case-insensitive fields repeat: Go keeps the last valid non-null value,
// and continues decoding the other fields after a type error.
fn audio_tracks(json: &str) -> Vec<AudioTrack> {
    use silo_gocompat::json::{RawMessage, unmarshal};
    fn assign<T: serde::de::DeserializeOwned>(slot: &mut T, raw: &RawMessage) {
        if let Some(bytes) = raw.as_bytes()
            && let Ok(Some(value)) = unmarshal::<Option<T>>(bytes)
        {
            *slot = value;
        }
    }
    let raw: Vec<RawMessage> = unmarshal(json.as_bytes()).unwrap_or_default();
    raw.iter()
        .map(|raw| {
            let mut track = AudioTrack::default();
            let object: HashMap<String, RawMessage> = raw
                .as_bytes()
                .and_then(|bytes| unmarshal(bytes).ok())
                .unwrap_or_default();
            let mut fields: Vec<_> = object.into_iter().collect();
            fields.sort_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then_with(|| a.cmp(b)));
            for (name, value) in fields {
                if equal_fold(&name, "title") {
                    assign(&mut track.title, &value);
                } else if equal_fold(&name, "embedded_title") {
                    assign(&mut track.embedded_title, &value);
                } else if equal_fold(&name, "language") {
                    assign(&mut track.language, &value);
                } else if equal_fold(&name, "codec") {
                    assign(&mut track.codec, &value);
                } else if equal_fold(&name, "layout") {
                    assign(&mut track.layout, &value);
                } else if equal_fold(&name, "channels") {
                    assign(&mut track.channels, &value);
                } else if equal_fold(&name, "default") {
                    assign(&mut track.default, &value);
                }
            }
            track
        })
        .collect()
}
fn component_decisions(
    method: &str,
    audio: bool,
    video_codec: &str,
) -> (&'static str, &'static str) {
    match trim_space(method) {
        "direct" => ("direct", "direct"),
        "remux" => ("remux", if audio { "transcode" } else { "remux" }),
        "transcode" => (
            if equal_fold(trim_space(video_codec), "copy") {
                "remux"
            } else {
                "transcode"
            },
            if audio { "transcode" } else { "remux" },
        ),
        _ => ("", ""),
    }
}
fn effective_play_method(video: &str, audio: &str) -> &'static str {
    match (video, audio) {
        ("", "") => "",
        ("transcode", _) => "transcode",
        (_, "transcode") => "direct_stream",
        ("direct", "direct") => "direct",
        _ => "remux",
    }
}
fn enrich(row: &mut AdminPlaybackSession, audio_json: &str, node_url: &str, compat_origin: bool) {
    row.client_label = client_display_name(
        &row.client_name,
        &row.client_version,
        &row.client_user_agent,
    );
    let full = client_full_display_name(
        &row.client_name,
        &row.client_version,
        &row.client_build,
        &row.client_channel,
        &row.client_user_agent,
    );
    if full != row.client_label {
        row.client_label_full = full;
    }
    let (video, audio) = component_decisions(
        &row.play_method,
        row.transcode_audio,
        &row.target_video_codec,
    );
    row.video_decision = video.into();
    row.audio_decision = audio.into();
    row.effective_play_method = effective_play_method(video, audio).into();
    if row.play_method == "direct" {
        row.output_container = row.source_container.clone();
        row.output_protocol = "http".into();
    }
    row.is_jellyfin_client =
        compat_origin || is_jellyfin_client(&row.client_name, &row.client_user_agent);
    let tracks = audio_tracks(audio_json);
    let track = usize::try_from(row.audio_track_index)
        .ok()
        .and_then(|index| tracks.get(index))
        .or_else(|| tracks.iter().find(|t| t.default))
        .or_else(|| tracks.first());
    if let Some(track) = track {
        if !trim_space(&track.codec).is_empty() {
            row.source_audio_codec = trim_space(&track.codec).into();
        }
        if track.channels > 0 {
            row.source_audio_channels = Some(track.channels);
        }
        row.source_audio_language = trim_space(&track.language).into();
        row.source_audio_title = if !trim_space(&track.title).is_empty() {
            trim_space(&track.title)
        } else {
            trim_space(&track.embedded_title)
        }
        .into();
        row.source_audio_layout = trim_space(&track.layout).into();
    }
    if row.stream_bitrate_kbps.is_none() {
        row.stream_bitrate_kbps = row.target_bitrate_kbps.or(row.source_bitrate_kbps);
    }
    if audio == "transcode" && trim_space(&row.target_audio_codec).is_empty() {
        row.target_audio_codec = "aac".into();
    }
    if video == "transcode" && trim_space(&row.target_video_codec).is_empty() {
        row.target_video_codec = "h264".into();
    }
    if video == "transcode" && trim_space(&row.target_resolution).is_empty() {
        row.target_resolution = row.source_video_resolution.clone();
    }
    if trim_space(&row.node_display_name).is_empty() {
        row.node_display_name = if trim_space(node_url).is_empty() {
            "Local server"
        } else {
            "Remote transcode"
        }
        .into();
    }
    if row.stream_location != "local" && row.stream_location != "remote" {
        row.stream_location = stream_location(
            &row.client_ip,
            row.routing_network_provider.as_deref().unwrap_or(""),
        )
        .into();
    }
}
fn stream_location(ip: &str, provider: &str) -> &'static str {
    if !provider.is_empty() {
        return "remote";
    }
    let Ok(ip) = ip.parse::<std::net::IpAddr>() else {
        return "remote";
    };
    let ip = match ip {
        std::net::IpAddr::V6(v6) => v6.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip),
        _ => ip,
    };
    let local = match ip {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        std::net::IpAddr::V6(ip) => {
            ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local()
        }
    };
    if local { "local" } else { "remote" }
}
fn is_jellyfin_client(name: &str, agent: &str) -> bool {
    const TOKENS: &[&str] = &[
        "jellyfin",
        "findroid",
        "streamyfin",
        "swiftfin",
        "jellycon",
        "wholphin",
        "fladder",
        "vidhub",
        "senplayer",
        "infuse",
        "delfin",
        "finamp",
        "kodi",
        "mpv",
    ];
    [name, agent].iter().any(|value| {
        let lower = to_lower(trim_space(value));
        TOKENS.iter().any(|token| lower.contains(token))
    })
}

fn client_full_display_name(
    name: &str,
    version: &str,
    build: &str,
    channel: &str,
    agent: &str,
) -> String {
    let mut label = client_display_name(name, version, agent);
    if label.is_empty() {
        return label;
    }
    let build = trim_space(build);
    let channel = trim_space(channel);
    let mut qualifiers = Vec::new();
    if !build.is_empty() {
        qualifiers.push(format!("build {build}"));
    }
    if !channel.is_empty() && !equal_fold(channel, "release") {
        qualifiers.push(channel.to_owned());
    }
    if !qualifiers.is_empty() {
        label.push_str(&format!(" ({})", qualifiers.join(", ")));
    }
    label
}
fn client_display_name(name: &str, version: &str, agent: &str) -> String {
    let name = trim_space(name);
    if !name.is_empty() {
        let version = trim_space(version);
        return if version.is_empty() {
            name.to_owned()
        } else {
            format!("{name} {version}")
        };
    }
    let agent = trim_space(agent);
    if agent.is_empty() {
        return String::new();
    }
    let rules: &[(&str, &[&str], &[&str])] = &[
        ("Infuse", &["infuse"], &["infuse-direct", "infuse"]),
        ("Findroid", &["findroid"], &["findroid"]),
        ("Streamyfin", &["streamyfin"], &["streamyfin"]),
        ("Swiftfin", &["swiftfin"], &["swiftfin"]),
        ("Jellyfin", &["jellyfin"], &["jellyfin"]),
        ("JellyCon", &["jellycon"], &["jellycon"]),
        ("Wholphin", &["wholphin"], &["wholphin"]),
        ("Fladder", &["fladder"], &["fladder"]),
        ("VidHub", &["vidhub"], &["vidhub"]),
        ("SenPlayer", &["senplayer"], &["senplayer"]),
        ("Kodi", &["kodi"], &["kodi"]),
        ("MPV", &["mpv"], &["mpv"]),
        ("Edge", &["edg/"], &["edg"]),
        ("Opera", &["opr/", "opera"], &["opr", "opera"]),
        ("Firefox", &["firefox/", "fxios/"], &["firefox", "fxios"]),
        ("Chrome", &["chrome/", "crios/"], &["chrome", "crios"]),
        ("Safari", &["safari/"], &["version"]),
    ];
    let lower = to_lower(agent);
    for (label, tokens, versions) in rules {
        if !tokens.iter().any(|token| lower.contains(token)) {
            continue;
        }
        let version = first_product_version(agent, versions);
        return if version.is_empty() {
            (*label).to_owned()
        } else {
            format!("{label} {version}")
        };
    }
    for (token, label) in [
        ("applecoremedia", "Apple player"),
        ("okhttp", "Android client"),
        ("dart/", "Flutter client"),
        ("go-http-client", "Go client"),
        ("curl/", "curl"),
        ("python-requests", "Python requests"),
    ] {
        if lower.contains(token) {
            return label.into();
        }
    }
    if let Some(label) = android_device_label(agent) {
        return label;
    }
    for field in fields(agent) {
        if let Some((name, _)) = field.split_once('/') {
            let name = name.trim_matches(['"', ';', '(', ')', ',']);
            if !name.is_empty() && !equal_fold(name, "Mozilla") {
                return name.into();
            }
        }
    }
    "Unknown client".into()
}
fn first_product_version(agent: &str, tokens: &[&str]) -> String {
    for field in fields(agent) {
        if let Some((name, version)) = field.split_once('/')
            && tokens
                .iter()
                .any(|token| to_lower(trim_space(name)) == to_lower(trim_space(token)))
        {
            return short_client_version(version);
        }
    }
    String::new()
}
fn short_client_version(version: &str) -> String {
    let version: String = trim_space(version)
        .trim_matches(['"', ';', ')', ','])
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let mut parts: Vec<&str> = version
        .split('.')
        .filter(|p| !p.is_empty())
        .take(2)
        .collect();
    if parts.len() == 2 && parts[1] == "0" {
        parts.pop();
    }
    parts.join(".")
}
fn android_device_label(agent: &str) -> Option<String> {
    let (prefix, _) = agent.split_once("Build/")?;
    let separator = prefix.rfind(';')?;
    if !prefix[..separator].split(';').any(|segment| {
        to_lower(trim_space(segment.trim_matches(['(', ')']))).starts_with("android ")
    }) {
        return None;
    }
    let model = trim_space(trim_space(&prefix[separator + 1..]).trim_matches(['(', ')', ';']));
    if model.is_empty() {
        return None;
    }
    let label = match to_upper(model).as_str() {
        "AFTKRT" => "Fire TV Stick 4K Max",
        "AFTMM" => "Fire TV Stick 4K",
        "AFTKM" => "Fire TV Stick 4K (2nd Gen)",
        "AFTKA" => "Fire TV Stick 4K Max (1st Gen)",
        "AFTSSS" => "Fire TV Stick (3rd Gen)",
        "AFTSS" => "Fire TV Stick Lite (1st Gen)",
        "AFTT" => "Fire TV Stick (2nd Gen)",
        "AFTB" => "Fire TV (1st Gen)",
        "AFTS" => "Fire TV (2nd Gen)",
        "AFTN" => "Fire TV (3rd Gen)",
        "AFTR" => "Fire TV Cube (2nd Gen)",
        "AFTA" => "Fire TV Cube (1st Gen)",
        "SHIELD ANDROID TV" => "NVIDIA Shield",
        _ => return Some(format!("Android · {model}")),
    };
    Some(label.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn observation() -> AdminPlaybackSession {
        AdminPlaybackSession {
            session_id: Default::default(),
            user_id: Default::default(),
            username: Default::default(),
            profile_id: Default::default(),
            profile_name: Default::default(),
            media_file_id: Default::default(),
            requested_media_file_id: Default::default(),
            content_id: Default::default(),
            media_title: Default::default(),
            media_type: Default::default(),
            series_name: Default::default(),
            episode_name: Default::default(),
            season_number: Default::default(),
            episode_number: Default::default(),
            poster_url: Default::default(),
            play_method: Default::default(),
            reporting_node: Default::default(),
            node_display_name: Default::default(),
            file_duration: Default::default(),
            started_at: Instant::new(time::OffsetDateTime::UNIX_EPOCH),
            updated_at: Instant::new(time::OffsetDateTime::UNIX_EPOCH),
            position_seconds: Default::default(),
            is_paused: Default::default(),
            has_playback_control: Default::default(),
            client_ip: Default::default(),
            stream_location: Default::default(),
            client_name: Default::default(),
            client_version: Default::default(),
            client_build: Default::default(),
            client_channel: Default::default(),
            client_label: Default::default(),
            client_label_full: Default::default(),
            client_user_agent: Default::default(),
            device_id: Default::default(),
            device_platform: Default::default(),
            audio_track_index: Default::default(),
            transcode_audio: Default::default(),
            stream_bitrate_kbps: Default::default(),
            target_resolution: Default::default(),
            target_video_codec: Default::default(),
            target_audio_codec: Default::default(),
            target_audio_channels: Default::default(),
            target_bitrate_kbps: Default::default(),
            transcode_hw_accel: Default::default(),
            tone_map_mode: Default::default(),
            output_container: Default::default(),
            output_protocol: Default::default(),
            source_container: Default::default(),
            source_bitrate_kbps: Default::default(),
            source_video_codec: Default::default(),
            source_video_resolution: Default::default(),
            source_video_height: Default::default(),
            source_audio_codec: Default::default(),
            source_audio_channels: Default::default(),
            source_audio_language: Default::default(),
            source_audio_title: Default::default(),
            source_audio_layout: Default::default(),
            requested_video_codec: Default::default(),
            requested_video_resolution: Default::default(),
            video_decision: Default::default(),
            audio_decision: Default::default(),
            effective_play_method: Default::default(),
            is_jellyfin_client: Default::default(),
            routing_network_provider: Default::default(),
            routing_workload: Default::default(),
            routing_execution: Default::default(),
            routing_execution_node_id: Default::default(),
            routing_execution_node_name: Default::default(),
            routing_egress: Default::default(),
            routing_egress_node_id: Default::default(),
            routing_egress_node_name: Default::default(),
            lifecycle_seq: Default::default(),
        }
    }
    #[test]
    fn native_method_tracks_components_instead_of_transport() {
        for (method, audio, codec, expected) in [
            ("direct", true, "copy", "direct"),
            ("remux", false, "", "remux"),
            ("remux", true, "", "direct_stream"),
            ("transcode", true, " COPY ", "direct_stream"),
            ("transcode", false, "copy", "remux"),
            ("transcode", false, "h264", "transcode"),
            ("unknown", true, "h264", ""),
        ] {
            let (video, audio) = component_decisions(method, audio, codec);
            assert_eq!(effective_play_method(video, audio), expected);
        }
    }
    #[test]
    fn client_labels_preserve_reported_versions_and_shorten_agent_versions() {
        assert_eq!(
            client_full_display_name(" Silo ", " 1.0.0 ", " 42 ", "beta", ""),
            "Silo 1.0.0 (build 42, beta)"
        );
        assert_eq!(
            client_full_display_name(
                "",
                "",
                "",
                "RELEASE",
                "Mozilla/5.0 Chrome/120.0.6099.1 Safari/537.36"
            ),
            "Chrome 120"
        );
        assert_eq!(
            client_display_name(
                "",
                "",
                "Dalvik/2.1.0 (Linux; U; Android 9; AFTKRT Build/PS7652)"
            ),
            "Fire TV Stick 4K Max"
        );
        assert_eq!(
            client_display_name("", "", "Mozilla/5.0 (Linux; Android 14; Pixel 7 Build/X)"),
            "Android · Pixel 7"
        );
        assert!(is_jellyfin_client("Infuse", ""));
        assert!(!is_jellyfin_client("Silo", "Mozilla/5.0 Chrome/120.0"));
    }
    #[test]
    fn selected_audio_and_fallbacks_match_observation_enrichment() {
        let mut row = observation();
        row.play_method = "transcode".into();
        row.transcode_audio = true;
        row.audio_track_index = 7;
        row.source_video_resolution = "2160p".into();
        row.source_bitrate_kbps = Some(2000);
        row.target_bitrate_kbps = Some(1000);
        row.client_ip = "::ffff:192.168.1.2".into();
        enrich(
            &mut row,
            r#"[{"codec":"mp3"},{"codec":" ac3 ","channels":6,"language":" eng ","embedded_title":" Director ","default":true}]"#,
            "node",
            false,
        );
        assert_eq!(row.source_audio_codec, "ac3");
        assert_eq!(row.source_audio_channels, Some(6));
        assert_eq!(row.source_audio_language, "eng");
        assert_eq!(row.source_audio_title, "Director");
        assert_eq!(row.target_video_codec, "h264");
        assert_eq!(row.target_audio_codec, "aac");
        assert_eq!(row.target_resolution, "2160p");
        assert_eq!(row.stream_bitrate_kbps, Some(1000));
        assert_eq!(row.node_display_name, "Remote transcode");
        assert_eq!(row.stream_location, "local");
        assert_eq!(stream_location("192.168.1.2", "vpn"), "remote");
        assert_eq!(stream_location("garbage", ""), "remote");
    }
    #[test]
    fn invalid_audio_fields_preserve_valid_values_and_track_positions() {
        let tracks = audio_tracks(
            r#"[false,{"CODEC":"ac3","codec":null,"title":123,"channels":6},{"codec":"aac","channels":"bad","default":true}]"#,
        );
        assert_eq!(tracks.len(), 3);
        assert!(tracks[0].codec.is_empty());
        assert_eq!(tracks[1].codec, "ac3");
        assert_eq!(tracks[1].channels, 6);
        assert!(tracks[1].title.is_empty());
        assert_eq!(tracks[2].codec, "aac");
        assert_eq!(tracks[2].channels, 0);
        assert!(tracks[2].default);
    }
    #[test]
    fn session_wire_preserves_order_nulls_and_omissions() {
        let mut row = observation();
        row.user_id = "3".into();
        row.media_file_id = "5".into();
        row.requested_media_file_id = "5".into();
        row.routing_network_provider = Some(String::new());
        let json = String::from_utf8(silo_gocompat::json::marshal(&row).unwrap()).unwrap();
        assert_eq!(
            json,
            r#"{"session_id":"","user_id":"3","username":"","profile_id":"","media_file_id":"5","requested_media_file_id":"5","media_title":"","media_type":"","play_method":"","reporting_node":"","file_duration":null,"started_at":"1970-01-01T00:00:00.000Z","updated_at":"1970-01-01T00:00:00.000Z","position_seconds":0,"is_paused":false,"has_playback_control":false,"stream_location":"","audio_track_index":0,"transcode_audio":false,"stream_bitrate_kbps":null,"target_bitrate_kbps":null,"source_bitrate_kbps":null,"source_audio_channels":null,"routing_network_provider":""}"#
        );
    }
}

/// `cardThumbnailPath`, `DetailService.PresignURL`, and local artwork resolution.
async fn poster_url(stack: &Stack, path: &str) -> String {
    if path.is_empty() || path == "-" {
        return String::new();
    }
    if path.starts_with("http://") || path.starts_with("https://") {
        return if !path.contains('\\') && silo_gocompat::url::parse(path).is_ok() {
            path.to_owned()
        } else {
            String::new()
        };
    }
    // Deployments with a plugin registry remain on Go, which owns resolver RPCs.
    if path.contains("://") {
        return String::new();
    }
    let key = path.replacen("/original.", "/w300.", 1);
    let key = published_poster_key(stack, &key).await;
    if key.is_empty() {
        return key;
    }
    signed_poster_url(
        &stack.artwork_secret,
        &key,
        stack.artwork_url_ttl,
        SystemTime::now(),
    )
}

fn artwork_variant(key: &str) -> &str {
    let name = silo_gocompat::path::base(trim_space(key));
    let stem = name
        .strip_suffix(silo_gocompat::path::ext(name))
        .unwrap_or(name);
    stem.split('.').next().unwrap_or_default()
}

fn artwork_revision(key: &str) -> &str {
    let name = silo_gocompat::path::base(trim_space(key));
    let stem = name
        .strip_suffix(silo_gocompat::path::ext(name))
        .unwrap_or(name);
    stem.split_once('.').map_or("", |(_, revision)| revision)
}

fn artwork_variant_key(key: &str, variant: &str) -> String {
    let dir = silo_gocompat::path::dir(trim_space(key));
    if dir == "." || dir == "/" || trim_space(key).is_empty() || key.contains("://") {
        return key.to_owned();
    }
    let revision = artwork_revision(key);
    let extension = silo_gocompat::path::ext(key);
    let extension = if extension.is_empty() {
        ".webp"
    } else {
        extension
    };
    if revision.is_empty() {
        format!("{}/{variant}{extension}", dir.trim_end_matches('/'))
    } else {
        format!(
            "{}/{variant}.{revision}{extension}",
            dir.trim_end_matches('/')
        )
    }
}

fn artwork_width(key: &str) -> Option<i64> {
    artwork_variant(key)
        .strip_prefix('w')?
        .parse::<i64>()
        .ok()
        .filter(|width| *width > 0)
}

/// `resolvePublishedLadderKeys`: established local variants need no manifest read.
async fn published_poster_key(stack: &Stack, key: &str) -> String {
    let Some((dir, _)) = key.rsplit_once('/') else {
        return key.to_owned();
    };
    let medium = match dir.rsplit('/').next().unwrap_or_default() {
        "poster" | "still" | "logo" => 500,
        "backdrop" => 1920,
        _ => return key.to_owned(),
    };
    let Some(width) = artwork_width(key).filter(|width| *width > medium) else {
        return key.to_owned();
    };
    let fallback = || artwork_variant_key(key, &format!("w{medium}"));
    let original = artwork_variant_key(key, "original");
    // The filesystem store retains this recorded identity across root aliases.
    let Ok(scope) = stack.settings.get("artwork.storage_identity").await else {
        return fallback();
    };
    let paths = vec![original.clone()];
    // `ArtworkDeliveryStore.ArtworkAvailability`, verbatim.
    let rows = stack.pool.query("SELECT original_path,
        CASE WHEN deleted_at IS NULL THEN published_keys ELSE '{}'::text[] END,
        CASE WHEN deleted_at IS NULL AND delivery_scope = $2 THEN delivery_keys ELSE '{}'::text[] END,
        delivery_scope = $2 AND delivery_checked_at IS NOT NULL
        FROM artwork_revision_gc_candidates
        WHERE original_path = ANY($1)
          AND (published_keys IS NOT NULL OR deleted_at IS NOT NULL
               OR (delivery_scope = $2 AND delivery_checked_at IS NOT NULL))", &[&paths, &scope]).await;
    let Ok(rows) = rows else { return fallback() };
    let Some(row) = rows.first() else {
        return fallback();
    };
    let verified = row
        .try_get::<_, Option<bool>>(3)
        .ok()
        .flatten()
        .unwrap_or(false);
    let Ok(keys) = row.try_get::<_, Option<Vec<String>>>(if verified { 2 } else { 1 }) else {
        return fallback();
    };
    let keys = keys.unwrap_or_default();
    let mut best = String::new();
    let mut best_width = 0;
    for published in &keys {
        if let Some(candidate_width) = artwork_width(published)
            && candidate_width <= width
            && candidate_width > best_width
            && artwork_variant_key(key, artwork_variant(published)) == *published
        {
            best.clone_from(published);
            best_width = candidate_width;
        }
    }
    if !best.is_empty() {
        best
    } else if keys.contains(&original) {
        original
    } else {
        String::new()
    }
}

/// `artworkurl.Signer.Sign`: default-lifetime revisioned images use daily windows.
fn signed_poster_url(secret: &str, key: &str, ttl: std::time::Duration, now: SystemTime) -> String {
    use base64::Engine as _;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let derive = |key: &[u8], message: &[u8]| {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key size");
        mac.update(message);
        mac.finalize().into_bytes()
    };
    let ttl = if ttl.is_zero() {
        std::time::Duration::from_secs(14_400)
    } else {
        ttl
    };
    let ttl = ttl.clamp(
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(86_400),
    );
    let bucket = if artwork_revision(key).is_empty() {
        ttl.min(std::time::Duration::from_secs(900))
    } else {
        std::time::Duration::from_secs(86_400)
    };
    let nanos = match now.duration_since(std::time::UNIX_EPOCH) {
        Ok(value) => value.as_nanos() as i128,
        Err(value) => -(value.duration().as_nanos() as i128),
    };
    let bucket_nanos = bucket.as_nanos() as i128;
    let exp = (nanos - (nanos + 62_135_596_800_000_000_000_i128).rem_euclid(bucket_nanos)
        + bucket_nanos
        + ttl.as_nanos() as i128)
        .div_euclid(1_000_000_000);
    let signing_key = derive(secret.as_bytes(), b"silo-artwork-url-v1");
    let signature = derive(&signing_key, format!("artwork-v1\n{key}\n{exp}").as_bytes());
    let sig = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature[..16]);
    let route = silo_gocompat::url::Url {
        path: format!("/api/v2/artwork/{}", key.strip_prefix('/').unwrap_or(key)),
        ..Default::default()
    };
    format!("{}?exp={exp}&sig={sig}", route.escaped_path())
}

#[cfg(test)]
mod poster_tests {
    use super::*;

    #[test]
    fn local_poster_signature_matches_go_and_preserves_escaping() {
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_789_560_000);
        assert_eq!(
            signed_poster_url(
                "test-secret",
                "tmdb/movies/550/poster/original.webp",
                std::time::Duration::from_secs(3600),
                now
            ),
            "/api/v2/artwork/tmdb/movies/550/poster/original.webp?exp=1789564500&sig=MWEDxdUKUUKZFZmGL_XsqA"
        );
        let key = "//uploads/a b;c?d#e.webp";
        let url = signed_poster_url("secret", key, std::time::Duration::from_secs(3600), now);
        assert!(url.starts_with("/api/v2/artwork//uploads/a%20b;c%3Fd%23e.webp?"));
    }

    #[test]
    fn revisioned_posters_hold_their_url_for_a_utc_day() {
        let now = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_789_560_000);
        let ttl = std::time::Duration::from_secs(14_400);
        let key = "tmdb/movie/1/poster/w300.0123abcd.webp";
        let first = signed_poster_url("secret", key, ttl, now);
        let later = signed_poster_url(
            "secret",
            key,
            ttl,
            now + std::time::Duration::from_secs(3600),
        );
        assert_eq!(first, later);
        assert_ne!(
            first,
            signed_poster_url(
                "secret",
                key,
                ttl,
                now + std::time::Duration::from_secs(86_400)
            )
        );
    }
}
