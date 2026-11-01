//! The Rust half of the format vectors: what each family computes, shared by the test that checks Go's
//! output and the example that writes Rust's output for Go to check.

#![allow(clippy::disallowed_methods)] // A test harness that writes its own JSON and never hits a format path.
#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use silo_core::apiv2::{self, CursorScope, ETagList, ViewerScope};
use silo_core::artworkurl::Signer;
use silo_core::contentid::{self, ProviderIds};
use silo_core::downloads::{self, ParamsHashParams, PrepareRequest};
use silo_core::goid::{NAMESPACE_OID, NAMESPACE_URL, Uuid};
use silo_core::jellycompat::{self, Kind};
use silo_core::models::{MarkerFile, MarkerSegment, SourceRevision};
use silo_core::playback::{self, AppliedQuirk, PlanIdentity, TrackIdentity, Transformation};
use silo_core::secret::{self, Cipher, aad};
use silo_core::tokens::{self, AbsClaims, AccessClaims, ProfileClaims, RoomClaims, ThemeGrant};
use silo_core::{
    apikey, artworkkey, digest, fspath, hexgo, idgen, jcs, lantls, nodeauth, oauth, passwordhash,
    streamtoken,
};
use silo_gocompat::json::{marshal, omit_empty};
use silo_gocompat::strings::decode_runes;
use silo_gocompat::time::GoTime;
use silo_jwt::gojson::{Field, pointer, value};
use silo_jwt::{Audience, NumericDate, Parser, RegisteredClaims, impl_claims};

pub fn vectors_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/vectors/core")
        .canonicalize()
        .expect("vectors directory")
}

pub fn repo_root() -> std::path::PathBuf {
    vectors_dir()
        .join("../../../..")
        .canonicalize()
        .expect("repository root")
}

/// A Go string in a vector.
pub fn bytes_of(v: &Value) -> Vec<u8> {
    match v {
        Value::String(s) => s.clone().into_bytes(),
        Value::Object(map) => hexgo::decode(map["hex"].as_str().expect("hex")).expect("hex digits"),
        Value::Null => Vec::new(),
        other => panic!("not a string: {other}"),
    }
}

pub fn gostr(bytes: impl AsRef<[u8]>) -> Value {
    let bytes = bytes.as_ref();
    match std::str::from_utf8(bytes) {
        Ok(s) => json!(s),
        Err(_) => json!({"hex": hexgo::encode(bytes)}),
    }
}

fn b(v: &Value, k: &str) -> Vec<u8> {
    bytes_of(&v[k])
}

/// A vector string the Rust API takes as `&str`. Go's input there is always valid UTF-8.
fn s(v: &Value, k: &str) -> String {
    String::from_utf8(bytes_of(&v[k])).expect("valid UTF-8 input")
}

fn text(v: &Value) -> String {
    String::from_utf8(bytes_of(v)).expect("valid UTF-8 input")
}

fn i(v: &Value, k: &str) -> i64 {
    v[k].as_i64()
        .unwrap_or_else(|| panic!("{k} is not an integer: {}", v[k]))
}

fn flag(v: &Value, k: &str) -> bool {
    v[k].as_bool().unwrap_or(false)
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|list| list.iter().map(text).collect())
        .unwrap_or_default()
}

fn opt_i(v: &Value, k: &str) -> Option<i64> {
    v[k].as_i64()
}

fn marshal_value<T: Serialize>(v: &T) -> Value {
    serde_json::from_slice(&marshal(v).expect("marshal")).expect("marshal output parses")
}

pub enum Kind2 {
    Det(fn(&Value) -> Value),
    Nondet {
        produce: fn(&Value) -> Value,
        check: fn(&Value, &Value) -> Result<(), String>,
    },
}

pub struct Family {
    pub name: &'static str,
    pub kind: Kind2,
    /// Input keys the mutator keeps, because a change would make the Go side panic or test nothing.
    pub frozen: &'static [&'static str],
}

const NOW_FIXED: i128 = 1_800_000_000_000_000_000;

fn cipher(master: &str) -> Cipher {
    Cipher::new(master.as_bytes()).expect("cipher")
}

fn token_out(token: String, decoded: Value) -> Value {
    json!({"token": token, "decoded": decoded})
}

// --- contentid, fspath, idgen ---

fn contentid_provider(v: &Value) -> Value {
    let ids = ProviderIds {
        tmdb: s(v, "Tmdb"),
        imdb: s(v, "Imdb"),
        tvdb: s(v, "Tvdb"),
    };
    let series = contentid::for_series(&ids);
    let series_text = series.clone().unwrap_or_default();
    json!({
        "Movie": contentid::for_movie(&ids),
        "Series": series,
        "Season": contentid::for_season(&series_text, i(v, "Season")),
        "Episode": contentid::for_episode(&series_text, i(v, "Season"), i(v, "Episode")),
        "SeriesAnchor": contentid::anchor_precedence(&ids.tmdb),
    })
}

fn contentid_local(v: &Value) -> Value {
    json!(contentid::for_local(&text(v)))
}

fn contentid_codec(v: &Value) -> Value {
    let id = text(v);
    let mut out = json!({
        "series": contentid::series_id_from_content_id(&id),
        "anchored": contentid::is_provider_anchored(&id),
        "anchor": contentid::provider_anchor(&id).map(|(p, a)| vec![p.to_owned(), a.to_owned()]),
        "local": contentid::is_local(&id),
        "packed": Value::Null,
        "unpacked": Value::Null,
        "unpacked_padded": Value::Null,
    });
    if let Some(packed) = contentid::pack(&id) {
        out["packed"] = json!(hexgo::encode(&packed));
        out["unpacked"] = json!(contentid::unpack(&packed));
        let mut padded = packed.clone();
        padded.extend_from_slice(&[0, 0, 0]);
        out["unpacked_padded"] = json!(contentid::unpack(&padded));
    }
    out
}

fn contentid_unpack(v: &Value) -> Value {
    json!(contentid::unpack(&bytes_of(v)))
}

fn fspath_family(v: &Value) -> Value {
    let raw = bytes_of(v);
    let enc = fspath::encode(&raw);
    json!({
        "encoded": gostr(&enc),
        "decoded": gostr(fspath::decode(&enc)),
        "display": gostr(fspath::display(&enc)),
        "is_encoded": fspath::is_encoded(&enc),
        "raw_decode": gostr(fspath::decode(&raw)),
        "raw_display": gostr(fspath::display(&raw)),
        "raw_is_encoded": fspath::is_encoded(&raw),
    })
}

fn sonyflake_compose(v: &Value) -> Value {
    let id = idgen::compose(
        i128::from(i(v, "unix_nanos")),
        i(v, "sequence"),
        i(v, "machine"),
    );
    match id {
        Err(e) => {
            let text = match e {
                idgen::Error::OverTimeLimit => "over the time limit",
                idgen::Error::StartTimeAhead => "start time is ahead",
                idgen::Error::InvalidSequence => "invalid sequence number",
                idgen::Error::InvalidMachineId => "invalid machine id",
                idgen::Error::LeaseExpired(_) => "lease",
            };
            json!({"id": null, "error": text, "parts": null, "to_unix_nanos": null})
        }
        Ok(id) => {
            let parts = idgen::decompose(id);
            json!({
                "id": id,
                "error": "",
                "parts": {"id": id, "time": parts.time, "sequence": parts.sequence, "machine": parts.machine},
                "to_unix_nanos": idgen::to_unix_nanos(id) as i64,
            })
        }
    }
}

fn sonyflake_produce(v: &Value) -> Value {
    let machine = v.as_u64().expect("machine") as u16;
    let generator = idgen::Generator::new(machine);
    let ids: Vec<String> = (0..600).map(|_| generator.next_id().expect("id")).collect();
    json!({"IDs": ids, "ids": ids})
}

fn sonyflake_check(v: &Value, out: &Value) -> Result<(), String> {
    let machine = v.as_i64().ok_or("machine")?;
    let mut last = 0i64;
    for text in out["ids"].as_array().ok_or("ids")? {
        let id: i64 = text
            .as_str()
            .ok_or("id")?
            .parse()
            .map_err(|e| format!("{e}"))?;
        if id <= last {
            return Err(format!("IDs do not increase: {id} after {last}"));
        }
        last = id;
        if idgen::decompose(id).machine != machine {
            return Err(format!("{id} has the wrong machine"));
        }
    }
    Ok(())
}

fn lantls_pin(v: &Value) -> Value {
    json!(lantls::pin(text(v).as_bytes()).expect("pin"))
}

// --- nodeauth ---

fn split_target(url: &str) -> (String, String) {
    let path = silo_core::gourl::parse_escaped_path(url).expect("request URL parses");
    let query = url
        .split_once('?')
        .map(|(_, q)| q.to_owned())
        .unwrap_or_default();
    (path, query)
}

fn nodeauth_sign(v: &Value) -> Value {
    let (path, query) = split_target(&s(v, "url"));
    let body = (!v["body"].is_null()).then(|| b(v, "body"));
    json!(
        nodeauth::sign(
            &s(v, "method"),
            &path,
            &query,
            body.as_deref(),
            &s(v, "node_url"),
            &s(v, "secret"),
            i(v, "now"),
        )
        .unwrap_or_default()
    )
}

fn nodeauth_verify(v: &Value) -> Value {
    let (path, query) = split_target(&s(v, "target"));
    let body = (!v["body"].is_null()).then(|| b(v, "body"));
    let outcome = nodeauth::verify_credential(
        &s(v, "authorization"),
        &s(v, "method"),
        &path,
        &query,
        &s(v, "secret"),
        i128::from(i(v, "now_nanos")),
    );
    json!(match outcome {
        Err(e) => e.to_string(),
        Ok(nodeauth::Verified::LegacyBearer) => "ok".to_owned(),
        Ok(nodeauth::Verified::Signed(signed)) => {
            if signed.body_matches(body.as_deref()) {
                "ok".to_owned()
            } else {
                nodeauth::Error::Unauthorized.to_string()
            }
        }
    })
}

// --- apiv2 ---

fn apiv2_etag(v: &Value) -> Value {
    json!(apiv2::render_etag(&b(v, "scope"), &b(v, "id"), i(v, "version")).to_wire())
}

fn apiv2_etag_list(v: &Value) -> Value {
    match apiv2::parse_etag_list(&bytes_of(v)) {
        Err(_) => json!({"star": false, "error": true, "tags": []}),
        Ok(ETagList::Star) => json!({"star": true, "error": false, "tags": []}),
        Ok(ETagList::Tags(tags)) => {
            let rendered: Vec<String> = tags
                .iter()
                .map(|(opaque, weak)| {
                    let opaque = decode_runes(opaque);
                    if *weak {
                        format!("W/\"{opaque}\"")
                    } else {
                        format!("\"{opaque}\"")
                    }
                })
                .collect();
            json!({"star": false, "error": false, "tags": rendered})
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(default)]
struct CursorPosition {
    key: String,
    #[serde(skip_serializing_if = "omit_empty")]
    sort: f64,
    id: i64,
    html: String,
}

fn scope_of(v: &Value) -> CursorScope {
    let list = strs(&v["scope"]);
    CursorScope {
        operation_id: list[0].clone(),
        security: list[1].clone(),
        filter: list[2].clone(),
        sort: list[3].clone(),
        tiebreaker: list[4].clone(),
    }
}

fn apiv2_cursor(v: &Value) -> Value {
    let pos = &v["pos"];
    let position = CursorPosition {
        key: s(pos, "key"),
        sort: pos["sort"].as_f64().unwrap_or(0.0),
        id: i(pos, "id"),
        html: s(pos, "html"),
    };
    json!(apiv2::encode_cursor(s(v, "secret").as_bytes(), &scope_of(v), &position).expect("cursor"))
}

fn apiv2_cursor_decode(v: &Value) -> Value {
    static FIELDS: [Field; 4] = [value("key"), value("sort"), value("id"), value("html")];
    let invalid = json!({"valid": false, "key": "", "id": 0, "sort": 0});
    let cursor = String::from_utf8_lossy(&b(v, "cursor")).into_owned();
    let Ok(raw) = apiv2::decode_cursor(s(v, "secret").as_bytes(), &scope_of(v), &cursor) else {
        return invalid;
    };
    let Ok(pos) = silo_jwt::gojson::unmarshal::<CursorPosition>(&raw, &FIELDS) else {
        return invalid;
    };
    json!({"valid": true, "key": pos.key, "id": pos.id, "sort": marshal_value(&pos.sort)})
}

fn ids(v: &Value) -> Option<Vec<i64>> {
    v.as_array()
        .map(|list| list.iter().map(|n| n.as_i64().expect("id")).collect())
}

fn apiv2_viewer(v: &Value) -> Value {
    if flag(v, "none") {
        return json!(apiv2::viewer_scope_digest(None));
    }
    let scope = ViewerScope {
        policy_revision: i(v, "policy_revision"),
        libraries_restricted: flag(v, "libraries_restricted"),
        allowed_library_ids: ids(&v["allowed"]),
        disabled_library_ids: ids(&v["disabled"]),
        max_content_rating: s(v, "max_content_rating"),
        allow_unrated_content: flag(v, "allow_unrated"),
        max_advisory_age: i(v, "max_advisory_age"),
        require_advisory_age: flag(v, "require_advisory_age"),
    };
    json!(apiv2::viewer_scope_digest(Some(&scope)))
}

fn artworkurl(v: &Value) -> Value {
    let signer = if flag(v, "job") {
        Signer::new_job_artifact(&s(v, "secret"), i(v, "ttl_nanos"))
    } else {
        Signer::new(&s(v, "secret"), i(v, "ttl_nanos"))
    };
    let key = s(v, "key");
    let now = i128::from(i(v, "now_nanos"));
    let (url, expires) = signer.sign_for(&key, now, i(v, "sign_ttl_nanos"));
    let sig = url.rsplit("sig=").next().unwrap_or_default();
    let exp = expires.div_euclid(1_000_000_000) as i64;
    let verified = signer
        .verify(&key, exp, sig, now.div_euclid(1_000_000_000) as i64)
        .is_ok();
    json!({"url": url, "expires_nanos": expires as i64, "verified": verified})
}

fn artworkkey_family(v: &Value) -> Value {
    let (a, b_, c, d, p) = (s(v, "A"), s(v, "B"), s(v, "C"), s(v, "D"), s(v, "Path"));
    const TYPES: [&str; 11] = [
        "poster", "BACKDROP", " still ", "logo", "profile", "banner", "thumb", "clearart", "disc",
        "unknown", "",
    ];
    let image_type = TYPES[(p.len() + a.len()) % TYPES.len()];
    let keys = artworkkey::object_keys(&p, image_type);
    let keys_value = if p.is_empty() || p.contains("://") {
        Value::Null
    } else {
        json!(keys)
    };
    json!({
        "Build": artworkkey::build(&a, &b_, &c, &d),
        "Original": artworkkey::original(&a, &c, &d),
        "Variant": artworkkey::variant(&p, &b_),
        "Directory": artworkkey::directory(&p),
        "Revision": artworkkey::revision(&p),
        "OriginalOf": artworkkey::original_of(&p),
        "ImageTypeOf": artworkkey::image_type_of(&p, "fallback"),
        "Local": artworkkey::is_local(&p),
        "Widths": artworkkey::variant_widths(image_type),
        "Names": artworkkey::variant_names(image_type),
        "Keys": keys_value,
        "Ladder": artworkkey::LADDER_VERSION,
    })
}

fn jellycompat_ids(v: &Value) -> Value {
    let kind = Kind::from_u8(i(v, "kind") as u8).expect("kind");
    let value_text = s(v, "value");
    let encoded = jellycompat::encode_string_id(kind, &value_text);
    let encoded_text = encoded.id.to_string();
    let decode = jellycompat::decode_string_id(kind, &encoded_text, |raw| {
        (encoded.needs_reverse_map && raw == encoded_text).then(|| (kind, value_text.clone()))
    });
    json!({
        "encoded": encoded_text,
        "decode": decode,
        "pseudo": jellycompat::pseudo_user_id(i(v, "user"), &s(v, "profile")).to_string(),
        "numeric": jellycompat::encode_numeric_id(kind, v["number"].as_u64().expect("number")).to_string(),
        "packed": jellycompat::pack_content_id_uuid(kind, &value_text).map(|u| u.to_string()),
        "unpacked": jellycompat::unpack_content_id_uuid(kind, &encoded_text),
        "decode_id": jellycompat::decode_id(&encoded_text).map(|(t, n)| format!("{t}:{n}")),
    })
}

fn uuid_parse(v: &Value) -> Value {
    json!(jellycompat::decode_id(&s(v, "raw")).map(|(t, n)| format!("{t}:{n}")))
}

fn oshash(v: &Value) -> Value {
    let seed = v["seed"].as_u64().expect("seed");
    let size = i(v, "size");
    let mut state = seed;
    let mut bytes = Vec::with_capacity(size as usize + 8);
    while (bytes.len() as i64) < size {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        bytes.extend_from_slice(&state.to_le_bytes());
    }
    bytes.truncate(size as usize);
    let head: &[u8; 65536] = bytes[..65536].try_into().expect("head");
    let tail: &[u8; 65536] = bytes[size as usize - 65536..].try_into().expect("tail");
    json!(digest::oshash(head, tail, size))
}

// --- secret ---

fn enc_produce(v: &Value) -> Value {
    json!(gostr(
        cipher(&s(v, "master"))
            .encrypt(b(v, "plaintext"), b(v, "aad"))
            .expect("encrypt")
    ))
}

fn enc_check(v: &Value, out: &Value) -> Result<(), String> {
    let c = cipher(&s(v, "master"));
    let plaintext = b(v, "plaintext");
    let ct = bytes_of(out);
    if plaintext.is_empty() {
        return if ct.is_empty() {
            Ok(())
        } else {
            Err("empty plaintext was wrapped".to_owned())
        };
    }
    let plain = c.decrypt(&ct, b(v, "aad")).map_err(|e| e.to_string())?;
    if plain != plaintext {
        return Err("plaintext differs".to_owned());
    }
    if !secret::is_encrypted(&ct) {
        return Err("not recognized as encrypted".to_owned());
    }
    if c.decrypt(&ct, b(v, "wrong_aad")).is_ok() {
        return Err("a different AAD decrypted".to_owned());
    }
    if cipher(&(s(v, "master") + "x"))
        .decrypt(&ct, b(v, "aad"))
        .is_ok()
    {
        return Err("a different key decrypted".to_owned());
    }
    // Same nonce, same bytes: this is where a format difference would show.
    let body = silo_jwt::base64go::raw_url_decode(&ct[7..]).map_err(|e| e.to_string())?;
    let nonce: [u8; 12] = body[..12].try_into().map_err(|_| "nonce")?;
    let resealed = c
        .seal(&nonce, &plaintext, &b(v, "aad"))
        .map_err(|e| e.to_string())?;
    if resealed.as_bytes() != ct.as_slice() {
        return Err(format!("reseal differs: {resealed}"));
    }
    Ok(())
}

fn err_class(e: &secret::Error) -> &'static str {
    match e {
        secret::Error::UnknownVersion(_) => "unknown_version",
        _ => "error",
    }
}

fn read_contract(v: &Value) -> Value {
    let c = cipher(&s(v, "master"));
    let value_bytes = b(v, "value");
    let aad_bytes = b(v, "aad");
    let (d, de) = match c.decrypt(&value_bytes, &aad_bytes) {
        Ok(p) => (gostr(p), ""),
        Err(e) => (Value::Null, err_class(&e)),
    };
    let (ie, iee) = match c.decrypt_if_encrypted(&value_bytes, &aad_bytes) {
        Ok(p) => (gostr(p), ""),
        Err(e) => (Value::Null, err_class(&e)),
    };
    json!({
        "decrypt": d,
        "decrypt_err": de,
        "if_encrypted": ie,
        "if_encrypted_err": iee,
        "is_encrypted": secret::is_encrypted(&value_bytes),
    })
}

fn aad_strings(v: &Value) -> Value {
    let (x, y, z, n) = (s(v, "a"), s(v, "b"), s(v, "c"), i(v, "n"));
    json!(match s(v, "fn").as_str() {
        "settings" => aad::settings(&x),
        "row" => aad::row(&x, &y, &z),
        "jellycompat_access" => aad::jellycompat_token("streamapp_access_token", &x),
        "jellycompat_refresh" => aad::jellycompat_token("streamapp_refresh_token", &x),
        "webhook_sync" => aad::webhook_sync_token(&x),
        "autoscan_secret" => aad::autoscan_webhook_secret(&x),
        "autoscan_connection" => aad::autoscan_connection_api_key(&x),
        "request_integration" => aad::request_integration_api_key(&x),
        "plugin_refresh_state" => aad::plugin_auth_refresh_state(n),
        "history_source" => aad::history_import_source_admin_token(n),
        "history_connect_session" => aad::history_import_connect_session(&x),
        "history_connect_server" => aad::history_import_connect_server(&x, n, &y),
        "history_plex_session" => aad::history_import_plex_session(&x),
        "history_plex_server" => aad::history_import_plex_server(&x, n, &y),
        "history_run" => aad::history_import_run_credential(&x),
        "watch_access" => aad::watch_provider_token("access_token", &x, n, &y),
        "watch_refresh" => aad::watch_provider_token("refresh_token", &x, n, &y),
        "watch_plugin" => aad::watch_provider_token("plugin_credentials", &x, n, &y),
        "watch_auth_state" => aad::watch_provider_auth_state(&x, n, &y),
        "subtitle_api_key" => aad::subtitle_provider_secret("api_key", &x),
        "subtitle_password" => aad::subtitle_provider_secret("password", &x),
        "push_apns" => aad::push_device_apns(&x),
        "push_fcm" => aad::push_device_fcm(&x),
        "plugin_runtime" => aad::plugin_runtime_config(n, &x),
        "plugin_instance" => aad::plugin_instance_state(n, &x, &y),
        "webhook_url" => aad::notification_webhook_url(&x),
        "webhook_secret" => aad::notification_webhook_secret(&x),
        "channel_url" => aad::server_channel_url(&x),
        "channel_secret" => aad::server_channel_secret(&x),
        "email_verification" => aad::email_verification(&x),
        "oauth_pending" => aad::oauth_pending_link(&x),
        other => panic!("unknown AAD function {other}"),
    })
}

fn state_produce(v: &Value) -> Value {
    gostr(
        secret::seal_instance_state(
            &cipher(&s(v, "master")),
            i(v, "id"),
            &s(v, "scope"),
            &s(v, "key"),
            &b(v, "value"),
        )
        .expect("seal"),
    )
}

fn state_check(v: &Value, out: &Value) -> Result<(), String> {
    let c = cipher(&s(v, "master"));
    let stored = bytes_of(out);
    let got = secret::open_instance_state(&c, i(v, "id"), &s(v, "scope"), &s(v, "key"), &stored)
        .map_err(|e| e.to_string())?;
    if got != b(v, "value") {
        return Err("value differs".to_owned());
    }
    if secret::open_instance_state(&c, i(v, "id") + 1, &s(v, "scope"), &s(v, "key"), &stored)
        .is_ok()
    {
        return Err("opened under another installation".to_owned());
    }
    Ok(())
}

fn config_produce(v: &Value) -> Value {
    gostr(
        secret::seal_runtime_config(
            &cipher(&s(v, "master")),
            i(v, "id"),
            &s(v, "key"),
            &b(v, "plaintext"),
        )
        .expect("seal"),
    )
}

fn config_check(v: &Value, out: &Value) -> Result<(), String> {
    let c = cipher(&s(v, "master"));
    let stored = bytes_of(out);
    let got = secret::open_runtime_config(&c, i(v, "id"), &s(v, "key"), &stored)
        .map_err(|e| e.to_string())?;
    if got != b(v, "plaintext") {
        return Err("plaintext differs".to_owned());
    }
    if secret::open_runtime_config(&c, i(v, "id") + 1, &s(v, "key"), &stored).is_ok() {
        return Err("opened under another installation".to_owned());
    }
    Ok(())
}

fn completion_produce(v: &Value) -> Value {
    json!(
        oauth::CompletionCipher::new(&b(v, "material"))
            .seal(&b(v, "plaintext"), &b(v, "aad"))
            .expect("seal")
    )
}

fn completion_check(v: &Value, out: &Value) -> Result<(), String> {
    let cipher = oauth::CompletionCipher::new(&b(v, "material"));
    let ct = out.as_str().ok_or("ciphertext")?;
    let got = cipher.open(ct, &b(v, "aad")).ok_or("does not open")?;
    if got != b(v, "plaintext") {
        return Err("plaintext differs".to_owned());
    }
    let mut wrong = b(v, "aad");
    wrong.push(b'x');
    if cipher.open(ct, &wrong).is_some() {
        return Err("a different AAD opened".to_owned());
    }
    Ok(())
}

// --- tokens ---

fn token_stream(v: &Value) -> Value {
    let claims: streamtoken::Claims =
        serde_json::from_value(v["claims"].clone()).expect("claims decode");
    let secret_text = s(v, "secret");
    let iat = i(v, "iat");
    let ttl = (i(v, "exp") - iat) * 1_000_000_000;
    let token = streamtoken::sign(claims, &secret_text, ttl, i128::from(iat) * 1_000_000_000)
        .expect("sign");
    let got = streamtoken::verify(&token, &secret_text).expect("verify");
    token_out(token, marshal_value(&got))
}

fn token_access(v: &Value) -> Value {
    let claims = AccessClaims {
        user_id: i(v, "user_id"),
        role: s(v, "role"),
        session_id: s(v, "session_id"),
        profile_id: s(v, "profile_id"),
        impersonator_user_id: opt_i(v, "impersonator"),
        password_change_required: flag(v, "password_change_required"),
        api_key_id: i(v, "api_key_id"),
        rate_tier: s(v, "rate_tier"),
        file_id: i(v, "file_id"),
        session_purpose: s(v, "session_purpose"),
        profile_pin_revision: opt_i(v, "pin_revision"),
        ..AccessClaims::default()
    };
    let secret_text = s(v, "secret");
    let iat = i(v, "iat");
    let expiry = (i(v, "exp") - iat) * 1_000_000_000;
    let token = tokens::sign_access(
        claims,
        &s(v, "token_type"),
        expiry,
        None,
        i128::from(iat) * 1_000_000_000,
        secret_text.as_bytes(),
    )
    .expect("sign");
    let got =
        tokens::validate_access(&token, secret_text.as_bytes(), Parser::new()).expect("validate");
    token_out(token, marshal_value(&got))
}

fn token_profile(v: &Value) -> Value {
    let claims = ProfileClaims {
        user_id: i(v, "user_id"),
        session_id: s(v, "session_id"),
        profile_id: s(v, "profile_id"),
        pin_revision: Some(i(v, "pin_revision")),
        policy_revision: i(v, "policy_revision"),
        ..ProfileClaims::default()
    };
    let secret_text = s(v, "secret");
    let iat = i(v, "iat");
    let ttl = opt_i(v, "exp").map_or(0, |exp| (exp - iat) * 1_000_000_000);
    let token = tokens::mint_profile(
        claims,
        ttl,
        i128::from(iat) * 1_000_000_000,
        secret_text.as_bytes(),
    )
    .expect("mint");
    let got =
        tokens::validate_profile(&token, secret_text.as_bytes(), Parser::new()).expect("validate");
    token_out(
        token,
        json!({
            "UserID": got.user_id,
            "SessionID": got.session_id,
            "ProfileID": got.profile_id,
            "PINRevision": got.pin_revision,
            "PolicyRevision": got.policy_revision,
        }),
    )
}

fn token_room(v: &Value) -> Value {
    let claims = RoomClaims {
        room_id: s(v, "room_id"),
        user_id: i(v, "user_id"),
        profile_id: s(v, "profile_id"),
        ..RoomClaims::default()
    };
    let secret_text = s(v, "secret");
    let iat = i(v, "iat");
    let ttl = (i(v, "exp") - iat) * 1_000_000_000;
    let token = tokens::mint_room(
        claims,
        ttl,
        i128::from(iat) * 1_000_000_000,
        secret_text.as_bytes(),
    )
    .expect("mint");
    let got =
        tokens::validate_room(&token, secret_text.as_bytes(), Parser::new()).expect("validate");
    let proof = tokens::validate_room_socket_proof(&token, secret_text.as_bytes(), Parser::new())
        .expect("proof");
    assert_eq!(got, proof);
    token_out(
        token,
        json!({"RoomID": got.room_id, "UserID": got.user_id, "ProfileID": got.profile_id}),
    )
}

fn token_theme(v: &Value) -> Value {
    let key = tokens::theme_grant_key(&s(v, "secret"));
    let converted = flag(v, "converted");
    let grant = ThemeGrant {
        user_id: i(v, "user_id"),
        profile_id: s(v, "profile_id"),
        session_id: s(v, "session_id"),
        policy_revision: i(v, "policy"),
        owner_id: s(v, "owner"),
        theme_id: s(v, "theme"),
        size: i(v, "size"),
        modified: i(v, "modified"),
        ..ThemeGrant::default()
    };
    let audience = if converted {
        tokens::THEME_AUDIENCE_CONVERTED
    } else {
        tokens::THEME_AUDIENCE_ORIGINAL
    };
    let token = tokens::mint_theme_grant(
        grant,
        audience,
        i128::from(i(v, "exp")) * 1_000_000_000,
        i128::from(i(v, "iat")) * 1_000_000_000,
        &key,
    )
    .expect("mint");
    let (owner, theme) = (s(v, "owner"), s(v, "theme"));
    match tokens::validate_theme_grant(&token, &owner, &theme, &key, Parser::new()) {
        None => {
            json!({"key": hexgo::encode(key), "token": token, "valid": false, "converted": false, "decoded": null})
        }
        Some((got, conv)) => json!({
            "key": hexgo::encode(key),
            "token": token,
            "valid": true,
            "converted": conv,
            "decoded": marshal_value(&got),
        }),
    }
}

fn token_abs(v: &Value) -> Value {
    let claims = AbsClaims {
        token_type: s(v, "type"),
        user_id: s(v, "user_id"),
        profile_id: s(v, "profile_id"),
        pin_revision: opt_i(v, "pin_rev"),
        jti: s(v, "jti"),
        device_id: s(v, "device_id"),
        session_id: s(v, "session_id"),
        book_id: s(v, "book_id"),
        file_idx: i(v, "file_idx"),
        issued_at: Some(NumericDate(i(v, "iat"))),
        expires_at: Some(NumericDate(i(v, "exp"))),
        ..AbsClaims::default()
    };
    let secret_text = s(v, "secret");
    let token = tokens::sign_abs(&claims, secret_text.as_bytes()).expect("sign");
    let got = tokens::parse_abs(&token, secret_text.as_bytes(), Parser::new()).expect("parse");
    token_out(token, marshal_value(&got))
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct ProbeClaims {
    sid: String,
    uid: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    ostn: i64,
    #[serde(skip_serializing_if = "omit_empty")]
    seek: f64,
    #[serde(skip_serializing_if = "omit_empty")]
    flag: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    rnp: Option<String>,
    #[serde(flatten)]
    registered: RegisteredClaims,
}

impl_claims!(
    ProbeClaims,
    [
        value("sid"),
        value("uid"),
        value("ostn"),
        value("seek"),
        value("flag"),
        pointer("rnp"),
    ]
);

fn jwt_semantics(v: &Value) -> Value {
    let token_bytes = b(v, "token");
    let secret_text = s(v, "secret");
    let secret_bytes = secret_text.as_bytes();
    let now = i128::from(i(v, "now_nanos"));
    let methods = ["HS256"];
    // Go decodes the token string as bytes. `str` cannot hold invalid UTF-8, and a segment with an
    // invalid byte never decodes as base64url in either language.
    let Ok(token) = std::str::from_utf8(&token_bytes) else {
        return json!({"class": "malformed", "expired": false, "decoded": null});
    };
    let parsed = match s(v, "mode").as_str() {
        "any_hmac" => Parser::new()
            .at(now)
            .parse_hmac::<ProbeClaims>(token, secret_bytes),
        "hs256_keyfunc" => Parser::new()
            .at(now)
            .parse_hs256_keyfunc::<ProbeClaims>(token, secret_bytes),
        "hs256_required" => Parser::new()
            .at(now)
            .valid_methods(&methods)
            .expiration_required()
            .parse::<ProbeClaims, _>(token, |_| Ok(silo_jwt::Key::Hmac(secret_bytes))),
        other => panic!("mode {other}"),
    };
    match parsed {
        Ok(t) => json!({"class": "ok", "expired": false, "decoded": marshal_value(&t.claims)}),
        Err(e) => json!({"class": e.class(), "expired": e.is_expired(), "decoded": null}),
    }
}

fn jwt_rs256(v: &Value) -> Value {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::signature::{SignatureEncoding, Signer as _};
    let pem = std::fs::read_to_string(vectors_dir().join("rs256_test_key.pem")).expect("test key");
    let key = rsa::RsaPrivateKey::from_pkcs1_pem(&pem).expect("test key parses");
    let mut claims = tokens::ChatGptIdentityClaims {
        nonce: s(v, "token_nonce"),
        email: s(v, "email"),
        ..Default::default()
    };
    claims.registered.issuer = s(v, "iss");
    claims.registered.subject = s(v, "sub");
    claims.registered.expires_at = Some(NumericDate(i(v, "exp")));
    let aud = s(v, "aud");
    if !aud.is_empty() {
        claims.registered.audience = Audience(vec![aud]);
    }
    let alg = s(v, "alg");
    let kid = s(v, "token_kid");
    #[derive(Serialize)]
    struct Header<'a> {
        alg: &'a str,
        #[serde(skip_serializing_if = "str::is_empty")]
        kid: &'a str,
        typ: &'a str,
    }
    let head = marshal(&Header {
        alg: &alg,
        kid: &kid,
        typ: "JWT",
    })
    .expect("header");
    let body = marshal(&claims).expect("claims");
    let text = format!(
        "{}.{}",
        silo_jwt::base64go::raw_url_encode(head),
        silo_jwt::base64go::raw_url_encode(body)
    );
    let sig = if alg == "RS384" {
        rsa::pkcs1v15::SigningKey::<sha2::Sha384>::new(key)
            .sign(text.as_bytes())
            .to_vec()
    } else {
        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key)
            .sign(text.as_bytes())
            .to_vec()
    };
    let token = format!("{text}.{}", silo_jwt::base64go::raw_url_encode(sig));
    let keys = [tokens::Jwk {
        kty: "RSA".to_owned(),
        kid: s(v, "kid"),
        n: s(v, "n"),
        e: s(v, "e"),
    }];
    let (issuer, client) = (s(v, "issuer"), s(v, "client_id"));
    let accepted = tokens::verify_chatgpt_id_token(
        &token,
        &keys,
        &issuer,
        &client,
        &s(v, "nonce"),
        Parser::new().at(i128::from(i(v, "now_nanos"))),
    )
    .is_some();
    json!({"token": token, "accepted": accepted})
}

fn vapid_keys(v: &Value) -> silo_jwt::VapidKeys {
    silo_jwt::VapidKeys {
        public: s(v, "public"),
        private: s(v, "private"),
    }
}

fn vapid_produce(v: &Value) -> Value {
    json!(
        silo_jwt::vapid_authorization_header(
            &s(v, "endpoint"),
            &s(v, "subscriber"),
            &vapid_keys(v),
            i(v, "exp")
        )
        .expect("header")
    )
}

fn vapid_check(v: &Value, out: &Value) -> Result<(), String> {
    let header = out.as_str().ok_or("header")?;
    let rest = header.strip_prefix("vapid t=").ok_or("prefix")?;
    let (token, k) = rest.split_once(", k=").ok_or("shape")?;
    let public = silo_jwt::decode_vapid_key(&s(v, "public")).map_err(|e| e.to_string())?;
    if k != silo_jwt::base64go::raw_url_encode(&public) {
        return Err(format!("k={k}"));
    }
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public).map_err(|e| e.to_string())?;
    let parsed = Parser::new()
        .at(1_000_000_000_000_000_000)
        .valid_methods(&["ES256"])
        .expiration_required()
        .parse::<RegisteredClaims, _>(token, |_| Ok(silo_jwt::Key::Es256(key)))
        .map_err(|e| e.to_string())?;
    if parsed.claims.subject != silo_jwt::vapid_subscriber(&s(v, "subscriber")) {
        return Err(format!("sub={}", parsed.claims.subject));
    }
    let aud = silo_jwt::scheme_host(&s(v, "endpoint")).map_err(|e| e.to_string())?;
    if parsed.claims.audience.0 != [aud.clone()] {
        return Err(format!("aud={:?}, want {aud}", parsed.claims.audience));
    }
    Ok(())
}

fn bcrypt_produce(v: &Value) -> Value {
    gostr(passwordhash::generate(&b(v, "password"), i(v, "cost")).expect("generate"))
}

fn bcrypt_check(v: &Value, out: &Value) -> Result<(), String> {
    let hash = bytes_of(out);
    let password = b(v, "password");
    if !passwordhash::compare(&hash, &password).map_err(|e| e.to_string())? {
        return Err("mismatch".to_owned());
    }
    let mut other = password.clone();
    other.push(b'x');
    if password.len() < 72 && passwordhash::compare(&hash, &other).map_err(|e| e.to_string())? {
        return Err("a different password matched".to_owned());
    }
    let salt = passwordhash::salt_of(&hash).ok_or("salt")?;
    let again = passwordhash::generate_with_salt(&password, i(v, "cost"), &salt)
        .map_err(|e| e.to_string())?;
    if again.as_bytes() != hash.as_slice() {
        return Err(format!("rehash differs: {again}"));
    }
    Ok(())
}

fn bcrypt_compare(v: &Value) -> Value {
    json!(
        match passwordhash::compare(&b(v, "hash"), &b(v, "password")) {
            Ok(true) => "ok",
            Ok(false) => "mismatch",
            Err(_) => "unreadable",
        }
    )
}

// --- hashes ---

fn credential_hashes(v: &Value) -> Value {
    let raw = b(v, "v");
    let t = || String::from_utf8(raw.clone()).expect("valid UTF-8 input");
    json!(match s(v, "fn").as_str() {
        "hash_link_token" => apikey::hash_link_token(&raw),
        "hash_device_login_secret" => apikey::hash_device_login_secret(&raw),
        "normalize_user_code" => apikey::normalize_user_code(&t()),
        "format_user_code" => decode_runes(&apikey::format_user_code(&t())).into_owned(),
        "quick_connect_code" => apikey::quick_connect_code(&t()),
        "quick_connect_session_token" => apikey::quick_connect_session_token(&t()),
        "sign_in_attempt_key" => apikey::sign_in_attempt_key(&t()),
        "binder_hash" => oauth::binder_hash(&raw),
        "binder_cookie_name" => oauth::binder_cookie_name(&raw),
        "pkce_challenge" => oauth::pkce_challenge_s256(&raw),
        "completion_code_hash" => oauth::completion_code_hash(&raw),
        "apns_token_hash" => apikey::apns_token_hash(&t()),
        "fcm_token_hash" => apikey::fcm_token_hash(&t()),
        "hash_email_token" => apikey::hash_email_token(&raw),
        "hash_webhook_token" => apikey::hash_webhook_token(&raw),
        "abs_token_hash" => apikey::abs_token_hash(&raw),
        "expired_stop_id" => playback::expired_stop_id(&t()),
        "abort_stop_id" => playback::abort_stop_id(&t()),
        "admin_stop_id" => playback::admin_stop_id(&t()),
        "node_hash" => playback::node_hash(&t()),
        "node_recipe_digest" => playback::node_recipe_digest(&raw),
        "smart_definition_key" => digest::smart_definition_key(&raw),
        "frontend_content_etag" => digest::frontend_content_etag(&raw),
        "tag_value" => jellycompat::tag_value(&t()),
        "canonical_image_tag" => jellycompat::canonical_image_tag(&t()).to_owned(),
        "plain_sha256_hex" => digest::object_sha256(&raw),
        other => panic!("unknown function {other}"),
    })
}

fn api_key(v: &Value) -> Value {
    let random: [u8; 32] = b(v, "random").try_into().expect("32 bytes");
    let key = apikey::format_api_key(&random);
    json!({"key": key, "key_hash": apikey::api_key_hash(key.as_bytes()), "key_prefix": apikey::api_key_prefix(&key)})
}

fn api_key_valid_text(v: &Value) -> Value {
    json!(apikey::valid_text_key(&bytes_of(v)))
}

fn time_of(nanos: i64) -> GoTime {
    GoTime::from_unix(
        nanos.div_euclid(1_000_000_000),
        nanos.rem_euclid(1_000_000_000) as u32,
    )
}

fn oauth_state(v: &Value) -> Value {
    let derived = oauth::derive_state_secret(&b(v, "secret"));
    let payload = oauth::StatePayload {
        nonce: s(v, "nonce"),
        install_id: s(v, "install"),
        expires_at: time_of(i(v, "expires_nanos")),
    };
    json!({"derived": hexgo::encode(derived), "signed": oauth::sign_state(&derived, &payload)})
}

fn oauth_state_verify(v: &Value) -> Value {
    let signed = String::from_utf8_lossy(&b(v, "signed")).into_owned();
    let render = |class: &str, p: &oauth::StatePayload| {
        let expires = if p.expires_at.is_zero() {
            String::new()
        } else {
            p.expires_at.to_utc().rfc3339_nano()
        };
        json!({"class": class, "nonce": p.nonce, "install": p.install_id, "expires": expires})
    };
    match oauth::verify_state(&b(v, "secret"), &signed, GoTime::now_utc()) {
        Ok(p) => render("ok", &p),
        Err(oauth::StateError::Expired(p)) => render("expired", &p),
        Err(_) => json!({"class": "error", "nonce": "", "install": "", "expires": ""}),
    }
}

fn track(v: &Value) -> Option<TrackIdentity> {
    let list = v.as_array()?;
    Some(TrackIdentity {
        id: text(&list[0]),
        index: list[1].as_i64(),
    })
}

fn plan_identity(v: &Value) -> Value {
    let plan = PlanIdentity {
        plan_id: s(v, "plan_id"),
        delivery: s(v, "delivery"),
        stream_protocol: s(v, "protocol"),
        stream_container: s(v, "container"),
        video_codec: s(v, "video"),
        audio_codec: s(v, "audio"),
        width: opt_i(v, "width"),
        height: opt_i(v, "height"),
        bitrate_kbps: opt_i(v, "bitrate"),
        dynamic_range: s(v, "range"),
        video_sample_entry: s(v, "sample"),
        segment_container: s(v, "segment"),
        selected_audio: track(&v["audio_track"]),
        selected_subtitle: track(&v["sub_track"]),
        subtitle_mode: s(v, "mode"),
        embedded_subtitle: opt_i(v, "embedded_idx").map(|idx| (idx, s(v, "embedded_id"))),
        hls_rendition: v["hls_group"]
            .as_str()
            .map(|g| (g.to_owned(), s(v, "hls_format"))),
        transformations: v["transforms"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|t| Transformation {
                        executor: text(&t[0]),
                        name: text(&t[1]),
                        recipe_version: text(&t[2]),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        applied_quirks: v["quirks"]
            .as_array()
            .map(|list| {
                list.iter()
                    .map(|q| AppliedQuirk {
                        registry_revision: text(&q[0]),
                        id: text(&q[1]),
                    })
                    .collect()
            })
            .unwrap_or_default(),
        runtime_corrections: strs(&v["corrections"]),
    };
    json!({
        "plan_id": playback::deterministic_plan_id(&s(v, "attempt"), i(v, "requested"), i(v, "effective"), &plan),
        "attempt_key": playback::plan_attempt_key(&plan, &s(v, "output"), &strs(&v["mutations"])),
    })
}

fn directplay_etag_of(out: &Value) -> String {
    let (dev, ino) = (
        out["dev"].as_u64().expect("dev"),
        out["ino"].as_u64().expect("ino"),
    );
    let (cs, cn, m, size) = (
        i(out, "ctime_sec"),
        i(out, "ctime_nsec"),
        i(out, "mtime_nano"),
        i(out, "size"),
    );
    let revision = match s(out, "os").as_str() {
        "linux" => playback::direct_play_revision_linux(dev, ino, cs, cn, m, size),
        _ => playback::direct_play_revision_darwin(dev, ino, cs, cn, m, size),
    };
    playback::direct_play_etag(&revision)
}

fn directplay_check(_v: &Value, out: &Value) -> Result<(), String> {
    let got = directplay_etag_of(out);
    if got != s(out, "etag") {
        return Err(format!("etag {got}, go said {}", s(out, "etag")));
    }
    Ok(())
}

fn directplay_produce(v: &Value) -> Value {
    use std::os::unix::fs::MetadataExt;
    let seed = v.as_u64().expect("seed");
    let dir = std::env::var_os("SILO_CORE_EMIT_DIR")
        .map_or_else(std::env::temp_dir, std::path::PathBuf::from);
    let path = dir.join("directplay-files");
    std::fs::create_dir_all(&path).expect("directory");
    let file = path.join(format!("f{seed}"));
    std::fs::write(&file, vec![0u8; (seed % 4096) as usize]).expect("write");
    let meta = std::fs::metadata(&file).expect("metadata");
    let mut out = json!({
        "dev": meta.dev(),
        "ino": meta.ino(),
        "ctime_sec": meta.ctime(),
        "ctime_nsec": meta.ctime_nsec(),
        "mtime_nano": meta.mtime() * 1_000_000_000 + meta.mtime_nsec(),
        "size": meta.size(),
        "os": if cfg!(target_os = "linux") { "linux" } else { "darwin" },
        "path": file.to_str().expect("path"),
    });
    out["etag"] = json!(directplay_etag_of(&out));
    out
}

fn connection_key(v: &Value) -> Value {
    let ip: std::net::IpAddr = s(v, "ip").parse().expect("IP");
    json!(playback::connection_key(&s(v, "secret"), ip))
}

fn revision_of(v: &Value) -> SourceRevision {
    SourceRevision {
        media_file_id: i(v, "media_file_id"),
        file_size: i(v, "file_size"),
        file_modified_unix_nano: i(v, "file_mod"),
        file_hash: s(v, "file_hash"),
        probe_updated_unix_nano: i(v, "probe_mod"),
        video_stream_index: i(v, "video_index"),
        stream_signature: s(v, "signature"),
    }
}

fn tonemap_revision(v: &Value) -> Value {
    let rev = revision_of(v);
    json!({
        "fingerprint": downloads::source_revision_fingerprint(&rev),
        "encoded": downloads::source_revision_encode(&rev),
        "is_zero": rev.is_zero(),
    })
}

fn params_hash(v: &Value) -> Value {
    json!(downloads::params_hash(&ParamsHashParams {
        format: s(v, "Format"),
        container: s(v, "Container"),
        codec_video: s(v, "Video"),
        codec_audio: s(v, "Audio"),
        resolution: s(v, "Resolution"),
        audio_track_index: i(v, "Track"),
        target_bitrate_kbps: i(v, "Bitrate"),
        subtitle_burn_in: flag(v, "BurnIn"),
        policy: s(v, "Policy"),
        mode: s(v, "Mode"),
        source_kind: s(v, "Kind"),
        recipe_version: s(v, "Recipe"),
        preflight_required: flag(v, "Preflight"),
        source_revision: revision_of(&v["Revision"]),
    }))
}

fn metadata_etag(v: &Value) -> Value {
    let modified = opt_i(v, "Modified")
        .map(|n| time_of(n).rfc3339_nano())
        .unwrap_or_default();
    json!(downloads::metadata_etag(
        &s(v, "ID"),
        i(v, "Revision"),
        &s(v, "Format"),
        &s(v, "Quality"),
        &s(v, "Effective"),
        i(v, "Bitrate"),
        i(v, "Size"),
        &modified,
    ))
}

fn execution_fingerprint(v: &Value) -> Value {
    let request: PrepareRequest = serde_json::from_value(v.clone()).expect("request decodes");
    let mut cleared = request.clone();
    cleared.artifact_id.clear();
    cleared.log_session_id.clear();
    json!({
        "fingerprint": downloads::execution_fingerprint(&request),
        "json": String::from_utf8(marshal(&cleared).expect("marshal")).expect("UTF-8"),
    })
}

fn marker_identity(v: &Value) -> Value {
    let modified = opt_i(v, "Modified").map(|n| {
        let t = time_of(n - n.rem_euclid(1000));
        t.rfc3339_nano()
    });
    let file = MarkerFile {
        id: i(v, "ID"),
        file_hash: s(v, "Hash"),
        file_size: i(v, "Size"),
        modified_at: modified,
        duration: i(v, "Duration"),
        content_id: s(v, "Content"),
        episode_id: s(v, "EpisodeID"),
        extra_id: s(v, "Extra"),
        season_number: i(v, "Season"),
        episode_number: i(v, "Episode"),
        file_path: s(v, "Path"),
    };
    let segment = MarkerSegment {
        kind: s(v, "Kind"),
        start_seconds: v["Start"].as_f64().unwrap_or(0.0),
        end_seconds: v["End"].as_f64().unwrap_or(0.0),
    };
    json!({"file": digest::marker_file_identity(&file), "thumb": digest::marker_thumbnail_identity(&file, &segment)})
}

fn image_tags(v: &Value) -> Value {
    let updated = opt_i(v, "updated").map(|n| time_of(n).rfc3339_nano());
    let seed = jellycompat::image_tag_seed(
        &s(v, "route"),
        &s(v, "type"),
        &s(v, "size"),
        &s(v, "raw_path"),
        &s(v, "thumb"),
        updated.as_deref(),
    );
    let secret_text = s(v, "secret");
    let collage = if silo_gocompat::strings::trim_space(&secret_text).is_empty() {
        String::new()
    } else {
        jellycompat::collage_image_tag(&secret_text, &s(v, "route"), &s(v, "key"))
    };
    json!({
        "seed": gostr(&seed),
        "tag": jellycompat::image_tag(&secret_text, &seed, &s(v, "fallback")),
        "collage": collage,
    })
}

fn persisted_hashes(v: &Value) -> Value {
    let (a, b_, c, d, e, f) = (
        s(v, "a"),
        s(v, "b"),
        s(v, "c"),
        s(v, "d"),
        s(v, "e"),
        s(v, "f"),
    );
    let (n, m, t, u) = (i(v, "n"), i(v, "m"), flag(v, "t"), flag(v, "u"));
    let l = strs(&v["l"]);
    json!(match s(v, "fn").as_str() {
        "collection_collage_key" => digest::collection_collage_key(&l),
        "media_artifact_config_hash" => digest::media_artifact_config_hash(&a, &b_),
        "translation_idempotency" => digest::translation_idempotency_key(&a, &b_, &c, &d, t, u),
        "translation_legacy" => digest::translation_legacy_idempotency_key(&a, &b_, &c, &d),
        "generated_work_id" => digest::generated_work_id(&a, &l),
        "sidecar_entry" => digest::sidecar_entry_key(&a, n, m),
        "sidecar_hash" => digest::hash_sidecar_entries(&l),
        "uploaded_source" => digest::uploaded_image_source(a.as_bytes()),
        "variant_revision" => {
            let variants: Vec<(String, Vec<u8>)> = l
                .iter()
                .enumerate()
                .map(|(idx, key)| (key.clone(), format!("data-{}-{b_}", idx % 3).into_bytes()))
                .collect();
            digest::variant_revision(&a, &variants)
        }
        "meili_schema_version" => digest::meilisearch_schema_version(&a, &l, t, u).to_string(),
        "local_sidecar_lock" => digest::local_sidecar_lock_key(n, &a).to_string(),
        "profile_refresh_lock" => digest::profile_refresh_lock(n, &a).to_string(),
        "rotation_uniform" => format!("{:x}", digest::rotation_uniform(&a, &b_, &c).to_bits()),
        "rotation_index" => {
            let count = if t { 0 } else { n % 20 + 1 };
            let days = m % 40 - 2;
            digest::rotation_index(1_700_000_000 + m * 86400, &a, count, days).to_string()
        }
        "cloudflare_url" => digest::cloudflare_token_url(&a, &b_, &c, &d, n),
        "delivery_scope" => digest::artwork_delivery_scope(&a, &b_, &c, &d, &e, &f),
        "webhook_signature" => digest::sign_generic_webhook(a.as_bytes(), n, b_.as_bytes()),
        "ebook_cache_key" => digest::ebook_cache_key(EBOOK_MODULE_VERSION, n, m, n + m, &a),
        "ebook_module_version" => EBOOK_MODULE_VERSION.to_owned(),
        "library_refresh_lock" => digest::library_refresh_lock_key(n - (1 << 29)).to_string(),
        other => panic!("unknown function {other}"),
    })
}

/// The first 16 hex digits of the SHA-256 of `internal/ebookconvert/mobitool.wasm`.
const EBOOK_MODULE_VERSION: &str = "38a544c5f516a6b5";

fn inline_expressions(v: &Value) -> Value {
    let (file_id, user, key, content) =
        (i(v, "file_id"), i(v, "user"), s(v, "key"), s(v, "content"));
    json!({
        "chapter": digest::chapter_thumbnails_lock_key(file_id).to_string(),
        "mutation": digest::setting_mutation_lock(user, &s(v, "mutation")),
        "daily_mix": digest::daily_mix_score(&key, i(v, "day"), &content).to_string(),
        "backdrop": digest::local_artwork_discriminator(content.as_bytes(), Some(&key)),
        "thumbnail": digest::chapter_thumbnail_key("chapter-images/", file_id, &key, content.as_bytes(), user % 3000),
    })
}

fn uuid_v5_ids(v: &Value) -> Value {
    let raw = bytes_of(v);
    json!([
        Uuid::new_sha1(NAMESPACE_OID, &raw).to_string(),
        Uuid::new_sha1(NAMESPACE_URL, &raw).to_string(),
        jellycompat::default_server_id().to_string(),
        jellycompat::default_server_id().to_string(),
    ])
}

fn settings_jcs(v: &Value) -> Value {
    let raw = b(v, "raw");
    match (jcs::canonicalize(&raw), jcs::canonicalize_public(&raw)) {
        (Ok(c), Ok(p)) => json!({"error": false, "canonical": gostr(c), "public": gostr(p)}),
        _ => json!({"error": true, "canonical": "", "public": ""}),
    }
}

fn ecmascript(v: &Value) -> Value {
    json!(jcs::format_ecmascript(f64::from_bits(
        v.as_u64().expect("bits")
    )))
}

fn contract_etag(v: &Value) -> Value {
    let dir = repo_root().join(text(v));
    let raw = std::fs::read(dir.join("manifest.json")).expect("manifest");
    let mut schemas = Vec::new();
    for entry in std::fs::read_dir(dir.join("schemas")).expect("schemas") {
        let entry = entry.expect("entry");
        schemas.push((
            entry.file_name().into_string().expect("name"),
            std::fs::read(entry.path()).expect("schema"),
        ));
    }
    let canonical = jcs::canonicalize(&raw).expect("canonical");
    let public = jcs::canonicalize_public(&raw).expect("public");
    json!({
        "canonical_sha256": hexgo::sha256_hex(&canonical),
        "public_sha256": hexgo::sha256_hex(&public),
        "etag": jcs::digest_with_schemas(&canonical, &schemas).expect("etag"),
        "public_etag": jcs::digest_with_schemas(&public, &schemas).expect("etag"),
    })
}

fn norm_table_produce(_v: &Value) -> Value {
    use unicode_normalization::UnicodeNormalization;
    use unicode_normalization::char::canonical_combining_class;
    let mut rows = Vec::new();
    for cp in 0..=0x10FFFFu32 {
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        if contentid::newer_than_go(c) {
            continue;
        }
        let single = c.to_string();
        let nfc: String = single.nfc().collect();
        let nfd: String = single.nfd().collect();
        let ccc = canonical_combining_class(c);
        if nfc != single || nfd != single || ccc != 0 {
            rows.push(json!({"cp": cp, "ccc": ccc, "nfc": nfc, "nfd": nfd}));
        }
    }
    Value::Array(rows)
}

/// Go's normalization tables are older than the Rust crate's, so the crate's newer data is filtered in
/// `contentid::nfc`. This checks that the two agree on every code point Go has data for.
fn norm_table_check(_v: &Value, out: &Value) -> Result<(), String> {
    let mut go_rows = std::collections::BTreeMap::new();
    for row in out.as_array().ok_or("rows")? {
        go_rows.insert(row["cp"].as_u64().ok_or("cp")? as u32, row.clone());
    }
    let mut problems = Vec::new();
    for cp in 0..=0x10FFFFu32 {
        let Some(c) = char::from_u32(cp) else {
            continue;
        };
        let single = c.to_string();
        let got_nfc = contentid::nfc(&single);
        let want = go_rows.get(&cp);
        let want_nfc = want.map_or(single.clone(), |r| text(&r["nfc"]));
        let want_ccc = want.map_or(0, |r| r["ccc"].as_u64().unwrap_or(0));
        let got_ccc = if contentid::newer_than_go(c) {
            0
        } else {
            u64::from(unicode_normalization::char::canonical_combining_class(c))
        };
        if got_nfc != want_nfc || got_ccc != want_ccc {
            problems.push(format!("{cp:X}"));
        }
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} code points differ: {}",
            problems.len(),
            problems.join(" ")
        ))
    }
}

fn naming_group_key(v: &Value) -> Value {
    json!({
        "key": silo_core::naming::make_content_group_key(&s(v, "type"), &s(v, "title"), i(v, "year"), &s(v, "root"), &s(v, "path")),
        "comparable": silo_core::naming::normalize_group_comparable(&s(v, "title")),
    })
}

fn naming_presentation_group(v: &Value) -> Value {
    json!(silo_core::naming::normalize_presentation_group(
        &s(v, "base"),
        &s(v, "matched")
    ))
}

fn embedding_text(v: &Value) -> Value {
    use silo_core::embeddings::{EmbeddingItem, ItemPerson, build_embedding_text};
    let people = v["People"]
        .as_array()
        .map(|list| {
            list.iter()
                .map(|p| ItemPerson {
                    id: i(p, "id"),
                    name: s(p, "name"),
                    kind: i(p, "kind"),
                    character: s(p, "character"),
                    sort_order: i(p, "sort"),
                })
                .collect()
        })
        .unwrap_or_default();
    json!(build_embedding_text(&EmbeddingItem {
        item_type: s(v, "Type"),
        title: s(v, "Title"),
        year: i(v, "Year"),
        overview: s(v, "Overview"),
        genres: strs(&v["Genres"]),
        content_rating: s(v, "ContentRating"),
        tagline: s(v, "Tagline"),
        people,
        keywords: strs(&v["Keywords"]),
        original_language: s(v, "Language"),
        studios: strs(&v["Studios"]),
        networks: strs(&v["Networks"]),
        countries: strs(&v["Countries"]),
    }))
}

fn floats(v: &Value) -> Vec<f64> {
    v.as_array()
        .map(|list| list.iter().map(|f| f.as_f64().expect("float")).collect())
        .unwrap_or_default()
}

fn float_list(list: &[f64], empty_is_null: bool) -> Value {
    if list.is_empty() && empty_is_null {
        return Value::Null;
    }
    Value::Array(list.iter().map(marshal_value).collect())
}

fn keyframe_plan(v: &Value) -> Value {
    use silo_core::keyframes::{CopyPlanRecord, plan_segments, segment_durations};
    let frames = floats(&v["keyframes"]);
    let segment = v["segment"].as_f64().expect("segment");
    let starts = plan_segments(&frames, segment);
    let durations = segment_durations(&starts, v["end"].as_f64().expect("end"));
    let record = CopyPlanRecord {
        planned: flag(v, "planned"),
        durations: durations.clone(),
    }
    .to_json();
    json!({
        "starts": float_list(&starts, true),
        // make() with no starts is an empty slice, not nil.
        "durations": if frames.is_empty() || segment <= 0.0 { json!([]) } else { float_list(&durations, false) },
        "record": String::from_utf8(record).expect("UTF-8"),
    })
}

fn search_fold(v: &Value) -> Value {
    json!(silo_core::searchfold::fold_search_diacritics(&text(v)))
}

fn blobstore_keys(v: &Value) -> Value {
    use silo_core::blobstore;
    let key = b(v, "key");
    let valid = std::str::from_utf8(&key).is_ok_and(blobstore::validate_key);
    let prefix = s(v, "prefix");
    let normalized = blobstore::normalize_key_prefix(&prefix);
    json!({
        "valid": valid,
        "endpoint": blobstore::normalize_endpoint(&s(v, "endpoint")),
        "prefix": normalized,
        "prefixed": blobstore::prefixed_key(normalized, &s(v, "obj_key")),
    })
}

fn s3_presign(v: &Value) -> Value {
    use silo_core::blobstore::{
        PresignRequest, normalize_key_prefix, prefixed_key, presign_get_url_at,
    };
    let prefix = s(v, "prefix");
    let key = prefixed_key(normalize_key_prefix(&prefix), &s(v, "key"));
    let (endpoint, region, access, secret_key, bucket) = (
        s(v, "endpoint"),
        s(v, "region"),
        s(v, "access"),
        s(v, "secret"),
        s(v, "bucket"),
    );
    let mut req = PresignRequest {
        endpoint: &endpoint,
        region: &region,
        access_key: &access,
        secret_key: &secret_key,
        path_style: flag(v, "path_style"),
        bucket: &bucket,
        key: &key,
        issued_unix: 0,
        lifetime_seconds: 0,
    };
    let (url, expires) = presign_get_url_at(
        &mut req,
        i128::from(i(v, "now_nanos")),
        i(v, "expiry_seconds"),
        i(v, "window_seconds"),
    )
    .expect("presign");
    json!({"url": url, "expires_unix": expires})
}

fn thumbhash_family(v: &Value) -> Value {
    json!(silo_core::thumbhash::thumbhash_nrgba(
        i(v, "w") as usize,
        i(v, "h") as usize,
        &b(v, "pix"),
    ))
}

fn redis_channels(v: &Value) -> Value {
    use silo_core::redis;
    let event = redis::Event {
        event_type: s(v, "type"),
        payload: s(v, "payload"),
    };
    json!({
        "channel": redis::channel(&s(v, "channel"), i(v, "db")),
        "event": String::from_utf8(marshal(&event).expect("event")).expect("UTF-8"),
        "attempt": redis::attempt_key(&s(v, "key")),
        "search": redis::search_session_prefix(i(v, "user")),
    })
}

fn push_intent(v: &Value) -> Value {
    let (user, profile, token, mode) = (i(v, "User"), s(v, "Profile"), s(v, "Token"), s(v, "Mode"));
    json!({
        "apple": apikey::apple_push_intent(user, &profile, &token, &s(v, "Environment"), &s(v, "Topic"), &mode),
        "android": apikey::android_push_intent(user, &profile, &token, &mode, flag(v, "Remove")),
        "key_hash": apikey::push_digest(&b(v, "InstallKey")),
    })
}

fn settings_etag_digest(v: &Value) -> Value {
    let schemas: Vec<(String, Vec<u8>)> = v["schemas"]
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(k, body)| (k.clone(), bytes_of(body)))
                .collect()
        })
        .unwrap_or_default();
    json!(jcs::digest_with_schemas(&b(v, "manifest"), &schemas).expect("digest"))
}

fn artwork_base_path(v: &Value) -> Value {
    json!(artworkkey::build_base_path(
        &s(v, "Provider"),
        &s(v, "ContentType"),
        &s(v, "ContentID"),
        &s(v, "Language"),
        opt_i(v, "Season"),
        opt_i(v, "Episode"),
        &s(v, "Discriminator"),
        &s(v, "ImageType"),
    ))
}

/// Read from the generated module, so a bad regeneration or a hand edit shows up on the Go side.
fn advisory_locks_produce(_v: &Value) -> Value {
    let source = include_str!("../../src/advisory_locks.rs");
    let mut out = serde_json::Map::new();
    for line in source.lines() {
        if let Some(rest) = line.strip_prefix("pub const ")
            && let Some((name, value)) = rest.split_once(": i64 = ")
        {
            let value: i64 = value.trim_end_matches(';').parse().expect("constant");
            out.insert(name.to_owned(), json!(value));
        }
    }
    Value::Object(out)
}

fn advisory_locks_check(v: &Value, out: &Value) -> Result<(), String> {
    let ours = advisory_locks_produce(v);
    if &ours == out {
        Ok(())
    } else {
        Err(format!("got {ours}\n   want {out}"))
    }
}

fn backfill_targets(_v: &Value) -> Value {
    Value::Array(
        secret::COLUMN_BACKFILL_TARGETS
            .iter()
            .map(|t| json!([t.table, t.column, t.key_expr, t.aad_expr]))
            .collect(),
    )
}

fn minted_produce(_v: &Value) -> Value {
    let (link, hash) = apikey::mint_link_token().expect("random");
    json!({
        "api_key": apikey::mint_api_key().expect("random"),
        "user_code": apikey::mint_user_code().expect("random"),
        "quick_connect": apikey::mint_quick_connect_secret().expect("random"),
        "link_token": link,
        "link_hash": hash,
        "jwt_secret": apikey::mint_jwt_secret().expect("random"),
    })
}

fn minted_check(_v: &Value, out: &Value) -> Result<(), String> {
    let api_key = s(out, "api_key");
    if !api_key.starts_with("sa_") || api_key.len() != 67 {
        return Err(format!("api key {api_key}"));
    }
    if apikey::format_user_code(&s(out, "user_code")) != s(out, "user_code").as_bytes()
        || s(out, "user_code").len() != 9
    {
        return Err("user code".to_owned());
    }
    if apikey::hash_link_token(s(out, "link_token").as_bytes()) != s(out, "link_hash") {
        return Err("link hash".to_owned());
    }
    Ok(())
}

fn redis_contract_produce(_v: &Value) -> Value {
    use sha1::{Digest, Sha1};
    use silo_core::{redis, redis_lua};
    let hash = |text: &str| hexgo::encode(Sha1::digest(text.as_bytes()));
    json!({
        "hashes": {
            "AUTOSCAN_CLAIM_STATE": hash(redis_lua::AUTOSCAN_CLAIM_STATE),
            "AUTOSCAN_RELEASE_STATE": hash(redis_lua::AUTOSCAN_RELEASE_STATE),
            "RATELIMIT_ATTEMPT": hash(redis_lua::RATELIMIT_ATTEMPT),
            "RATELIMIT_QUOTA": hash(redis_lua::RATELIMIT_QUOTA),
            "RATELIMIT_WINDOW": hash(redis_lua::RATELIMIT_WINDOW),
            "NODERECIPE_PUT": hash(redis_lua::NODERECIPE_PUT),
            "NODERECIPE_VALIDATE_LEGACY": hash(redis_lua::NODERECIPE_VALIDATE_LEGACY),
            "NODERECIPE_REVOKE_NODE": hash(redis_lua::NODERECIPE_REVOKE_NODE),
            "DOWNLOADS_SHARED_BANDWIDTH": hash(redis_lua::DOWNLOADS_SHARED_BANDWIDTH),
        },
        "prefixes": {
            "NODE_RECIPE_KEY_PREFIX": redis::NODE_RECIPE_KEY_PREFIX,
            "PROXY_GRANT_KEY_PREFIX": redis::PROXY_GRANT_KEY_PREFIX,
            "SESSION_RECIPE_KEY_PREFIX": redis::SESSION_RECIPE_KEY_PREFIX,
            "NODE_AUTHORITY_GENERATION_KEY_PREFIX": redis::NODE_AUTHORITY_GENERATION_KEY_PREFIX,
            "NODE_AUTHORITY_RECORD_KEY_PREFIX": redis::NODE_AUTHORITY_RECORD_KEY_PREFIX,
            "NODE_AUTHORITY_DIGEST_KEY_PREFIX": redis::NODE_AUTHORITY_DIGEST_KEY_PREFIX,
            "EVENTS_WS_TICKET_PREFIX": redis::EVENTS_WS_TICKET_PREFIX,
            "EVENTS_WS_TICKET_PROOF_PREFIX": redis::EVENTS_WS_TICKET_PROOF_PREFIX,
            "SESSIONS_KEY_PREFIX": redis::SESSIONS_KEY_PREFIX,
            "PLAYBACK_DELIVERY_KEY_PREFIX": redis::PLAYBACK_DELIVERY_KEY_PREFIX,
            "SUPPRESS_KEY_PREFIX": redis::SUPPRESS_KEY_PREFIX,
            "ROOM_SOCKET_TICKET_PREFIX": redis::ROOM_SOCKET_TICKET_PREFIX,
            "API_REPLICA_KEY_PREFIX": redis::API_REPLICA_KEY_PREFIX,
            "STREAM_DENY_KEY_PREFIX": redis::STREAM_DENY_KEY_PREFIX,
            "PLAYBACK_CONTROL_TICKET_PREFIX": redis::PLAYBACK_CONTROL_TICKET_PREFIX,
        },
    })
}

fn redis_contract_check(_v: &Value, out: &Value) -> Result<(), String> {
    let ours = redis_contract_produce(&Value::Null);
    if &ours == out {
        Ok(())
    } else {
        Err(format!("got {ours}\n   want {out}"))
    }
}

macro_rules! det {
    ($name:literal, $f:expr) => {
        Family {
            name: $name,
            kind: Kind2::Det($f),
            frozen: &[],
        }
    };
    ($name:literal, $f:expr, $frozen:expr) => {
        Family {
            name: $name,
            kind: Kind2::Det($f),
            frozen: $frozen,
        }
    };
}

macro_rules! nondet {
    ($name:literal, $p:expr, $c:expr, $frozen:expr) => {
        Family {
            name: $name,
            kind: Kind2::Nondet {
                produce: $p,
                check: $c,
            },
            frozen: $frozen,
        }
    };
}

pub fn families() -> Vec<Family> {
    vec![
        det!("contentid_provider", contentid_provider),
        det!("contentid_local", contentid_local),
        det!("contentid_codec", contentid_codec),
        det!("contentid_unpack", contentid_unpack),
        det!("fspath", fspath_family),
        det!("sonyflake_compose", sonyflake_compose, &["unix_nanos"]),
        nondet!("sonyflake_mint", sonyflake_produce, sonyflake_check, &["*"]),
        det!("lantls_pin", lantls_pin, &["*"]),
        det!(
            "nodeauth_sign",
            nodeauth_sign,
            &["url", "method", "secret", "now"]
        ),
        det!(
            "nodeauth_verify",
            nodeauth_verify,
            &["target", "method", "secret"]
        ),
        det!("apiv2_etag", apiv2_etag),
        det!("apiv2_etag_list", apiv2_etag_list),
        det!("apiv2_cursor", apiv2_cursor, &["secret", "sort"]),
        det!("apiv2_cursor_decode", apiv2_cursor_decode, &["secret"]),
        det!("apiv2_viewer_scope_digest", apiv2_viewer),
        det!(
            "artworkurl",
            artworkurl,
            &["secret", "now_nanos", "ttl_nanos", "sign_ttl_nanos"]
        ),
        det!("artworkkey", artworkkey_family),
        det!("jellycompat_ids", jellycompat_ids, &["kind"]),
        det!("uuid_parse", uuid_parse),
        det!("oshash", oshash, &["size"]),
        nondet!(
            "secret_enc_v1",
            enc_produce,
            enc_check,
            &["master", "wrong_aad"]
        ),
        det!("secret_read_contract", read_contract, &["master"]),
        det!("secret_aad_strings", aad_strings, &["fn"]),
        nondet!(
            "secret_plugin_state",
            state_produce,
            state_check,
            &["master"]
        ),
        nondet!(
            "secret_plugin_config",
            config_produce,
            config_check,
            &["master", "plaintext"]
        ),
        nondet!(
            "oauth_completion_aead",
            completion_produce,
            completion_check,
            &["material"]
        ),
        det!("token_stream", token_stream, &["secret", "iat", "exp"]),
        det!(
            "token_access",
            token_access,
            &["secret", "iat", "exp", "token_type"]
        ),
        det!("token_profile", token_profile, &["secret", "iat", "exp"]),
        det!("token_room", token_room, &["secret", "iat", "exp"]),
        det!("token_theme_grant", token_theme, &["secret", "iat", "exp"]),
        det!("token_abs", token_abs, &["secret", "iat", "exp", "type"]),
        det!(
            "jwt_semantics",
            jwt_semantics,
            &["secret", "mode", "now_nanos"]
        ),
        det!(
            "jwt_rs256",
            jwt_rs256,
            &["n", "e", "alg", "now_nanos", "exp", "kid", "token_kid"]
        ),
        nondet!(
            "jwt_vapid",
            vapid_produce,
            vapid_check,
            &["endpoint", "public", "private", "exp"]
        ),
        nondet!(
            "bcrypt_generate",
            bcrypt_produce,
            bcrypt_check,
            &["password", "cost"]
        ),
        det!("bcrypt_compare", bcrypt_compare, &["*"]),
        det!("credential_hashes", credential_hashes, &["fn"]),
        det!("api_key", api_key),
        det!("api_key_valid_text", api_key_valid_text),
        det!("oauth_state", oauth_state, &["expires_nanos"]),
        det!("oauth_state_verify", oauth_state_verify, &["secret"]),
        det!(
            "playback_plan_identity",
            plan_identity,
            &[
                "audio_track",
                "sub_track",
                "transforms",
                "quirks",
                "hls_group",
                "embedded_idx",
                "width",
                "height",
                "bitrate"
            ]
        ),
        nondet!(
            "playback_directplay_etag",
            directplay_produce,
            directplay_check,
            &["*"]
        ),
        det!("playback_connection_key", connection_key, &["ip", "secret"]),
        det!("tonemap_revision", tonemap_revision),
        det!("downloads_params_hash", params_hash),
        det!("downloads_metadata_etag", metadata_etag, &["Modified"]),
        det!(
            "downloads_execution_fingerprint",
            execution_fingerprint,
            &[
                "tone_map_source_revision",
                "prepared_tracks",
                "total_duration"
            ]
        ),
        det!(
            "marker_identity",
            marker_identity,
            &["Modified", "Start", "End"]
        ),
        det!(
            "jellycompat_image_tags",
            image_tags,
            &["updated", "secret", "key"]
        ),
        det!("persisted_hashes", persisted_hashes, &["fn", "n", "m"]),
        det!(
            "inline_hash_expressions",
            inline_expressions,
            &["file_id", "user", "day"]
        ),
        det!("uuid_v5_ids", uuid_v5_ids),
        det!("settings_jcs", settings_jcs, &["*"]),
        det!("settings_ecmascript_number", ecmascript, &["*"]),
        det!("settings_contract_etag", contract_etag, &["*"]),
        nondet!(
            "unicode_norm_table",
            norm_table_produce,
            norm_table_check,
            &["*"]
        ),
        det!("push_intent", push_intent),
        det!("settings_etag_digest", settings_etag_digest, &["*"]),
        det!("artwork_base_path", artwork_base_path, &["ImageType"]),
        det!("secret_backfill_targets", backfill_targets, &["*"]),
        nondet!(
            "advisory_lock_constants",
            advisory_locks_produce,
            advisory_locks_check,
            &["*"]
        ),
        nondet!("minted_credentials", minted_produce, minted_check, &["*"]),
        det!("naming_group_key", naming_group_key),
        det!("naming_presentation_group", naming_presentation_group),
        det!("embedding_text", embedding_text, &["kind", "Overview"]),
        det!(
            "keyframe_plan",
            keyframe_plan,
            &["keyframes", "segment", "end"]
        ),
        det!("search_fold", search_fold),
        det!("blobstore_keys", blobstore_keys, &["endpoint"]),
        det!(
            "s3_presign",
            s3_presign,
            &[
                "endpoint",
                "region",
                "bucket",
                "now_nanos",
                "expiry_seconds",
                "window_seconds"
            ]
        ),
        det!("thumbhash", thumbhash_family, &["*"]),
        det!("redis_channels_events", redis_channels, &["channel"]),
        nondet!(
            "redis_contract",
            redis_contract_produce,
            redis_contract_check,
            &["*"]
        ),
    ]
}

/// A small deterministic generator for the mutator.
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const POOL: &[&str] = &[
    "rust-side",
    "Ελληνικά",
    "ﾊﾝｶｸ",
    "a\u{301}b",
    " spaced ",
    "UPPER",
    "tt123",
    "42",
    "x<y>&z",
    "/some/path.mkv",
    "😀😀",
    "\u{2028}",
    "ſ",
    "\u{212a}elvin",
];

/// Changes an input so Rust's output covers inputs Go's generator never chose. Frozen keys stay put.
pub fn mutate(v: &Value, rng: &mut Rng, frozen: &[&str]) -> Value {
    if frozen.contains(&"*") {
        return v.clone();
    }
    match v {
        Value::String(text) => match rng.below(4) {
            0 => json!(POOL[rng.below(POOL.len() as u64) as usize]),
            1 => {
                let mut chars: Vec<char> = text.chars().collect();
                if chars.is_empty() {
                    return json!("z");
                }
                let at = rng.below(chars.len() as u64) as usize;
                chars[at] = char::from_u32(0x61 + rng.below(26) as u32).expect("ASCII");
                json!(chars.into_iter().collect::<String>())
            }
            2 => json!(format!(
                "{text}{}",
                POOL[rng.below(POOL.len() as u64) as usize]
            )),
            _ => v.clone(),
        },
        Value::Number(n) => match n.as_i64() {
            Some(x) if rng.below(2) == 0 => json!(x.wrapping_add(rng.below(1000) as i64)),
            _ => v.clone(),
        },
        Value::Bool(x) => json!(if rng.below(2) == 0 { !x } else { *x }),
        Value::Array(list) => {
            Value::Array(list.iter().map(|item| mutate(item, rng, frozen)).collect())
        }
        Value::Object(map) => {
            if map.len() == 1
                && let Some(Value::String(hex)) = map.get("hex")
            {
                let mut raw = hexgo::decode(hex).expect("hex");
                if !raw.is_empty() {
                    let at = rng.below(raw.len() as u64) as usize;
                    raw[at] ^= (rng.below(255) + 1) as u8;
                }
                return json!({"hex": hexgo::encode(raw)});
            }
            let mut out = serde_json::Map::new();
            for (k, item) in map {
                if frozen.contains(&k.as_str()) {
                    out.insert(k.clone(), item.clone());
                } else {
                    out.insert(k.clone(), mutate(item, rng, frozen));
                }
            }
            Value::Object(out)
        }
        Value::Null => Value::Null,
    }
}

pub fn read_cases(name: &str) -> Vec<(Value, Value)> {
    let path = vectors_dir().join(format!("{name}.json"));
    let file: Value =
        serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("{name}: {e}")))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
    file["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .map(|c| (c["in"].clone(), c["out"].clone()))
        .collect()
}

pub fn check_directplay(input: &Value, output: &Value) -> Result<(), String> {
    directplay_check(input, output)
}
