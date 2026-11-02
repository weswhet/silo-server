//! Differential test against the real Go packages: `internal/catalog`'s two settings repos and
//! `internal/userstore/pgstore`. It replays `rust/conformance/vectors/store/ops.json` through
//! `rust/conformance/harness/storediff` and through this crate, on two databases with one schema, then
//! asserts:
//! 1. every operation's outcome (ok/error kind/returned fields) is identical, in order;
//! 2. the two databases' relevant tables end in byte-identical content (`server_settings`,
//!    `user_setting_values`, `user_setting_mutations`), decrypting `enc:v1:` values first, since
//!    AES-GCM's random nonce makes raw ciphertext bytes differ between the two runs even when both
//!    are correct.
//!
//! Needs, as env vars (the test skips with a message if any are unset):
//! - `SILO_STORE_DIFFTEST_GO_REF_URL` / `SILO_STORE_DIFFTEST_RUST_REF_URL`: two already-migrated
//!   Postgres databases with `users` rows 1 and 2, and `user_profiles` rows `p1`, `p2`, and `p3` under
//!   user 1.
//! - `SILO_STORE_DIFFTEST_SECRET_KEY`: the `SECRET_KEY` both sides derive the cipher from.
//!
//! `cargo test -p silo-store --test differential -- --ignored --nocapture`

#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Arc;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use silo_config::resolve::{SettingIdentity, SettingResolutionQuery};
use silo_config::settings::{ClientFamily, Scope};
use silo_core::secret::{self, Cipher};
use silo_pg::{Pool, PoolConfig};
use silo_store::settings::{EncryptedSettingsRepo, ServerSettingsRepo};
use silo_store::userstore::SettingMutationRecord;
use silo_store::userstore::pgstore::PostgresUserStore;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

#[tokio::test]
#[ignore = "needs a throwaway two-database Postgres and a silo-server checkout; see module doc"]
async fn matches_go_byte_for_byte() {
    let Some(go_ref_url) = env("SILO_STORE_DIFFTEST_GO_REF_URL") else {
        eprintln!("SILO_STORE_DIFFTEST_GO_REF_URL is not set; skipping");
        return;
    };
    let repo_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let ops_path = repo_root
        .join("rust/conformance/vectors/store/ops.json")
        .to_string_lossy()
        .into_owned();
    let rust_ref_url =
        env("SILO_STORE_DIFFTEST_RUST_REF_URL").expect("SILO_STORE_DIFFTEST_RUST_REF_URL");
    let secret_key = env("SILO_STORE_DIFFTEST_SECRET_KEY").expect("SILO_STORE_DIFFTEST_SECRET_KEY");

    // 1. Run the real Go program against go_ref.
    let go_out = std::env::temp_dir().join(format!(
        "silo-store-difftest-go-{}.jsonl",
        std::process::id()
    ));
    let status = Command::new("go")
        .args([
            "run",
            "./rust/conformance/harness/storediff",
            &ops_path,
            &go_ref_url,
            &secret_key,
            go_out.to_str().unwrap(),
        ])
        .env("GOTOOLCHAIN", "go1.26.10")
        .current_dir(&repo_root)
        .status()
        .expect("running the go harness");
    assert!(status.success(), "go harness exited non-zero");
    let go_outcomes = read_jsonl(&go_out);

    // 2. Run this crate against rust_ref, replaying the same ops.json.
    let file: Value = serde_json::from_str(&std::fs::read_to_string(&ops_path).unwrap()).unwrap();
    let ops = file["ops"].as_array().expect("ops array");

    let pool = Arc::new(
        Pool::connect(PoolConfig::parse(&rust_ref_url).unwrap())
            .await
            .unwrap(),
    );
    let cipher = Cipher::new(secret_key.as_bytes()).unwrap();
    let raw_repo = ServerSettingsRepo::new(pool.clone());
    let enc_repo =
        EncryptedSettingsRepo::new(ServerSettingsRepo::new(pool.clone()), cipher.clone());
    let store1 = PostgresUserStore::new(pool.clone(), 1);
    let store2 = PostgresUserStore::new(pool.clone(), 2);

    let mut rust_outcomes = Vec::with_capacity(ops.len());
    for op in ops {
        rust_outcomes.push(run_op(op, &enc_repo, &raw_repo, &store1, &store2).await);
    }

    assert_eq!(rust_outcomes.len(), go_outcomes.len(), "op count mismatch");
    for (i, (rust, go)) in rust_outcomes.iter().zip(go_outcomes.iter()).enumerate() {
        assert_eq!(rust, go, "op #{} ({}) diverged", i + 1, op_kind(&ops[i]));
    }

    for outcome in &go_outcomes {
        let kind = outcome["error_kind"].as_str().unwrap_or("");
        assert!(
            kind != "MISSING_EXPECTED_ERROR" && !kind.starts_with("unknown_op_kind"),
            "{outcome}"
        );
    }

    // 3. Compare final table content, byte for byte after decrypting enc:v1 values.
    let go_pool = Pool::connect(PoolConfig::parse(&go_ref_url).unwrap())
        .await
        .unwrap();
    let (go_digest, go_dump) = dump_digest(&go_pool, &cipher).await;
    let (rust_digest, rust_dump) = dump_digest(&pool, &cipher).await;
    assert_eq!(
        go_dump, rust_dump,
        "final table content diverged (digests: go={go_digest} rust={rust_digest})"
    );
    assert_eq!(go_digest, rust_digest);
    println!(
        "silo-store differential: {} ops, table digest {go_digest}",
        ops.len()
    );

    let _ = std::fs::remove_file(&go_out);
}

fn op_kind(op: &Value) -> &str {
    op["kind"].as_str().unwrap_or("?")
}

fn read_jsonl(path: &std::path::Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn s(op: &Value, field: &str) -> String {
    op[field].as_str().unwrap_or("").to_owned()
}

fn ident_from_json(v: &Value) -> SettingIdentity {
    SettingIdentity {
        key: s(v, "key"),
        scope: Scope::new(s(v, "scope")),
        profile_id: s(v, "profile_id"),
        client_family: ClientFamily::new(s(v, "client_family")),
        device_id: s(v, "device_id"),
        library_id: v["library_id"].as_i64().unwrap_or(0),
        series_id: s(v, "series_id"),
    }
}

fn identity_json(id: &SettingIdentity) -> Value {
    json!({
        "key": id.key, "scope": id.scope.as_str(), "profile_id": id.profile_id,
        "client_family": id.client_family.as_str(), "device_id": id.device_id,
        "library_id": id.library_id, "series_id": id.series_id,
    })
}

/// The same sort key the Go harness's `valuesDetail` uses (`fmt.Sprint` of a map sorts its keys
/// alphabetically): client_family, device_id, key, library_id, profile_id, scope, series_id.
fn sort_key(id: &SettingIdentity) -> (String, String, String, String, String, String, String) {
    (
        id.client_family.as_str().to_owned(),
        id.device_id.clone(),
        id.key.clone(),
        id.library_id.to_string(),
        id.profile_id.clone(),
        id.scope.as_str().to_owned(),
        id.series_id.clone(),
    )
}

fn setting_value_detail(v: Option<&silo_config::resolve::SettingValue>) -> Value {
    match v {
        None => json!({"found": false}),
        Some(v) => json!({
            "found": true,
            "revision": v.revision,
            "value": String::from_utf8_lossy(&v.value),
            "identity": identity_json(&v.identity),
        }),
    }
}

fn values_detail(mut vals: Vec<silo_config::resolve::SettingValue>) -> Value {
    vals.sort_by_key(|v| sort_key(&v.identity));
    Value::Array(vals.iter().map(|v| setting_value_detail(Some(v))).collect())
}

fn ok(id: &Value, kind: &str, detail: Option<Value>) -> Value {
    let mut m = Map::new();
    m.insert("id".into(), id.clone());
    m.insert("kind".into(), json!(kind));
    m.insert("ok".into(), json!(true));
    if let Some(d) = detail {
        m.insert("detail".into(), d);
    }
    Value::Object(m)
}

fn err(id: &Value, kind: &str, error_kind: &str) -> Value {
    json!({"id": id, "kind": kind, "ok": false, "error_kind": error_kind})
}

fn classify_settings_err(e: &silo_store::settings::Error) -> &'static str {
    use silo_store::settings::Error as E;
    match e {
        E::NotUtf8 { .. } => "other_error",
        _ => "other_error",
    }
}

fn classify_pgstore_err(e: &silo_store::userstore::pgstore::Error) -> &'static str {
    use silo_store::userstore::Error as UE;
    use silo_store::userstore::pgstore::Error as E;
    match e {
        E::RevisionConflict => "revision_conflict",
        E::Invalid(UE::InvalidIdentity(_)) => "invalid_identity",
        E::Invalid(UE::InvalidValue(_)) => "invalid_value",
        E::Invalid(UE::RevisionConflict) => "revision_conflict",
        _ => "other_error",
    }
}

async fn run_op(
    op: &Value,
    enc_repo: &EncryptedSettingsRepo,
    raw_repo: &ServerSettingsRepo,
    store1: &PostgresUserStore,
    store2: &PostgresUserStore,
) -> Value {
    let id = &op["id"];
    let kind = op_kind(op);
    let store = if op["user"].as_str() == Some("other") {
        store2
    } else {
        store1
    };
    let expect_error = op["expect_error"].as_bool().unwrap_or(false);

    match kind {
        "settings_set" => match enc_repo
            .set(&s(op, "key"), op["value"].as_str().unwrap())
            .await
        {
            Ok(()) => ok(id, kind, None),
            Err(e) => err(id, kind, classify_settings_err(&e)),
        },
        "settings_raw_set" => match raw_repo
            .set(&s(op, "key"), op["value"].as_str().unwrap())
            .await
        {
            Ok(()) => ok(id, kind, None),
            Err(e) => err(id, kind, classify_settings_err(&e)),
        },
        "settings_get" => match enc_repo.get(&s(op, "key")).await {
            Ok(v) => ok(id, kind, Some(json!({"value": v}))),
            Err(e) => err(id, kind, classify_settings_err(&e)),
        },
        "settings_get_many" => {
            let keys: Vec<&str> = op["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k.as_str().unwrap())
                .collect();
            match enc_repo.get_many(&keys).await {
                Ok(m) => ok(id, kind, Some(json!({"values": sorted(&m)}))),
                Err(e) => err(id, kind, classify_settings_err(&e)),
            }
        }
        "settings_get_all" => match enc_repo.get_all().await {
            Ok(m) => {
                let filtered: BTreeMap<String, String> = m
                    .into_iter()
                    .filter(|(k, _)| k.starts_with("difftest."))
                    .collect();
                ok(id, kind, Some(json!({"values": filtered})))
            }
            Err(e) => err(id, kind, classify_settings_err(&e)),
        },
        "settings_set_many" => {
            let values = op["values"].as_object().unwrap();
            let pairs: Vec<(&str, &str)> = values
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str().unwrap()))
                .collect();
            match enc_repo.set_many(&pairs).await {
                Ok(()) => ok(id, kind, None),
                Err(e) => err(id, kind, classify_settings_err(&e)),
            }
        }
        "settings_set_if_absent" => {
            match enc_repo
                .set_if_absent(&s(op, "key"), op["value"].as_str().unwrap())
                .await
            {
                Ok(inserted) => ok(id, kind, Some(json!({"inserted": inserted}))),
                Err(e) => err(id, kind, classify_settings_err(&e)),
            }
        }
        "settings_backfill" => {
            let (n, errs) = enc_repo.backfill_sensitive_settings().await;
            if !errs.is_empty() {
                err(id, kind, "other_error")
            } else {
                ok(id, kind, Some(json!({"encrypted_count_nonzero": n > 0})))
            }
        }
        "settings_update_atomic" => {
            let derive_key = s(op, "derive_key");
            let write_key = s(op, "write_key");
            let suffix = s(op, "suffix");
            let result = enc_repo
                .update_atomic(|current| {
                    let mut out = std::collections::HashMap::new();
                    let base = current.get(&derive_key).cloned().unwrap_or_default();
                    out.insert(write_key.clone(), base + &suffix);
                    Ok::<_, String>(out)
                })
                .await;
            match result {
                Ok(()) => ok(id, kind, None),
                Err(_) => err(id, kind, "other_error"),
            }
        }
        "settings_update_atomic_fail" => {
            let result: Result<(), _> = enc_repo
                .update_atomic(|_current| {
                    Err::<std::collections::HashMap<String, String>, _>(
                        "deliberate validator failure".to_owned(),
                    )
                })
                .await;
            match result {
                Ok(()) => ok(id, kind, None),
                Err(silo_store::settings::UpdateError::Update(_)) => {
                    err(id, kind, "validator_error")
                }
                Err(silo_store::settings::UpdateError::Store(_)) => err(id, kind, "other_error"),
            }
        }

        "uv_upsert" => {
            let identity = ident_from_json(&op["identity"]);
            let value = op["value"].to_string();
            let result = store
                .upsert_setting_value(&identity, value.as_bytes())
                .await;
            finish_uv(id, kind, result.map(Some), expect_error)
        }
        "uv_upsert_raw_value" => {
            let identity = ident_from_json(&op["identity"]);
            let raw = s(op, "raw_value");
            let result = store.upsert_setting_value(&identity, raw.as_bytes()).await;
            finish_uv(id, kind, result.map(|_| None), expect_error)
        }
        "uv_get" => {
            let identity = ident_from_json(&op["identity"]);
            match store.get_setting_value(&identity).await {
                Ok(v) => ok(id, kind, Some(setting_value_detail(v.as_ref()))),
                Err(e) => err(id, kind, classify_pgstore_err(&e)),
            }
        }
        "uv_compare_and_set" => {
            let identity = ident_from_json(&op["identity"]);
            let value = op["value"].to_string();
            let expected_revision = op["expected_revision"].as_i64().unwrap_or(0);
            let result = store
                .compare_and_set_setting_value(&identity, value.as_bytes(), expected_revision)
                .await;
            finish_uv(id, kind, result.map(Some), expect_error)
        }
        "uv_delete" => {
            let identity = ident_from_json(&op["identity"]);
            match store.delete_setting_value(&identity).await {
                Ok(deleted) => ok(id, kind, Some(json!({"deleted": deleted}))),
                Err(e) => err(id, kind, classify_pgstore_err(&e)),
            }
        }
        "uv_delete_for_profile" => match store
            .delete_setting_values_for_profile(&s(op, "profile_id"))
            .await
        {
            Ok(n) => ok(id, kind, Some(json!({"count": n}))),
            Err(e) => err(id, kind, classify_pgstore_err(&e)),
        },
        "uv_delete_for_device" => match store
            .delete_setting_values_for_device(&s(op, "profile_id"), &s(op, "device_id"))
            .await
        {
            Ok(n) => ok(id, kind, Some(json!({"count": n}))),
            Err(e) => err(id, kind, classify_pgstore_err(&e)),
        },
        "uv_delete_for_library" => match store
            .delete_setting_values_for_library(op["library_id"].as_i64().unwrap_or(0))
            .await
        {
            Ok(n) => ok(id, kind, Some(json!({"count": n}))),
            Err(e) => err(id, kind, classify_pgstore_err(&e)),
        },
        "uv_delete_for_series" => match store
            .delete_setting_values_for_series(&s(op, "series_id"))
            .await
        {
            Ok(n) => ok(id, kind, Some(json!({"count": n}))),
            Err(e) => err(id, kind, classify_pgstore_err(&e)),
        },
        "uv_list_for_resolution" => {
            let q = &op["query"];
            let query = SettingResolutionQuery {
                keys: str_vec(&q["keys"]),
                profile_ids: str_vec(&q["profile_ids"]),
                client_family: ClientFamily::new(s(q, "client_family")),
                device_id: s(q, "device_id"),
                library_ids: i64_vec(&q["library_ids"]),
                series_ids: str_vec(&q["series_ids"]),
            };
            match store.list_setting_values_for_resolution(&query).await {
                Ok(vals) => ok(id, kind, Some(json!({"values": values_detail(vals)}))),
                Err(e) => err(id, kind, classify_pgstore_err(&e)),
            }
        }
        "uv_list_all" => match store.list_all_setting_values().await {
            Ok(vals) => ok(id, kind, Some(json!({"values": values_detail(vals)}))),
            Err(e) => err(id, kind, classify_pgstore_err(&e)),
        },
        "uv_list_by_scope" => {
            let profile_id = s(op, "profile_id");
            let scope = Scope::new(s(op, "scope"));
            let keys = str_vec(&op["keys"]);
            match store
                .list_setting_values_by_scope(&profile_id, &scope, &keys)
                .await
            {
                Ok(vals) => ok(id, kind, Some(json!({"values": values_detail(vals)}))),
                Err(e) => err(id, kind, classify_pgstore_err(&e)),
            }
        }
        "uv_mutation_put" => {
            let record = SettingMutationRecord {
                mutation_id: s(op, "mutation_id"),
                request_hash: s(op, "request_hash"),
                result: op["result"].to_string().into_bytes(),
                created_at: String::new(),
                expires_at: s(op, "expires_at"),
            };
            let result = store.put_setting_mutation(&record).await;
            if expect_error {
                return match result {
                    Ok(_) => err(id, kind, "MISSING_EXPECTED_ERROR"),
                    Err(e) => err(id, kind, classify_pgstore_err(&e)),
                };
            }
            match result {
                Ok((rec, inserted)) => ok(
                    id,
                    kind,
                    Some(json!({
                        "inserted": inserted, "mutation_id": rec.mutation_id,
                        "request_hash": rec.request_hash,
                        "result": String::from_utf8_lossy(&rec.result),
                    })),
                ),
                Err(e) => err(id, kind, classify_pgstore_err(&e)),
            }
        }
        "uv_mutation_get" => match store.get_setting_mutation(&s(op, "mutation_id")).await {
            Ok(None) => ok(id, kind, Some(json!({"found": false}))),
            Ok(Some(rec)) => ok(
                id,
                kind,
                Some(json!({
                    "found": true, "mutation_id": rec.mutation_id,
                    "request_hash": rec.request_hash,
                    "result": String::from_utf8_lossy(&rec.result),
                })),
            ),
            Err(e) => err(id, kind, classify_pgstore_err(&e)),
        },
        "uv_mutation_delete_expired" => match store
            .delete_expired_setting_mutations(&s(op, "before"))
            .await
        {
            Ok(n) => ok(id, kind, Some(json!({"count": n}))),
            Err(e) => err(id, kind, classify_pgstore_err(&e)),
        },
        other => err(id, kind, &format!("unknown_op_kind:{other}")),
    }
}

fn finish_uv(
    id: &Value,
    kind: &str,
    result: Result<
        Option<silo_config::resolve::SettingValue>,
        silo_store::userstore::pgstore::Error,
    >,
    expect_error: bool,
) -> Value {
    if expect_error {
        return match result {
            Ok(_) => err(id, kind, "MISSING_EXPECTED_ERROR"),
            Err(e) => err(id, kind, classify_pgstore_err(&e)),
        };
    }
    match result {
        Ok(v) => ok(id, kind, Some(setting_value_detail(v.as_ref()))),
        Err(e) => err(id, kind, classify_pgstore_err(&e)),
    }
}

fn str_vec(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().unwrap_or("").to_owned())
                .collect()
        })
        .unwrap_or_default()
}

fn i64_vec(v: &Value) -> Vec<i64> {
    v.as_array()
        .map(|a| a.iter().map(|x| x.as_i64().unwrap_or(0)).collect())
        .unwrap_or_default()
}

fn sorted(m: &std::collections::HashMap<String, String>) -> BTreeMap<String, String> {
    m.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
}

/// Dumps `server_settings`, `user_setting_values` and `user_setting_mutations`, decrypting any
/// `enc:v1:` value (both databases share the one `cipher`), excluding the server-generated
/// `created_at`/`updated_at` timestamps (real, but not reproducible across two separate runs), and
/// returns (sha256 hex digest, the canonical text itself, for a readable assertion failure).
async fn dump_digest(pool: &Pool, cipher: &Cipher) -> (String, String) {
    let mut session = pool.acquire().await.unwrap();
    let mut out = String::new();

    let mut settings: Vec<(String, String)> = session
        .query(
            "SELECT key, value FROM server_settings WHERE key LIKE 'difftest.%' \
             OR key IN ('tmdb.api_key','discord.bot_token','mdblist.api_key','introdb.api_key',\
             'requests.radarr.api_key','requests.sonarr.api_key','email.smtp_password') \
             ORDER BY key",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get::<_, String>(0), r.get::<_, String>(1)))
        .collect();
    settings.sort();
    for (key, value) in settings {
        let plain = cipher
            .decrypt_if_encrypted(&value, secret::aad::settings(&key))
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_else(|e| format!("<undecryptable: {e}>"));
        out.push_str(&format!("server_settings\t{key}\t{plain}\n"));
    }

    let rows = session
        .query(
            "SELECT user_id, key, scope, profile_id, client_family, device_id, library_id, series_id, \
                    value::text, revision \
             FROM user_setting_values ORDER BY user_id, key, scope, COALESCE(profile_id,''), \
                    COALESCE(client_family,''), COALESCE(device_id,''), COALESCE(library_id,0), \
                    COALESCE(series_id,'')",
            &[],
        )
        .await
        .unwrap();
    for r in &rows {
        let user_id: i32 = r.get(0);
        let key: String = r.get(1);
        let scope: String = r.get(2);
        let profile_id: Option<String> = r.get(3);
        let client_family: Option<String> = r.get(4);
        let device_id: Option<String> = r.get(5);
        let library_id: Option<i32> = r.get(6);
        let series_id: Option<String> = r.get(7);
        let value: String = r.get(8);
        let revision: i64 = r.get(9);
        out.push_str(&format!(
            "user_setting_values\t{user_id}\t{key}\t{scope}\t{}\t{}\t{}\t{}\t{}\t{revision}\t{value}\n",
            profile_id.unwrap_or_default(),
            client_family.unwrap_or_default(),
            device_id.unwrap_or_default(),
            library_id.map_or_else(String::new, |v| v.to_string()),
            series_id.unwrap_or_default(),
        ));
    }

    let rows = session
        .query(
            "SELECT user_id, mutation_id, request_hash, result::text \
             FROM user_setting_mutations ORDER BY user_id, mutation_id",
            &[],
        )
        .await
        .unwrap();
    for r in &rows {
        let user_id: i32 = r.get(0);
        let mutation_id: String = r.get(1);
        let request_hash: String = r.get(2);
        let result: String = r.get(3);
        out.push_str(&format!(
            "user_setting_mutations\t{user_id}\t{mutation_id}\t{request_hash}\t{result}\n"
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(out.as_bytes());
    (format!("{:x}", hasher.finalize()), out)
}
