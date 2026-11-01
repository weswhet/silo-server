//! Rows and tokens from the running conformance stack, read only:
//!
//!     cargo test -p silo-core --test conformance_pg -- --ignored
//!
//! It needs the baseline stack from `rust/conformance`. The fixture's secrets are synthetic, and nothing
//! here writes to the database.

#![allow(clippy::disallowed_methods)] // Plain relative paths to test data.

use std::io::{Read, Write};

use postgres::{Client, NoTls};
use silo_core::secret::{Cipher, Error, aad};
use silo_core::{apikey, lantls, passwordhash, tokens};
use silo_jwt::{Parser, VapidKeys, parse_unverified, vapid_authorization_header};

fn fixture() -> std::collections::HashMap<String, String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/baseline/fixture.env");
    std::fs::read_to_string(path)
        .expect("fixture.env")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| {
            let v = v.trim_matches('"');
            // Port lines read ${NAME:-default}.
            let v = v
                .strip_prefix("${")
                .and_then(|inner| inner.strip_suffix('}'))
                .and_then(|inner| inner.split_once(":-"))
                .map_or(v, |(_, default)| default);
            (k.to_owned(), v.to_owned())
        })
        .collect()
}

fn connect(env: &std::collections::HashMap<String, String>) -> Client {
    let port = env.get("CONF_PG_PORT").map_or("25432", String::as_str);
    Client::connect(
        &format!("host=127.0.0.1 port={port} user=silo password=silo dbname=silo"),
        NoTls,
    )
    .expect("conformance Postgres on its loopback port")
}

fn http_get(port: &str, path: &str, bearer: &str) -> (u16, String) {
    let mut stream = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).expect("server");
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {bearer}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    )
    .expect("request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("response");
    let status = response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status");
    (status, response)
}

#[test]
#[ignore = "needs the conformance stack"]
fn decrypts_every_enc_v1_row() {
    let env = fixture();
    let cipher = Cipher::new(env["CONF_SECRET_KEY"].as_bytes()).expect("cipher");
    let mut db = connect(&env);
    let mut total = 0;

    let settings = db
        .query(
            "SELECT key, value FROM server_settings WHERE value LIKE 'enc:v1:%'",
            &[],
        )
        .expect("settings");
    assert!(!settings.is_empty(), "the seed has encrypted settings");
    let mut jwt_secret = String::new();
    let mut vapid = None;
    for row in &settings {
        let (key, value): (String, String) = (row.get(0), row.get(1));
        let plain = cipher
            .decrypt(&value, aad::settings(&key))
            .unwrap_or_else(|e| panic!("{key}: {e}"));
        total += 1;
        // A row is GCM-bound to its key name, so renaming it must make it undecryptable.
        assert_eq!(
            cipher.decrypt(&value, aad::settings(&format!("{key}.renamed"))),
            Err(Error::Authenticate),
            "{key} decrypted under another name"
        );
        assert_eq!(
            cipher
                .decrypt_if_encrypted(&value, aad::settings(&key))
                .expect("read path"),
            plain
        );
        match key.as_str() {
            "auth.jwt_secret" => jwt_secret = String::from_utf8(plain).expect("text"),
            "notifications.web_push.vapid_keypair" => {
                vapid = Some(String::from_utf8(plain).expect("text"));
            }
            _ => {}
        }
    }
    assert_eq!(
        jwt_secret, env["CONF_JWT_SECRET"],
        "the decrypted signing secret is the fixture's"
    );

    for row in db
        .query(
            "SELECT token, streamapp_access_token, streamapp_refresh_token FROM jellycompat_sessions \
             WHERE streamapp_access_token LIKE 'enc:v1:%'",
            &[],
        )
        .expect("sessions")
    {
        let (token, access, refresh): (String, String, String) = (row.get(0), row.get(1), row.get(2));
        let access_plain = cipher
            .decrypt(&access, aad::jellycompat_token("streamapp_access_token", &token))
            .expect("access token");
        let refresh_plain = cipher
            .decrypt(&refresh, aad::jellycompat_token("streamapp_refresh_token", &token))
            .expect("refresh token");
        assert_eq!(
            cipher.decrypt(&access, aad::jellycompat_token("streamapp_refresh_token", &token)),
            Err(Error::Authenticate),
            "a credential moved to another column must fail"
        );
        total += 2;

        // Go signed these. Check them at their own issue time, because they may have expired since.
        for raw in [&access_plain, &refresh_plain] {
            let raw = std::str::from_utf8(raw).expect("JWT text");
            let claims = parse_unverified::<tokens::AccessClaims>(raw).expect("claims").claims;
            let iat = i128::from(claims.registered.issued_at.expect("iat").0) * 1_000_000_000;
            let verified = tokens::validate_access(raw, jwt_secret.as_bytes(), Parser::new().at(iat))
                .expect("a Go-signed token verifies");
            assert_eq!(verified, claims);
            // Same claims, same bytes: our signature over Go's claims is Go's token.
            let again = silo_jwt::sign_hs256(&claims, jwt_secret.as_bytes()).expect("sign");
            assert_eq!(again, raw, "re-signing a Go token");
        }
        assert!(
            tokens::stored_refresh_token_session_id(std::str::from_utf8(&refresh_plain).unwrap()).is_some()
        );
    }

    for row in db
        .query(
            "SELECT id::text, fcm_token_ciphertext, fcm_token_hash FROM push_devices \
             WHERE fcm_token_ciphertext LIKE 'enc:v1:%'",
            &[],
        )
        .expect("push devices")
    {
        let (id, ciphertext, hash): (String, String, String) = (row.get(0), row.get(1), row.get(2));
        let plain = cipher
            .decrypt(&ciphertext, aad::push_device_fcm(&id))
            .expect("FCM token");
        total += 1;
        assert_eq!(
            apikey::fcm_token_hash(std::str::from_utf8(&plain).unwrap()),
            hash
        );
    }
    assert!(total >= 9, "decrypted only {total} rows");
    println!("decrypted {total} enc:v1 rows");

    // A real VAPID pair, decrypted, signs a header the pair's public key verifies.
    let pair: serde_json::Value = serde_json::from_str(&vapid.expect("VAPID row")).expect("pair");
    let keys = VapidKeys {
        public: pair["public"].as_str().expect("public").to_owned(),
        private: pair["private"].as_str().expect("private").to_owned(),
    };
    let header = vapid_authorization_header(
        "https://push.example/x",
        "admin@example.com",
        &keys,
        1_900_000_000,
    )
    .expect("header");
    let token = header
        .strip_prefix("vapid t=")
        .and_then(|h| h.split(", k=").next())
        .expect("shape");
    let public = silo_jwt::decode_vapid_key(&keys.public).expect("key");
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&public).expect("point");
    Parser::new()
        .at(1_000_000_000_000_000_000)
        .valid_methods(&["ES256"])
        .parse::<silo_jwt::RegisteredClaims, _>(token, |_| Ok(silo_jwt::Key::Es256(key)))
        .expect("signature");
}

#[test]
#[ignore = "needs the conformance stack"]
fn stored_credentials_verify() {
    let env = fixture();
    let mut db = connect(&env);
    for (name, key_var, password_var) in [
        ("conf-admin", "CONF_ADMIN_API_KEY", "CONF_ADMIN_PASSWORD"),
        ("conf-user", "CONF_USER_API_KEY", "CONF_USER_PASSWORD"),
    ] {
        let username = env
            .get(if name == "conf-admin" {
                "CONF_ADMIN_USERNAME"
            } else {
                "CONF_USER_USERNAME"
            })
            .unwrap();
        let row = db
            .query_one(
                "SELECT id, password_hash FROM users WHERE username = $1",
                &[username],
            )
            .expect("user");
        let (id, hash): (i64, String) = (row.get(0), row.get(1));
        assert_eq!(
            passwordhash::compare(hash.as_bytes(), env[password_var].as_bytes()),
            Ok(true),
            "{name} password"
        );
        assert_eq!(passwordhash::compare(hash.as_bytes(), b"wrong"), Ok(false));

        let key = &env[key_var];
        let found = db
            .query_opt(
                "SELECT key_prefix FROM api_keys WHERE user_id = $1::bigint AND key_hash = $2",
                &[&id, &apikey::api_key_hash(key.as_bytes())],
            )
            .expect("api key");
        let prefix: Option<String> = found.expect("the fixture key's hash is stored").get(0);
        // The fixture inserts its keys directly, as a legacy row would be.
        if let Some(prefix) = prefix.filter(|p| !p.is_empty()) {
            assert_eq!(prefix, apikey::api_key_prefix(key));
        }
    }
}

#[test]
#[ignore = "needs the conformance stack"]
fn the_go_server_accepts_rust_tokens_and_publishes_our_pin() {
    let env = fixture();
    let port = env.get("CONF_API_PORT").map_or("28080", String::as_str);
    let mut db = connect(&env);

    // An existing live session, so the check passes without writing anything.
    let row = db
        .query_opt(
            "SELECT s.id::text, s.user_id::bigint, u.role::text FROM auth_sessions s JOIN users u ON u.id = s.user_id \
             WHERE s.revoked_at IS NULL AND s.expires_at > now() AND s.impersonator_user_id IS NULL \
             AND s.purpose IS DISTINCT FROM 'remote_playback' LIMIT 1",
            &[],
        )
        .expect("sessions");
    let Some(row) = row else {
        panic!("the stack has no live login session to authenticate against");
    };
    let (session, user, role): (String, i64, String) = (row.get(0), row.get(1), row.get(2));
    let claims = tokens::AccessClaims {
        user_id: user,
        role,
        session_id: session,
        ..Default::default()
    };
    let now = silo_jwt::now_unix_nanos();
    let token = tokens::sign_access(
        claims,
        tokens::TOKEN_TYPE_ACCESS,
        3_600_000_000_000,
        None,
        now,
        env["CONF_JWT_SECRET"].as_bytes(),
    )
    .expect("sign");
    let (status, body) = http_get(port, "/api/v1/auth/me", &token);
    assert_eq!(
        status, 200,
        "the Go server refused a Rust-signed token: {body}"
    );
    let (refused, _) = http_get(port, "/api/v1/auth/me", &(token + "x"));
    assert_eq!(refused, 401, "control: a bad signature is refused");

    // The pin the Go server publishes is the one Rust derives from the same SECRET_KEY.
    let pin = lantls::pin(env["CONF_SECRET_KEY"].as_bytes()).expect("pin");
    let (status, body) = http_get(
        port,
        "/api/v2/system/connections",
        &env["CONF_ADMIN_API_KEY"],
    );
    assert_eq!(status, 200, "connections document: {body}");
    assert!(
        body.contains(&format!("\"spki_sha256\":\"{pin}\"")),
        "the served pin differs from {pin}: {body}"
    );
}
