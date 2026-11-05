//! Database-only autoscan mutations, matching the v2 services rather than legacy HTTP handlers.
use super::*;
use crate::native::chain::{Step, write_v2_json_status};
use crate::native::personal::raw_body;

const ADMIN_WRITE: &[Step] = &[
    Step::Auth,
    Step::DemoRestricted,
    Step::RateLimit,
    Step::Viewer,
    Step::ActingAdmin,
];

#[derive(Default, Deserialize)]
#[serde(default)]
struct ConnectionBody {
    name: String,
    kind: String,
    base_url: String,
    api_key_ref: String,
    request_integration_id: Option<String>,
}

fn failure(detail: &str) -> Problem {
    Problem::new(internal_error(), detail)
}
fn missing(detail: &str) -> Problem {
    Problem::new(silo_api_v2::problem::type_for_status(404), detail)
}
fn connection_input(r: &Request) -> Result<store::Connection, Problem> {
    // The shared Huma wrapper validates required/unknown properties, lengths, URI format,
    // and path bounds. Optional null values retain Go's zero values.
    let body: ConnectionBody = silo_gocompat::json::unmarshal(&raw_body(r)).unwrap_or_default();
    normalize_connection(body, r.url_param("id"))
}
fn normalize_connection(body: ConnectionBody, id: &str) -> Result<store::Connection, Problem> {
    let request_integration_id = body.request_integration_id.and_then(|v| {
        let v = trim_space(&v);
        (!v.is_empty()).then(|| v.to_owned())
    });
    let name = trim_space(&body.name);
    let base_url = trim_space(&body.base_url);
    if name.is_empty() || (base_url.is_empty() && request_integration_id.is_none()) {
        return Err(Problem::new(
            silo_api_v2::problem::validation_failed(),
            "A connection name and base URL or request integration are required.",
        ));
    }
    Ok(store::Connection {
        id: trim_space(id).into(),
        name: name.into(),
        kind: trim_space(&body.kind).into(),
        base_url: base_url.into(),
        api_key_ref: trim_space(&body.api_key_ref).into(),
        request_integration_id,
    })
}
async fn write_connection(
    s: &Stack,
    r: &Request,
    create: bool,
) -> Result<AdminAutoscanConnection, Problem> {
    let input = connection_input(r)?;
    let result = if create {
        store::create_connection(&s.pool, &s.cipher, &input).await
    } else {
        store::update_connection(&s.pool, &s.cipher, &input).await
    };
    let row = result.map_err(|err| match err {
        store::WriteError::NotFound if !create => missing("Autoscan connection not found."),
        _ => failure(if create {
            "Connection creation could not be confirmed."
        } else {
            "Connection update could not be confirmed."
        }),
    })?;
    if row.id.is_empty() {
        return Err(failure(if create {
            "Connection creation returned no identity; completion is uncertain."
        } else {
            "Connection update returned no identity; completion is uncertain."
        }));
    }
    Ok(AdminAutoscanConnection {
        id: row.id,
        name: row.name,
        kind: row.kind,
        base_url: row.base_url,
        request_integration_id: row.request_integration_id,
        has_api_key: !trim_space(&row.api_key_ref).is_empty(),
    })
}
fn webhook_problem(err: store::WriteError) -> Problem {
    match err {
        store::WriteError::NotFound => missing("Source or webhook endpoint not found."),
        _ => failure(
            "Webhook change could not be confirmed. Refresh source state before another explicit submission.",
        ),
    }
}
async fn webhook_source(s: &Stack, row: store::Source) -> AdminAutoscanSource {
    let mut body = source(row);
    let endpoint = match store::get_webhook_endpoint(&s.pool, &body.id).await {
        Ok(v) => v,
        Err(store::WriteError::NotFound) => return body,
        Err(error) => {
            tracing::warn!(?error, source_id = %body.id, "autoscan: load webhook endpoint failed");
            return body;
        }
    };
    body.webhook_configured = true;
    body.webhook_secret_suffix = endpoint.secret_suffix;
    body.webhook_last_received_at = instant_opt(endpoint.last_received_at);
    body.webhook_last_error_at = instant_opt(endpoint.last_error_at);
    body.webhook_last_error_message = endpoint.last_error_message;
    match store::reveal_webhook_token(&s.pool, &s.cipher, &endpoint.source_id).await {
        Ok(token) => {
            let public_url = s
                .settings
                .get("server.public_url")
                .await
                .unwrap_or_default();
            let public_url = trim_space(&public_url).trim_end_matches('/');
            body.webhook_url = format!("{public_url}/api/v2/autoscan/webhooks/{token}");
        }
        Err(error) => {
            tracing::warn!(%error, source_id = %body.id, "autoscan: reveal webhook token failed")
        }
    }
    body
}
async fn write_webhook(
    s: &Stack,
    r: &Request,
    rotate: bool,
) -> Result<AdminAutoscanSource, Problem> {
    let id = trim_space(r.url_param("id"));
    let row = store::get_source(&s.pool, id)
        .await
        .map_err(webhook_problem)?;
    if rotate {
        store::rotate_webhook_endpoint(&s.pool, &s.cipher, id)
            .await
            .map_err(webhook_problem)?;
    } else {
        if row.delivery_mode != "webhook" {
            return Err(Problem::new(
                silo_api_v2::problem::validation_failed(),
                "Source is not in webhook delivery mode.",
            ));
        }
        store::create_webhook_endpoint(&s.pool, &s.cipher, id)
            .await
            .map_err(webhook_problem)?;
    }
    Ok(webhook_source(s, row).await)
}
#[derive(Clone, Copy)]
enum Delete {
    Connection,
    Source,
    Webhook,
}
async fn delete(s: &Stack, r: &Request, kind: Delete) -> Result<(), Problem> {
    let id = trim_space(r.url_param("id"));
    let (result, not_found, detail) = match kind {
        Delete::Connection => (
            store::delete_connection(&s.pool, id).await,
            "Autoscan connection not found.",
            "Connection deletion could not be confirmed. Refresh connections and check source bindings before submitting again.",
        ),
        Delete::Source => (
            store::delete_source(&s.pool, id).await,
            "Autoscan source not found.",
            "Source deletion could not be confirmed. Refresh sources before submitting again; running work may continue.",
        ),
        Delete::Webhook => {
            return store::delete_webhook_endpoint(&s.pool, id)
                .await
                .map_err(webhook_problem);
        }
    };
    result.map_err(|err| match err {
        store::WriteError::NotFound => missing(not_found),
        _ => failure(detail),
    })
}
pub(super) fn mount(stack: &Arc<Stack>, v2: &Mux) {
    for (path, create) in [
        ("/api/v2/admin/autoscan/connections", true),
        ("/api/v2/admin/autoscan/connections/{id}", false),
    ] {
        let s = stack.clone();
        let handler = stack.v2_steps(
            path,
            ADMIN_WRITE,
            handler_fn(move |w, r| {
                let s = s.clone();
                Box::pin(async move {
                    match write_connection(&s, r, create).await {
                        Ok(body) => {
                            write_v2_json_status(w, if create { 201 } else { 200 }, &body).await
                        }
                        Err(p) => write_problem(w, r, p).await,
                    }
                })
            }),
        );
        if create {
            v2.post(path, handler);
        } else {
            v2.put(path, handler);
        }
    }
    for (path, rotate) in [
        ("/api/v2/admin/autoscan/sources/{id}/webhook", false),
        ("/api/v2/admin/autoscan/sources/{id}/webhook/rotate", true),
    ] {
        let s = stack.clone();
        v2.post(
            path,
            stack.v2_steps(
                path,
                ADMIN_WRITE,
                handler_fn(move |w, r| {
                    let s = s.clone();
                    Box::pin(async move {
                        match write_webhook(&s, r, rotate).await {
                            Ok(body) => write_v2_json(w, &body).await,
                            Err(p) => write_problem(w, r, p).await,
                        }
                    })
                }),
            ),
        );
    }
    for (path, kind) in [
        (
            "/api/v2/admin/autoscan/connections/{id}",
            Delete::Connection,
        ),
        ("/api/v2/admin/autoscan/sources/{id}", Delete::Source),
        (
            "/api/v2/admin/autoscan/sources/{id}/webhook",
            Delete::Webhook,
        ),
    ] {
        let s = stack.clone();
        v2.delete(
            path,
            stack.v2_steps(
                path,
                ADMIN_WRITE,
                handler_fn(move |w, r| {
                    let s = s.clone();
                    Box::pin(async move {
                        match delete(&s, r, kind).await {
                            Ok(()) => w.write_header(204).await,
                            Err(p) => write_problem(w, r, p).await,
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
    fn connection_normalization_matches_go_zero_values_and_whitespace() {
        for raw in [
            r#"{"name":" name ","kind":" kind ","base_url":" /relative ","api_key_ref":null,"request_integration_id":null}"#,
            r#"{"name":" name ","kind":" kind ","base_url":" /relative ","api_key_ref":"\u2003 ","request_integration_id":"\u2003 "}"#,
        ] {
            let input = silo_gocompat::json::unmarshal(raw.as_bytes()).unwrap();
            let row = normalize_connection(input, " id ").unwrap();
            assert_eq!(row.id, "id");
            assert_eq!(row.name, "name");
            assert_eq!(row.kind, "kind");
            assert_eq!(row.base_url, "/relative");
            assert!(row.api_key_ref.is_empty()); // A blank update preserves the stored key.
            assert!(row.request_integration_id.is_none());
        }
        let input = silo_gocompat::json::unmarshal(
            br#"{"name":"name","request_integration_id":" integration ","api_key_ref":" secret value "}"#,
        ).unwrap();
        let row = normalize_connection(input, "").unwrap();
        assert_eq!(row.request_integration_id.as_deref(), Some("integration"));
        assert_eq!(row.api_key_ref, "secret value");
        let input = silo_gocompat::json::unmarshal(
            br#"{"name":"name","base_url":null,"request_integration_id":" "}"#,
        )
        .unwrap();
        assert!(normalize_connection(input, "").is_err());
    }
}
