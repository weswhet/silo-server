//! `internal/auditmutation`: a successful domain action's row, in the transaction that made the change.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use silo_pg::Session;

/// `auditmutation.Action*` and `Target*`.
pub const ACTION_IMPERSONATION_ENDED: &str = "user.impersonation_ended";
pub const ACTION_PASSWORD_CHANGED: &str = "user.password_changed";
pub const ACTION_LOGIN_SESSION_REVOKED: &str = "user.login_session_revoked";
pub const ACTION_API_KEY_CREATED: &str = "api_key.created";
pub const ACTION_API_KEY_UPDATED: &str = "api_key.updated";
pub const ACTION_API_KEY_DELETED: &str = "api_key.deleted";
pub const ACTION_PROFILE_CREATED: &str = "profile.created";
pub const ACTION_PROFILE_UPDATED: &str = "profile.updated";
pub const ACTION_PROFILE_DELETED: &str = "profile.deleted";
pub const ACTION_SETTINGS_UPDATED: &str = "settings.updated";
pub const TARGET_PROFILE: &str = "profile";
pub const TARGET_USER: &str = "user";
pub const TARGET_API_KEY: &str = "api_key";
pub const FIELD_PASSWORD: &str = "password";
pub const FIELD_IMPERSONATION_SESSION: &str = "impersonation_session_id";
pub const FIELD_LOGIN_SESSION: &str = "login_session_id";

/// `Change`.
#[derive(Debug, Clone, Serialize)]
pub struct Change {
    pub field: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

/// `Changes`, over values already marshaled to their canonical JSON.
pub fn changes(
    before: Option<&BTreeMap<&'static str, String>>,
    after: Option<&BTreeMap<&'static str, String>>,
) -> Vec<Change> {
    let empty = BTreeMap::new();
    let (old, new) = (before.unwrap_or(&empty), after.unwrap_or(&empty));
    let mut keys: Vec<&&str> = old.keys().chain(new.keys()).collect();
    keys.sort_unstable();
    keys.dedup();
    let mut out = Vec::new();
    for key in keys {
        let (a, b) = (old.get(*key), new.get(*key));
        if a == b {
            continue;
        }
        out.push(Change {
            field: (*key).to_owned(),
            before: a.cloned(),
            after: b.cloned(),
        });
    }
    out
}

/// `Created`'s and `Removed`'s single string field, whose canonical JSON is the quoted id.
pub fn removed(field: &str, value: &str) -> Vec<Change> {
    vec![Change {
        field: field.to_owned(),
        before: Some(silo_gocompat::json::marshal_to_string(value).unwrap_or_default()),
        after: None,
    }]
}

/// `SecretChanged`.
pub fn secret_changed(field: &str) -> Vec<Change> {
    vec![Change {
        field: field.to_owned(),
        before: None,
        after: None,
    }]
}

/// The request a domain row is about: `LogContext`, and `WithDomainAudit`'s opt-in.
#[derive(Clone)]
pub struct AuditRequest {
    pub opted_in: bool,
    pub client_ip: String,
    pub user_id: Option<i64>,
    pub impersonator_user_id: Option<i64>,
    pub session_id: String,
    pub request_id: String,
    pub node_id: String,
    pub method: String,
    pub path: String,
    pub pattern: String,
    pub user_agent: String,
    pub started: Instant,
    /// `LogContext.Publish`: takes the entry's JSON to the live tail.
    pub publish: Option<Arc<dyn Fn(String) + Send + Sync>>,
    /// `LogContext.Committed`: takes the status of a row that committed, so the request logger can skip
    /// its second row for the same operation.
    pub committed: Option<Arc<dyn Fn(i32) + Send + Sync>>,
}

impl AuditRequest {
    /// `Recording`: every v2 administration operation, and v2 operations that opted in.
    pub fn recording(&self) -> bool {
        self.path.starts_with("/api/v2/admin/")
            || (self.opted_in && self.path.starts_with("/api/v2/"))
    }

    /// `ActorIDs`.
    pub fn actor_ids(&self) -> Vec<i64> {
        if !self.recording() {
            return Vec::new();
        }
        [self.user_id, self.impersonator_user_id]
            .into_iter()
            .flatten()
            .collect()
    }

    /// `LockActors`.
    pub async fn lock_actors(&self, tx: &mut Session) -> Result<(), silo_pg::Error> {
        let ids = self.actor_ids();
        if ids.is_empty() {
            return Ok(());
        }
        tx.query(
            "SELECT 1 FROM users WHERE id = ANY($1) ORDER BY id FOR KEY SHARE",
            &[&ids],
        )
        .await
        .map(|_| ())
    }

    /// `RecordMutation`. Run [`Committed::publish`] after the transaction commits.
    pub async fn record(
        &self,
        tx: &mut Session,
        action: &str,
        target_type: &str,
        target_id: &str,
        status: i32,
        changes: Vec<Change>,
    ) -> Result<Option<Committed>, silo_pg::Error> {
        if !self.recording() || changes.is_empty() {
            return Ok(None);
        }
        let timestamp = std::time::SystemTime::now();
        let raw = silo_gocompat::json::marshal_to_string(&changes).unwrap_or_default();
        let duration_ms = self.started.elapsed().as_millis() as i32;
        let user_agent = silo_gocompat_valid_text(&self.user_agent);
        let user = self.user_id.map(|v| v as i32);
        let impersonator = self.impersonator_user_id.map(|v| v as i32);
        let rows = tx
            .query(
                "INSERT INTO activity_log(timestamp,client_ip,user_id,impersonator_user_id,session_id,request_id,node_id,method,path,path_pattern,status_code,user_agent,duration_ms,action,target_type,target_id,changes)
                 VALUES ($1,$2::text::inet,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17::text::jsonb) RETURNING id",
                &[
                    &timestamp,
                    &self.client_ip,
                    &user,
                    &impersonator,
                    &self.session_id,
                    &self.request_id,
                    &self.node_id,
                    &self.method,
                    &self.path,
                    &self.pattern,
                    &status,
                    &user_agent,
                    &duration_ms,
                    &action,
                    &target_type,
                    &target_id,
                    &raw,
                ],
            )
            .await?;
        let id: i64 = match rows.first() {
            Some(row) => row.try_get(0).unwrap_or_default(),
            None => 0,
        };
        let entry = Entry {
            action: action.to_owned(),
            target_type: target_type.to_owned(),
            target_id: target_id.to_owned(),
            changes,
            id,
            timestamp: silo_gocompat::time::GoTime::from_system_time(timestamp)
                .format(silo_gocompat::time::RFC3339_NANO),
            client_ip: self.client_ip.clone(),
            user_id: self.user_id,
            impersonator_user_id: self.impersonator_user_id,
            session_id: self.session_id.clone(),
            request_id: self.request_id.clone(),
            node_id: self.node_id.clone(),
            method: self.method.clone(),
            path: self.path.clone(),
            path_pattern: self.pattern.clone(),
            status_code: status,
            user_agent,
            duration_ms,
        };
        Ok(Some(Committed {
            entry,
            publish: self.publish.clone(),
            committed: self.committed.clone(),
        }))
    }
}

fn silo_gocompat_valid_text(text: &str) -> String {
    text.replace('\0', "")
}

/// `Entry`.
#[derive(Serialize)]
struct Entry {
    #[serde(skip_serializing_if = "String::is_empty")]
    action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    target_type: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    target_id: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    changes: Vec<Change>,
    id: i64,
    timestamp: String,
    client_ip: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_id: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    impersonator_user_id: Option<i64>,
    #[serde(skip_serializing_if = "String::is_empty")]
    session_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    request_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    node_id: String,
    method: String,
    path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    path_pattern: String,
    status_code: i32,
    #[serde(skip_serializing_if = "String::is_empty")]
    user_agent: String,
    duration_ms: i32,
}

/// A row in a transaction that has not committed yet.
pub struct Committed {
    entry: Entry,
    publish: Option<Arc<dyn Fn(String) + Send + Sync>>,
    committed: Option<Arc<dyn Fn(i32) + Send + Sync>>,
}

impl Committed {
    /// `CommitMutation`. Persistence is authoritative: a missed live frame is recovered by history.
    pub fn publish(self) {
        if let Some(committed) = &self.committed {
            committed(self.entry.status_code);
        }
        if let Some(publish) = self.publish
            && let Ok(json) = silo_gocompat::json::marshal_to_string(&self.entry)
        {
            publish(json);
        }
    }
}

/// `CommitMutation` for an optional row.
pub fn commit(entry: Option<Committed>) {
    if let Some(entry) = entry {
        entry.publish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changes_list_differences_in_field_order() {
        let a = BTreeMap::from([
            ("label", "\"a\"".to_owned()),
            ("rate_tier", "\"x\"".to_owned()),
        ]);
        let b = BTreeMap::from([
            ("label", "\"b\"".to_owned()),
            ("rate_tier", "\"x\"".to_owned()),
        ]);
        let got = changes(Some(&a), Some(&b));
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].field, "label");
        assert_eq!(got[0].before.as_deref(), Some("\"a\""));
        assert_eq!(changes(Some(&a), Some(&a)).len(), 0);
    }

    #[test]
    fn only_v2_administration_or_an_opt_in_records() {
        let mut r = AuditRequest {
            opted_in: false,
            client_ip: String::new(),
            user_id: None,
            impersonator_user_id: None,
            session_id: String::new(),
            request_id: String::new(),
            node_id: String::new(),
            method: String::new(),
            path: "/api/v1/auth/sessions/x".to_owned(),
            pattern: String::new(),
            user_agent: String::new(),
            started: Instant::now(),
            publish: None,
            committed: None,
        };
        assert!(!r.recording());
        r.opted_in = true;
        assert!(!r.recording());
        r.path = "/api/v2/auth/sessions/x".to_owned();
        assert!(r.recording());
        r.opted_in = false;
        assert!(!r.recording());
        r.path = "/api/v2/admin/api-keys/1".to_owned();
        assert!(r.recording());
    }
}
