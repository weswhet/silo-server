//! `internal/userstore/pgstore`: the Postgres backend for the canonical setting-values engine.
//! SQL is copied verbatim from `setting_values.go` where the table shape makes that possible.
//!
//! Ported: `GetSettingValue`, `ListSettingValuesForResolution`, `ListAllSettingValues`,
//! `ListSettingValuesByScope`, `UpsertSettingValue`, `CompareAndSetSettingValue`,
//! `DeleteSettingValue`, `DeleteSettingValuesFor{Profile,Device,Library,Series}`,
//! `GetSettingMutation`, `PutSettingMutation`, `DeleteExpiredSettingMutations`.
//!
//! The transaction-scoped writers are in [`super::prefs`].
//!
//! The SQLite `internal/userdb` backend (`userdb.backend=sqlite`) is not ported. Nothing here is
//! backend-selected; this is the Postgres path only, which Go also treats as primary.

use std::sync::Arc;

use silo_config::resolve::{self, SettingIdentity, SettingResolutionQuery, SettingValue};
use silo_config::settings::{ClientFamily, Scope};
use silo_pg::{AnyInt, Error as PgError, Pool, Row};

use super::{Error as UserstoreError, SettingMutationRecord, normalized, validate_identity};

/// The projection every read shares, in the order [`scan_setting_value`] expects.
/// `pgstore.settingValueColumns`. `value` reads as `::text`: `jsonb`'s own canonical text form,
/// identical from Go or Rust since Postgres (not either client) produced it, and scannable without
/// a JSON library in the loop.
pub(super) const SETTING_VALUE_COLUMNS: &str = "key, scope, profile_id, client_family, device_id, library_id, series_id, \
     value::text, revision, created_at, updated_at";

/// An error from a Postgres userstore operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Invalid(#[from] UserstoreError),
    #[error("{op}: {source}")]
    Pg {
        op: &'static str,
        #[source]
        source: PgError,
    },
    #[error("setting value revision conflict")]
    RevisionConflict,
    #[error("scope {0:?} has no storage identity")]
    NoStorageIdentity(String),
    #[error("library id {0} does not fit a Postgres integer column")]
    LibraryIdOutOfRange(i64),
}

type Result<T> = std::result::Result<T, Error>;

fn library_id_i32(value: i64) -> Result<i32> {
    i32::try_from(value).map_err(|_| Error::LibraryIdOutOfRange(value))
}

/// `pgstore.PostgresUserStore`.
pub struct PostgresUserStore {
    pool: Arc<Pool>,
    /// A Go `int`: a value past `int4` fails the bind, as pgx does, and never reaches another account.
    user_id: AnyInt,
}

impl PostgresUserStore {
    pub fn new(pool: Arc<Pool>, user_id: i64) -> Self {
        Self {
            pool,
            user_id: AnyInt(user_id),
        }
    }

    /// `PostgresUserStore.GetSettingValue`.
    pub async fn get_setting_value(&self, id: &SettingIdentity) -> Result<Option<SettingValue>> {
        validate_identity(id)?;
        let sql = format!(
            "SELECT {SETTING_VALUE_COLUMNS} FROM user_setting_values WHERE {}",
            identity_clause(1, id)
        );
        let boxed = identity_params_boxed(self.user_id, id)?;
        let params: Vec<&(dyn silo_pg::ToSql + Sync)> = boxed
            .iter()
            .map(|b| b.as_ref() as &(dyn silo_pg::ToSql + Sync))
            .collect();
        let rows = self
            .pool
            .query(&sql, &params)
            .await
            .map_err(|source| Error::Pg {
                op: "get setting value",
                source,
            })?;
        Ok(rows.first().map(scan_setting_value))
    }

    /// `PostgresUserStore.ListSettingValuesForResolution`: one query covers all six scopes, so a
    /// multi-scope chain still costs one round trip. Ranking by resolution order happens in the
    /// caller (`silo_config::resolve`).
    pub async fn list_setting_values_for_resolution(
        &self,
        query: &SettingResolutionQuery,
    ) -> Result<Vec<SettingValue>> {
        let q = normalized(query);
        if q.keys.is_empty() {
            return Ok(Vec::new());
        }
        let library_ids: Vec<i32> = q
            .library_ids
            .iter()
            .map(|&v| library_id_i32(v))
            .collect::<Result<_>>()?;
        let sql = format!(
            "SELECT {SETTING_VALUE_COLUMNS}
                FROM user_setting_values
                WHERE user_id = $1
                  AND key = ANY($2::text[])
                  AND (
                        scope = 'account'
                     OR (
                          profile_id = ANY($3::text[])
                              AND (
                                    scope = 'profile'
                                 OR (scope = 'profile_client' AND client_family = $4)
                                 OR (scope = 'profile_device' AND device_id = $5)
                                 OR (scope = 'profile_library' AND library_id = ANY($6::integer[]))
                                 OR (scope = 'profile_series' AND series_id = ANY($7::text[]))
                              )
                            )
                      )
                ORDER BY key, scope, COALESCE(profile_id, ''), COALESCE(client_family, ''), COALESCE(device_id, ''),
                         COALESCE(library_id, 0), COALESCE(series_id, '')"
        );
        let rows = self
            .pool
            .query(
                &sql,
                &[
                    &self.user_id,
                    &q.keys,
                    &q.profile_ids,
                    &q.client_family.as_str(),
                    &q.device_id,
                    &library_ids,
                    &q.series_ids,
                ],
            )
            .await
            .map_err(|source| Error::Pg {
                op: "listing setting values for resolution",
                source,
            })?;
        Ok(rows.iter().map(scan_setting_value).collect())
    }

    /// `PostgresUserStore.ListAllSettingValues`.
    pub async fn list_all_setting_values(&self) -> Result<Vec<SettingValue>> {
        let sql = format!(
            "SELECT {SETTING_VALUE_COLUMNS}
                FROM user_setting_values
                WHERE user_id = $1
                ORDER BY key, scope, COALESCE(profile_id, ''), COALESCE(client_family, ''), COALESCE(device_id, ''),
                         COALESCE(library_id, 0), COALESCE(series_id, '')"
        );
        let rows = self
            .pool
            .query(&sql, &[&self.user_id])
            .await
            .map_err(|source| Error::Pg {
                op: "listing all setting values",
                source,
            })?;
        Ok(rows.iter().map(scan_setting_value).collect())
    }

    /// `PostgresUserStore.ListSettingValuesByScope`.
    pub async fn list_setting_values_by_scope(
        &self,
        profile_id: &str,
        scope: &Scope,
        keys: &[String],
    ) -> Result<Vec<SettingValue>> {
        super::validate_scope_listing(profile_id, scope)?;
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT {SETTING_VALUE_COLUMNS}
                FROM user_setting_values
                WHERE user_id = $1 AND profile_id = $2 AND scope = $3 AND key = ANY($4::text[])
                ORDER BY key, scope, COALESCE(profile_id, ''), COALESCE(client_family, ''), COALESCE(device_id, ''),
                         COALESCE(library_id, 0), COALESCE(series_id, '')"
        );
        let rows = self
            .pool
            .query(&sql, &[&self.user_id, &profile_id, &scope.as_str(), &keys])
            .await
            .map_err(|source| Error::Pg {
                op: "listing setting values by scope",
                source,
            })?;
        Ok(rows.iter().map(scan_setting_value).collect())
    }

    /// `PostgresUserStore.UpsertSettingValue`.
    pub async fn upsert_setting_value(
        &self,
        id: &SettingIdentity,
        value: &[u8],
    ) -> Result<SettingValue> {
        validate_identity(id)?;
        super::validate_setting_value_json(value)?;
        let target = conflict_target(&id.scope)?;
        let value_text = std::str::from_utf8(value)
            .map_err(|_| UserstoreError::InvalidValue("value is not valid UTF-8".to_owned()))?;
        let library_id = nullable_library_id(id.library_id)?;
        let sql = format!(
            "INSERT INTO user_setting_values
                (user_id, key, scope, profile_id, client_family, device_id, library_id, series_id, value)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb)
             ON CONFLICT {target} DO UPDATE SET
                value = excluded.value,
                revision = user_setting_values.revision + 1,
                updated_at = now()
             RETURNING {SETTING_VALUE_COLUMNS}"
        );
        let row = self
            .pool
            .query(
                &sql,
                &[
                    &self.user_id,
                    &id.key.as_str(),
                    &id.scope.as_str(),
                    &nullable(&id.profile_id),
                    &nullable(id.client_family.as_str()),
                    &nullable(&id.device_id),
                    &library_id,
                    &nullable(&id.series_id),
                    &value_text,
                ],
            )
            .await
            .map_err(|source| Error::Pg {
                op: "upserting setting value",
                source,
            })?
            .into_iter()
            .next()
            .ok_or(Error::Pg {
                op: "upserting setting value",
                source: PgError::NoRows,
            })?;
        Ok(scan_setting_value(&row))
    }

    /// `PostgresUserStore.CompareAndSetSettingValue`: a revision of zero is insert-if-absent;
    /// otherwise the exact current revision must still match. Postgres performs the compare and
    /// the write in one statement, so concurrent document mutations can retry without clobbering
    /// one another.
    pub async fn compare_and_set_setting_value(
        &self,
        id: &SettingIdentity,
        value: &[u8],
        expected_revision: i64,
    ) -> Result<SettingValue> {
        validate_identity(id)?;
        super::validate_setting_value_json(value)?;
        if expected_revision < 0 {
            return Err(UserstoreError::InvalidIdentity(
                "expected revision must be non-negative".to_owned(),
            )
            .into());
        }
        let value_text = std::str::from_utf8(value)
            .map_err(|_| UserstoreError::InvalidValue("value is not valid UTF-8".to_owned()))?;

        let row = if expected_revision == 0 {
            let target = conflict_target(&id.scope)?;
            let library_id = nullable_library_id(id.library_id)?;
            let sql = format!(
                "INSERT INTO user_setting_values
                    (user_id, key, scope, profile_id, client_family, device_id, library_id, series_id, value)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb)
                 ON CONFLICT {target} DO NOTHING
                 RETURNING {SETTING_VALUE_COLUMNS}"
            );
            self.pool
                .query(
                    &sql,
                    &[
                        &self.user_id,
                        &id.key.as_str(),
                        &id.scope.as_str(),
                        &nullable(&id.profile_id),
                        &nullable(id.client_family.as_str()),
                        &nullable(&id.device_id),
                        &library_id,
                        &nullable(&id.series_id),
                        &value_text,
                    ],
                )
                .await
        } else {
            let sql = format!(
                "UPDATE user_setting_values
                 SET value = $1::text::jsonb, revision = revision + 1, updated_at = now()
                 WHERE {} AND revision = $2
                 RETURNING {SETTING_VALUE_COLUMNS}",
                identity_clause(3, id)
            );
            let boxed = identity_params_boxed(self.user_id, id)?;
            let mut params: Vec<&(dyn silo_pg::ToSql + Sync)> =
                vec![&value_text, &expected_revision];
            params.extend(boxed.iter().map(|b| b.as_ref() as &(dyn silo_pg::ToSql + Sync)));
            self.pool.query(&sql, &params).await
        }
        .map_err(|source| Error::Pg {
            op: "compare-and-setting value",
            source,
        })?;
        row.first()
            .map(scan_setting_value)
            .ok_or(Error::RevisionConflict)
    }

    /// `PostgresUserStore.DeleteSettingValue`.
    pub async fn delete_setting_value(&self, id: &SettingIdentity) -> Result<bool> {
        validate_identity(id)?;
        let sql = format!(
            "DELETE FROM user_setting_values WHERE {}",
            identity_clause(1, id)
        );
        let boxed = identity_params_boxed(self.user_id, id)?;
        let params: Vec<&(dyn silo_pg::ToSql + Sync)> = boxed
            .iter()
            .map(|b| b.as_ref() as &(dyn silo_pg::ToSql + Sync))
            .collect();
        let affected = self
            .pool
            .execute(&sql, &params)
            .await
            .map_err(|source| Error::Pg {
                op: "deleting setting value",
                source,
            })?;
        Ok(affected > 0)
    }

    /// `PostgresUserStore.DeleteSettingValuesForProfile`: account-scope rows carry a NULL
    /// `profile_id` and survive.
    pub async fn delete_setting_values_for_profile(&self, profile_id: &str) -> Result<u64> {
        self.pool
            .execute(
                "DELETE FROM user_setting_values WHERE user_id = $1 AND profile_id = $2",
                &[&self.user_id, &profile_id],
            )
            .await
            .map_err(|source| Error::Pg {
                op: "deleting setting values for profile",
                source,
            })
    }

    pub async fn delete_setting_values_for_device(
        &self,
        profile_id: &str,
        device_id: &str,
    ) -> Result<u64> {
        self.pool
            .execute(
                "DELETE FROM user_setting_values
                 WHERE user_id = $1 AND scope = 'profile_device' AND profile_id = $2 AND device_id = $3",
                &[&self.user_id, &profile_id, &device_id],
            )
            .await
            .map_err(|source| Error::Pg {
                op: "deleting setting values for device",
                source,
            })
    }

    pub async fn delete_setting_values_for_library(&self, library_id: i64) -> Result<u64> {
        let library_id = library_id_i32(library_id)?;
        self.pool
            .execute(
                "DELETE FROM user_setting_values
                 WHERE user_id = $1 AND scope = 'profile_library' AND library_id = $2",
                &[&self.user_id, &library_id],
            )
            .await
            .map_err(|source| Error::Pg {
                op: "deleting setting values for library",
                source,
            })
    }

    pub async fn delete_setting_values_for_series(&self, series_id: &str) -> Result<u64> {
        self.pool
            .execute(
                "DELETE FROM user_setting_values
                 WHERE user_id = $1 AND scope = 'profile_series' AND series_id = $2",
                &[&self.user_id, &series_id],
            )
            .await
            .map_err(|source| Error::Pg {
                op: "deleting setting values for series",
                source,
            })
    }

    /// `PostgresUserStore.GetSettingMutation`.
    pub async fn get_setting_mutation(
        &self,
        mutation_id: &str,
    ) -> Result<Option<SettingMutationRecord>> {
        let rows = self
            .pool
            .query(
                "SELECT mutation_id, request_hash, result::text, created_at, expires_at
                 FROM user_setting_mutations WHERE user_id = $1 AND mutation_id = $2",
                &[&self.user_id, &mutation_id],
            )
            .await
            .map_err(|source| Error::Pg {
                op: "getting setting mutation",
                source,
            })?;
        Ok(rows.first().map(scan_setting_mutation))
    }

    /// `PostgresUserStore.PutSettingMutation`: never overwrites a receipt — `DO NOTHING` plus a
    /// second read on conflict keeps a replayed `mutation_id` answering with the first attempt's
    /// result. Returns `(record, inserted)`.
    pub async fn put_setting_mutation(
        &self,
        record: &SettingMutationRecord,
    ) -> Result<(SettingMutationRecord, bool)> {
        record.validate()?;
        let result_text = std::str::from_utf8(&record.result)
            .map_err(|_| UserstoreError::InvalidValue("value is not valid UTF-8".to_owned()))?;
        let rows = self
            .pool
            .query(
                "INSERT INTO user_setting_mutations (user_id, mutation_id, request_hash, result, expires_at)
                 VALUES ($1, $2, $3, $4::text::jsonb, $5::text::timestamptz)
                 ON CONFLICT (user_id, mutation_id) DO NOTHING
                 RETURNING mutation_id, request_hash, result::text, created_at, expires_at",
                &[
                    &self.user_id,
                    &record.mutation_id.as_str(),
                    &record.request_hash.as_str(),
                    &result_text,
                    &record.expires_at.as_str(),
                ],
            )
            .await
            .map_err(|source| Error::Pg {
                op: "recording setting mutation",
                source,
            })?;
        if let Some(row) = rows.first() {
            return Ok((scan_setting_mutation(row), true));
        }
        let existing = self.get_setting_mutation(&record.mutation_id).await?;
        let existing = existing.ok_or_else(|| Error::Pg {
            op: "recording setting mutation",
            source: PgError::NoRows,
        })?;
        Ok((existing, false))
    }

    /// `PostgresUserStore.DeleteExpiredSettingMutations`.
    pub async fn delete_expired_setting_mutations(&self, before: &str) -> Result<u64> {
        self.pool
            .execute(
                "DELETE FROM user_setting_mutations WHERE user_id = $1 AND expires_at <= $2::text::timestamptz",
                &[&self.user_id, &before],
            )
            .await
            .map_err(|source| Error::Pg {
                op: "sweeping expired setting mutations",
                source,
            })
    }
}

/// Implements the read surface `silo_config::resolve::Resolver` needs.
impl resolve::Store for PostgresUserStore {
    fn list_setting_values_for_resolution<'a>(
        &'a self,
        query: &'a SettingResolutionQuery,
    ) -> silo_config::config::BoxFuture<
        'a,
        std::result::Result<Vec<SettingValue>, resolve::ReadError>,
    > {
        Box::pin(async move {
            self.list_setting_values_for_resolution(query)
                .await
                .map_err(|e| Box::new(e) as resolve::ReadError)
        })
    }
}

pub(super) fn nullable(value: &str) -> Option<&str> {
    if value.is_empty() { None } else { Some(value) }
}

pub(super) fn nullable_library_id(value: i64) -> Result<Option<i32>> {
    if value == 0 {
        Ok(None)
    } else {
        Ok(Some(library_id_i32(value)?))
    }
}

/// `settingConflictTargets`: the partial unique index matching one scope, so a repeated write
/// updates its own row rather than inserting a duplicate.
pub(super) fn conflict_target(scope: &Scope) -> Result<&'static str> {
    Ok(match scope.as_str() {
        "account" => "(user_id, key) WHERE scope = 'account'",
        "profile" => "(user_id, profile_id, key) WHERE scope = 'profile'",
        "profile_client" => {
            "(user_id, profile_id, client_family, key) WHERE scope = 'profile_client'"
        }
        "profile_device" => "(user_id, profile_id, device_id, key) WHERE scope = 'profile_device'",
        "profile_library" => {
            "(user_id, profile_id, library_id, key) WHERE scope = 'profile_library'"
        }
        "profile_series" => "(user_id, profile_id, series_id, key) WHERE scope = 'profile_series'",
        other => return Err(Error::NoStorageIdentity(other.to_owned())),
    })
}

/// `settingIdentityPredicate`: the WHERE fragment addressing exactly one row, with placeholders
/// starting at `$start`.
pub(super) fn identity_clause(start: usize, id: &SettingIdentity) -> String {
    match id.scope.as_str() {
        "account" => format!(
            "user_id = ${} AND key = ${} AND scope = ${}",
            start,
            start + 1,
            start + 2
        ),
        "profile" => format!(
            "user_id = ${} AND key = ${} AND scope = ${} AND profile_id = ${}",
            start,
            start + 1,
            start + 2,
            start + 3
        ),
        "profile_client" => format!(
            "user_id = ${} AND key = ${} AND scope = ${} AND profile_id = ${} AND client_family = ${}",
            start,
            start + 1,
            start + 2,
            start + 3,
            start + 4
        ),
        "profile_device" => format!(
            "user_id = ${} AND key = ${} AND scope = ${} AND profile_id = ${} AND device_id = ${}",
            start,
            start + 1,
            start + 2,
            start + 3,
            start + 4
        ),
        "profile_library" => format!(
            "user_id = ${} AND key = ${} AND scope = ${} AND profile_id = ${} AND library_id = ${}",
            start,
            start + 1,
            start + 2,
            start + 3,
            start + 4
        ),
        "profile_series" => format!(
            "user_id = ${} AND key = ${} AND scope = ${} AND profile_id = ${} AND series_id = ${}",
            start,
            start + 1,
            start + 2,
            start + 3,
            start + 4
        ),
        _ => format!(
            "user_id = ${} AND key = ${} AND scope = ${}",
            start,
            start + 1,
            start + 2
        ),
    }
}

/// The bound values matching [`identity_clause`] (called with `start: 1`), in the same order, as
/// owned boxed values so the caller can turn them into a `Params` slice without fighting
/// borrow lifetimes across a `match`. `library_id` binds as `i32`; the `profile_library` CHECK
/// constraint guarantees it is positive whenever this scope is reached, and `validate_identity`
/// has already run by the time any caller builds these.
pub(super) fn identity_params_boxed(
    user_id: AnyInt,
    id: &SettingIdentity,
) -> Result<Vec<Box<dyn silo_pg::ToSql + Sync + Send>>> {
    let key = id.key.clone();
    let scope = id.scope.as_str().to_owned();
    let mut params: Vec<Box<dyn silo_pg::ToSql + Sync + Send>> =
        vec![Box::new(user_id), Box::new(key), Box::new(scope)];
    match id.scope.as_str() {
        "profile" => params.push(Box::new(id.profile_id.clone())),
        "profile_client" => {
            params.push(Box::new(id.profile_id.clone()));
            params.push(Box::new(id.client_family.as_str().to_owned()));
        }
        "profile_device" => {
            params.push(Box::new(id.profile_id.clone()));
            params.push(Box::new(id.device_id.clone()));
        }
        "profile_library" => {
            params.push(Box::new(id.profile_id.clone()));
            params.push(Box::new(library_id_i32(id.library_id)?));
        }
        "profile_series" => {
            params.push(Box::new(id.profile_id.clone()));
            params.push(Box::new(id.series_id.clone()));
        }
        _ => {}
    }
    Ok(params)
}

/// `scanSettingValue`.
pub(super) fn scan_setting_value(row: &Row) -> SettingValue {
    let key: String = row.get(0);
    let scope: String = row.get(1);
    let profile_id: Option<String> = row.get(2);
    let client_family: Option<String> = row.get(3);
    let device_id: Option<String> = row.get(4);
    let library_id: Option<i32> = row.get(5);
    let series_id: Option<String> = row.get(6);
    let value: String = row.get(7);
    let revision: i64 = row.get(8);
    let created_at: std::time::SystemTime = row.get(9);
    let updated_at: std::time::SystemTime = row.get(10);
    SettingValue {
        identity: SettingIdentity {
            key,
            scope: Scope::new(scope),
            profile_id: profile_id.unwrap_or_default(),
            client_family: ClientFamily::new(client_family.unwrap_or_default()),
            device_id: device_id.unwrap_or_default(),
            library_id: library_id.map_or(0, i64::from),
            series_id: series_id.unwrap_or_default(),
        },
        value: value.into_bytes(),
        revision,
        created_at: pg_time_to_string(created_at),
        updated_at: pg_time_to_string(updated_at),
    }
}

/// `scanSettingMutation`.
pub(super) fn scan_setting_mutation(row: &Row) -> SettingMutationRecord {
    let mutation_id: String = row.get(0);
    let request_hash: String = row.get(1);
    let result: String = row.get(2);
    let created_at: std::time::SystemTime = row.get(3);
    let expires_at: std::time::SystemTime = row.get(4);
    SettingMutationRecord {
        mutation_id,
        request_hash,
        result: result.into_bytes(),
        created_at: pg_time_to_string(created_at),
        expires_at: pg_time_to_string(expires_at),
    }
}

/// `timeToString`: `t.UTC().Format(time.RFC3339)` — whole seconds, any sub-second part truncated,
/// matching Go's layout exactly (see `silo_gocompat::time::GoTime::rfc3339`).
pub(super) fn pg_time_to_string(t: std::time::SystemTime) -> String {
    let dur = t
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO);
    silo_gocompat::time::GoTime::from_unix(dur.as_secs() as i64, dur.subsec_nanos())
        .to_utc()
        .rfc3339()
}
