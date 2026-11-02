//! `pgstore/settings.go`, `preference_settings_tx.go`, `setting_mutation_tx.go`, and the writes of
//! `profiles.go`: what a settings or profile request does in the account's preference transaction.

use silo_config::resolve::{SettingIdentity, SettingValue};
use silo_gocompat::time::GoTime;
use silo_pg::{AnyInt, Pool, Session, ToSql};

use super::pgstore::{
    Error, SETTING_VALUE_COLUMNS, conflict_target, identity_clause, identity_params_boxed,
    nullable, nullable_library_id, scan_setting_mutation, scan_setting_value,
};
use super::{Error as UserstoreError, SettingMutationRecord, validate_identity};

type Result<T> = std::result::Result<T, Error>;

/// `preferenceSettingsAdvisoryClass`.
const PREFERENCE_CLASS: i32 = 0x5349_4c4f;
/// `settingMutationAdvisoryClass`.
const MUTATION_CLASS: i32 = 0x534d_5554;

fn pg(op: &'static str) -> impl Fn(silo_pg::Error) -> Error {
    move |source| Error::Pg { op, source }
}

fn utf8(value: &[u8]) -> Result<&str> {
    std::str::from_utf8(value)
        .map_err(|_| UserstoreError::InvalidValue("value is not valid UTF-8".to_owned()).into())
}

/// `userstore.SettingEntry`.
#[derive(Debug, Clone)]
pub struct SettingEntry {
    pub key: String,
    pub value: String,
}

/// `userstore.DeviceSettingEntry`.
#[derive(Debug, Clone, Default)]
pub struct DeviceSettingEntry {
    pub profile_id: String,
    pub device_id: String,
    pub device_name: String,
    pub device_platform: String,
    pub key: String,
    pub value: String,
    pub updated_at: String,
}

/// `userstore.UpdateProfileInput`.
#[derive(Debug, Clone, Default)]
pub struct UpdateProfileInput {
    pub name: Option<String>,
    pub avatar: Option<String>,
    pub pin_hash: Option<String>,
    pub is_child: Option<bool>,
    pub max_content_rating: Option<String>,
    pub max_advisory_age: Option<i32>,
    pub require_advisory_age: Option<bool>,
    pub quality_preference: Option<String>,
    pub language: Option<String>,
    pub preferred_metadata_language: Option<String>,
    pub subtitle_language: Option<String>,
    pub subtitle_mode: Option<String>,
    pub auto_skip_intro: Option<bool>,
    pub auto_skip_credits: Option<bool>,
    pub auto_skip_recap: Option<bool>,
    pub auto_play_next_preview: Option<bool>,
    pub show_forced_subtitles: Option<bool>,
    pub library_restrictions_enabled: Option<bool>,
    pub allowed_library_ids: Option<Vec<i32>>,
    pub max_playback_quality: Option<String>,
}

/// `userstore.Profile`, as `createProfile` inserts it.
#[derive(Debug, Clone, Default)]
pub struct NewProfile {
    pub id: String,
    pub name: String,
    pub pin_hash: String,
    pub avatar: String,
    pub is_child: bool,
    pub max_content_rating: String,
    pub max_advisory_age: i32,
    pub require_advisory_age: bool,
    pub quality_preference: String,
    pub language: String,
    pub preferred_metadata_language: String,
    pub subtitle_language: String,
    pub subtitle_mode: String,
    pub auto_skip_intro: bool,
    pub auto_skip_credits: bool,
    pub auto_skip_recap: bool,
    pub auto_play_next_preview: bool,
    pub library_restrictions_enabled: bool,
    pub allowed_library_ids: Vec<i32>,
    pub max_playback_quality: String,
}

/// Reads outside a transaction, and `RegisterDevice`.
pub struct Reader<'a> {
    pub pool: &'a Pool,
    /// A Go `int`: a value past `int4` fails the bind, as pgx does.
    pub user_id: AnyInt,
}

impl Reader<'_> {
    /// `GetSetting`: "" when there is no row.
    pub async fn get_setting(&self, key: &str) -> Result<String> {
        let rows = self
            .pool
            .query(
                "SELECT value FROM user_settings WHERE user_id = $1 AND key = $2",
                &[&self.user_id, &key],
            )
            .await
            .map_err(pg("getting setting"))?;
        Ok(rows.first().map(|r| r.get(0)).unwrap_or_default())
    }

    /// `ListSettings`.
    pub async fn list_settings(&self) -> Result<Vec<SettingEntry>> {
        let rows = self
            .pool
            .query(
                "SELECT key, value FROM user_settings WHERE user_id = $1 ORDER BY key",
                &[&self.user_id],
            )
            .await
            .map_err(pg("listing settings"))?;
        Ok(rows
            .iter()
            .map(|r| SettingEntry {
                key: r.get(0),
                value: r.get(1),
            })
            .collect())
    }

    /// `GetDeviceSetting`.
    pub async fn get_device_setting(
        &self,
        profile_id: &str,
        device_id: &str,
        key: &str,
    ) -> Result<Option<DeviceSettingEntry>> {
        let rows = self
            .pool
            .query(
                "SELECT profile_id, device_id, device_name, device_platform, key, value, updated_at::text
                 FROM user_device_settings
                 WHERE user_id = $1 AND profile_id = $2 AND device_id = $3 AND key = $4",
                &[&self.user_id, &profile_id, &device_id, &key],
            )
            .await
            .map_err(pg("getting device setting"))?;
        Ok(rows.first().map(|r| DeviceSettingEntry {
            profile_id: r.get(0),
            device_id: r.get(1),
            device_name: r.get(2),
            device_platform: r.get(3),
            key: r.get(4),
            value: r.get(5),
            updated_at: r.get(6),
        }))
    }

    /// `SetDeviceSetting`: registers the device, then upserts, as two statements outside a transaction.
    pub async fn set_device_setting(&self, entry: &DeviceSettingEntry) -> Result<()> {
        self.register_device(
            &entry.profile_id,
            &entry.device_id,
            &entry.device_name,
            &entry.device_platform,
        )
        .await?;
        self.pool
            .execute(
                UPSERT_DEVICE_SETTING,
                &[
                    &self.user_id,
                    &entry.profile_id,
                    &entry.device_id,
                    &entry.key,
                    &entry.value,
                    &entry.device_name,
                    &entry.device_platform,
                ],
            )
            .await
            .map_err(pg("setting device setting"))?;
        Ok(())
    }

    /// `RegisterDevice`.
    pub async fn register_device(
        &self,
        profile_id: &str,
        device_id: &str,
        name: &str,
        platform: &str,
    ) -> Result<()> {
        if silo_gocompat::strings::trim_space(profile_id).is_empty()
            || silo_gocompat::strings::trim_space(device_id).is_empty()
        {
            return Ok(());
        }
        self.pool
            .execute(
                REGISTER_DEVICE,
                &[&self.user_id, &profile_id, &device_id, &name, &platform],
            )
            .await
            .map_err(pg("registering device"))?;
        Ok(())
    }

    /// `DeviceExists`.
    pub async fn device_exists(&self, profile_id: &str, device_id: &str) -> Result<bool> {
        if silo_gocompat::strings::trim_space(profile_id).is_empty()
            || silo_gocompat::strings::trim_space(device_id).is_empty()
        {
            return Ok(false);
        }
        let rows = self
            .pool
            .query(
                "SELECT EXISTS(SELECT 1 FROM user_devices WHERE user_id = $1 AND profile_id = $2 AND device_id = $3)",
                &[&self.user_id, &profile_id, &device_id],
            )
            .await
            .map_err(pg("checking device"))?;
        Ok(rows.first().is_some_and(|r| r.get(0)))
    }
}

impl Reader<'_> {
    /// `ListAdminSettingValuesPage`.
    pub async fn list_admin_page(
        &self,
        after: &SettingIdentity,
        limit: i64,
    ) -> Result<(Vec<SettingValue>, bool)> {
        let limit = limit.clamp(1, 200);
        let page = limit + 1;
        let library = i32::try_from(after.library_id).unwrap_or(0);
        let sql = format!(
            "SELECT {SETTING_VALUE_COLUMNS} FROM user_setting_values WHERE user_id = $1 AND
             (key, scope, COALESCE(profile_id,''), COALESCE(client_family,''), COALESCE(device_id,''), COALESCE(library_id,0), COALESCE(series_id,''))
             > ($2, $3, $4, $5, $6, $7, $8)
             ORDER BY key, scope, COALESCE(profile_id,''), COALESCE(client_family,''), COALESCE(device_id,''), COALESCE(library_id,0), COALESCE(series_id,'')
             LIMIT $9"
        );
        let rows = self
            .pool
            .query(
                &sql,
                &[
                    &self.user_id,
                    &after.key,
                    &after.scope.as_str(),
                    &after.profile_id,
                    &after.client_family.as_str(),
                    &after.device_id,
                    &library,
                    &after.series_id,
                    &page,
                ],
            )
            .await
            .map_err(pg("listing admin setting values"))?;
        let more = rows.len() as i64 > limit;
        let values = rows
            .iter()
            .take(limit as usize)
            .map(scan_setting_value)
            .collect();
        Ok((values, more))
    }
}

const REGISTER_DEVICE: &str = "INSERT INTO user_devices
        (user_id, profile_id, device_id, device_name, device_platform, last_seen_at)
     VALUES ($1, $2, $3, $4, $5, NOW())
     ON CONFLICT(user_id, profile_id, device_id) DO UPDATE SET
        device_name = CASE WHEN excluded.device_name <> '' THEN excluded.device_name ELSE user_devices.device_name END,
        device_platform = CASE WHEN excluded.device_platform <> '' THEN excluded.device_platform ELSE user_devices.device_platform END,
        last_seen_at = NOW()";

const UPSERT_DEVICE_SETTING: &str = "INSERT INTO user_device_settings
        (user_id, profile_id, device_id, key, value, device_name, device_platform, updated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
     ON CONFLICT(user_id, profile_id, device_id, key) DO UPDATE SET
        value = excluded.value, device_name = excluded.device_name,
        device_platform = excluded.device_platform, updated_at = NOW()";

/// `preferenceSettingsTx` and `postgresSettingMutationWriter`: one account's preference transaction.
pub struct Writer<'a> {
    pub tx: &'a mut Session,
    pub user_id: AnyInt,
}

impl Writer<'_> {
    /// The lock `WithPreferenceSettingsTransaction` and `WithSettingMutationTransaction` share.
    pub async fn lock_preferences(&mut self) -> Result<()> {
        self.tx
            .execute(
                "SELECT pg_advisory_xact_lock($1, $2)",
                &[&PREFERENCE_CLASS, &self.user_id],
            )
            .await
            .map_err(pg("locking preference settings transaction"))?;
        Ok(())
    }

    /// The receipt lock, `fnv32a(userID \0 mutationID)`.
    pub async fn lock_mutation(&mut self, mutation_id: &str) -> Result<()> {
        let mut hash: u32 = 0x811c_9dc5;
        let user = self.user_id.0.to_string();
        for byte in user
            .as_bytes()
            .iter()
            .chain(std::iter::once(&0u8))
            .chain(mutation_id.as_bytes())
        {
            hash ^= u32::from(*byte);
            hash = hash.wrapping_mul(0x0100_0193);
        }
        let key = hash as i32;
        self.tx
            .execute(
                "SELECT pg_advisory_xact_lock($1, $2)",
                &[&MUTATION_CLASS, &key],
            )
            .await
            .map_err(pg("locking setting mutation transaction"))?;
        Ok(())
    }

    /// `ListProfileIDs`.
    pub async fn list_profile_ids(&mut self) -> Result<Vec<String>> {
        let rows = self
            .tx
            .query(
                "SELECT id FROM user_profiles WHERE user_id = $1 ORDER BY created_at, id",
                &[&self.user_id],
            )
            .await
            .map_err(pg("listing profile ids"))?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
    }

    /// `ListSettings`.
    pub async fn list_settings(&mut self) -> Result<Vec<SettingEntry>> {
        let rows = self
            .tx
            .query(
                "SELECT key, value FROM user_settings WHERE user_id = $1 ORDER BY key",
                &[&self.user_id],
            )
            .await
            .map_err(pg("listing settings"))?;
        Ok(rows
            .iter()
            .map(|r| SettingEntry {
                key: r.get(0),
                value: r.get(1),
            })
            .collect())
    }

    /// `SetSetting`.
    pub async fn set_setting(&mut self, key: &str, value: &str) -> Result<()> {
        self.tx
            .execute(
                "INSERT INTO user_settings (user_id, key, value) VALUES ($1, $2, $3)
                 ON CONFLICT(user_id, key) DO UPDATE SET value = excluded.value",
                &[&self.user_id, &key, &value],
            )
            .await
            .map_err(pg("setting"))?;
        Ok(())
    }

    /// `DeleteSetting`.
    pub async fn delete_setting(&mut self, key: &str) -> Result<()> {
        self.tx
            .execute(
                "DELETE FROM user_settings WHERE user_id = $1 AND key = $2",
                &[&self.user_id, &key],
            )
            .await
            .map_err(pg("deleting setting"))?;
        Ok(())
    }

    /// `SetDeviceSetting`.
    pub async fn set_device_setting(&mut self, entry: &DeviceSettingEntry) -> Result<()> {
        self.tx
            .execute(
                REGISTER_DEVICE,
                &[
                    &self.user_id,
                    &entry.profile_id,
                    &entry.device_id,
                    &entry.device_name,
                    &entry.device_platform,
                ],
            )
            .await
            .map_err(pg("registering device"))?;
        self.tx
            .execute(
                UPSERT_DEVICE_SETTING,
                &[
                    &self.user_id,
                    &entry.profile_id,
                    &entry.device_id,
                    &entry.key,
                    &entry.value,
                    &entry.device_name,
                    &entry.device_platform,
                ],
            )
            .await
            .map_err(pg("setting device setting"))?;
        Ok(())
    }

    /// `DeleteDeviceSetting`.
    pub async fn delete_device_setting(
        &mut self,
        profile_id: &str,
        device_id: &str,
        key: &str,
    ) -> Result<()> {
        self.tx
            .execute(
                "DELETE FROM user_device_settings WHERE user_id = $1 AND profile_id = $2 AND device_id = $3 AND key = $4",
                &[&self.user_id, &profile_id, &device_id, &key],
            )
            .await
            .map_err(pg("deleting device setting"))?;
        Ok(())
    }

    /// `getSettingValue`.
    pub async fn get_setting_value(
        &mut self,
        id: &SettingIdentity,
    ) -> Result<Option<SettingValue>> {
        validate_identity(id)?;
        let sql = format!(
            "SELECT {SETTING_VALUE_COLUMNS} FROM user_setting_values WHERE {}",
            identity_clause(1, id)
        );
        let boxed = identity_params_boxed(self.user_id, id)?;
        let params: Vec<&(dyn ToSql + Sync)> = boxed
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect();
        let rows = self
            .tx
            .query(&sql, &params)
            .await
            .map_err(pg("getting setting value"))?;
        Ok(rows.first().map(scan_setting_value))
    }

    /// `upsertSettingValue`.
    pub async fn upsert_setting_value(
        &mut self,
        id: &SettingIdentity,
        value: &[u8],
    ) -> Result<SettingValue> {
        validate_identity(id)?;
        super::validate_setting_value_json(value)?;
        let target = conflict_target(&id.scope)?;
        let text = utf8(value)?;
        let library = nullable_library_id(id.library_id)?;
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
        let rows = self
            .tx
            .query(
                &sql,
                &[
                    &self.user_id,
                    &id.key.as_str(),
                    &id.scope.as_str(),
                    &nullable(&id.profile_id),
                    &nullable(id.client_family.as_str()),
                    &nullable(&id.device_id),
                    &library,
                    &nullable(&id.series_id),
                    &text,
                ],
            )
            .await
            .map_err(pg("upserting setting value"))?;
        rows.first().map(scan_setting_value).ok_or(Error::Pg {
            op: "upserting setting value",
            source: silo_pg::Error::NoRows,
        })
    }

    /// `compareAndSetSettingValue`.
    pub async fn compare_and_set(
        &mut self,
        id: &SettingIdentity,
        value: &[u8],
        expected: i64,
    ) -> Result<SettingValue> {
        validate_identity(id)?;
        super::validate_setting_value_json(value)?;
        let text = utf8(value)?;
        let rows = if expected == 0 {
            let target = conflict_target(&id.scope)?;
            let library = nullable_library_id(id.library_id)?;
            let sql = format!(
                "INSERT INTO user_setting_values
                    (user_id, key, scope, profile_id, client_family, device_id, library_id, series_id, value)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::text::jsonb)
                 ON CONFLICT {target} DO NOTHING
                 RETURNING {SETTING_VALUE_COLUMNS}"
            );
            self.tx
                .query(
                    &sql,
                    &[
                        &self.user_id,
                        &id.key.as_str(),
                        &id.scope.as_str(),
                        &nullable(&id.profile_id),
                        &nullable(id.client_family.as_str()),
                        &nullable(&id.device_id),
                        &library,
                        &nullable(&id.series_id),
                        &text,
                    ],
                )
                .await
        } else {
            let boxed = identity_params_boxed(self.user_id, id)?;
            let mut params: Vec<&(dyn ToSql + Sync)> = boxed
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect();
            let value_at = params.len() + 1;
            let revision_at = value_at + 1;
            params.push(&text);
            params.push(&expected);
            let sql = format!(
                "UPDATE user_setting_values
                 SET value = ${value_at}::text::jsonb, revision = revision + 1, updated_at = now()
                 WHERE {} AND revision = ${revision_at}
                 RETURNING {SETTING_VALUE_COLUMNS}",
                identity_clause(1, id)
            );
            self.tx.query(&sql, &params).await
        }
        .map_err(pg("compare-and-setting value"))?;
        rows.first()
            .map(scan_setting_value)
            .ok_or(Error::RevisionConflict)
    }

    /// `deleteSettingValue`.
    pub async fn delete_setting_value(&mut self, id: &SettingIdentity) -> Result<bool> {
        validate_identity(id)?;
        let sql = format!(
            "DELETE FROM user_setting_values WHERE {}",
            identity_clause(1, id)
        );
        let boxed = identity_params_boxed(self.user_id, id)?;
        let params: Vec<&(dyn ToSql + Sync)> = boxed
            .iter()
            .map(|b| b.as_ref() as &(dyn ToSql + Sync))
            .collect();
        let n = self
            .tx
            .execute(&sql, &params)
            .await
            .map_err(pg("deleting setting value"))?;
        Ok(n > 0)
    }

    /// `getSettingMutation`.
    pub async fn get_mutation(&mut self, id: &str) -> Result<Option<SettingMutationRecord>> {
        let rows = self
            .tx
            .query(
                "SELECT mutation_id, request_hash, result::text, created_at, expires_at
                 FROM user_setting_mutations WHERE user_id = $1 AND mutation_id = $2",
                &[&self.user_id, &id],
            )
            .await
            .map_err(pg("getting setting mutation"))?;
        Ok(rows.first().map(scan_setting_mutation))
    }

    /// `putSettingMutation`: `(record, inserted)`.
    pub async fn put_mutation(
        &mut self,
        record: &SettingMutationRecord,
    ) -> Result<(SettingMutationRecord, bool)> {
        record.validate()?;
        let text = utf8(&record.result)?;
        let rows = self
            .tx
            .query(
                "INSERT INTO user_setting_mutations (user_id, mutation_id, request_hash, result, expires_at)
                 VALUES ($1, $2, $3, $4::text::jsonb, $5::text::timestamptz)
                 ON CONFLICT (user_id, mutation_id) DO NOTHING
                 RETURNING mutation_id, request_hash, result::text, created_at, expires_at",
                &[
                    &self.user_id,
                    &record.mutation_id,
                    &record.request_hash,
                    &text,
                    &record.expires_at,
                ],
            )
            .await
            .map_err(pg("recording setting mutation"))?;
        if let Some(row) = rows.first() {
            return Ok((scan_setting_mutation(row), true));
        }
        match self.get_mutation(&record.mutation_id).await? {
            Some(existing) => Ok((existing, false)),
            None => Err(Error::Pg {
                op: "recording setting mutation: conflicting receipt disappeared",
                source: silo_pg::Error::NoRows,
            }),
        }
    }

    /// `CheckProfilePINRevision`.
    pub async fn check_pin_revision(&mut self, id: &str, revision: i64) -> Result<bool> {
        let rows = self
            .tx
            .query(
                "SELECT pin_revision = $3 FROM user_profiles WHERE user_id = $1 AND id = $2 FOR UPDATE",
                &[&self.user_id, &id, &revision],
            )
            .await
            .map_err(pg("checking pin revision"))?;
        Ok(rows.first().is_some_and(|r| r.get(0)))
    }

    /// `createProfile`.
    pub async fn create_profile(&mut self, p: &NewProfile) -> Result<()> {
        let now = GoTime::now_utc().rfc3339();
        let rows = self
            .tx
            .query(
                "SELECT EXISTS(SELECT 1 FROM user_profiles WHERE user_id = $1)",
                &[&self.user_id],
            )
            .await
            .map_err(pg("checking existing profiles"))?;
        let has_existing: bool = rows.first().is_some_and(|r| r.get(0));
        let is_primary = !has_existing;
        // The first profile becomes primary; `createProfile` also forces show_forced_subtitles on.
        let show_forced = true;
        let age = i16::try_from(p.max_advisory_age).unwrap_or(0);
        self.tx
            .execute(
                "INSERT INTO user_profiles (
                    id, user_id, name, avatar, pin_hash, is_child, is_primary, max_content_rating, max_advisory_age,
                    require_advisory_age,
                    quality_preference, language, preferred_metadata_language, subtitle_language, subtitle_mode,
                    auto_skip_intro, auto_skip_credits, auto_skip_recap, auto_play_next_preview,
                    library_restrictions_enabled,
                    show_forced_subtitles, max_playback_quality, created_at, updated_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9::smallint, 0), $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23::text::timestamptz, $23::text::timestamptz)",
                &[
                    &p.id,
                    &self.user_id,
                    &p.name,
                    &p.avatar,
                    &p.pin_hash,
                    &p.is_child,
                    &is_primary,
                    &p.max_content_rating,
                    &age,
                    &p.require_advisory_age,
                    &p.quality_preference,
                    &p.language,
                    &p.preferred_metadata_language,
                    &p.subtitle_language,
                    &p.subtitle_mode,
                    &p.auto_skip_intro,
                    &p.auto_skip_credits,
                    &p.auto_skip_recap,
                    &p.auto_play_next_preview,
                    &p.library_restrictions_enabled,
                    &show_forced,
                    &p.max_playback_quality,
                    &now,
                ],
            )
            .await
            .map_err(pg("inserting profile"))?;
        self.replace_allowed_libraries(&p.id, &p.allowed_library_ids)
            .await
    }

    /// `replaceProfileAllowedLibraries`.
    pub async fn replace_allowed_libraries(&mut self, id: &str, libraries: &[i32]) -> Result<()> {
        self.tx
            .execute(
                "DELETE FROM user_profile_allowed_libraries WHERE user_id = $1 AND profile_id = $2",
                &[&self.user_id, &id],
            )
            .await
            .map_err(pg("clearing allowed libraries"))?;
        for library in libraries {
            self.tx
                .execute(
                    "INSERT INTO user_profile_allowed_libraries (user_id, profile_id, library_id) VALUES ($1, $2, $3)",
                    &[&self.user_id, &id, library],
                )
                .await
                .map_err(pg("adding allowed library"))?;
        }
        Ok(())
    }

    /// `updateProfile`. `Ok(false)` is its "profile not found" error.
    pub async fn update_profile(&mut self, id: &str, u: &UpdateProfileInput) -> Result<bool> {
        let policy_changed = u.pin_hash.is_some()
            || u.is_child.is_some()
            || u.max_content_rating.is_some()
            || u.max_advisory_age.is_some()
            || u.require_advisory_age.is_some()
            || u.library_restrictions_enabled.is_some()
            || u.allowed_library_ids.is_some()
            || u.max_playback_quality.is_some();
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<Box<dyn ToSql + Sync + Send>> = Vec::new();
        macro_rules! add {
            ($column:literal, $value:expr) => {
                if let Some(value) = &$value {
                    args.push(Box::new(value.clone()));
                    clauses.push(format!(concat!($column, " = ${}"), args.len()));
                }
            };
        }
        add!("name", u.name);
        add!("avatar", u.avatar);
        add!("pin_hash", u.pin_hash);
        add!("is_child", u.is_child);
        add!("max_content_rating", u.max_content_rating);
        if let Some(age) = u.max_advisory_age {
            let age: Option<i16> = (age != 0).then(|| i16::try_from(age).unwrap_or(i16::MAX));
            args.push(Box::new(age));
            clauses.push(format!("max_advisory_age = ${}", args.len()));
        }
        add!("require_advisory_age", u.require_advisory_age);
        add!("quality_preference", u.quality_preference);
        add!("language", u.language);
        add!("preferred_metadata_language", u.preferred_metadata_language);
        add!("subtitle_language", u.subtitle_language);
        add!("subtitle_mode", u.subtitle_mode);
        add!("auto_skip_intro", u.auto_skip_intro);
        add!("auto_skip_credits", u.auto_skip_credits);
        add!("auto_skip_recap", u.auto_skip_recap);
        add!("auto_play_next_preview", u.auto_play_next_preview);
        add!(
            "library_restrictions_enabled",
            u.library_restrictions_enabled
        );
        add!("show_forced_subtitles", u.show_forced_subtitles);
        add!("max_playback_quality", u.max_playback_quality);
        if clauses.is_empty() && u.allowed_library_ids.is_none() {
            return Ok(true);
        }
        let rows = self
            .tx
            .query(
                "SELECT EXISTS(SELECT 1 FROM user_profiles WHERE user_id = $1 AND id = $2)",
                &[&self.user_id, &id],
            )
            .await
            .map_err(pg("checking profile existence"))?;
        if !rows.first().is_some_and(|r| r.get::<_, bool>(0)) {
            return Ok(false);
        }
        if !clauses.is_empty() {
            args.push(Box::new(GoTime::now_utc().rfc3339()));
            clauses.push(format!("updated_at = ${}::text::timestamptz", args.len()));
            args.push(Box::new(self.user_id));
            let user_at = args.len();
            args.push(Box::new(id.to_owned()));
            let sql = format!(
                "UPDATE user_profiles SET {} WHERE user_id = ${user_at} AND id = ${}",
                clauses.join(", "),
                user_at + 1
            );
            let params: Vec<&(dyn ToSql + Sync)> = args
                .iter()
                .map(|b| b.as_ref() as &(dyn ToSql + Sync))
                .collect();
            let n = self
                .tx
                .execute(&sql, &params)
                .await
                .map_err(pg("updating profile"))?;
            if n == 0 {
                return Ok(false);
            }
        }
        if let Some(libraries) = &u.allowed_library_ids {
            self.replace_allowed_libraries(id, libraries).await?;
        }
        if policy_changed {
            self.tx
                .execute(
                    "UPDATE users SET access_policy_revision = access_policy_revision + 1 WHERE id = $1::int4",
                    &[&self.user_id],
                )
                .await
                .map_err(pg("bumping access policy revision"))?;
        }
        Ok(true)
    }
}
