//! Every fixed advisory lock integer in the Go tree, read from its source by the format generator. Do
//! not edit. Go and Rust replicas that disagree on one of these lose their mutual exclusion.

/// `schemaMigrationsLockID` in `internal/database/migrate.go`.
pub const SCHEMA_MIGRATIONS: i64 = 8034219741;

/// `StorageNodeAdmissionLockKey` in `internal/database/pglock/node_admission.go`.
pub const STORAGE_NODE_ADMISSION: i64 = 23443015164187726;

/// `ArtworkReconcileLockKey` in `internal/database/pglock/pglock.go`.
pub const ARTWORK_RECONCILE: i64 = 23443015164187730;

/// `taskHistoryCleanupAdvisoryLock` in `internal/taskmanager/repository/postgres_history.go`.
pub const TASK_HISTORY_CLEANUP: i64 = 6001411881846788948;

/// `requestReconcileAdvisoryLock` in `internal/taskmanager/tasks/reconcile_requests.go`.
pub const REQUEST_RECONCILE: i64 = 6001411882015085123;

/// `requestTargetWriteAdvisoryLock` in `internal/taskmanager/tasks/reconcile_requests.go`.
pub const REQUEST_TARGET_WRITE: i64 = 6001411882015085655;

/// `bulkMetadataEnrichmentAdvisoryLock` in `internal/taskmanager/tasks/bulk_metadata_enrichment.go`.
pub const BULK_METADATA_ENRICHMENT: i64 = 6001411881796784706;

/// `fullMetadataRefreshAdvisoryLock` in `internal/taskmanager/tasks/refresh_all_library_metadata.go`.
pub const FULL_METADATA_REFRESH: i64 = 6001411881814019154;

/// `detectMarkersAdvisoryLock` in `internal/taskmanager/tasks/detect_intro_markers.go`.
pub const DETECT_MARKERS: i64 = 6001411881931262802;

/// `hdr10PlusBackfillAdvisoryLock` in `internal/taskmanager/tasks/backfill_hdr10plus.go`.
pub const HDR10PLUS_BACKFILL: i64 = 6001411881846461008;

/// `matroskaTrackBackfillAdvisoryLock` in `internal/taskmanager/tasks/backfill_matroska_track_numbers.go`.
pub const MATROSKA_TRACK_BACKFILL: i64 = 6001411881930806868;

/// `databaseMaintenanceAdvisoryLock` in `internal/taskmanager/tasks/database_maintenance.go`.
pub const DATABASE_MAINTENANCE: i64 = 6001411881779219796;

/// `recheckExternalIdentitiesAdvisoryLock` in `internal/taskmanager/tasks/recheck_external_identities.go`.
pub const RECHECK_EXTERNAL_IDENTITIES: i64 = 6001411881863238211;

/// `reconcileLock` in `internal/trickplay/service.go`.
pub const TRICKPLAY_RECONCILE: i64 = 6001411882048703312;

/// `claimLockKey` in `internal/idgen/lease.go`.
pub const IDGEN_CLAIM: i64 = 23443015163528269;

/// `InitialSetupAdvisoryLock` in `internal/auth/repository.go`.
pub const INITIAL_SETUP: i64 = 6001411882031076437;

/// `libraryRefreshAdvisoryLockNamespace` in `internal/adminjob/library_refresh.go`.
pub const LIBRARY_REFRESH_NAMESPACE: i64 = 1397312594;

/// `searchIndexMaintenanceLockID` in `internal/catalog/search_index_repo.go`.
pub const SEARCH_INDEX_MAINTENANCE: i64 = 375088242626942257;

/// `EmbeddingWritersLock` in `internal/recommendations/embedding_reset.go`.
pub const EMBEDDING_WRITERS: i64 = 6001411882015150932;

/// `embeddingsJobLock` in `internal/recommendations/jobs.go`.
pub const RECS_EMBEDDINGS_JOB: i64 = 6001411882014297410;

/// `tasteProfilesJobLock` in `internal/recommendations/jobs.go`.
pub const RECS_TASTE_PROFILES_JOB: i64 = 6001411882015282004;

/// `cowatchJobLock` in `internal/recommendations/jobs.go`.
pub const RECS_COWATCH_JOB: i64 = 6001411882014168916;

/// `cacheJobLock` in `internal/recommendations/jobs.go`.
pub const RECS_CACHE_JOB: i64 = 6001411882014163267;

/// `staleSweepLock` in `internal/recommendations/jobs.go`.
pub const RECS_STALE_SWEEP: i64 = 6001411882015216716;

/// `quotaLockNamespace` in `internal/requests/repository.go`.
pub const REQUEST_QUOTA_NAMESPACE: i64 = 139;

/// `ratingSyncLockClass` in `internal/watchsync/repository.go`.
pub const WATCHSYNC_RATING_SYNC_CLASS: i64 = 1465078356;

/// `tokenRefreshLockClass` in `internal/watchsync/repository.go`.
pub const WATCHSYNC_TOKEN_REFRESH_CLASS: i64 = 1465078854;

/// `settingMutationAdvisoryClass` in `internal/userstore/pgstore/setting_mutation_tx.go`.
pub const SETTING_MUTATION_CLASS: i64 = 1397577044;

/// `sectionOverridesAdvisoryClass` in `internal/userstore/pgstore/section_overrides.go`.
pub const SECTION_OVERRIDES_CLASS: i64 = 1397048143;

/// `preferenceSettingsAdvisoryClass` in `internal/userstore/pgstore/preference_settings_tx.go`.
pub const PREFERENCE_SETTINGS_CLASS: i64 = 1397312591;

/// `libraryClaimAdvisoryLockID` in `internal/scanqueue/repository.go`.
pub const LIBRARY_CLAIM: i64 = 8500001;

/// `storageTransitionAdmissionLockKey` in `internal/storagetransition/service.go`.
pub const STORAGE_TRANSITION_ADMISSION: i64 = 23443015164187731;

/// `diagnosticQuotaLockNamespace` in `internal/diagnostics/repo.go`.
pub const DIAGNOSTIC_QUOTA_NAMESPACE: i64 = 173;

/// `refreshLock` in `internal/apiusage/apiusage.go`.
pub const API_USAGE_REFRESH: i64 = 6001411881729804629;

/// `originalsCleanupAdvisoryLock` in `internal/chapterthumbs/originals_cleanup.go`.
pub const CHAPTER_ORIGINALS_CLEANUP: i64 = 6001411881762837586;

/// `transcribeQuotaLockNamespace` in `internal/subtitles/ai/pgrepo.go`.
pub const TRANSCRIBE_QUOTA_NAMESPACE: i64 = 412;

/// `sweepAdvisoryLock` in `internal/blobgc/sweep.go`.
pub const BLOB_GC_SWEEP: i64 = 6001411881745990483;

/// `lockKey` in `internal/extrastills/generator.go`.
pub const EXTRA_STILLS: i64 = 23443015163271252;

/// `storageMaintenanceLockClassID` in `internal/downloads/storage_repo.go`.
pub const DOWNLOAD_STORAGE_MAINTENANCE_CLASS: i64 = 5312721;

/// `downloadQuotaLockClassID` in `internal/downloads/repo.go`.
pub const DOWNLOAD_QUOTA_CLASS: i64 = 1684828001;

/// `artworkStorageSweepAdvisoryLock` in `internal/metadata/artwork_storage_sweep.go`.
pub const ARTWORK_STORAGE_SWEEP: i64 = 6001411882032252240;

/// `storedArtworkReleaseAdvisoryLock` in `internal/metadata/artwork_release.go`.
pub const STORED_ARTWORK_RELEASE: i64 = 6001411882014297171;

/// The literal in the SQL at `internal/autoscan/repository.go:922`.
pub const AUTOSCAN_SOURCE_CLASS: i64 = 900173;
