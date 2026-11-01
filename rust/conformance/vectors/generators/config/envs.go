//go:build silo_config_vectors

package main

import (
	"os"
	"path/filepath"

	"github.com/Silo-Server/silo-server/internal/clientip"
	"github.com/Silo-Server/silo-server/internal/config"
	"github.com/Silo-Server/silo-server/internal/database"
	"github.com/Silo-Server/silo-server/internal/debugserver"
	"github.com/Silo-Server/silo-server/internal/envutil"
	"github.com/Silo-Server/silo-server/internal/streamtelemetry"
	"github.com/Silo-Server/silo-server/internal/telemetry"
	"github.com/Silo-Server/silo-server/internal/tuning"

	xaudiobooks "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xaudiobooks"
	xcatalog "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xcatalog"
	xcmdsilo "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xcmdsilo"
	xebooks "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xebooks"
	xhttpstream "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xhttpstream"
	xmanga "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xmanga"
	xmetadata "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xmetadata"
	xscanner "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xscanner"
	xtasks "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xtasks"
)

type envCase struct {
	Name    string            `json:"name"`
	Env     map[string]string `json:"env"`
	Dotenv  *string           `json:"dotenv,omitempty"`
	EnvFile string            `json:"env_file,omitempty"`
	// Each entry: section name to Go's JSON of the result, or "error: ..." text.
	Resolved map[string]string `json:"resolved"`
}

const secret = "0123456789abcdef0123456789abcdef"

func base(extra ...string) map[string]string {
	m := map[string]string{"DATABASE_URL": "postgres://db/silo", "SECRET_KEY": secret}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	return m
}

func ptr(s string) *string { return &s }

func jsonOrError(v any, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	return goJSON(v)
}

func resolve(c *envCase) {
	os.Clearenv()
	for k, v := range c.Env {
		os.Setenv(k, v)
	}
	dir, err := os.MkdirTemp("", "silo-config-vectors")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	envFile := c.EnvFile
	if c.Dotenv != nil {
		envFile = filepath.Join(dir, "test.env")
		if err := os.WriteFile(envFile, []byte(*c.Dotenv), 0o644); err != nil {
			panic(err)
		}
	}
	r := map[string]string{}
	bc, bootErr := config.LoadBootstrap(envFile)
	r["bootstrap"] = jsonOrError(bc, bootErr)
	if bootErr == nil {
		cfg := mustLoad(map[string]string{"redis.url": "redis://stored:1/2", "redis.db": "9"})
		xcmdsilo.ApplyBootstrapOverrides(cfg, bc)
		r["bootstrap_overrides"] = goJSON(cfg)
		off := mustLoad(map[string]string{"audiobookshelf_compat.enabled": "false"})
		xcmdsilo.ApplyBootstrapOverrides(off, bc)
		r["bootstrap_abs_disabled"] = off.AudiobookshelfCompat.Listen
		configured, values := map[string]bool{}, map[string]string{}
		xcmdsilo.AddRedisBootstrapSettings(bc.RedisURL, configured, values)
		r["redis_bootstrap_settings"] = goJSON([]any{configured, values})
	}
	dbu, dbErr := config.LoadDatabaseURL(envFile)
	r["database_url"] = jsonOrError(dbu, dbErr)
	cfg, adj := tuning.Parse(os.Getenv)
	if adj == nil {
		adj = []tuning.Adjustment{}
	}
	r["tuning"] = goJSON([]any{cfg, adj})
	dc, dErr := debugserver.LoadConfig(os.Getenv)
	r["debug_server"] = jsonOrError(dc, dErr)
	r["telemetry"] = goJSON(telemetry.LoadConfig("node-1"))
	r["stream_telemetry"] = goJSON(streamtelemetry.ConfigFromEnv("node-1"))
	pg, pgErr := database.LoadPostgresTuneOptionsFromEnv(20)
	r["postgres_tune"] = jsonOrError(pg, pgErr)
	se, seErr := xcatalog.SearchSettingsFromEnv(os.Getenv)
	r["search_env"] = jsonOrError(se, seErr)
	r["migration_timeout"] = goJSON(int64(database.MigrationTimeout()))
	tp := ""
	if raw := os.Getenv(clientip.EnvTrustedProxies); raw != "" {
		n, tErr := clientip.NormalizeCIDRList(trim(raw))
		if tErr != nil {
			tp = "error: " + tErr.Error()
		} else {
			tp = n
		}
	}
	r["trusted_proxies"] = tp
	r["node_drain"] = goJSON(int64(xcmdsilo.NodeDrainTimeout(os.Getenv("SILO_NODE_DRAIN_TIMEOUT"))))
	r["shutdown_delay"] = goJSON(int64(xcmdsilo.APIShutdownDelay(os.Getenv("SILO_SHUTDOWN_DELAY"))))
	if os.Getenv("SILO_NODE_NAME") != "" || os.Getenv("NODE_NAME") != "" {
		r["node_identity"] = xcmdsilo.ResolveNodeIdentity()
	}
	r["metrics_listen"] = trim(os.Getenv("SILO_METRICS_LISTEN"))
	r["plugin_cache_dir"] = trim(os.Getenv("SILO_PLUGIN_CACHE_DIR"))
	r["stall_window"] = goJSON(int64(xhttpstream.StallWindow()))
	r["ebook_rate_limit"] = goJSON(int64(xebooks.RateLimitCooldownFloor()))
	r["ebook_workers"] = goJSON(xebooks.EnrichWorkers())
	batch := xaudiobooks.EnrichBatchSize()
	r["audiobook_batch"] = goJSON(batch)
	r["audiobook_workers"] = goJSON(xaudiobooks.EnrichWorkers(batch))
	r["manga_batch"] = goJSON(xmanga.EnrichBatchSize())
	r["manga_workers"] = goJSON(xmanga.EnrichWorkers())
	r["audiobook_scan"] = goJSON(xscanner.AudiobookScanWorkers())
	r["ebook_scan"] = goJSON(xscanner.EbookScanWorkers())
	r["match_threshold"] = goJSON(xmetadata.MatchThreshold())
	claims, cErr := xtasks.MaxClaims(os.Getenv("SILO_EBOOK_BACKFILL_MAX_CLAIMS"))
	r["ebook_backfill_claims"] = jsonOrError(claims, cErr)
	delay, dlErr := xtasks.BatchDelay(os.Getenv("SILO_EBOOK_BACKFILL_BATCH_DELAY"))
	r["ebook_backfill_delay"] = jsonOrError(int64(delay), dlErr)
	r["query_attribution"] = goJSON(envutil.BoolDefault("SILO_QUERY_ATTRIBUTION_ENABLED", false))
	c.Resolved = r
}

func trim(s string) string {
	return string(trimBytes([]byte(s)))
}

func writeEnvVectors() {
	cases := []envCase{
		{Name: "empty environment", Env: map[string]string{}},
		{Name: "database url only", Env: map[string]string{"DATABASE_URL": "postgres://x"}},
		{Name: "secret too short", Env: map[string]string{"DATABASE_URL": "postgres://x", "SECRET_KEY": "short"}},
		{Name: "secret exactly 31", Env: map[string]string{"DATABASE_URL": "postgres://x", "SECRET_KEY": secret[:31]}},
		{Name: "secret exactly 32", Env: base()},
		{Name: "multibyte secret counts bytes", Env: map[string]string{"DATABASE_URL": "x", "SECRET_KEY": "日本語日本語日本語日本語"}},
		{Name: "ports and redis", Env: base("PORT", "9090", "JF_PORT", "9096", "ABS_PORT", "23378", "REDIS_URL", "redis://r:6379/2")},
		{Name: "empty port uses default", Env: base("PORT", "", "JF_PORT", "", "ABS_PORT", "", "MODE", "")},
		{Name: "odd port is unchecked", Env: base("PORT", "abc")},
		{Name: "mode api", Env: base("MODE", "api")},
		{Name: "mode frontend", Env: base("MODE", "frontend")},
		{Name: "mode unknown passes bootstrap", Env: base("MODE", "banana")},
		{Name: "mode proxy needs node url", Env: base("MODE", "proxy")},
		{Name: "mode transcode needs node url", Env: base("MODE", "transcode")},
		{Name: "mode proxy with node url", Env: base("MODE", "proxy", "NODE_URL", "http://n:1", "NODE_NAME", "n1")},
		{Name: "mode transcode with node url", Env: base("MODE", "transcode", "NODE_URL", "http://n:2", "SILO_NODE_NAME", "n2", "NODE_NAME", "ignored")},
		{Name: "dotenv fills unset", Env: map[string]string{}, Dotenv: ptr("DATABASE_URL=postgres://from-file\nSECRET_KEY=" + secret + "\nPORT=1234\nSILO_SHUTDOWN_DELAY=9s\n")},
		{Name: "environment beats dotenv", Env: map[string]string{"PORT": "1"}, Dotenv: ptr("DATABASE_URL=d\nSECRET_KEY=" + secret + "\nPORT=2\n")},
		{Name: "set-but-empty env beats dotenv", Env: map[string]string{"DATABASE_URL": ""}, Dotenv: ptr("DATABASE_URL=d\nSECRET_KEY=" + secret + "\n")},
		{Name: "dotenv syntax error is ignored", Env: base(), Dotenv: ptr("PORT=1\nnot valid here!\n")},
		{Name: "dotenv quotes export and comments", Env: map[string]string{}, Dotenv: ptr("# comment\nexport DATABASE_URL=\"postgres://q\" # trailing\nSECRET_KEY='" + secret + "'\nMODE: api\nREDIS_URL=redis://a#notcomment\nSILO_METRICS_LISTEN= :9100 # note\n")},
		{Name: "dotenv expansion", Env: map[string]string{"HOST": "fromenv"}, Dotenv: ptr("HOST=h\nDATABASE_URL=postgres://${HOST}/$HOST\\$x\nSECRET_KEY=" + secret + "\nNODE_NAME=\"a\\nb\"\n")},
		{Name: "missing env file", Env: base(), EnvFile: "/nonexistent/silo.env"},
		{Name: "tuning off", Env: base("SILO_NET_TCP_CONGESTION", " Off ", "SILO_NET_TCP_SEND_BUFFER", " Off ")},
		{Name: "tuning mistyped", Env: base("SILO_NET_TCP_CONGESTION", "false", "SILO_NET_TCP_SEND_BUFFER", "0")},
		{Name: "tuning sized", Env: base("SILO_NET_TCP_CONGESTION", "BBR", "SILO_NET_TCP_SEND_BUFFER", " 16777216 ")},
		{Name: "tuning oversize", Env: base("SILO_NET_TCP_SEND_BUFFER", "1073741824")},
		{Name: "debug loopback", Env: base("SILO_DEBUG_LISTEN", "127.0.0.1:6060", "SILO_DEBUG_BLOCK_RATE", "1000000", "SILO_DEBUG_MUTEX_FRACTION", "100")},
		{Name: "debug ipv6 loopback", Env: base("SILO_DEBUG_LISTEN", "[::1]:6060")},
		{Name: "debug mapped loopback", Env: base("SILO_DEBUG_LISTEN", "[::ffff:127.0.0.1]:6060")},
		{Name: "debug zero port", Env: base("SILO_DEBUG_LISTEN", "127.0.0.1:0")},
		{Name: "debug not loopback", Env: base("SILO_DEBUG_LISTEN", "0.0.0.0:6060")},
		{Name: "debug hostname", Env: base("SILO_DEBUG_LISTEN", "localhost:6060")},
		{Name: "debug sampling without listener", Env: base("SILO_DEBUG_BLOCK_RATE", "1000000")},
		{Name: "debug sampling out of range", Env: base("SILO_DEBUG_LISTEN", "127.0.0.1:1", "SILO_DEBUG_MUTEX_FRACTION", "5")},
		{Name: "otel endpoint enables", Env: base("OTEL_EXPORTER_OTLP_ENDPOINT", " http://c:4317 ", "OTEL_SERVICE_NAME", " silo-a ", "OTEL_SERVICE_VERSION", " 1.2 ")},
		{Name: "otel flag and protocols", Env: base("SILO_OTEL_ENABLED", "Yes", "OTEL_EXPORTER_OTLP_PROTOCOL", "http", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "grpc", "OTEL_EXPORTER_OTLP_LOGS_PROTOCOL", "bad")},
		{Name: "otel sampler ratio clamps", Env: base("OTEL_TRACES_SAMPLER", " TraceIDRatio ", "OTEL_TRACES_SAMPLER_ARG", "5")},
		{Name: "otel sampler bad arg", Env: base("OTEL_TRACES_SAMPLER", "jaeger_remote", "OTEL_TRACES_SAMPLER_ARG", "nan")},
		{Name: "otel sampler inf arg", Env: base("OTEL_TRACES_SAMPLER", "always_off", "OTEL_TRACES_SAMPLER_ARG", "inf")},
		{Name: "otel sampler small arg", Env: base("OTEL_TRACES_SAMPLER_ARG", "0.25")},
		{Name: "stream telemetry off", Env: base("SILO_STREAM_TELEMETRY_ENABLED", "false")},
		{Name: "stream telemetry typo reads off", Env: base("SILO_STREAM_TELEMETRY_ENABLED", "flase")},
		{Name: "stream telemetry whitespace keeps default", Env: base("SILO_STREAM_TELEMETRY_ENABLED", "   ")},
		{Name: "stream telemetry distributed", Env: base("SILO_STREAM_TELEMETRY_DISTRIBUTED", "on", "SILO_STREAM_TELEMETRY_KEY_PREFIX", "abc", "SILO_STREAM_TELEMETRY_FULL_RESYNC_EVERY", "5", "SILO_STREAM_TELEMETRY_MAX_PUBLISHERS", "7", "SILO_STREAM_TELEMETRY_MAX_MERGED_SESSIONS", "8", "SILO_STREAM_TELEMETRY_MAX_MERGED_TRANSFERS", "9", "SILO_STREAM_TELEMETRY_VIEW_TTL", "2s")},
		{Name: "stream telemetry bad key prefix", Env: base("SILO_STREAM_TELEMETRY_DISTRIBUTED", "off", "SILO_STREAM_TELEMETRY_KEY_PREFIX", "a b")},
		{Name: "stream telemetry core invalid", Env: base("SILO_STREAM_TELEMETRY_SWEEP_INTERVAL", "soon", "SILO_STREAM_TELEMETRY_MAX_SESSIONS", "0")},
		{Name: "stream telemetry core invalid while off", Env: base("SILO_STREAM_TELEMETRY_ENABLED", "0", "SILO_STREAM_TELEMETRY_RETENTION", "-1s")},
		{Name: "stream telemetry families narrow", Env: base("SILO_STREAM_TELEMETRY_FAMILIES", " Native, proxy ,,")},
		{Name: "stream telemetry families blank list", Env: base("SILO_STREAM_TELEMETRY_FAMILIES", ",")},
		{Name: "stream telemetry families bad", Env: base("SILO_STREAM_TELEMETRY_FAMILIES", "native,bogus")},
		{Name: "stream telemetry sweep moves freshness", Env: base("SILO_STREAM_TELEMETRY_SWEEP_INTERVAL", "10s")},
		{Name: "stream telemetry freshness moves sweep and ttl", Env: base("SILO_STREAM_TELEMETRY_FRESHNESS", "2m")},
		{Name: "stream telemetry ttl moves freshness", Env: base("SILO_STREAM_TELEMETRY_MEMBERSHIP_TTL", "2s")},
		{Name: "stream telemetry pinned conflict", Env: base("SILO_STREAM_TELEMETRY_SWEEP_INTERVAL", "10s", "SILO_STREAM_TELEMETRY_FRESHNESS", "5s", "SILO_STREAM_TELEMETRY_MEMBERSHIP_TTL", "1s")},
		{Name: "stream telemetry huge ttl", Env: base("SILO_STREAM_TELEMETRY_MEMBERSHIP_TTL", "2000000h")},
		{Name: "stream telemetry huge sweep", Env: base("SILO_STREAM_TELEMETRY_SWEEP_INTERVAL", "1000000h")},
		{Name: "pg tune off", Env: base("POSTGRES_TUNE", "off", "POSTGRES_TUNE_MEMORY", "junk")},
		{Name: "pg tune bad mode", Env: base("POSTGRES_TUNE", "maybe")},
		{Name: "pg tune explicit", Env: base("POSTGRES_TUNE", "true", "POSTGRES_TUNE_MEMORY", "8 GB", "POSTGRES_TUNE_CPUS", "4", "POSTGRES_TUNE_CONNECTIONS", "5", "POSTGRES_TUNE_STORAGE", "NVME", "POSTGRES_TUNE_DB_SIZE", "mid", "POSTGRES_TUNE_OS", "LINUX", "POSTGRES_TUNE_IO_METHOD", "IO_URING")},
		{Name: "pg tune silo aliases", Env: base("SILO_POSTGRES_TUNE", "oltp", "SILO_POSTGRES_TUNE_MEMORY", "1.5g", "SILO_POSTGRES_TUNE_CPUS", "2", "SILO_POSTGRES_TUNE_STORAGE", "hard_drive_hdd", "SILO_POSTGRES_TUNE_DB_SIZE", "fits-in-ram")},
		{Name: "pg tune bad profile", Env: base("POSTGRES_TUNE", "1", "POSTGRES_TUNE_PROFILE", "dw", "POSTGRES_TUNE_MEMORY", "1GB")},
		{Name: "pg tune memory without unit", Env: base("POSTGRES_TUNE", "1", "POSTGRES_TUNE_MEMORY", "1024")},
		{Name: "pg tune memory negative", Env: base("POSTGRES_TUNE", "1", "POSTGRES_TUNE_MEMORY", "-1GB")},
		{Name: "pg tune cpus bad", Env: base("POSTGRES_TUNE", "1", "POSTGRES_TUNE_MEMORY", "1GB", "POSTGRES_TUNE_CPUS", "0")},
		{Name: "pg tune connections bad", Env: base("POSTGRES_TUNE", "1", "POSTGRES_TUNE_MEMORY", "1GB", "POSTGRES_TUNE_CPUS", "1", "POSTGRES_TUNE_CONNECTIONS", "x")},
		{Name: "pg tune storage bad", Env: base("POSTGRES_TUNE", "1", "POSTGRES_TUNE_MEMORY", "1GB", "POSTGRES_TUNE_CPUS", "1", "POSTGRES_TUNE_STORAGE", "tape")},
		{Name: "pg tune db size bad", Env: base("POSTGRES_TUNE", "1", "POSTGRES_TUNE_MEMORY", "1GB", "POSTGRES_TUNE_CPUS", "1", "POSTGRES_TUNE_DB_SIZE", "huge")},
		{Name: "search provider and meilisearch", Env: base("SILO_SEARCH_PROVIDER", " MeiliSearch ", "SILO_MEILISEARCH_URL", "http://m:7700/", "SILO_MEILISEARCH_API_KEY", " k ")},
		{Name: "search provider bad", Env: base("SILO_SEARCH_PROVIDER", "elastic")},
		{Name: "search url bad", Env: base("SILO_MEILISEARCH_URL", "ftp://m")},
		{Name: "migrate timeout", Env: base("SILO_MIGRATE_TIMEOUT", " 1h ")},
		{Name: "migrate timeout off", Env: base("SILO_MIGRATE_TIMEOUT", "0")},
		{Name: "migrate timeout negative", Env: base("SILO_MIGRATE_TIMEOUT", "-5s")},
		{Name: "migrate timeout bad", Env: base("SILO_MIGRATE_TIMEOUT", "soon")},
		{Name: "trusted proxies", Env: base("SILO_TRUSTED_PROXIES", " 10.0.0.0/8 ,, ::1/128 ")},
		{Name: "trusted proxies bad", Env: base("SILO_TRUSTED_PROXIES", "10.0.0.0/33")},
		{Name: "drain and shutdown durations", Env: base("SILO_NODE_DRAIN_TIMEOUT", " 15m ", "SILO_SHUTDOWN_DELAY", "10s")},
		{Name: "drain and shutdown seconds", Env: base("SILO_NODE_DRAIN_TIMEOUT", "900", "SILO_SHUTDOWN_DELAY", "0")},
		{Name: "drain and shutdown invalid", Env: base("SILO_NODE_DRAIN_TIMEOUT", "-5", "SILO_SHUTDOWN_DELAY", "soon")},
		{Name: "drain overflow seconds", Env: base("SILO_NODE_DRAIN_TIMEOUT", "9223372037", "SILO_SHUTDOWN_DELAY", "9223372036")},
		{Name: "node identity prefers silo name", Env: base("SILO_NODE_NAME", "a", "NODE_NAME", "b")},
		{Name: "node identity falls to node name", Env: base("NODE_NAME", "b")},
		{Name: "listeners and cache", Env: base("SILO_METRICS_LISTEN", " :9100 ", "SILO_PLUGIN_CACHE_DIR", " /p ")},
		{Name: "stall window", Env: base("SILO_STREAM_WRITE_STALL_TIMEOUT", "60")},
		{Name: "stall window bad", Env: base("SILO_STREAM_WRITE_STALL_TIMEOUT", "0")},
		{Name: "worker overrides", Env: base("SILO_EBOOK_ENRICH_WORKERS", "9999", "SILO_AUDIOBOOK_ENRICH_BATCH_SIZE", "3", "SILO_AUDIOBOOK_ENRICH_WORKERS", "7", "SILO_MANGA_ENRICH_BATCH", "2", "SILO_MANGA_ENRICH_WORKERS", "9", "SILO_AUDIOBOOK_SCAN_WORKERS", "5", "SILO_EBOOK_RATE_LIMIT_COOLDOWN", "1m")},
		{Name: "worker overrides invalid", Env: base("SILO_EBOOK_ENRICH_WORKERS", "x", "SILO_AUDIOBOOK_ENRICH_BATCH_SIZE", "-1", "SILO_AUDIOBOOK_ENRICH_WORKERS", "0", "SILO_MANGA_ENRICH_BATCH", " 2", "SILO_EBOOK_SCAN_WORKERS", "2", "SILO_AUDIOBOOK_SCAN_WORKERS", "x", "SILO_EBOOK_RATE_LIMIT_COOLDOWN", "-1m")},
		{Name: "match threshold", Env: base("SILO_METADATA_MATCH_MIN_SCORE", " 0.75 ")},
		{Name: "match threshold out of range", Env: base("SILO_METADATA_MATCH_MIN_SCORE", "5")},
		{Name: "ebook backfill", Env: base("SILO_EBOOK_BACKFILL_MAX_CLAIMS", " 5 ", "SILO_EBOOK_BACKFILL_BATCH_DELAY", " 2s ")},
		{Name: "ebook backfill bad", Env: base("SILO_EBOOK_BACKFILL_MAX_CLAIMS", "0", "SILO_EBOOK_BACKFILL_BATCH_DELAY", "0s")},
		{Name: "query attribution", Env: base("SILO_QUERY_ATTRIBUTION_ENABLED", "1")},
		{Name: "bootstrap redis names the database", Env: base("REDIS_URL", "redis://r:1/4")},
		{Name: "bootstrap redis unreadable", Env: base("REDIS_URL", "bad://r")},
		{Name: "bootstrap redis negative database", Env: base("REDIS_URL", "redis://r:1/-2")},
	}
	for i := range cases {
		resolve(&cases[i])
	}
	os.Clearenv()
	os.Setenv("TZ", "UTC")
	write("env_permutations.json", cases)
}
