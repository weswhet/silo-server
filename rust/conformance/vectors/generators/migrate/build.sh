#!/usr/bin/env bash
# Builds the Go migration harness with internal/database's private provider constructor exported
# through -overlay, leaving the Go tree untouched. Usage: build.sh OUTPUT_BINARY
set -euo pipefail
output="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
cd "$(git rev-parse --show-toplevel)"
export GOTOOLCHAIN="${GOTOOLCHAIN:-go1.26.7}"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cat > "$tmp/export.go" <<'GO'
package database

import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"

	"github.com/Silo-Server/silo-server/migrations"
)

// ConformanceProvider exposes the real provider to the migration harness.
func ConformanceProvider(pool *pgxpool.Pool) (*goose.Provider, error) {
	return newMigrationProvider(pool, migrations.FS, "sql")
}

// ConformanceRepair exposes repairExternalSubtitleNames.
func ConformanceRepair(video string, stored []byte) ([]byte, bool, error) {
	return repairExternalSubtitleNames(video, stored)
}

// ConformanceRewrites exposes subtitleLanguageRewrites.
func ConformanceRewrites(stored []string) (map[string]string, []string) {
	return subtitleLanguageRewrites(stored)
}
GO
printf '{"Replace":{"%s/internal/database/zz_conformance_export.go":"%s/export.go"}}' "$PWD" "$tmp" > "$tmp/overlay.json"
go build -overlay "$tmp/overlay.json" -tags migrate_harness -o "$output" ./rust/conformance/vectors/generators/migrate
