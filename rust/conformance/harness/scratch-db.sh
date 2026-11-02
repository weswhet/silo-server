#!/usr/bin/env bash
# Starts a throwaway Postgres and Redis for the interop tests. The schema comes from a schema-only dump
# of a running conformance stack, read-only. Prints env assignments for the tests on stdout.
# Usage: scratch-db.sh up <project> <source-postgres-container> | scratch-db.sh down <project>
set -euo pipefail
action=$1 project=$2
compose=(docker compose -p "$project" -f "$(dirname "$0")/scratch-db.yml")
if [ "$action" = down ]; then
  "${compose[@]}" down -v >&2
  exit 0
fi
source=$3
"${compose[@]}" up -d --wait >&2
schema=$(mktemp)
trap 'rm -f "$schema"' EXIT
docker exec "$source" pg_dump -U silo -d silo --schema-only --no-owner --no-privileges > "$schema"
container=$("${compose[@]}" ps -q postgres)
sql() { docker exec -i "$container" psql -q -v ON_ERROR_STOP=1 -U silo "$@" >&2; }
for db in sess gostore ruststore; do
  sql -d silo -c "CREATE DATABASE $db"
  sql -d "$db" < "$schema"
  sql -d "$db" <<'SQL'
INSERT INTO users (id, username, password_hash, role) OVERRIDING SYSTEM VALUE
VALUES (1, 'interop-a', 'x', 'admin'), (2, 'interop-b', 'x', 'user');
INSERT INTO user_profiles (id, user_id, name) VALUES ('p1', 1, 'p1'), ('p2', 1, 'p2'), ('p3', 1, 'p3');
SQL
done
pg_port=$("${compose[@]}" port postgres 5432 | sed 's/.*://')
redis_port=$("${compose[@]}" port redis 6379 | sed 's/.*://')
base="postgres://silo:silo@127.0.0.1:$pg_port"
cat <<ENV
export DATABASE_URL=$base/sess?sslmode=disable
export SESSIONCHECK_TEST_USER_ID=1
export SILO_RUNTIME_TEST_DATABASE_URL=$base/silo?sslmode=disable
export SILO_RUNTIME_TEST_REDIS_URL=redis://127.0.0.1:$redis_port
export SILO_STORE_DIFFTEST_GO_REF_URL=$base/gostore?sslmode=disable
export SILO_STORE_DIFFTEST_RUST_REF_URL=$base/ruststore?sslmode=disable
ENV
