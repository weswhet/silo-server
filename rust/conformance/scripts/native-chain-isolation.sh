#!/usr/bin/env bash
# What a plan comparison cannot show, because it starts the front with SILO_FRONT_SPLIT_RATE_BUDGETS: the
# deployments whose rows behind a credential stay on Go, and one budget across native and Go rows.
#
# Starts its own front on stack B, on port 18180, once per deployment, so the row each request reached is
# in that front's origin log. Run it with both stacks up. It restarts stack B's Go server and restores it.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
set +e
cd "$CONF_REPO" || exit 1
cargo build --quiet --manifest-path rust/Cargo.toml -j 3 -p silo-server

front="http://127.0.0.1:18180"
go_b="http://127.0.0.1:${CONF_B_API_PORT:-38080}"
b_pg=silo-conformance-b-postgres-1
b_silo=silo-conformance-b-silo-1
K="Authorization: Bearer $CONF_USER_API_KEY"
PROF="X-Profile-Id: $CONF_USER_PROFILE_ID"
admin=(-H "Authorization: Bearer $CONF_ADMIN_API_KEY" -H "X-Profile-Id: $CONF_ADMIN_PROFILE_ID" -H 'Content-Type: application/json')
out="$(mktemp -d)"
fail=0
pid=""

psql_b() { docker exec "$b_pg" psql -qAt -U silo silo -c "$1"; }
setting() { psql_b "INSERT INTO server_settings(key,value) VALUES ('$1','$2') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value"; }
unset_setting() { psql_b "DELETE FROM server_settings WHERE key='$1'"; }
stop_front() { [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null; pid=""; }
trap 'stop_front; rm -rf "$out"' EXIT
start_front() {
  stop_front
  : >"$out/origin.jsonl"
  DATABASE_URL="postgres://silo:silo@127.0.0.1:${CONF_B_PG_PORT:-35432}/silo?sslmode=disable" \
    SECRET_KEY="$CONF_SECRET_KEY" \
    REDIS_URL="redis://127.0.0.1:${CONF_B_REDIS_PORT:-36379}" \
    SILO_FRONT_ORIGIN_LOG="$out/origin.jsonl" \
    rust/target/debug/silo --front "main=127.0.0.1:18180,$go_b" >"$out/front.log" 2>&1 &
  pid=$!
  for _ in $(seq 150); do
    curl -fsS -o /dev/null "$front/api/v1/ready" 2>/dev/null && return 0
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  echo "the front did not start:"
  tail -5 "$out/front.log"
  fail=1
  return 1
}
restart_go() {
  docker restart "$b_silo" >/dev/null
  for _ in $(seq 150); do
    curl -fsS -o /dev/null "$go_b/api/v1/ready" 2>/dev/null && return 0
    sleep 0.2
  done
  conf_die "stack B's Go server did not come back"
}
# The origin of the last request for a target.
origin_of() { python3 -c 'import json,sys
last=""
for l in open(sys.argv[1]):
    d=json.loads(l)
    if d["target"]==sys.argv[2]: last=d["origin"]
print(last)' "$out/origin.jsonl" "$1"; }
expect() {
  if [ "$2" = "$3" ]; then echo "ok   $1 $3"; else echo "DIFF $1: want $2 got $3"; fail=1; fi
}
budget() {
  curl -s -o /dev/null -X PUT "${admin[@]}" -d "{\"ip_requests_per_second\":1000,\"ip_requests_per_minute\":$1,\"ip_burst\":$2}" "$go_b/api/v1/admin/rate-limits/config"
  sleep 1
}
# Eight native requests spend the budget, then a row that was always Go's must see it spent.
one_budget() {
  budget 8 8
  for _ in 1 2 3 4 5 6 7 8; do curl -s -o /dev/null -H "$K" "$front/api/v2/account/me"; done
  expect "$1 next_native" 429 "$(curl -s -o /dev/null -w '%{http_code}' -H "$K" "$front/api/v2/account/me")"
  expect "$1 go_row" 429 "$(curl -s -o /dev/null -w '%{http_code}' -H "$K" -H "$PROF" "$front/api/v2/profiles")"
  budget 60000 1000
  sleep 2
}

# From the seed: a policy document another script left enabled would refuse this one's.
env CONF_PROJECT=silo-conformance-b CONF_RUN="$CONF_ROOT/.run/stack-b" CONF_PG_PORT="${CONF_B_PG_PORT:-35432}" \
  CONF_REDIS_PORT="${CONF_B_REDIS_PORT:-36379}" CONF_API_PORT="${CONF_B_API_PORT:-38080}" \
  CONF_JF_PORT="${CONF_B_JF_PORT:-38096}" CONF_ABS_PORT="${CONF_B_ABS_PORT:-38378}" \
  CONF_METRICS_PORT="${CONF_B_METRICS_PORT:-39090}" "$CONF_SCRIPTS_DIR/reset.sh" --fast >/dev/null

# The default: memory counters in Go, so credentialed rows go to Go and there is one budget.
start_front
expect memory_origin go "$(curl -s -o /dev/null -H "$K" "$front/api/v2/images/capabilities"; origin_of /api/v2/images/capabilities)"
expect memory_public native "$(curl -s -o /dev/null "$front/api/v2/auth/device/capability"; origin_of /api/v2/auth/device/capability)"
one_budget memory

# A SQLite user store: Rust reads only Postgres, so viewer rows stay on Go.
setting userdb.backend sqlite
setting ratelimit.backend redis
start_front
expect sqlite_origin go "$(curl -s -o /dev/null -H "$K" "$front/api/v2/images/capabilities"; origin_of /api/v2/images/capabilities)"
unset_setting userdb.backend

# Redis counters are shared: the rows are native and the budget is one.
restart_go
start_front
expect redis_origin native "$(curl -s -o /dev/null -H "$K" "$front/api/v2/images/capabilities"; origin_of /api/v2/images/capabilities)"
one_budget redis
unset_setting ratelimit.backend
restart_go

# A policy compile_check refuses, stored before the front starts: it boots, and Go answers.
doc="$(curl -s "${admin[@]}" -d '{"domain":"scope","name":"isolation-'"$RANDOM"'"}' "$go_b/api/v2/admin/policy/documents" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
etag() { curl -s -D - -o /dev/null "${admin[@]}" "$go_b/api/v2/admin/policy/documents/$doc" | tr -d '\r' | awk 'tolower($1)=="etag:"{print $2}'; }
source="$(printf 'package silo_custom.scope\n\nimport rego.v1\n\n# METADATA\n# title: revoke\noverride(_, i) := {"profile_verified": false} if {\n\ti.profile_id == "%s"\n}\n' "$CONF_USER_PROFILE_ID")"
version="$(python3 -c 'import json,sys;print(json.dumps({"source":sys.argv[1]}))' "$source" | curl -s "${admin[@]}" -d @- "$go_b/api/v2/admin/policy/documents/$doc/versions" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
curl -s -o /dev/null -X PUT "${admin[@]}" -H "If-Match: $(etag)" -d '{"version_id":"'"$version"'"}' "$go_b/api/v2/admin/policy/documents/$doc/active-version"
curl -s -o /dev/null -X PATCH "${admin[@]}" -H "If-Match: $(etag)" -d '{"enabled":true}' "$go_b/api/v2/admin/policy/documents/$doc"
setting ratelimit.backend redis
restart_go
if start_front; then
  expect refused_at_boot 403 "$(curl -s -o /dev/null -w '%{http_code}' -H "$K" -H "$PROF" "$front/api/v2/images/capabilities")"
  expect refused_origin go "$(origin_of /api/v2/images/capabilities)"
fi
curl -s -o /dev/null -X PATCH "${admin[@]}" -H "If-Match: $(etag)" -d '{"enabled":false}' "$go_b/api/v2/admin/policy/documents/$doc"
unset_setting ratelimit.backend
stop_front
restart_go

exit "$fail"
