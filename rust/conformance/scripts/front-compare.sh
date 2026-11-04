#!/usr/bin/env bash
# Runs the comparison with the Go baseline as reference and the Rust front, on a second Go stack, as
# candidate. Arguments go to `silo-conformance run`.
#
#   front-compare.sh [--proxy-all] [--out DIR] [run arguments...]
#
# --proxy-all sends every native row to Go, so any difference at all is the front's. The front's log
# and origin log land next to the report.
#
# The baseline keeps ratelimit.backend at memory. A plan comparison asks one row at a time, so it turns on
# SILO_FRONT_SPLIT_RATE_BUDGETS to reach the native rows; native-chain-isolation.sh covers the default.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

B_RUN="$CONF_ROOT/.run/stack-b"
b_env=(
  "CONF_PROJECT=${CONF_B_PROJECT:-silo-conformance-b}" "CONF_RUN=$B_RUN"
  "CONF_PG_PORT=${CONF_B_PG_PORT:-35432}" "CONF_REDIS_PORT=${CONF_B_REDIS_PORT:-36379}"
  "CONF_API_PORT=${CONF_B_API_PORT:-38080}" "CONF_JF_PORT=${CONF_B_JF_PORT:-38096}"
  "CONF_ABS_PORT=${CONF_B_ABS_PORT:-38378}" "CONF_METRICS_PORT=${CONF_B_METRICS_PORT:-39090}"
)
b_port() { env "${b_env[@]}" sh -c "echo \$$1"; }

force_go=""
if [ "${1:-}" = "--proxy-all" ]; then
  force_go=all
  shift
fi
out="$CONF_ROOT/.run/report-front"
if [ "${1:-}" = "--out" ]; then
  out="$2"
  shift 2
fi
mkdir -p "$out"
origin="$out/origin.jsonl"
: >"$origin"

cd "$CONF_REPO" || exit 1
"$CONF_SCRIPTS_DIR/self-compare.sh" --up-only
cargo build --quiet --manifest-path rust/Cargo.toml -j 3 -p silo-server -p silo-conformance

DATABASE_URL="postgres://silo:silo@127.0.0.1:$(b_port CONF_PG_PORT)/silo?sslmode=disable" \
  SECRET_KEY="$CONF_SECRET_KEY" \
  REDIS_URL="redis://127.0.0.1:$(b_port CONF_REDIS_PORT)" \
  SILO_FRONT_WEB_DIST=rust/conformance/baseline/web-dist \
  SILO_FRONT_ORIGIN_LOG="$origin" \
  SILO_FRONT_FORCE_GO="$force_go" \
  SILO_FRONT_SPLIT_RATE_BUDGETS=1 \
  SILO_FRONT_GO_WORKDIR=/var/lib/silo \
  SILO_FRONT_GO_REDIS_URL=redis://redis:6379 \
  SILO_NODE_NAME=silo-conformance \
  TZ=Etc/UTC \
  rust/target/debug/silo \
  --front "main=127.0.0.1:18080,http://127.0.0.1:$(b_port CONF_API_PORT)" \
  --front "jellycompat=127.0.0.1:18096,http://127.0.0.1:$(b_port CONF_JF_PORT)" \
  --front "abs=127.0.0.1:18378,http://127.0.0.1:$(b_port CONF_ABS_PORT)" \
  --front "metrics=127.0.0.1:19090,http://127.0.0.1:$(b_port CONF_METRICS_PORT)" \
  >"$out/front.log" 2>&1 &
front=$!
trap 'kill "$front" 2>/dev/null || true' EXIT

deadline=$((SECONDS + 30))
until curl -fsS -o /dev/null http://127.0.0.1:18080/api/v1/ready 2>/dev/null; do
  kill -0 "$front" 2>/dev/null || conf_die "the front exited; see $out/front.log"
  [ "$SECONDS" -lt "$deadline" ] || conf_die "the front did not answer; see $out/front.log"
  sleep 0.2
done

conf_wait_listener_sweep "$origin"

# CONF_ACTIVITY_DIR saves each stage's activity rows for activity-diff.py.
dump_a=""
dump_b=""
if [ -n "${CONF_ACTIVITY_DIR:-}" ]; then
  mkdir -p "$CONF_ACTIVITY_DIR"
  : >"$CONF_ACTIVITY_DIR/reference.txt"
  : >"$CONF_ACTIVITY_DIR/candidate.txt"
  dump_a="$CONF_SCRIPTS_DIR/activity-dump.sh silo-conformance $CONF_ACTIVITY_DIR/reference.txt;"
  dump_b="$CONF_SCRIPTS_DIR/activity-dump.sh ${CONF_B_PROJECT:-silo-conformance-b} $CONF_ACTIVITY_DIR/candidate.txt;"
fi

rc=0
digest_skip='idgen_machine_leases|operational_logs'
# The resets wait out the front's 2-second log batches: the front outlives them, and a row it flushed into
# the restored database would fail the seed digest. Two writers run on the front's own clocks and can still land
# between the restore and the digest check: the machine ID lease renewal, which claims again in the restored
# table, and log batch retries from inserts that failed while the database was gone. Those tables are left out
# of the candidate's digest. Both wait, so both servers start together: their
# background jobs race the first requests, as catalog export-jobs shows when one starts later.
rust/target/debug/silo-conformance run \
  --reference "http://127.0.0.1:$CONF_API_PORT" \
  --candidate http://127.0.0.1:18080 \
  --surface "jellycompat=http://127.0.0.1:$CONF_JF_PORT,http://127.0.0.1:18096" \
  --surface "abs=http://127.0.0.1:$CONF_ABS_PORT,http://127.0.0.1:18378" \
  --surface "metrics=http://127.0.0.1:$CONF_METRICS_PORT,http://127.0.0.1:19090" \
  --origin-log "$origin" \
  --candidate-kind strangler \
  --reference-forwarded-for 127.0.0.1 \
  --reset-reference "sleep 3; $dump_a $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --reset-candidate "sleep 3; $dump_b env ${b_env[*]} CONF_DIGEST_SKIP='$digest_skip' $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --empty-users-reference "$CONF_SCRIPTS_DIR/empty-users.sh silo-conformance" \
  --empty-users-candidate "$CONF_SCRIPTS_DIR/empty-users.sh ${CONF_B_PROJECT:-silo-conformance-b}" \
  --effects-reference "pg=postgres://silo:silo@127.0.0.1:$CONF_PG_PORT/silo?sslmode=disable,redis=127.0.0.1:$CONF_REDIS_PORT" \
  --effects-candidate "pg=postgres://silo:silo@127.0.0.1:$(b_port CONF_PG_PORT)/silo?sslmode=disable,redis=127.0.0.1:$(b_port CONF_REDIS_PORT)" \
  --source-revision "$(conf_revision)" \
  --out "$out" \
  "$@" || rc=$?
if [ -n "$dump_a" ]; then
  sleep 3
  sh -c "$dump_a $dump_b"
  python3 "$CONF_SCRIPTS_DIR/activity-diff.py" "$CONF_ACTIVITY_DIR/reference.txt" "$CONF_ACTIVITY_DIR/candidate.txt" \
    >"$CONF_ACTIVITY_DIR/diff.txt" || true
fi
# A command to run against the running front, such as native-chain-traits.sh.
if [ -n "${CONF_FRONT_AFTER:-}" ]; then
  # From the seed, not from what the plan's writes left behind.
  sleep 3
  "$CONF_SCRIPTS_DIR/reset.sh" --fast >/dev/null
  env "${b_env[@]}" CONF_DIGEST_SKIP="$digest_skip" "$CONF_SCRIPTS_DIR/reset.sh" --fast >/dev/null
  CONF_FRONT_ORIGIN_LOG="$origin" $CONF_FRONT_AFTER || rc=1
fi
exit "$rc"
