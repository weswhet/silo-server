#!/usr/bin/env bash
# Runs the comparison with the Go baseline as reference and the Rust front, on a second Go stack, as
# candidate. Arguments go to `silo-conformance run`.
#
#   front-compare.sh [--proxy-all] [--out DIR] [run arguments...]
#
# --proxy-all sends every native row to Go, so any difference at all is the front's. The front's log
# and origin log land next to the report.
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
cargo build --quiet --manifest-path rust/Cargo.toml -j 4 -p silo-server -p silo-conformance

DATABASE_URL="postgres://silo:silo@127.0.0.1:$(b_port CONF_PG_PORT)/silo?sslmode=disable" \
  SILO_FRONT_WEB_DIST=rust/conformance/baseline/web-dist \
  SILO_FRONT_ORIGIN_LOG="$origin" \
  SILO_FRONT_FORCE_GO="$force_go" \
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

rc=0
rust/target/debug/silo-conformance run \
  --reference "http://127.0.0.1:$CONF_API_PORT" \
  --candidate http://127.0.0.1:18080 \
  --surface "jellycompat=http://127.0.0.1:$CONF_JF_PORT,http://127.0.0.1:18096" \
  --surface "abs=http://127.0.0.1:$CONF_ABS_PORT,http://127.0.0.1:18378" \
  --surface "metrics=http://127.0.0.1:$CONF_METRICS_PORT,http://127.0.0.1:19090" \
  --origin-log "$origin" \
  --candidate-kind strangler \
  --reset-reference "$CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --reset-candidate "env ${b_env[*]} $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --source-revision "$(conf_revision)" \
  --out "$out" \
  "$@" || rc=$?
exit "$rc"
