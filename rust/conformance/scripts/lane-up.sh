#!/usr/bin/env bash
# Brings up one lane for front-compare.sh: this pair's two Go stacks (CONF_PAIR) and a Rust front on the
# candidate stack. It returns once the front answers and a local client's sweep of its new listeners is over,
# leaving the front running.
#
#   lane-up.sh DIR FORCE_GO
#   lane-up.sh DIR --go
#
# With --go there is no front: the lane compares the two Go stacks, as self-compare.sh does.
# DIR receives front.log, origin.jsonl, front.pid, and lane.json, the `--lane` file `silo-conformance run`
# reads for this pair. FORCE_GO is SILO_FRONT_FORCE_GO for the front (empty or `all`). The front binary must
# already be built (conf_build).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

dir="$1"
force_go="${2:-}"
mkdir -p "$dir"
origin="$dir/origin.jsonl"
: >"$origin"

"$CONF_SCRIPTS_DIR/self-compare.sh" --up-only

a_env="${conf_a_env[*]}"
b_env="${conf_b_env[*]}"
common=(
  --arg empty_ref "$CONF_SCRIPTS_DIR/empty-users.sh $CONF_PROJECT"
  --arg empty_cand "$CONF_SCRIPTS_DIR/empty-users.sh $CONF_B_PROJECT"
  --arg fx_ref "pg=postgres://silo:silo@127.0.0.1:$CONF_PG_PORT/silo?sslmode=disable,redis=127.0.0.1:$CONF_REDIS_PORT"
  --arg fx_cand "pg=postgres://silo:silo@127.0.0.1:$CONF_B_PG_PORT/silo?sslmode=disable,redis=127.0.0.1:$CONF_B_REDIS_PORT"
  --arg jf_ref "http://127.0.0.1:$CONF_JF_PORT" --arg abs_ref "http://127.0.0.1:$CONF_ABS_PORT"
  --arg m_ref "http://127.0.0.1:$CONF_METRICS_PORT" --arg ref "http://127.0.0.1:$CONF_API_PORT"
)
lane_json='{reference: $ref, candidate: $cand,
  surfaces: {jellycompat: [$jf_ref, $jf_cand], abs: [$abs_ref, $abs_cand], metrics: [$m_ref, $m_cand]},
  reset_reference: $reset_ref, reset_candidate: $reset_cand,
  empty_users_reference: $empty_ref, empty_users_candidate: $empty_cand,
  effects_reference: $fx_ref, effects_candidate: $fx_cand}'
if [ "$force_go" = --go ]; then
  rm -f "$origin"
  jq -n "${common[@]}" \
    --arg cand "http://127.0.0.1:$CONF_B_API_PORT" --arg jf_cand "http://127.0.0.1:$CONF_B_JF_PORT" \
    --arg abs_cand "http://127.0.0.1:$CONF_B_ABS_PORT" --arg m_cand "http://127.0.0.1:$CONF_B_METRICS_PORT" \
    --arg reset_ref "env $a_env $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
    --arg reset_cand "env $b_env $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
    "$lane_json" >"$dir/lane.json"
  exit 0
fi

cd "$CONF_REPO" || exit 1
DATABASE_URL="postgres://silo:silo@127.0.0.1:$CONF_B_PG_PORT/silo?sslmode=disable" \
  SECRET_KEY="$CONF_SECRET_KEY" \
  REDIS_URL="redis://127.0.0.1:$CONF_B_REDIS_PORT" \
  SILO_FRONT_WEB_DIST=rust/conformance/baseline/web-dist \
  SILO_FRONT_ORIGIN_LOG="$origin" \
  SILO_FRONT_FORCE_GO="$force_go" \
  SILO_FRONT_SPLIT_RATE_BUDGETS=1 \
  SILO_FRONT_GO_WORKDIR=/var/lib/silo \
  SILO_FRONT_GO_REDIS_URL=redis://redis:6379 \
  SILO_NODE_NAME=silo-conformance \
  TZ=Etc/UTC \
  nohup "$CONF_BIN/silo" \
  --front "main=127.0.0.1:$CONF_FRONT_API_PORT,http://127.0.0.1:$CONF_B_API_PORT" \
  --front "jellycompat=127.0.0.1:$CONF_FRONT_JF_PORT,http://127.0.0.1:$CONF_B_JF_PORT" \
  --front "abs=127.0.0.1:$CONF_FRONT_ABS_PORT,http://127.0.0.1:$CONF_B_ABS_PORT" \
  --front "metrics=127.0.0.1:$CONF_FRONT_METRICS_PORT,http://127.0.0.1:$CONF_B_METRICS_PORT" \
  >"$dir/front.log" 2>&1 </dev/null &
front=$!
echo "$front" >"$dir/front.pid"

deadline=$((SECONDS + 30))
until curl -fsS -o /dev/null "http://127.0.0.1:$CONF_FRONT_API_PORT/api/v1/ready" 2>/dev/null; do
  kill -0 "$front" 2>/dev/null || conf_die "the front exited; see $dir/front.log"
  [ "$SECONDS" -lt "$deadline" ] || conf_die "the front did not answer; see $dir/front.log"
  sleep 0.2
done
conf_wait_listener_sweep "$origin"

# The resets wait out the front's 2-second log batches; see front-compare.sh for the tables the candidate's digest
# leaves out.
digest_skip='idgen_machine_leases|operational_logs'
jq -n "${common[@]}" \
  --arg cand "http://127.0.0.1:$CONF_FRONT_API_PORT" --arg jf_cand "http://127.0.0.1:$CONF_FRONT_JF_PORT" \
  --arg abs_cand "http://127.0.0.1:$CONF_FRONT_ABS_PORT" --arg m_cand "http://127.0.0.1:$CONF_FRONT_METRICS_PORT" \
  --arg reset_ref "sleep 3; env $a_env $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --arg reset_cand "sleep 3; env $b_env CONF_DIGEST_SKIP='$digest_skip' $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --arg origin "$origin" \
  "$lane_json + {origin_log: \$origin}" >"$dir/lane.json"
