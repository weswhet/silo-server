#!/usr/bin/env bash
# Runs the comparison with the Go baseline as reference and the Rust front, on a second Go stack, as
# candidate. Arguments go to `silo-conformance run`.
#
#   front-compare.sh [--proxy-all] [--out DIR] [run arguments...]
#
# The scope defaults to v2 (`--scope v2`); pass `--scope full` for every surface. CONF_PAIR moves the stacks and
# the front's listeners (see lib.sh), so several pairs can compare at once.
#
# --proxy-all sends every native row to Go, so any difference at all is the front's. The front's log
# and origin log land next to the report.
#
# The baseline keeps ratelimit.backend at memory. A plan comparison asks one row at a time, so it turns on
# SILO_FRONT_SPLIT_RATE_BUDGETS to reach the native rows; native-chain-isolation.sh covers the default.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

b_env=("${conf_b_env[@]}")
b_port() { env "${b_env[@]}" sh -c "echo \$$1"; }

force_go=""
if [ "${1:-}" = "--proxy-all" ]; then
  force_go=all
  shift
fi
out="$CONF_PAIR_RUN/report-front"
if [ "${1:-}" = "--out" ]; then
  out="$2"
  shift 2
fi
scope=(--scope v2)
case " $* " in *" --scope "* | *" --scope="*) scope=() ;; esac
lanes="${CONF_LANES:-1}"
case "$lanes" in [1-9]) ;; *) conf_die "CONF_LANES must be 1-9" ;; esac
[ "$((CONF_PAIR + lanes - 1))" -le 9 ] || conf_die "CONF_PAIR $CONF_PAIR leaves no room for $lanes lanes"
if [ "$lanes" -gt 1 ] && [ -n "${CONF_ACTIVITY_DIR:-}${CONF_FRONT_AFTER:-}" ]; then
  conf_die "CONF_ACTIVITY_DIR and CONF_FRONT_AFTER need CONF_LANES=1"
fi
mkdir -p "$out"
origin="$out/origin.jsonl"

cd "$CONF_REPO" || exit 1
conf_build -p silo-server -p silo-conformance

# Lane 0 is this pair; lane N is pair CONF_PAIR+N, with that pair's default ports and projects. The lanes come up
# at once, since a pair's first start seeds it from scratch.
lane_dir() { if [ "$1" = 0 ]; then echo "$out"; else echo "$out/lane$1"; fi; }
stop_fronts() {
  local lane pid
  for lane in $(seq 0 $((lanes - 1))); do
    pid="$(cat "$(lane_dir "$lane")/front.pid" 2>/dev/null || true)"
    [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
  done
}
trap stop_fronts EXIT
pids=()
for lane in $(seq 0 $((lanes - 1))); do
  rm -f "$(lane_dir "$lane")/front.pid"
  if [ "$lane" = 0 ]; then
    "$CONF_SCRIPTS_DIR/lane-up.sh" "$out" "$force_go" &
  else
    conf_pair_shell "$((CONF_PAIR + lane))" "$CONF_SCRIPTS_DIR/lane-up.sh" "$(lane_dir "$lane")" "$force_go" \
      >"$out/lane$lane.up.log" 2>&1 &
  fi
  pids+=($!)
done
for pid in "${pids[@]}"; do
  wait "$pid" || conf_die "a lane did not come up; see $out/lane*.up.log"
done
lane_args=()
for lane in $(seq 1 $((lanes - 1))); do
  lane_args+=(--lane "$(lane_dir "$lane")/lane.json")
done

# CONF_ACTIVITY_DIR saves each stage's activity rows for activity-diff.py.
dump_a=""
dump_b=""
if [ -n "${CONF_ACTIVITY_DIR:-}" ]; then
  mkdir -p "$CONF_ACTIVITY_DIR"
  : >"$CONF_ACTIVITY_DIR/reference.txt"
  : >"$CONF_ACTIVITY_DIR/candidate.txt"
  dump_a="$CONF_SCRIPTS_DIR/activity-dump.sh $CONF_PROJECT $CONF_ACTIVITY_DIR/reference.txt;"
  dump_b="$CONF_SCRIPTS_DIR/activity-dump.sh $CONF_B_PROJECT $CONF_ACTIVITY_DIR/candidate.txt;"
fi

rc=0
digest_skip='idgen_machine_leases|operational_logs'
# The resets wait out the front's 2-second log batches: the front outlives them, and a row it flushed into
# the restored database would fail the seed digest. Two writers run on the front's own clocks and can still land
# between the restore and the digest check: the machine ID lease renewal, which claims again in the restored
# table, and log batch retries from inserts that failed while the database was gone. Those tables are left out
# of the candidate's digest. Both wait, so both servers start together: their
# background jobs race the first requests, as catalog export-jobs shows when one starts later.
"$CONF_BIN/silo-conformance" run ${scope[@]+"${scope[@]}"} \
  --reference "http://127.0.0.1:$CONF_API_PORT" \
  --candidate http://127.0.0.1:$CONF_FRONT_API_PORT \
  --surface "jellycompat=http://127.0.0.1:$CONF_JF_PORT,http://127.0.0.1:$CONF_FRONT_JF_PORT" \
  --surface "abs=http://127.0.0.1:$CONF_ABS_PORT,http://127.0.0.1:$CONF_FRONT_ABS_PORT" \
  --surface "metrics=http://127.0.0.1:$CONF_METRICS_PORT,http://127.0.0.1:$CONF_FRONT_METRICS_PORT" \
  --origin-log "$origin" \
  --candidate-kind strangler \
  --reference-forwarded-for 127.0.0.1 \
  --reset-reference "sleep 3; $dump_a $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --reset-candidate "sleep 3; $dump_b env ${b_env[*]} CONF_DIGEST_SKIP='$digest_skip' $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --empty-users-reference "$CONF_SCRIPTS_DIR/empty-users.sh $CONF_PROJECT" \
  --empty-users-candidate "$CONF_SCRIPTS_DIR/empty-users.sh $CONF_B_PROJECT" \
  --effects-reference "pg=postgres://silo:silo@127.0.0.1:$CONF_PG_PORT/silo?sslmode=disable,redis=127.0.0.1:$CONF_REDIS_PORT" \
  --effects-candidate "pg=postgres://silo:silo@127.0.0.1:$(b_port CONF_PG_PORT)/silo?sslmode=disable,redis=127.0.0.1:$(b_port CONF_REDIS_PORT)" \
  --source-revision "$(conf_revision)" \
  ${lane_args[@]+"${lane_args[@]}"} \
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
