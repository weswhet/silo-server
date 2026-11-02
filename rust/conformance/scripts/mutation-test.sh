#!/usr/bin/env bash
# Proves the differ reports faults: runs the whole plan with the Go baseline on both
# sides and conformance-mutproxy in front of the candidate, once per fault, then
# checks that every fault it applied was reported on its case.
#
#   mutation-test.sh [--baseline FILE] [--out DIR] [--salt N] FAULT...
#
# FAULT is a name from `conformance-mutproxy list`, or `all` (every fault in one run,
# one per case), `none` or `reserialize` (controls that must report nothing), or
# `refuse_401` / `refuse_404` (both sides answer only that status, so every route is
# identical and parity must still read 0).
# Results go to DIR/<fault>/ (default .run/mutation). Exit 1 if a fault escaped, a
# control reported a regression, or a refusal run read any parity.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

B_PROJECT="${CONF_B_PROJECT:-silo-conformance-b}"
B_RUN="$CONF_ROOT/.run/stack-b"
B_API="${CONF_B_API_PORT:-38080}"
B_JF="${CONF_B_JF_PORT:-38096}"
B_ABS="${CONF_B_ABS_PORT:-38378}"
B_METRICS="${CONF_B_METRICS_PORT:-39090}"
b_env=(
  "CONF_PROJECT=$B_PROJECT" "CONF_RUN=$B_RUN"
  "CONF_PG_PORT=${CONF_B_PG_PORT:-35432}" "CONF_REDIS_PORT=${CONF_B_REDIS_PORT:-36379}"
  "CONF_API_PORT=$B_API" "CONF_JF_PORT=$B_JF"
  "CONF_ABS_PORT=$B_ABS" "CONF_METRICS_PORT=$B_METRICS"
)
P_API="${CONF_MUT_API_PORT:-48080}"
P_JF="${CONF_MUT_JF_PORT:-48096}"
P_ABS="${CONF_MUT_ABS_PORT:-48378}"
P_METRICS="${CONF_MUT_METRICS_PORT:-49090}"

baseline=()
out="$CONF_ROOT/.run/mutation"
salt=0
faults=()
while [ $# -gt 0 ]; do
  case "$1" in
    --baseline) baseline=(--baseline "$2"); shift 2 ;;
    --out) out="$2"; shift 2 ;;
    --salt) salt="$2"; shift 2 ;;
    *) faults+=("$1"); shift ;;
  esac
done
[ "${#faults[@]}" -gt 0 ] || conf_die "name at least one fault"

cd "$CONF_REPO" || exit 1
cargo build --quiet --manifest-path rust/Cargo.toml -j 3
proxy=rust/target/debug/conformance-mutproxy
proxy_pid=""
stop_proxy() {
  if [ -n "$proxy_pid" ]; then
    kill "$proxy_pid" 2>/dev/null || true
    wait "$proxy_pid" 2>/dev/null || true
    proxy_pid=""
  fi
}
trap stop_proxy EXIT

failed=0
for fault in "${faults[@]}"; do
  dir="$out/$fault"
  rm -rf "$dir"
  mkdir -p "$dir/report"
  case "$fault" in
    refuse_*)
      status="${fault#refuse_}"
      "$proxy" serve --listen "$P_API=127.0.0.1:1" --listen "$P_JF=127.0.0.1:1" \
        --listen "$P_ABS=127.0.0.1:1" --listen "$P_METRICS=127.0.0.1:1" \
        --mutation none --refuse "$status" --log "$dir/applied.jsonl" &
      proxy_pid=$!
      "$proxy" serve --listen "$((P_API + 100))=127.0.0.1:1" --listen "$((P_JF + 100))=127.0.0.1:1" \
        --listen "$((P_ABS + 100))=127.0.0.1:1" --listen "$((P_METRICS + 100))=127.0.0.1:1" \
        --mutation none --refuse "$status" --log "$dir/applied-reference.jsonl" &
      reference_proxy_pid=$!
      until curl -s -o /dev/null "http://127.0.0.1:$P_METRICS/" &&
        curl -s -o /dev/null "http://127.0.0.1:$((P_METRICS + 100))/"; do
        kill -0 "$proxy_pid" 2>/dev/null || conf_die "the proxy did not start for $fault"
      done
      set +e
      rust/target/debug/silo-conformance run --quiet \
        --reference "http://127.0.0.1:$((P_API + 100))" --candidate "http://127.0.0.1:$P_API" \
        --surface "jellycompat=http://127.0.0.1:$((P_JF + 100)),http://127.0.0.1:$P_JF" \
        --surface "abs=http://127.0.0.1:$((P_ABS + 100)),http://127.0.0.1:$P_ABS" \
        --surface "metrics=http://127.0.0.1:$((P_METRICS + 100)),http://127.0.0.1:$P_METRICS" \
        --out "$dir/report" >"$dir/run.txt" 2>&1
      echo "$?" >"$dir/run-exit.txt"
      set -e
      stop_proxy
      kill "$reference_proxy_pid" 2>/dev/null || true
      wait "$reference_proxy_pid" 2>/dev/null || true
      parity="$(jq -r .overall.parity_percent "$dir/report/report.json")"
      conf_log "$fault: parity $parity%, $(jq -r '.overall | "\(.matched) matched, \(.weak_evidence) weak, \(.weak_refusals_only) refusals only"' "$dir/report/report.json")"
      [ "$parity" = 0 ] || [ "$parity" = 0.0 ] || failed=1
      continue
      ;;
  esac
  "$proxy" serve \
    --listen "$P_API=127.0.0.1:$B_API" --listen "$P_JF=127.0.0.1:$B_JF" \
    --listen "$P_ABS=127.0.0.1:$B_ABS" --listen "$P_METRICS=127.0.0.1:$B_METRICS" \
    --mutation "$fault" --salt "$salt" --log "$dir/applied.jsonl" &
  proxy_pid=$!
  # Wait on the listener rather than a fixed delay.
  until curl -s -o /dev/null "http://127.0.0.1:$P_METRICS/"; do
    kill -0 "$proxy_pid" 2>/dev/null || conf_die "the proxy did not start for $fault"
  done

  started=$SECONDS
  set +e
  rust/target/debug/silo-conformance run --quiet --tag-cases \
    --reference "http://127.0.0.1:$CONF_API_PORT" \
    --candidate "http://127.0.0.1:$P_API" \
    --surface "jellycompat=http://127.0.0.1:$CONF_JF_PORT,http://127.0.0.1:$P_JF" \
    --surface "abs=http://127.0.0.1:$CONF_ABS_PORT,http://127.0.0.1:$P_ABS" \
    --surface "metrics=http://127.0.0.1:$CONF_METRICS_PORT,http://127.0.0.1:$P_METRICS" \
    --reset-reference "$CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
    --reset-candidate "env ${b_env[*]} $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
    --empty-users-reference "$CONF_SCRIPTS_DIR/empty-users.sh silo-conformance" \
    --empty-users-candidate "$CONF_SCRIPTS_DIR/empty-users.sh $B_PROJECT" \
    --effects-reference "pg=postgres://silo:silo@127.0.0.1:$CONF_PG_PORT/silo?sslmode=disable,redis=127.0.0.1:$CONF_REDIS_PORT" \
    --effects-candidate "pg=postgres://silo:silo@127.0.0.1:${CONF_B_PG_PORT:-35432}/silo?sslmode=disable,redis=127.0.0.1:${CONF_B_REDIS_PORT:-36379}" \
    ${CONF_MUT_ONLY:+--only "$CONF_MUT_ONLY"} \
    --out "$dir/report" ${baseline[@]+"${baseline[@]}"} >"$dir/run.txt" 2>&1
  run_exit=$?
  set -e
  stop_proxy
  echo "$run_exit" >"$dir/run-exit.txt"

  set +e
  "$proxy" check --log "$dir/applied.jsonl" --report "$dir/report" --json "$dir/check.json" \
    >"$dir/check.txt" 2>&1
  check_exit=$?
  set -e
  conf_log "$fault: run exit $run_exit, check exit $check_exit, $((SECONDS - started))s: $(tail -1 "$dir/check.txt")"

  case "$fault" in
    none | reserialize) [ "$run_exit" = 0 ] || failed=1 ;;
    *)
      [ "$check_exit" = 0 ] || failed=1
      [ -s "$dir/applied.jsonl" ] || { conf_log "$fault: applied nowhere"; failed=1; }
      ;;
  esac
done
exit "$failed"
