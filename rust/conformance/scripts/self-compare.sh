#!/usr/bin/env bash
# Runs the comparison tool with the Go baseline on both sides: the running stack as
# reference, and a second stack from the same image as candidate. Arguments go to
# `silo-conformance run` (for example --baseline or --record-baseline).
#
#   self-compare.sh [--up-only] [run arguments...]
#
# The run's scope defaults to v2 (`--scope v2`); pass `--scope full` for every surface. The second stack uses
# its own compose project and ports: CONF_PAIR or the CONF_B_* variables move it (see lib.sh).
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

B_PROJECT="$CONF_B_PROJECT"
B_RUN="$CONF_B_RUN"
b_env=("${conf_b_env[@]}")
mkdir -p "$B_RUN"

up_only=false
if [ "${1:-}" = "--up-only" ]; then
  up_only=true
  shift
fi

"$CONF_SCRIPTS_DIR/start.sh"
env "${b_env[@]}" "$CONF_SCRIPTS_DIR/start.sh"
a_digest="$(tail -1 "$CONF_RUN/seed-digest.txt")"
b_digest="$(tail -1 "$B_RUN/seed-digest.txt")"
if [ "$a_digest" != "$b_digest" ]; then
  conf_die "the two stacks hold different seed state: $a_digest vs $b_digest"
fi
[ "$up_only" = true ] && exit 0

b_port() { env "${b_env[@]}" sh -c "echo \$$1"; }
cd "$CONF_REPO" || exit 1
conf_build -p silo-conformance
# CONF_LANES=N spreads the run over pairs CONF_PAIR..CONF_PAIR+N-1 (see front-compare.sh).
lanes="${CONF_LANES:-1}"
case "$lanes" in [1-9]) ;; *) conf_die "CONF_LANES must be 1-9" ;; esac
[ "$((CONF_PAIR + lanes - 1))" -le 9 ] || conf_die "CONF_PAIR $CONF_PAIR leaves no room for $lanes lanes"
lane_args=()
pids=()
for lane in $(seq 1 $((lanes - 1))); do
  dir="$CONF_PAIR_RUN/lanes/$lane"
  mkdir -p "$dir"
  conf_pair_shell "$((CONF_PAIR + lane))" "$CONF_SCRIPTS_DIR/lane-up.sh" "$dir" --go >"$dir/up.log" 2>&1 &
  pids+=($!)
  lane_args+=(--lane "$dir/lane.json")
done
for pid in ${pids[@]+"${pids[@]}"}; do
  wait "$pid" || conf_die "a lane did not come up; see $CONF_PAIR_RUN/lanes/*/up.log"
done
defaults=()
case " $* " in *" --scope "* | *" --scope="*) ;; *) defaults+=(--scope v2) ;; esac
case " $* " in *" --out "* | *" --out="*) ;; *) defaults+=(--out "$CONF_PAIR_RUN/report") ;; esac
exec "$CONF_BIN/silo-conformance" run ${defaults[@]+"${defaults[@]}"} \
  --reference "http://127.0.0.1:$CONF_API_PORT" \
  --candidate "http://127.0.0.1:$(b_port CONF_API_PORT)" \
  --surface "jellycompat=http://127.0.0.1:$CONF_JF_PORT,http://127.0.0.1:$(b_port CONF_JF_PORT)" \
  --surface "abs=http://127.0.0.1:$CONF_ABS_PORT,http://127.0.0.1:$(b_port CONF_ABS_PORT)" \
  --surface "metrics=http://127.0.0.1:$CONF_METRICS_PORT,http://127.0.0.1:$(b_port CONF_METRICS_PORT)" \
  --reset-reference "$CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --reset-candidate "env ${b_env[*]} $CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
  --empty-users-reference "$CONF_SCRIPTS_DIR/empty-users.sh $CONF_PROJECT" \
  --empty-users-candidate "$CONF_SCRIPTS_DIR/empty-users.sh $B_PROJECT" \
  --effects-reference "pg=postgres://silo:silo@127.0.0.1:$CONF_PG_PORT/silo?sslmode=disable,redis=127.0.0.1:$CONF_REDIS_PORT" \
  --effects-candidate "pg=postgres://silo:silo@127.0.0.1:$(b_port CONF_PG_PORT)/silo?sslmode=disable,redis=127.0.0.1:$(b_port CONF_REDIS_PORT)" \
  --source-revision "$(conf_revision)" \
  ${lane_args[@]+"${lane_args[@]}"} \
  "$@"
