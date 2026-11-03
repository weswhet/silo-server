#!/usr/bin/env bash
# Runs the comparison tool with the Go baseline on both sides: the running stack as
# reference, and a second stack from the same image as candidate. Arguments go to
# `silo-conformance run` (for example --baseline or --record-baseline).
#
#   self-compare.sh [--up-only] [run arguments...]
#
# The second stack uses its own compose project and ports. Set CONF_B_* to change them.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

B_PROJECT="${CONF_B_PROJECT:-silo-conformance-b}"
B_RUN="${CONF_B_RUN:-$CONF_ROOT/.run/stack-b}"
b_env=(
  "CONF_PROJECT=$B_PROJECT" "CONF_RUN=$B_RUN"
  "CONF_PG_PORT=${CONF_B_PG_PORT:-35432}" "CONF_REDIS_PORT=${CONF_B_REDIS_PORT:-36379}"
  "CONF_API_PORT=${CONF_B_API_PORT:-38080}" "CONF_JF_PORT=${CONF_B_JF_PORT:-38096}"
  "CONF_ABS_PORT=${CONF_B_ABS_PORT:-38378}" "CONF_METRICS_PORT=${CONF_B_METRICS_PORT:-39090}"
)
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
cargo build --quiet --manifest-path rust/Cargo.toml -j 3
exec rust/target/debug/silo-conformance run \
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
  "$@"
