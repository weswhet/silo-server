# Shared helpers for the conformance baseline scripts. Source, don't execute.
# shellcheck shell=bash
set -euo pipefail

CONF_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_ROOT="$(cd "$CONF_SCRIPTS_DIR/.." && pwd)"
CONF_REPO="$(cd "$CONF_ROOT/../.." && pwd)"
CONF_BASELINE="$CONF_ROOT/baseline"
CONF_SEED="$CONF_BASELINE/seed"

# CONF_PAIR=N (1-9) moves a whole stack pair, so several pairs can run at once: the reference stack becomes
# project silo-conformance-pN, the candidate silo-conformance-pN-b, every host port below moves up by 10*N, and
# the run state goes to .run/pairN. Any variable set explicitly still wins. Pair 0, the default, is the
# historical layout.
CONF_PAIR="${CONF_PAIR:-0}"
case "$CONF_PAIR" in [0-9]) ;; *) printf '[conformance] ERROR: CONF_PAIR must be 0-9\n' >&2; exit 1 ;; esac
conf_off=$((CONF_PAIR * 10))
if [ "$CONF_PAIR" = 0 ]; then
  conf_pair_name=silo-conformance
  conf_pair_run="$CONF_ROOT/.run"
else
  conf_pair_name="silo-conformance-p$CONF_PAIR"
  conf_pair_run="$CONF_ROOT/.run/pair$CONF_PAIR"
fi
: "${CONF_PROJECT:=$conf_pair_name}"
: "${CONF_PG_PORT:=$((25432 + conf_off))}" "${CONF_REDIS_PORT:=$((26379 + conf_off))}"
: "${CONF_API_PORT:=$((28080 + conf_off))}" "${CONF_JF_PORT:=$((28096 + conf_off))}"
: "${CONF_ABS_PORT:=$((28378 + conf_off))}" "${CONF_METRICS_PORT:=$((29090 + conf_off))}"
# The candidate stack, which self-compare.sh, front-compare.sh and mutation-test.sh start next to the reference.
: "${CONF_B_PROJECT:=$conf_pair_name-b}" "${CONF_B_RUN:=$conf_pair_run/stack-b}"
: "${CONF_B_PG_PORT:=$((35432 + conf_off))}" "${CONF_B_REDIS_PORT:=$((36379 + conf_off))}"
: "${CONF_B_API_PORT:=$((38080 + conf_off))}" "${CONF_B_JF_PORT:=$((38096 + conf_off))}"
: "${CONF_B_ABS_PORT:=$((38378 + conf_off))}" "${CONF_B_METRICS_PORT:=$((39090 + conf_off))}"
# The Rust front's listeners in front-compare.sh, and the mutation proxy's in mutation-test.sh.
: "${CONF_FRONT_API_PORT:=$((18080 + conf_off))}" "${CONF_FRONT_JF_PORT:=$((18096 + conf_off))}"
: "${CONF_FRONT_ABS_PORT:=$((18378 + conf_off))}" "${CONF_FRONT_METRICS_PORT:=$((19090 + conf_off))}"
: "${CONF_MUT_API_PORT:=$((48080 + conf_off))}" "${CONF_MUT_JF_PORT:=$((48096 + conf_off))}"
: "${CONF_MUT_ABS_PORT:=$((48378 + conf_off))}" "${CONF_MUT_METRICS_PORT:=$((49090 + conf_off))}"
# Gitignored: digests and verification output from the last run. A second stack sets this so the two do not
# overwrite each other's state.
CONF_RUN="${CONF_RUN:-$conf_pair_run}"
# Reports and logs of this pair's comparison runs.
CONF_PAIR_RUN="$conf_pair_run"
export CONF_PAIR CONF_B_PROJECT CONF_B_RUN CONF_B_PG_PORT CONF_B_REDIS_PORT CONF_B_API_PORT CONF_B_JF_PORT \
  CONF_B_ABS_PORT CONF_B_METRICS_PORT

# The environment that points these scripts at the reference stack, and at the candidate stack.
conf_a_env=(
  "CONF_PAIR=$CONF_PAIR" "CONF_PROJECT=$CONF_PROJECT" "CONF_RUN=$CONF_RUN"
  "CONF_PG_PORT=$CONF_PG_PORT" "CONF_REDIS_PORT=$CONF_REDIS_PORT"
  "CONF_API_PORT=$CONF_API_PORT" "CONF_JF_PORT=$CONF_JF_PORT"
  "CONF_ABS_PORT=$CONF_ABS_PORT" "CONF_METRICS_PORT=$CONF_METRICS_PORT"
)
conf_b_env=(
  "CONF_PAIR=$CONF_PAIR" "CONF_PROJECT=$CONF_B_PROJECT" "CONF_RUN=$CONF_B_RUN"
  "CONF_PG_PORT=$CONF_B_PG_PORT" "CONF_REDIS_PORT=$CONF_B_REDIS_PORT"
  "CONF_API_PORT=$CONF_B_API_PORT" "CONF_JF_PORT=$CONF_B_JF_PORT"
  "CONF_ABS_PORT=$CONF_B_ABS_PORT" "CONF_METRICS_PORT=$CONF_B_METRICS_PORT"
)

# conf_pair_shell N CMD...: runs CMD for pair N, with every pair variable taken from N's defaults rather than
# from this shell's environment.
conf_pair_shell() {
  local pair="$1" v unset_args=()
  shift
  for v in PROJECT RUN PG_PORT REDIS_PORT API_PORT JF_PORT ABS_PORT METRICS_PORT; do
    unset_args+=(-u "CONF_$v" -u "CONF_B_$v")
  done
  for v in API JF ABS METRICS; do
    unset_args+=(-u "CONF_FRONT_${v}_PORT" -u "CONF_MUT_${v}_PORT")
  done
  env "${unset_args[@]}" CONF_PAIR="$pair" "$@"
}

# Comparison runs use release builds: the front and the harness then cost the run little CPU. CONF_PROFILE=debug
# switches back.
CONF_PROFILE="${CONF_PROFILE:-release}"
case "$CONF_PROFILE" in
  release) conf_cargo_profile=(--release) ;;
  debug) conf_cargo_profile=() ;;
  *) printf '[conformance] ERROR: CONF_PROFILE must be release or debug\n' >&2; exit 1 ;;
esac
CONF_BIN="$CONF_REPO/rust/target/$CONF_PROFILE"
# conf_build <cargo args...>: builds rust/ in the comparison profile.
conf_build() {
  cargo build --quiet --manifest-path "$CONF_REPO/rust/Cargo.toml" -j "${CONF_BUILD_JOBS:-4}" \
    ${conf_cargo_profile[@]+"${conf_cargo_profile[@]}"} "$@"
}

set -a
# shellcheck source=../baseline/fixture.env
. "$CONF_BASELINE/fixture.env"
set +a

# The image is tagged by the Go source it was built from. rust/ never reaches the
# image, so commits and changes under it neither change the tag nor count as dirty.
conf_revision() { git -C "$CONF_REPO" log -1 --format=%H -- . ':(exclude)rust'; }
conf_dirty() {
  if [ -n "$(git -C "$CONF_REPO" status --porcelain -- . ':(exclude)rust')" ]; then echo true; else echo false; fi
}
conf_image() {
  local tag
  tag="$(conf_revision | cut -c1-12)"
  [ "$(conf_dirty)" = true ] && tag="$tag-dirty"
  echo "silo-conformance-baseline:$tag"
}
CONF_IMAGE="$(conf_image)"
export CONF_IMAGE

conf_compose() {
  docker compose --project-name "$CONF_PROJECT" -f "$CONF_BASELINE/compose.yml" "$@"
}

conf_log() { printf '[conformance] %s\n' "$*" >&2; }
conf_die() { printf '[conformance] ERROR: %s\n' "$*" >&2; exit 1; }

# Runs a command silently, showing its output only if it fails.
conf_quiet() {
  local out
  if ! out="$("$@" 2>&1)"; then
    printf '%s\n' "$out" >&2
    conf_die "command failed: $*"
  fi
}

# True when the published host port is held by this project's own container.
conf_port_is_ours() {
  docker ps --filter "label=com.docker.compose.project=$CONF_PROJECT" --format '{{.Ports}}' |
    grep -q "127.0.0.1:$1->"
}

conf_require_free_ports() {
  local port
  for port in "$CONF_PG_PORT" "$CONF_REDIS_PORT" "$CONF_API_PORT" "$CONF_JF_PORT" "$CONF_ABS_PORT" "$CONF_METRICS_PORT"; do
    if conf_port_is_ours "$port"; then continue; fi
    if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
      conf_die "host port $port is in use by another process; override it in the environment (see baseline/fixture.env)"
    fi
  done
}

# Builds the image only when it is missing, or always for a dirty tree so the
# tag cannot point at stale source. BuildKit's cache makes a no-op rebuild cheap.
conf_ensure_image() {
  if [ "$(conf_dirty)" = false ] && docker image inspect "$CONF_IMAGE" >/dev/null 2>&1; then
    return 0
  fi
  conf_log "building $CONF_IMAGE"
  docker buildx build --load \
    -f "$CONF_BASELINE/Dockerfile" \
    --build-arg "BUILD_REVISION=$(conf_revision)" \
    --build-arg "BUILD_DIRTY=$(conf_dirty)" \
    -t "$CONF_IMAGE" "$CONF_REPO" >&2
}

# conf_psql <args...>: psql inside the Postgres container, as the app role.
conf_psql() {
  conf_compose exec -T postgres psql -v ON_ERROR_STOP=1 -U silo -d "${CONF_DB:-silo}" "$@"
}

conf_wait_for_api() {
  local deadline=$((SECONDS + ${1:-120}))
  until curl -fsS -o /dev/null "http://127.0.0.1:$CONF_API_PORT/api/v1/ready" 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      conf_compose logs --tail 40 silo >&2 || true
      conf_die "the API did not become ready on port $CONF_API_PORT"
    fi
    sleep 1
  done
}

# A local Go HTTP client on the development hosts sweeps each new listener once, about 20 seconds after it
# opens: GET / twice on every port, following redirects. The relayed requests land in Go's request log, on
# the front's side only. Waiting for them keeps them out of the stage counts. Without such a client this
# waits the full 45 seconds. conf_wait_listener_sweep <origin log>
conf_wait_listener_sweep() {
  local deadline=$((SECONDS + 45))
  until grep -q '"listener":"jellycompat"' "$1" 2>/dev/null; do
    [ "$SECONDS" -lt "$deadline" ] || return 0
    sleep 0.5
  done
  sleep 3
}

# The same sweep through a proxy that keeps no origin log: the candidate Go logs the sweep's jellycompat requests
# under Go's own client name. conf_wait_proxy_sweep <compose project> <UTC start time>
conf_wait_proxy_sweep() {
  local deadline=$((SECONDS + 45))
  until docker logs --since "$2" "$1-silo-1" 2>&1 | grep -q 'msg="jellycompat request".*user_agent=Go-http-client'; do
    [ "$SECONDS" -lt "$deadline" ] || return 0
    sleep 0.5
  done
  sleep 3
}
