# Shared helpers for the conformance baseline scripts. Source, don't execute.
# shellcheck shell=bash
set -euo pipefail

CONF_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF_ROOT="$(cd "$CONF_SCRIPTS_DIR/.." && pwd)"
CONF_REPO="$(cd "$CONF_ROOT/../.." && pwd)"
CONF_BASELINE="$CONF_ROOT/baseline"
CONF_SEED="$CONF_BASELINE/seed"
# Gitignored: digests and verification output from the last run. A second stack
# (see self-compare.sh) sets this so the two do not overwrite each other's state.
CONF_RUN="${CONF_RUN:-$CONF_ROOT/.run}"

set -a
# shellcheck source=../baseline/fixture.env
. "$CONF_BASELINE/fixture.env"
set +a

# The image is tagged by the Go source it was built from. rust/ never reaches the
# image, so changes under it do not count as dirty.
conf_revision() { git -C "$CONF_REPO" rev-parse HEAD; }
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
