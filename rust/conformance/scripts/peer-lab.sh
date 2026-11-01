#!/usr/bin/env bash
# The peer lab: real source addresses on both sides of the comparison.
#
# The baseline's socat edge makes every client one private, trusted address, so a run through it cannot
# see what a relay does to the peer trust decision. Here each client is a socat container with its own
# static address, on a network shared by both stacks, and a Linux build of the front runs in the
# candidate Go server's network namespace, which is how it would be deployed:
#
#   harness -> client (203.0.113.11) -> reference Go                       Go's peer is the client
#   harness -> client (203.0.113.11) -> front -> 127.x.y.z -> candidate Go Go's peer is a hashed loopback
#   harness -> client (203.0.113.11) -> candidate Go, straight             Go vs Go, to find its own noise
#
# 203.0.113.0/24 is outside the default trusted list and 10.77.0.0/24 is inside it.
#
#   peer-lab.sh build                   build the Linux front
#   peer-lab.sh up                      networks and clients; both baseline stacks must be running
#   peer-lab.sh front [--proxy-all]     (re)start the front
#   peer-lab.sh compare [--proxy-all|--go] [--from SOURCE] [--out DIR] [run arguments...]
#                                       the whole plan from one client, plus the peer cases
#   peer-lab.sh down                    remove everything above; the stacks keep running
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

LAB_DIR="$CONF_ROOT/.run/lab"
A_SILO="${CONF_PROJECT}-silo-1"
B_PROJECT="${CONF_B_PROJECT:-silo-conformance-b}"
B_SILO="${B_PROJECT}-silo-1"
B_RUN="$CONF_ROOT/.run/stack-b"
b_env=(
  "CONF_PROJECT=$B_PROJECT" "CONF_RUN=$B_RUN"
  "CONF_PG_PORT=${CONF_B_PG_PORT:-35432}" "CONF_REDIS_PORT=${CONF_B_REDIS_PORT:-36379}"
  "CONF_API_PORT=${CONF_B_API_PORT:-38080}" "CONF_JF_PORT=${CONF_B_JF_PORT:-38096}"
  "CONF_ABS_PORT=${CONF_B_ABS_PORT:-38378}" "CONF_METRICS_PORT=${CONF_B_METRICS_PORT:-39090}"
)

NET_UNTRUSTED=silo-conf-lab-untrusted
NET_TRUSTED=silo-conf-lab-trusted
NET_EDGE=silo-conf-lab-edge
FRONT=silo-conf-lab-front
PORT_BASE="${CONF_LAB_PORT_BASE:-41000}"

# name, network, address
CLIENTS=(
  "untrusted_a $NET_UNTRUSTED 203.0.113.11"
  "untrusted_b $NET_UNTRUSTED 203.0.113.12"
  "trusted_a $NET_TRUSTED 10.77.0.11"
  "trusted_b $NET_TRUSTED 10.77.0.12"
)
# Listener ports inside a client and on the servers: main, jellycompat, abs, metrics.
LISTENERS=(8080 8096 13378 9090)
LISTENER_NAMES=(main jellycompat abs metrics)
A_IPS=([0]=203.0.113.2 [1]=10.77.0.2)
B_IPS=([0]=203.0.113.3 [1]=10.77.0.3)

net_index() { [ "$1" = "$NET_UNTRUSTED" ] && echo 0 || echo 1; }

build() {
  mkdir -p "$LAB_DIR"
  docker run --rm \
    -v "$CONF_REPO:/src:ro" \
    -v silo-conf-lab-target:/target \
    -v silo-conf-lab-cargo:/usr/local/cargo/registry \
    -e CARGO_TARGET_DIR=/target \
    -w /src/rust \
    rust:1.97-bookworm \
    cargo build --locked -j 4 -p silo-server
  docker rm -f "$FRONT" >/dev/null 2>&1 || true
  docker run --rm \
    -v silo-conf-lab-target:/target:ro \
    -v "$LAB_DIR:/out" \
    debian:bookworm-slim cp /target/debug/silo /out/silo
  rm -rf "$LAB_DIR/web-dist"
  cp -R "$CONF_BASELINE/web-dist" "$LAB_DIR/web-dist"
}

ensure_network() { # name [create args...]
  local name="$1"
  shift
  docker network inspect "$name" >/dev/null 2>&1 || docker network create "$@" "$name" >/dev/null
}

connect() { # network container ip
  docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$2" | grep -qw "$1" ||
    docker network connect --ip "$3" "$1" "$2"
}

# A client's published port for one listener on one target (0 reference, 1 front, 2 candidate Go).
host_port() { echo $((PORT_BASE + 100 * $1 + 10 * $2 + $3)); }

up() {
  ensure_network "$NET_UNTRUSTED" --internal --subnet 203.0.113.0/24
  ensure_network "$NET_TRUSTED" --internal --subnet 10.77.0.0/24
  ensure_network "$NET_EDGE"
  connect "$NET_UNTRUSTED" "$A_SILO" "${A_IPS[0]}"
  connect "$NET_TRUSTED" "$A_SILO" "${A_IPS[1]}"
  connect "$NET_UNTRUSTED" "$B_SILO" "${B_IPS[0]}"
  connect "$NET_TRUSTED" "$B_SILO" "${B_IPS[1]}"

  local sources="{}"
  local c=0 entry name net ip n script ports l port
  for entry in "${CLIENTS[@]}"; do
    read -r name net ip <<<"$entry"
    n="$(net_index "$net")"
    script=""
    ports=()
    for l in 0 1 2 3; do
      port="${LISTENERS[$l]}"
      # Container ports: reference, then front, then candidate Go.
      script+="socat TCP-LISTEN:$((20000 + l)),fork,reuseaddr TCP:${A_IPS[$n]}:$port &"$'\n'
      script+="socat TCP-LISTEN:$((21000 + l)),fork,reuseaddr TCP:${B_IPS[$n]}:$((10000 + port)) &"$'\n'
      script+="socat TCP-LISTEN:$((22000 + l)),fork,reuseaddr TCP:${B_IPS[$n]}:$port &"$'\n'
      ports+=(-p "127.0.0.1:$(host_port "$c" 0 "$l"):$((20000 + l))")
      ports+=(-p "127.0.0.1:$(host_port "$c" 1 "$l"):$((21000 + l))")
      ports+=(-p "127.0.0.1:$(host_port "$c" 2 "$l"):$((22000 + l))")
    done
    script+="wait"
    docker rm -f "silo-conf-lab-$name" >/dev/null 2>&1 || true
    docker create --name "silo-conf-lab-$name" --network "$NET_EDGE" "${ports[@]}" \
      --entrypoint /bin/sh alpine/socat:1.8.0.3 -c "$script" >/dev/null
    docker network connect --ip "$ip" "$net" "silo-conf-lab-$name"
    docker start "silo-conf-lab-$name" >/dev/null
    c=$((c + 1))
  done
  conf_log "lab clients are up on host ports from $PORT_BASE"
}

# The sources file the harness reads, for one candidate target (1 front, 2 candidate Go).
write_sources() { # target
  local target="$1" c=0 entry name net ip l json=""
  for entry in "${CLIENTS[@]}"; do
    read -r name net ip <<<"$entry"
    [ -n "$json" ] && json+=","
    json+="\"$name\":{\"ip\":\"$ip\""
    for l in 0 1 2 3; do
      json+=",\"${LISTENER_NAMES[$l]}\":[\"http://127.0.0.1:$(host_port "$c" 0 "$l")\",\"http://127.0.0.1:$(host_port "$c" "$target" "$l")\"]"
    done
    json+="}"
    c=$((c + 1))
  done
  printf '{%s}\n' "$json" >"$LAB_DIR/sources.json"
}

# The Linux build, in the candidate Go server's network namespace. It dies with that container, so
# anything that restarts the server starts it again.
start_front() {
  local force_go="$(cat "$LAB_DIR/force-go" 2>/dev/null || true)"
  [ -x "$LAB_DIR/silo" ] || conf_die "no Linux front; run peer-lab.sh build"
  docker rm -f "$FRONT" >/dev/null 2>&1 || true
  touch "$LAB_DIR/origin.jsonl"
  docker run -d --name "$FRONT" --network "container:$B_SILO" \
    -v "$LAB_DIR:/lab" \
    -e 'DATABASE_URL=postgres://silo:silo@postgres:5432/silo?sslmode=disable' \
    -e SILO_FRONT_WEB_DIST=/lab/web-dist \
    -e SILO_FRONT_ORIGIN_LOG=/lab/origin.jsonl \
    -e "SILO_FRONT_FORCE_GO=$force_go" \
    --entrypoint /lab/silo debian:bookworm-slim \
    --front main=0.0.0.0:18080,http://127.0.0.1:8080 \
    --front jellycompat=0.0.0.0:18096,http://127.0.0.1:8096 \
    --front abs=0.0.0.0:23378,http://127.0.0.1:13378 \
    --front metrics=0.0.0.0:19090,http://127.0.0.1:9090 >/dev/null
  local deadline=$((SECONDS + 30))
  until curl -fsS -o /dev/null "http://127.0.0.1:$(host_port 0 1 0)/api/v1/ready" 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      docker logs --tail 20 "$FRONT" >&2 || true
      conf_die "the lab front did not answer"
    fi
    sleep 0.2
  done
}

reset_candidate() {
  docker rm -f "$FRONT" >/dev/null 2>&1 || true
  env "${b_env[@]}" "$CONF_SCRIPTS_DIR/reset.sh" --fast >/dev/null
  # A restart can leave the lab's extra interfaces on the old sandbox for a moment.
  if [ -f "$LAB_DIR/use-front" ]; then
    start_front
  fi
}

compare() {
  local target=1 from=trusted_a out="$CONF_ROOT/.run/report-lab"
  mkdir -p "$LAB_DIR"
  rm -f "$LAB_DIR/force-go" "$LAB_DIR/use-front"
  while [ $# -gt 0 ]; do
    case "$1" in
      --proxy-all) echo all >"$LAB_DIR/force-go"; shift ;;
      --go) target=2; shift ;;
      --from) from="$2"; shift 2 ;;
      --out) out="$2"; shift 2 ;;
      *) break ;;
    esac
  done
  mkdir -p "$out"
  local c=0 entry name net ip found=""
  for entry in "${CLIENTS[@]}"; do
    read -r name net ip <<<"$entry"
    [ "$name" = "$from" ] && found="$c"
    c=$((c + 1))
  done
  [ -n "$found" ] || conf_die "no client named $from"
  write_sources "$target"
  local origin_args=()
  : >"$LAB_DIR/origin.jsonl"
  if [ "$target" = 1 ]; then
    touch "$LAB_DIR/use-front"
    start_front
    origin_args=(--origin-log "$LAB_DIR/origin.jsonl")
  else
    docker rm -f "$FRONT" >/dev/null 2>&1 || true
  fi
  cd "$CONF_REPO" || exit 1
  cargo build --quiet --manifest-path rust/Cargo.toml -j 4 -p silo-conformance
  rust/target/debug/silo-conformance run \
    --reference "http://127.0.0.1:$(host_port "$found" 0 0)" \
    --candidate "http://127.0.0.1:$(host_port "$found" "$target" 0)" \
    --surface "jellycompat=http://127.0.0.1:$(host_port "$found" 0 1),http://127.0.0.1:$(host_port "$found" "$target" 1)" \
    --surface "abs=http://127.0.0.1:$(host_port "$found" 0 2),http://127.0.0.1:$(host_port "$found" "$target" 2)" \
    --surface "metrics=http://127.0.0.1:$(host_port "$found" 0 3),http://127.0.0.1:$(host_port "$found" "$target" 3)" \
    --sources "$LAB_DIR/sources.json" \
    ${origin_args[@]+"${origin_args[@]}"} \
    --candidate-kind strangler \
    --reset-reference "$CONF_SCRIPTS_DIR/reset.sh --fast >/dev/null" \
    --reset-candidate "$CONF_SCRIPTS_DIR/peer-lab.sh reset-candidate" \
    --source-revision "$(conf_revision)" \
    --out "$out" \
    "$@"
}

down() {
  local entry name net ip
  docker rm -f "$FRONT" >/dev/null 2>&1 || true
  for entry in "${CLIENTS[@]}"; do
    read -r name net ip <<<"$entry"
    docker rm -f "silo-conf-lab-$name" >/dev/null 2>&1 || true
  done
  for net in "$NET_UNTRUSTED" "$NET_TRUSTED"; do
    docker network disconnect -f "$net" "$A_SILO" >/dev/null 2>&1 || true
    docker network disconnect -f "$net" "$B_SILO" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
  done
  docker network rm "$NET_EDGE" >/dev/null 2>&1 || true
}

case "${1:-}" in
  build) build ;;
  up) up ;;
  front)
    rm -f "$LAB_DIR/force-go"
    [ "${2:-}" = "--proxy-all" ] && echo all >"$LAB_DIR/force-go"
    start_front
    ;;
  reset-candidate) reset_candidate ;;
  compare) shift; compare "$@" ;;
  down) down ;;
  *) conf_die "usage: peer-lab.sh build|up|front [--proxy-all]|compare ...|down" ;;
esac
