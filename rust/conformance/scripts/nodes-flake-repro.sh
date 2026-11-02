#!/usr/bin/env bash
# Shows the admin nodes last_health_check known flake with Go alone: creates the same node on both Go
# stacks at once, reads it back a moment later, and prints each stack's value.
#
#   nodes-flake-repro.sh [rounds] [wait seconds]
#
# A reset restarts both servers together, so their 30-second health tickers can line up. Restart one
# Go server about 10 seconds before running this, or no round can differ.
#
# Exits 0 when at least one round had a stamp on one stack and null on the other.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

rounds="${1:-12}"
wait_s="${2:-4}"
a="http://127.0.0.1:$CONF_API_PORT"
b="http://127.0.0.1:${CONF_B_API_PORT:-38080}"

call() { # call <base> <method> <path> [json]
  curl -sS -X "$2" "$1$3" \
    -H "Authorization: Bearer $CONF_ADMIN_API_KEY" \
    -H "X-Profile-Id: $CONF_ADMIN_PROFILE_ID" \
    -H 'Content-Type: application/json' \
    ${4:+--data "$4"}
}
field() { python3 -c "import json,sys; print(json.load(sys.stdin).get('$1'))"; }
# The listing is the only read of a node on v2, and the only one that shows the stamp.
stamp() { # stamp <base> <name>
  call "$1" GET /api/v2/admin/nodes | python3 -c "
import json, sys
print(next(n['last_health_check'] for n in json.load(sys.stdin)['items'] if n['name'] == '$2'))"
}

seen=0
for n in $(seq 1 "$rounds"); do
  body="{\"name\":\"flake-$n\",\"type\":\"proxy\",\"url\":\"http://127.0.0.1:9/flake-$n\"}"
  call "$a" POST /api/v2/admin/nodes "$body" >"$CONF_RUN/flake-a.json" &
  call "$b" POST /api/v2/admin/nodes "$body" >"$CONF_RUN/flake-b.json" &
  wait
  id_a="$(field id <"$CONF_RUN/flake-a.json")"
  id_b="$(field id <"$CONF_RUN/flake-b.json")"
  sleep "$wait_s"
  hc_a="$(stamp "$a" "flake-$n")"
  hc_b="$(stamp "$b" "flake-$n")"
  echo "round $n: a=$hc_a b=$hc_b"
  if { [ "$hc_a" = None ] && [ "$hc_b" != None ]; } || { [ "$hc_a" != None ] && [ "$hc_b" = None ]; }; then
    seen=$((seen + 1))
  fi
  call "$a" DELETE "/api/v1/admin/nodes/$id_a" >/dev/null
  call "$b" DELETE "/api/v1/admin/nodes/$id_b" >/dev/null
done
rm -f "$CONF_RUN/flake-a.json" "$CONF_RUN/flake-b.json"
echo "differing rounds: $seen of $rounds"
[ "$seen" -gt 0 ]
