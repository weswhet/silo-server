#!/usr/bin/env bash
# Compares what the request plan cannot reach on the chain rows, against the two stacks front-compare.sh
# started: the rate_limited refusal, with the per-address budget lowered, and demo_guarded, a GET under
# demo mode. Run through front-compare.sh's CONF_FRONT_AFTER, with the front listening on 18080.
#
# The reference gets the X-Forwarded-For the front's Go gets, so both file the client under 127.0.0.1.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
set +e
ref="http://127.0.0.1:$CONF_API_PORT"
cand="http://127.0.0.1:18080"
rows=(
  /api/v1/images/capability
  /api/v2/account/me
  /api/v2/images/capabilities
  /api/v2/user/libraries/capabilities
  /api/v2/account/password/capability
)
fail=0

# Status, sorted header names, and the body with the seconds and request id masked: both change per answer.
fetch() {
  curl -s -D - "$1$2" -H "Authorization: Bearer $CONF_USER_API_KEY" -H "X-Forwarded-For: 127.0.0.1" |
    tr -d '\r' | awk 'NR==1{print $2; next} /^$/{b=1; next} !b{split($0,a,":"); print tolower(a[1]) | "sort"; next} b{close("sort"); print}' |
    sed -E 's/"retry_after":[0-9]+/"retry_after":N/; s/retry after [0-9]+ seconds/retry after N seconds/; s/urn:silo:request:[0-9a-f]+/urn:silo:request:ID/'
}

compare() {
  local a b
  a="$(fetch "$ref" "$2")"
  b="$(fetch "$cand" "$2")"
  if [ "$a" = "$b" ]; then
    echo "ok   $1 $2 $(head -1 <<<"$a")"
  else
    echo "DIFF $1 $2"
    diff <(echo "$a") <(echo "$b") | head -20
    fail=1
  fi
}

# The limiter's budgets, through the admin route each server reloads from. The front polls settings.
budget() {
  for base in "$ref" "$cand"; do
    curl -fsS -o /dev/null -X PUT "$base/api/v1/admin/rate-limits/config" \
      -H "Authorization: Bearer $CONF_ADMIN_API_KEY" -H "X-Profile-Id: $CONF_ADMIN_PROFILE_ID" \
      -H "Content-Type: application/json" \
      -d "{\"ip_requests_per_second\":$1,\"ip_requests_per_minute\":$2,\"ip_burst\":$3}"
  done
  sleep 4
}

demo() {
  for c in silo-conformance-postgres-1 silo-conformance-b-postgres-1; do
    docker exec "$c" psql -q -U silo silo -c \
      "INSERT INTO server_settings(key,value) VALUES ('demo.enabled','$1') ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value" >/dev/null
  done
}

budget 1 6000 1
for row in "${rows[@]}"; do
  compare rate_limited_first "$row"
  compare rate_limited_refused "$row"
  sleep 2
done
budget 1000 60000 1000

# A PIN-locked profile, on a login session: a key skips the PIN, a session must prove it.
pin() {
  for c in silo-conformance-postgres-1 silo-conformance-b-postgres-1; do
    docker exec "$c" psql -q -U silo silo -c \
      "UPDATE user_profiles SET pin_hash='$1' WHERE id='$CONF_USER_SECOND_PROFILE_ID'" >/dev/null
  done
}
login() {
  curl -fsS -X POST "$1/api/v2/auth/login" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$CONF_USER_USERNAME\",\"password\":\"$CONF_USER_PASSWORD\"}" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])'
}
locked() {
  curl -s -D - "$1$3" -H "Authorization: Bearer $2" -H "X-Profile-Id: $CONF_USER_SECOND_PROFILE_ID" -H "X-Forwarded-For: 127.0.0.1" |
    tr -d '\r' | awk 'NR==1{print $2; next} /^$/{b=1; next} !b{split($0,a,":"); print tolower(a[1]) | "sort"; next} b{close("sort"); print}' |
    sed -E 's/urn:silo:request:[0-9a-f]+/urn:silo:request:ID/'
}
pin locked
ref_token="$(login "$ref")"
cand_token="$(login "$cand")"
for row in /api/v1/images/capability /api/v1/auth/account/capability /api/v2/images/capabilities /api/v2/account/password/capability; do
  a="$(locked "$ref" "$ref_token" "$row")"
  b="$(locked "$cand" "$cand_token" "$row")"
  if [ "$a" = "$b" ]; then
    echo "ok   locked_profile $row $(head -1 <<<"$a")"
  else
    echo "DIFF locked_profile $row"
    diff <(echo "$a") <(echo "$b") | head -20
    fail=1
  fi
done
pin ""

demo true
for row in "${rows[@]}"; do compare demo_guarded "$row"; done
demo false

exit "$fail"
