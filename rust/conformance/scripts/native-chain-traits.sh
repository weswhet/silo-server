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
  /api/v1/settings/
  /api/v1/profiles/
  /api/v1/admin/settings
  /api/v1/settings/contract
  /api/v1/images/capability
  /api/v2/account/me
  /api/v2/images/capabilities
  /api/v2/user/libraries/capabilities
  /api/v2/account/password/capability
  /api/v1/user/libraries
  /api/v2/user/libraries
  /api/v1/libraries/
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

# Header bytes that are not UTF-8. A Go string holds them, so none of them may read as an absent header.
status() { curl -s -o /dev/null -w '%{http_code}' "$@" -H "X-Forwarded-For: 127.0.0.1"; }
raw_rows=(
  /api/v1/auth/account/capability /api/v1/images/capability /api/v2/account/password/capability
  /api/v2/images/capabilities /api/v2/user/libraries/capabilities /api/v2/account/me
)
for row in "${raw_rows[@]}"; do
  for header in $'X-Profile-Id: \xff' $'Accept: \xff' $'Content-Encoding: gzip\xff'; do
    for key in "$CONF_USER_API_KEY" "$CONF_ADMIN_API_KEY"; do
      a="$(status -H "Authorization: Bearer $key" -H "$header" "$ref$row")"
      b="$(status -H "Authorization: Bearer $key" -H "$header" "$cand$row")"
      if [ "$a" = "$b" ]; then
        echo "ok   non_utf8 $row $a"
      else
        echo "DIFF non_utf8 $row $(printf '%q' "$header"): go $a front $b"
        fail=1
      fi
    done
  done
done

# Through the front, against the Go behind it.
go_b="http://127.0.0.1:${CONF_B_API_PORT:-38080}"
b_pg=silo-conformance-b-postgres-1
b_redis=silo-conformance-b-redis-1
psql_b() { docker exec "$b_pg" psql -qAt -U silo silo -c "$1"; }
settings_event() { docker exec "$b_redis" redis-cli PUBLISH silo:admin '{"type":"settings_changed","payload":""}' >/dev/null; }
K="Authorization: Bearer $CONF_USER_API_KEY"
PROF="X-Profile-Id: $CONF_USER_PROFILE_ID"
admin=(-H "Authorization: Bearer $CONF_ADMIN_API_KEY" -H "X-Profile-Id: $CONF_ADMIN_PROFILE_ID" -H 'Content-Type: application/json')

# Clearing the trusted list means the default list, on the native path as on the relay.
psql_b "update server_settings set value='198.51.100.0/24' where key='clientip.trusted_proxies'"
settings_event
sleep 1
psql_b "update server_settings set value='' where key='clientip.trusted_proxies'"
settings_event
sleep 1
curl -s -o /dev/null -H "$K" -H 'X-Forwarded-For: 203.0.113.50' "$cand/api/v1/images/capability"
sleep 3
got="$(psql_b "select client_ip from activity_log where path='/api/v1/images/capability' order by timestamp desc limit 1")"
if [ "$got" = "203.0.113.50" ] || [ "$got" = "203.0.113.50/32" ]; then
  echo "ok   trusted_cleared $got"
else
  echo "DIFF trusted_cleared: the native path resolved $got"
  fail=1
fi
psql_b "update server_settings set value='10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,::1/128' where key='clientip.trusted_proxies'"
settings_event

# Native scope decisions reach the decision log at Go's sample rate.
decisions() { psql_b "select count(*) from policy_decisions where decision_name='silo.scope.decision'"; }
s0="$(decisions)"
for _ in $(seq 300); do curl -s -o /dev/null -H "$K" -H "$PROF" "$cand/api/v2/images/capabilities"; done
sleep 4
s1="$(decisions)"
for _ in $(seq 300); do curl -s -o /dev/null -H "$K" -H "$PROF" "$go_b/api/v2/images/capabilities"; done
sleep 4
s2="$(decisions)"
native=$((s1 - s0))
gone=$((s2 - s1))
if [ "$native" -ge 5 ] && [ "$native" -le 7 ] && [ "$gone" -ge 5 ] && [ "$gone" -le 7 ]; then
  echo "ok   decision_log native $native go $gone"
else
  echo "DIFF decision_log: native $native go $gone"
  fail=1
fi
digest="$(psql_b "select length(input_digest), request_id is not null, policy_generation >= 0 from policy_decisions where decision_name='silo.scope.decision' order by id desc limit 1")"
[ "$digest" = "64|t|t" ] || { echo "DIFF decision_log row: $digest"; fail=1; }

# Native activity rows reach the live tail on silo:logs, in the shape Go's rows have there.
tail_file="$(mktemp)"
docker exec "$b_redis" sh -c 'exec timeout 8 redis-cli --raw SUBSCRIBE silo:logs' >"$tail_file" &
tail_pid=$!
sleep 1
curl -s -o /dev/null -H "$K" -H "$PROF" -H 'User-Agent: tail-check' "$cand/api/v2/images/capabilities"
curl -s -o /dev/null -H "$K" -H "$PROF" -H 'User-Agent: tail-check' "$go_b/api/v2/images/capabilities"
wait "$tail_pid"
if python3 - "$tail_file" <<'PY'
import json, sys
rows = []
for line in open(sys.argv[1]):
    line = line.strip()
    if line.startswith('{"type":"audit_log_appended"'):
        env = json.loads(json.loads(line)["payload"])
        if env["entry"].get("user_agent") == "tail-check":
            rows.append(env)
front = [r for r in rows if "-front-" in r["source"]]
go = [r for r in rows if "-front-" not in r["source"]]
assert front and go, f"front {len(front)} go {len(go)}"
assert sorted(front[0]["entry"]) == sorted(go[0]["entry"]), (front[0], go[0])
assert list(front[0]) == list(go[0]) == ["source", "stream", "entry"]
PY
then
  echo "ok   live_tail"
else
  echo "DIFF live_tail: $(wc -l <"$tail_file") lines"
  fail=1
fi
rm -f "$tail_file"

# A custom policy compile_check refuses: Go enforces it, so the rows go to Go until it is gone.
policy_doc=""
etag() { curl -s -D - -o /dev/null "${admin[@]}" "$go_b/api/v2/admin/policy/documents/$policy_doc" | tr -d '\r' | awk 'tolower($1)=="etag:"{print $2}'; }
policy() {
  policy_doc="$(curl -s "${admin[@]}" -d '{"domain":"scope","name":"'"$2"'"}' "$go_b/api/v2/admin/policy/documents" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
  version="$(python3 -c 'import json,sys;print(json.dumps({"source":sys.argv[1]}))' "$1" |
    curl -s "${admin[@]}" -d @- "$go_b/api/v2/admin/policy/documents/$policy_doc/versions" | python3 -c 'import json,sys;print(json.load(sys.stdin)["id"])')"
  curl -s -o /dev/null -X PUT "${admin[@]}" -H "If-Match: $(etag)" -d '{"version_id":"'"$version"'"}' "$go_b/api/v2/admin/policy/documents/$policy_doc/active-version"
  curl -s -o /dev/null -X PATCH "${admin[@]}" -H "If-Match: $(etag)" -d '{"enabled":true}' "$go_b/api/v2/admin/policy/documents/$policy_doc"
  sleep 1
}
unpolicy() {
  curl -s -o /dev/null -X PATCH "${admin[@]}" -H "If-Match: $(etag)" -d '{"enabled":false}' "$go_b/api/v2/admin/policy/documents/$policy_doc"
  sleep 1
}
source_for() {
  printf 'package silo_custom.scope\n\nimport rego.v1\n\n%boverride(_, i) := {"profile_verified": false} if {\n\ti.profile_id == "%s"\n}\n' "$1" "$CONF_USER_PROFILE_ID"
}
for spelled in '# METADATA\n# title: revoke\n' ''; do
  policy "$(source_for "$spelled")" "traits-$RANDOM"
  for row in /api/v2/images/capabilities /api/v1/images/capability /api/v2/account/password/capability; do
    a="$(status -H "$K" -H "$PROF" "$go_b$row")"
    b="$(status -H "$K" -H "$PROF" "$cand$row")"
    if [ "$a" = "403" ] && [ "$b" = "403" ]; then
      echo "ok   custom_policy $row $b"
    else
      echo "DIFF custom_policy $row: go $a front $b"
      fail=1
    fi
  done
  unpolicy
  b="$(status -H "$K" -H "$PROF" "$cand/api/v2/images/capabilities")"
  if [ "$b" = "200" ]; then echo "ok   custom_policy_disabled $b"; else echo "DIFF custom_policy_disabled $b"; fail=1; fi
done

exit "$fail"
