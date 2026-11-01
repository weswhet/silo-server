#!/usr/bin/env bash
# Sends real requests to the running baseline and checks the answers. Response
# bodies go to .run/verify/ so two runs can be diffed. Exits non-zero on failure.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

API="http://127.0.0.1:$CONF_API_PORT"
JF="http://127.0.0.1:$CONF_JF_PORT"
ABS="http://127.0.0.1:$CONF_ABS_PORT"
OUT="$CONF_RUN/verify"
rm -rf "$OUT"
mkdir -p "$OUT"

failures=0
BODY=""

# check <name> <want-status> <jq-predicate> <curl args...>
check() {
  local name="$1" want="$2" predicate="$3" status
  shift 3
  BODY="$OUT/$name.json"
  status="$(curl -sS -o "$BODY" -w '%{http_code}' "$@" || echo 000)"
  if [ "$status" = "$want" ] && jq -e "$predicate" "$BODY" >/dev/null 2>&1; then
    printf 'ok    %-34s %s\n' "$name" "$status"
  else
    printf 'FAIL  %-34s got %s, want %s where %s\n' "$name" "$status" "$want" "$predicate"
    head -c 300 "$BODY" 2>/dev/null; echo
    failures=$((failures + 1))
  fi
}

admin=(-H "Authorization: Bearer $CONF_ADMIN_API_KEY" -H "X-Profile-Id: $CONF_ADMIN_PROFILE_ID")
user=(-H "Authorization: Bearer $CONF_USER_API_KEY" -H "X-Profile-Id: $CONF_USER_PROFILE_ID")
kid=(-H "Authorization: Bearer $CONF_USER_API_KEY" -H "X-Profile-Id: $CONF_USER_SECOND_PROFILE_ID")
json=(-H 'Content-Type: application/json')

# /api/v1
check v1-health 200 '.status == "ok" and .server_name == "Silo Conformance"' "$API/api/v1/health"
check v1-setup-status 200 '.needs_setup == false' "$API/api/v1/auth/setup"
check v1-login-admin 200 '.access_token | length > 0' -X POST "${json[@]}" \
  -d "{\"username\":\"$CONF_ADMIN_USERNAME\",\"password\":\"$CONF_ADMIN_PASSWORD\"}" "$API/api/v1/auth/login"
ADMIN_JWT="$(jq -r .access_token "$BODY")"
check v1-login-user 200 '.access_token | length > 0' -X POST "${json[@]}" \
  -d "{\"username\":\"$CONF_USER_USERNAME\",\"password\":\"$CONF_USER_PASSWORD\"}" "$API/api/v1/auth/login"
check v1-login-wrong-password 401 'true' -X POST "${json[@]}" \
  -d "{\"username\":\"$CONF_USER_USERNAME\",\"password\":\"wrong-password\"}" "$API/api/v1/auth/login"
check v1-profiles-jwt 200 '(.profiles | length) == 1 and .profiles[0].name == "Conf Admin"' \
  -H "Authorization: Bearer $ADMIN_JWT" "$API/api/v1/profiles/"
check v1-profiles-user 200 '(.profiles | map(.name) | sort) == ["Conf Kid","Conf User"]' "${user[@]}" "$API/api/v1/profiles/"
check v1-libraries-admin 200 'length == 2 and (map(.name) | sort) == ["Conformance Movies","Conformance Series"]' \
  "${admin[@]}" "$API/api/v1/libraries/"
check v1-libraries-as-user 403 'true' "${user[@]}" "$API/api/v1/libraries/"
check v1-no-credentials 401 'true' "$API/api/v1/profiles/"

# /api/v2
check v2-me 200 '.username == "conf-admin"' "${admin[@]}" "$API/api/v2/account/me"
check v2-profiles 200 '.items | length == 2' "${user[@]}" "$API/api/v2/profiles"
check v2-libraries 200 '.items | length == 2' "${admin[@]}" "$API/api/v2/libraries"
check v2-libraries-as-user 403 '.status == 403' "${user[@]}" "$API/api/v2/libraries"
check v2-catalog 200 '(.items | map(.title) | sort) == ["Conformance Alpha","Conformance Beta","Conformance Show"]' \
  "${user[@]}" "$API/api/v2/catalog"
check v2-catalog-kid 200 '(.items | map(.title)) | index("Conformance Beta") == null' \
  "${kid[@]}" "$API/api/v2/catalog"
check v2-item 200 '.title == "Conformance Alpha"' "${user[@]}" "$API/api/v2/catalog/items/movie-tmdb-9000001"
check v2-item-missing 404 '.status == 404' "${user[@]}" "$API/api/v2/catalog/items/movie-tmdb-404"
check v2-seasons 200 '.items | length == 1' "${user[@]}" "$API/api/v2/catalog/series/series-tvdb-9000003/seasons"
check v2-episodes 200 '(.items | map(.title)) == ["Pilot","Second"]' \
  "${user[@]}" "$API/api/v2/catalog/series/series-tvdb-9000003/seasons/1/episodes"
check v2-home-sections 200 '.sections | length > 0' "${user[@]}" "$API/api/v2/home/sections"
check v2-no-credentials 401 '.status == 401' "$API/api/v2/account/me"

# Artwork: the local poster the scan picked up is served as a real image.
POSTER="$(jq -r .poster_url "$OUT/v2-item.json")"
poster_type="$(curl -sS -o /dev/null -w '%{http_code} %{content_type}' "$API$POSTER" || true)"
if [ "$poster_type" = "200 image/webp" ]; then
  printf 'ok    %-34s %s\n' v2-poster "$poster_type"
else
  printf 'FAIL  %-34s got %s\n' v2-poster "$poster_type"
  failures=$((failures + 1))
fi

# Jellyfin protocol
jf_auth='MediaBrowser Client="conformance", Device="harness", DeviceId="conformance-1", Version="1.0"'
check jf-info-public 200 '.ProductName == "Jellyfin Server" and .StartupWizardCompleted == true' "$JF/System/Info/Public"
check jf-login 200 '.AccessToken | length > 0' -X POST "${json[@]}" -H "X-Emby-Authorization: $jf_auth" \
  -d "{\"Username\":\"$CONF_USER_USERNAME#Conf User\",\"Pw\":\"$CONF_USER_PASSWORD\"}" "$JF/Users/AuthenticateByName"
JF_TOKEN="$(jq -r .AccessToken "$BODY")"
JF_USER="$(jq -r .User.Id "$BODY")"
jf=(-H "X-Emby-Authorization: $jf_auth, Token=\"$JF_TOKEN\"")
check jf-views 200 '.Items | length == 2' "${jf[@]}" "$JF/Users/$JF_USER/Views"
check jf-items 200 '(.Items | map(.Name) | sort) == ["Conformance Alpha","Conformance Beta","Conformance Show"]' \
  "${jf[@]}" "$JF/Users/$JF_USER/Items?Recursive=true&IncludeItemTypes=Movie,Series"
check jf-no-token 401 'true' "$JF/Users/$JF_USER/Views"

# Audiobookshelf protocol
check abs-ping 200 '.success == true' "$ABS/ping"

if [ "$failures" -gt 0 ]; then
  conf_die "$failures check(s) failed"
fi
conf_log "all checks passed; bodies in .run/verify/"
