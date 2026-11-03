#!/usr/bin/env bash
# Rebuilds the baseline's seed state and leaves the server running.
#
#   reset.sh          wipe everything, migrate, seed, scan the sample library
#   reset.sh --fast   restore the database from the last full reset's snapshot,
#                     for use between test runs
#
# Safe to run at any time and in any state. Only this project's containers and
# volumes are touched.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

API="http://127.0.0.1:$CONF_API_PORT/api/v1"

admin_api() { # admin_api <method> <path> [json]
  curl -fsS -X "$1" "$API$2" \
    -H "Authorization: Bearer $CONF_ADMIN_API_KEY" \
    -H "X-Profile-Id: $CONF_ADMIN_PROFILE_ID" \
    -H 'Content-Type: application/json' \
    ${3:+--data "$3"}
}

apply_accounts_seed() {
  conf_compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U silo -d silo \
    -v "admin_profile=$CONF_ADMIN_PROFILE_ID" \
    -v "user_profile=$CONF_USER_PROFILE_ID" \
    -v "user_second_profile=$CONF_USER_SECOND_PROFILE_ID" \
    -v "jwt_secret=$CONF_JWT_SECRET" \
    <"$CONF_SEED/accounts.sql" >/dev/null
}

# Waits until the scan has recorded its files, then until the catalog tables stop
# changing, so normalization does not race the metadata workers.
wait_for_catalog() {
  local deadline=$((SECONDS + 180)) last="" now stable=0 ready
  while :; do
    now="$(conf_psql -At -c "
      SELECT (SELECT count(*) FROM media_files),
             (SELECT count(*) FROM media_items),
             (SELECT count(*) FROM episodes),
             (SELECT count(*) FROM media_folders WHERE last_scanned_at IS NOT NULL),
             (SELECT coalesce(md5(string_agg(t::text, '' ORDER BY t::text)), '') FROM media_items t),
             (SELECT coalesce(md5(string_agg(t::text, '' ORDER BY t::text)), '') FROM media_files t),
             (SELECT coalesce(md5(string_agg(t::text, '' ORDER BY t::text)), '') FROM episodes t)")"
    ready="$(cut -d'|' -f1-4 <<<"$now")"
    if [ "$ready" = "4|3|2|2" ] && [ "$now" = "$last" ]; then
      stable=$((stable + 1))
      [ "$stable" -ge 8 ] && return 0
    else
      stable=0
    fi
    last="$now"
    [ "$SECONDS" -lt "$deadline" ] || conf_die "catalog did not settle; last state: $now"
    sleep 1
  done
}

full_reset() {
  conf_ensure_image
  conf_require_free_ports
  conf_log "wiping project $CONF_PROJECT"
  conf_quiet conf_compose --profile tools down -v --remove-orphans

  conf_quiet conf_compose up -d --wait postgres redis edge

  conf_log "generating sample library"
  mkdir -p "$CONF_RUN"
  conf_compose --profile tools run --rm media-gen >"$CONF_RUN/media-sha256.txt" 2>/dev/null

  conf_log "applying migrations"
  conf_quiet conf_compose run --rm --no-deps silo --migrate-only

  conf_log "seeding accounts"
  apply_accounts_seed

  conf_log "first server start and library scan"
  conf_quiet conf_compose up -d silo
  conf_wait_for_api 180

  local movies tv
  movies="$(admin_api POST /libraries/ '{"paths":["/media/movies"],"type":"movies","name":"Conformance Movies"}' | jq -r .id)"
  tv="$(admin_api POST /libraries/ '{"paths":["/media/tv"],"type":"series","name":"Conformance Series"}' | jq -r .id)"
  admin_api POST /scan "{\"library_id\":$movies}" >/dev/null
  admin_api POST /scan "{\"library_id\":$tv}" >/dev/null
  wait_for_catalog

  conf_log "normalizing and snapshotting"
  conf_quiet conf_compose stop --timeout 30 silo
  conf_compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U silo -d silo \
    <"$CONF_SEED/normalize.sql" >/dev/null

  if [ -f "$CONF_RUN/seed-digest.txt" ]; then
    cp "$CONF_RUN/seed-digest.txt" "$CONF_RUN/seed-digest.previous.txt"
  fi
  "$CONF_SCRIPTS_DIR/seed-digest.sh" >"$CONF_RUN/seed-digest.txt"
  snapshot
}

snapshot() {
  conf_compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U silo -d postgres \
    -c 'SET client_min_messages = warning' \
    -c 'DROP DATABASE IF EXISTS silo_seed' \
    -c 'CREATE DATABASE silo_seed TEMPLATE silo' >/dev/null
}

fast_reset() {
  conf_compose exec -T postgres psql -At -U silo -d postgres \
    -c "SELECT 1 FROM pg_database WHERE datname = 'silo_seed'" 2>/dev/null | grep -q 1 ||
    conf_die "no snapshot yet; run reset.sh without --fast first"
  conf_quiet conf_compose stop --timeout 30 silo
  conf_compose exec -T postgres psql -q -v ON_ERROR_STOP=1 -U silo -d postgres \
    -c 'DROP DATABASE IF EXISTS silo WITH (FORCE)' \
    -c 'CREATE DATABASE silo TEMPLATE silo_seed' >/dev/null
}

case "${1:-}" in
  "") full_reset ;;
  --fast)
    conf_quiet conf_compose up -d --wait postgres redis edge
    fast_reset
    # The restored database must be the snapshot, byte for byte in seed terms.
    # CONF_DIGEST_SKIP names tables that a process outliving the reset writes on its own clock, such as the
    # front's machine ID lease renewal and its log batch retries (front-compare.sh). Their lines and the total
    # are left out on both sides.
    digest_filter() {
      if [ -n "${CONF_DIGEST_SKIP:-}" ]; then grep -v -E "^(seq:)?(${CONF_DIGEST_SKIP})[|_]|^TOTAL[|]"; else cat; fi
    }
    if [ -f "$CONF_RUN/seed-digest.txt" ] &&
      ! cmp -s <("$CONF_SCRIPTS_DIR/seed-digest.sh" | digest_filter) <(digest_filter <"$CONF_RUN/seed-digest.txt"); then
      diff <(digest_filter <"$CONF_RUN/seed-digest.txt") <("$CONF_SCRIPTS_DIR/seed-digest.sh" | digest_filter) >&2 || true
      conf_die "restored database does not match the recorded seed digest"
    fi
    ;;
  *) conf_die "usage: reset.sh [--fast]" ;;
esac

conf_compose exec -T redis redis-cli FLUSHALL >/dev/null
conf_quiet conf_compose up -d silo
conf_wait_for_api 180

if [ -f "$CONF_RUN/seed-digest.txt" ]; then
  conf_log "seed digest $(tail -1 "$CONF_RUN/seed-digest.txt" | cut -d'|' -f2)"
fi
if [ "${1:-}" = "" ] && [ -f "$CONF_RUN/seed-digest.previous.txt" ]; then
  if cmp -s "$CONF_RUN/seed-digest.txt" "$CONF_RUN/seed-digest.previous.txt"; then
    conf_log "seed state matches the previous full reset"
  else
    conf_log "WARNING: seed state differs from the previous full reset:"
    diff "$CONF_RUN/seed-digest.previous.txt" "$CONF_RUN/seed-digest.txt" >&2 || true
  fi
fi
conf_log "ready: API http://127.0.0.1:$CONF_API_PORT  Jellyfin http://127.0.0.1:$CONF_JF_PORT  ABS http://127.0.0.1:$CONF_ABS_PORT"
