#!/usr/bin/env bash
# Starts the baseline, seeding it first when no seed snapshot exists. Running it
# again while the baseline is up changes nothing.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

conf_ensure_image
conf_require_free_ports

conf_quiet conf_compose up -d --wait postgres redis edge

if ! conf_compose exec -T postgres psql -At -U silo -d postgres \
  -c "SELECT 1 FROM pg_database WHERE datname = 'silo_seed'" | grep -q 1; then
  conf_log "no seed snapshot; running a full reset"
  exec "$CONF_SCRIPTS_DIR/reset.sh"
fi

conf_quiet conf_compose up -d silo
conf_wait_for_api 180
conf_log "ready: API http://127.0.0.1:$CONF_API_PORT  Jellyfin http://127.0.0.1:$CONF_JF_PORT  ABS http://127.0.0.1:$CONF_ABS_PORT"
