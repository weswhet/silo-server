#!/usr/bin/env bash
# Stops the baseline. Data stays, so start.sh resumes quickly.
#
#   stop.sh          stop the containers
#   stop.sh --wipe   also delete this project's containers, networks and volumes
#
# Only the compose project named in fixture.env is touched.
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

case "${1:-}" in
  "") conf_quiet conf_compose --profile tools stop --timeout 30 ;;
  --wipe)
    conf_quiet conf_compose --profile tools down -v --remove-orphans
    rm -rf "$CONF_RUN"
    ;;
  *) conf_die "usage: stop.sh [--wipe]" ;;
esac
conf_log "stopped project $CONF_PROJECT"
