#!/usr/bin/env bash
# Deletes every account on one stack, so a first-run setup can succeed. The next reset restores the seed.
#
#   empty-users.sh COMPOSE_PROJECT
#
# TRUNCATE can deadlock with the server's own background writes, so it retries.
set -u
for _ in 1 2 3 4 5; do
  docker exec "$1-postgres-1" psql -q -U silo silo -c "TRUNCATE users CASCADE" >/dev/null 2>&1 && exit 0
  sleep 1
done
docker exec "$1-postgres-1" psql -q -U silo silo -c "TRUNCATE users CASCADE" >/dev/null
