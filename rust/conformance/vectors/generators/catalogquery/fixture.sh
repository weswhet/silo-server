#!/bin/sh
# Creates the catalogquery scratch database: a clone of the conformance seed (silo_seed) plus
# fixture.sql. Prints its URL. Commands assume the repository root is the cwd and the primary
# conformance stack is up (Postgres published on 127.0.0.1:25432).
#
#   url=$(rust/conformance/vectors/generators/catalogquery/fixture.sh)
#   rust/conformance/vectors/generators/catalogquery/run.sh db "$url"
#   SILO_CATALOG_DATABASE_URL="$url" cargo test -p silo-catalog --test query_db -- --test-threads=1
set -eu
here=rust/conformance/vectors/generators/catalogquery
container=${SILO_CONFORMANCE_PG_CONTAINER:-silo-conformance-postgres-1}
db=catalogquery_scratch
docker exec "$container" psql -q -U silo -d postgres \
  -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db TEMPLATE silo_seed" >/dev/null
docker exec -i "$container" psql -q -v ON_ERROR_STOP=1 -U silo -d "$db" <"$here/fixture.sql" >/dev/null
echo "postgres://silo:silo@127.0.0.1:25432/$db?sslmode=disable"
