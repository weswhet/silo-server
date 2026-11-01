#!/usr/bin/env bash
# Prints one line per populated table: <table>|<rows>|<md5 of its rows>, then a
# line per sequence that has advanced, then a TOTAL line. Ciphertext is masked because each encryption uses a fresh nonce, so
# encrypted values differ between resets even when they decrypt to the same thing.
#
# Usage: seed-digest.sh [database]   (default: silo)
. "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
CONF_DB="${1:-silo}"

digest="$(conf_psql -At -F'|' <<'SQL'
SELECT format(
  $q$SELECT %L, count(*), coalesce(md5(string_agg(r, E'\n' ORDER BY r)), '-')
     FROM (SELECT regexp_replace(t::text, 'enc:v1:[A-Za-z0-9_-]+', 'enc:v1:<masked>', 'g') AS r FROM %I.%I t) s$q$,
  c.relname, n.nspname, c.relname)
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE n.nspname = 'public' AND c.relkind = 'r'
ORDER BY c.relname
\gexec
SQL
)"
sequences="$(conf_psql -At -F'|' -c "
  SELECT 'seq:' || sequencename, last_value, ''
  FROM pg_sequences WHERE schemaname = 'public' AND last_value IS NOT NULL ORDER BY 1")"

body="$({ printf '%s\n' "$digest" | awk -F'|' '$2 != "0"'; printf '%s\n' "$sequences"; } | LC_ALL=C sort)"
printf '%s\n' "$body"
printf 'TOTAL|%s\n' "$(printf '%s\n' "$body" | shasum -a 256 | cut -d' ' -f1)"
