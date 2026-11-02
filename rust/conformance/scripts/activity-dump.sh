#!/usr/bin/env bash
# Appends one stage's activity_log rows, grouped, to a file, for activity-diff.py. front-compare.sh runs it
# before each reset when CONF_ACTIVITY_DIR is set.
#
#   activity-dump.sh <compose project> <file>
#
# The route patterns and the audit actions are in the rows, and both feed client-visible listings that the
# differ treats as feeds, so this is the only place a plan run compares them.
set -eu
project="$1"
file="$2"
docker exec "$project-postgres-1" psql -qAt -U silo silo -c "
  select method, coalesce(path_pattern,''), path, coalesce(status_code,0), coalesce(user_id,0),
         coalesce(impersonator_user_id,0), action, target_type, coalesce(node_id,''), count(*)
  from activity_log group by 1,2,3,4,5,6,7,8,9" >>"$file"
echo '--stage--' >>"$file"
