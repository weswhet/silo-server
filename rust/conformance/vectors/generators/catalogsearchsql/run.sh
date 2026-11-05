#!/bin/sh
# Writes the search SQL and fuzzy rerank vectors from the real internal/catalog package.
#
#   rust/conformance/vectors/generators/catalogsearch/run.sh           # search_sql.json
#
# Commands assume the repository root is the cwd. The Go tree is not modified: the unexported
# search helpers are reached through a build overlay that adds one export-shim file to
# internal/catalog (overlay/catalog.go.txt), and libvips is replaced through a temporary go.mod
# with a stub nothing here calls, as rust/conformance/vectors/generators/apiv2wire/run.sh does.
set -eu

here=rust/conformance/vectors/generators/catalogsearchsql
export GOTOOLCHAIN=go1.26.10 CGO_ENABLED=0 TZ=UTC
root=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir "$work/bimg"
cp "$here/bimg_stub.go.txt" "$work/bimg/stub.go"
printf 'module github.com/h2non/bimg\n\ngo 1.21\n' > "$work/bimg/go.mod"
cp go.mod "$work/go.mod"
cp go.sum "$work/go.sum"
printf '\nreplace github.com/h2non/bimg => %s/bimg\n' "$work" >> "$work/go.mod"

printf '{"Replace":{\n"%s/internal/catalog/zz_vectors_catalogsearchsql.go": "%s/%s/overlay/catalog.go.txt"\n}}\n' \
  "$root" "$root" "$here" > "$work/overlay.json"

go build -modfile "$work/go.mod" -overlay "$work/overlay.json" -tags catalogsearchsql_vectors -o "$work/catalogsearchsql" "./$here"
"$work/catalogsearchsql" "$@"
