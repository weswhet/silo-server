#!/bin/sh
# Writes the webhook guard lookup vectors from Go's resolver inside the Go server's container
# (stack A of the conformance pair), whose /etc/nsswitch.conf reads `hosts: files dns`.
#
#   rust/conformance/vectors/generators/webhookguard/run.sh [container]
#
# Commands assume the repository root is the cwd.
set -eu
container=${1:-silo-conformance-silo-1}
arch=$(docker exec "$container" uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
bin=$(mktemp)
trap 'rm -f "$bin"' EXIT
GOTOOLCHAIN=go1.26.10 CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
  go build -o "$bin" ./rust/conformance/vectors/generators/webhookguard
docker cp "$bin" "$container:/tmp/webhookguard"
docker exec "$container" /tmp/webhookguard > rust/conformance/vectors/netguard/lookup.json
docker exec "$container" rm -f /tmp/webhookguard
