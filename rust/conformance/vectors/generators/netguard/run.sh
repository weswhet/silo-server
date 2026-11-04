#!/bin/sh
# Writes the outbound address guard vectors from the real internal/netguard package.
#
#   rust/conformance/vectors/generators/netguard/run.sh
#
# Commands assume the repository root is the cwd.
set -eu
export GOTOOLCHAIN=go1.26.10 CGO_ENABLED=0
go run ./rust/conformance/vectors/generators/netguard > rust/conformance/vectors/netguard/classify.json
