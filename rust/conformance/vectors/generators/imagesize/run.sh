#!/bin/sh
# Writes rust/conformance/vectors/core/imagesize.json from the real internal/imagesize package.
# Commands assume the repository root is the cwd.
set -eu
export GOTOOLCHAIN=go1.26.10 CGO_ENABLED=0 TZ=UTC
go run ./rust/conformance/vectors/generators/imagesize > rust/conformance/vectors/core/imagesize.json
