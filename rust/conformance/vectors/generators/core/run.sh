#!/bin/sh
# Writes the silo-core format vectors from the real Go packages, or checks Rust's output against them.
#
#   rust/conformance/vectors/generators/core/run.sh gen
#   rust/conformance/vectors/generators/core/run.sh verify <directory of Rust output>
#
# Commands assume the repository root is the cwd. The Go tree is not modified: unexported functions are
# reached through a build overlay that adds export files to their packages, and libvips is replaced
# through a temporary go.mod with a stub that nothing here calls, so the generator builds without cgo.
#
# Two families need Linux on amd64, so run these too. They need Docker:
#
#   rust/conformance/vectors/generators/core/run.sh linux-gen
#   rust/conformance/vectors/generators/core/run.sh linux-verify <directory of Rust output>
#
# The Linux direct-play ETag reads Linux stat fields, and thumbhash floating point differs on arm64.
set -eu

here=rust/conformance/vectors/generators/core
export GOTOOLCHAIN=go1.26.7 CGO_ENABLED=0 TZ=UTC
root=$(pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir "$work/bimg"
cp "$here/bimg_stub.go.txt" "$work/bimg/stub.go"
printf 'module github.com/h2non/bimg\n\ngo 1.21\n' > "$work/bimg/go.mod"
cp go.mod "$work/go.mod"
cp go.sum "$work/go.sum"
printf '\nreplace github.com/h2non/bimg => %s/bimg\n' "$work" >> "$work/go.mod"

{
  printf '{"Replace":{\n'
  first=1
  for src in "$here"/overlay/*.go.txt; do
    pkg=$(sed -n 's|^// overlay-package: ||p' "$src")
    name=$(basename "$src" .go.txt)
    [ "$first" = 1 ] || printf ',\n'
    first=0
    printf '"%s/%s/zz_vectors_%s.go": "%s/%s"' "$root" "$pkg" "$name" "$root" "$src"
  done
  printf '\n}}\n'
} > "$work/overlay.json"

case "${1:-}" in
linux-rust)
  # The other half of the Linux direct-play family: Rust on Linux stats real files and signs them with
  # its ETag, and the Go Linux build reads the same files. Builds in a container, so it takes minutes.
  # It builds in a throwaway workspace with the committed crates, and writes nothing outside rust/target.
  linux_dir=rust/target/core-vectors
  mkdir -p "$linux_dir"
  rust_image=rust:1.97-bookworm
  arch=$(docker image inspect "$rust_image" --format '{{.Architecture}}')
  GOOS=linux GOARCH="$arch" go build -modfile "$work/go.mod" -overlay "$work/overlay.json" -tags core_vectors -o "$linux_dir/corevectors-linux" "./$here"
  docker run --rm --platform "linux/$arch" -v "$root:/repo" -v "${CARGO_HOME:-$HOME/.cargo}/registry:/usr/local/cargo/registry" \
    -e CARGO_NET_OFFLINE=true -e CORE_ONLY=playback_directplay_etag -w /repo "$rust_image" sh -eu -c '
      ws=$(mktemp -d)
      mkdir "$ws/crates"
      for c in silo-gocompat silo-jwt silo-core; do ln -s "/repo/rust/crates/$c" "$ws/crates/$c"; done
      printf "[workspace]\nresolver = \"2\"\nmembers = [\"crates/*\"]\n[workspace.package]\nedition = \"2024\"\nlicense = \"AGPL-3.0-only\"\npublish = false\n" > "$ws/Cargo.toml"
      out=/repo/rust/target/core-vectors/linux-rust-out
      rm -rf "$out"
      (cd "$ws" && CARGO_TARGET_DIR="$ws/target" cargo run -q -j 4 -p silo-core --example emit_core_vectors -- "$out")
      /repo/rust/target/core-vectors/corevectors-linux verify "$out"
    '
  rm -f "$linux_dir/corevectors-linux"
  exit 0
  ;;
linux-gen|linux-verify)
  # Inside the repository, because Docker Desktop and similar VMs may not share the temporary directory.
  linux_dir=rust/target/core-vectors
  mkdir -p "$linux_dir"
  GOOS=linux GOARCH=amd64 go build -modfile "$work/go.mod" -overlay "$work/overlay.json" -tags core_vectors -o "$linux_dir/corevectors-linux" "./$here"
  docker_run() {
    docker run --rm --platform linux/amd64 -v "$root:/repo" -w /repo -e CORE_ONLY=thumbhash debian:bookworm-slim "/repo/$linux_dir/corevectors-linux" "$@"
  }
  if [ "$1" = linux-gen ]; then
    docker_run gen
    docker_run directplay rust/conformance/vectors/core/playback_directplay_etag_linux.json
  else
    case "$2" in
      "$root"/*) ;;
      *) echo "linux-verify needs a directory inside the repository" >&2; exit 2 ;;
    esac
    docker_run verify "/repo/${2#"$root"/}"
  fi
  rm -f "$linux_dir/corevectors-linux"
  exit 0
  ;;
esac
go build -modfile "$work/go.mod" -overlay "$work/overlay.json" -tags core_vectors -o "$work/corevectors" "./$here"
"$work/corevectors" "$@"
