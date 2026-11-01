#!/bin/sh
# Runs the whole silo-core format gate and writes rust/parity/formats.json. It needs Go, Docker, and the
# conformance stack, and it does not regenerate the committed vectors. Commands assume the repository
# root is the cwd. CORE_CARGO_DIR picks another workspace root if rust/ cannot load.
set -eu

here=rust/conformance/vectors/generators/core
root=$(pwd)
out="$root/rust/target/core-vectors/rust-out"
log="$root/rust/target/core-vectors/gate.log"
rm -rf "$out"
mkdir -p "$out"
: > "$log"
cargo_dir="${CORE_CARGO_DIR:-$root/rust}"
export PYTHONDONTWRITEBYTECODE=1

(cd "$cargo_dir" && cargo test -p silo-core -j 4 --test vectors) 2>&1 | tee -a "$log" | grep -E '^test |^test result' 
if grep -q '^test go_vectors \.\.\. ok' "$log"; then echo "GATE go_to_rust ok" >> "$log"; fi
if grep -q '^test directplay_linux_vector \.\.\. ok' "$log"; then echo "GATE directplay_linux ok" >> "$log"; fi

(cd "$cargo_dir" && cargo run -q -p silo-core -j 4 --example emit_core_vectors -- "$out") > "$out.emit" 2>&1
sed -n 's/^emit-det \(.*\)$/DET \1/p' "$out.emit" >> "$log"

sh "$here/run.sh" verify "$out" 2>/dev/null | tee -a "$log" | grep -Ev 'cases, ok$' || true
sh "$here/run.sh" linux-verify "$out" 2>/dev/null | tee -a "$log" | grep -E 'thumbhash|FAIL' || true

if sh "$here/run.sh" linux-rust 2>&1 | tee -a "$log" | grep -E 'verify playback_directplay_etag +[0-9]+ cases, ok'; then
  echo "GATE directplay_linux_rust ok" >> "$log"
fi

(cd "$cargo_dir" && cargo test -p silo-core -j 4 --test conformance_pg -- --ignored --nocapture) 2>&1 | tee -a "$log" | grep -E '^test |^test result|^decrypted'
if grep -q '^test result: ok. 3 passed' "$log"; then echo "GATE conformance_pg ok" >> "$log"; fi

python3 "$here/formats.py" "$log"
