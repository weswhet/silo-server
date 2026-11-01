//go:build gocompat_vectors

// Command gocompat writes the silo-gocompat differential vectors and its Unicode tables from the
// real Go standard library. Run it from the repository root with the toolchain the server ships
// with, because the Unicode tables and the outputs follow the toolchain:
//
//	GOTOOLCHAIN=go1.26.7 TZ=UTC go run -tags gocompat_vectors ./rust/conformance/vectors/generators/gocompat
//
// The output is deterministic: the random corpora use a fixed seed.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"unicode/utf8"
)

const outDir = "rust/conformance/vectors/gocompat"

// S is a Go string in a vector: a JSON string when it is valid UTF-8, or {"hex": "..."} when not.
type S string

func (s S) MarshalJSON() ([]byte, error) {
	if !utf8.ValidString(string(s)) {
		return json.Marshal(map[string]string{"hex": hex.EncodeToString([]byte(s))})
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(string(s)); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

func strs(in []string) []S {
	out := make([]S, len(in))
	for i, s := range in {
		out[i] = S(s)
	}
	return out
}

func newRand(stream uint64) *rand.Rand { return rand.New(rand.NewPCG(0x51100, stream)) }

// writeVector writes one file, with each top-level key's array on its own lines so diffs stay
// readable.
func writeVector(name string, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		panic(name + ": " + err.Error())
	}
	if err := os.WriteFile(filepath.Join(outDir, name+".json"), b.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

func main() {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	writeUnicodeTables("rust/crates/silo-gocompat/src/unicode_tables.rs")
	writeVector("unicode", genUnicode())
	writeVector("strings", genStrings())
	writeVector("path", genPath())
	writeVector("time", genTime())
	writeVector("url", genURL())
	writeVector("strconv", genStrconv())
	writeVector("json", genJSON())
	writeRegexpVector(genRegexp())
}
