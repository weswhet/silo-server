//go:build silo_config_vectors

// Command config writes the silo-config differential vectors and its language tables from the real
// Go packages. Run it from the repository root with the toolchain the server ships with:
//
//	GOTOOLCHAIN=go1.26.7 go run -tags silo_config_vectors ./rust/conformance/vectors/generators/config/extract
//	GOTOOLCHAIN=go1.26.7 TZ=UTC go run -tags silo_config_vectors ./rust/conformance/vectors/generators/config
//
// Packages it cannot import (cmd/silo, and those that need libvips through cgo) come from the
// extracted subpackages, which hold their real source. The output is deterministic.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const outDir = "rust/conformance/vectors/config"

// A vector's outcome: exactly one of Ok, Error, Panic.
type result struct {
	Ok    any    `json:"ok,omitempty"`
	Error string `json:"error,omitempty"`
	Panic string `json:"panic,omitempty"`
}

// goJSON is Go's own encoding of a value, kept as a string so the Rust side can compare bytes.
func goJSON(v any) string {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func write(name string, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, name), b.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

func catch(f func() result) (out result) {
	defer func() {
		if r := recover(); r != nil {
			out = result{Panic: fmt.Sprint(r)}
		}
	}()
	return f()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func main() {
	writeLangTables()
	writeLangVectors()
	writeParseVectors()
	writeNetVectors()
	writeCronVectors()
	writeEnvVectors()
	writeSettingsMapVectors()
	writeNormalizeVectors()
	writeRedisVectors()
	writeAIVectors()
	writeYAMLVectors()
	writeDotenvVectors()
	writeFlagVectors()
	writeContractVectors()
	writeResolverVectors()
}
