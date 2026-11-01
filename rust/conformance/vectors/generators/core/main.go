//go:build core_vectors

// Command core writes the silo-core format vectors from the real Go packages and verifies Rust's
// output against them. See run.sh for how to invoke it.
//
// Each family has an input type I, and either a compute function (deterministic: Rust must produce
// the same bytes) or a produce and check pair (randomized: each side checks the other's output with
// its real verifier). Inputs are generated with a seed fixed per family, so the output is
// reproducible apart from the families that use crypto/rand.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const outDir = "rust/conformance/vectors/core"

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

func (s *S) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '{' {
		var v struct {
			Hex string `json:"hex"`
		}
		if err := json.Unmarshal(data, &v); err != nil {
			return err
		}
		raw, err := hex.DecodeString(v.Hex)
		if err != nil {
			return err
		}
		*s = S(raw)
		return nil
	}
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*s = S(v)
	return nil
}

// H is bytes that always travel as {"hex": "..."}, so a mutator on the Rust side keeps their length.
type H []byte

func (h H) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{"hex": hex.EncodeToString(h)})
}

func (h *H) UnmarshalJSON(data []byte) error {
	var v struct {
		Hex string `json:"hex"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	raw, err := hex.DecodeString(v.Hex)
	if err != nil {
		return err
	}
	*h = raw
	return nil
}

type family struct {
	name   string
	cases  int
	source string
	gen    func(r *rand.Rand, i int) (in, out any, err error)
	verify func(in, out json.RawMessage) error
}

var families []family

func newRand(name string) *rand.Rand {
	h := fnv.New64a()
	_, _ = h.Write([]byte(name))
	return rand.New(rand.NewPCG(0x51100c0e, h.Sum64()))
}

// det registers a deterministic family.
func det[I, O any](name, source string, cases int, gen func(*rand.Rand, int) I, compute func(I) O) {
	families = append(families, family{
		name: name, cases: cases, source: source,
		gen: func(r *rand.Rand, i int) (any, any, error) {
			in := gen(r, i)
			return in, compute(in), nil
		},
		verify: func(rawIn, rawOut json.RawMessage) error {
			var in I
			if err := json.Unmarshal(rawIn, &in); err != nil {
				return fmt.Errorf("decode input: %w", err)
			}
			return sameJSON(compute(in), rawOut)
		},
	})
}

// nondet registers a randomized family. check verifies an output with the real Go verifier.
func nondet[I, O any](name, source string, cases int, gen func(*rand.Rand, int) I, produce func(I) (O, error), check func(I, O) error) {
	families = append(families, family{
		name: name, cases: cases, source: source,
		gen: func(r *rand.Rand, i int) (any, any, error) {
			in := gen(r, i)
			out, err := produce(in)
			if err != nil {
				return nil, nil, err
			}
			if err := check(in, out); err != nil {
				return nil, nil, fmt.Errorf("self check: %w", err)
			}
			return in, out, nil
		},
		verify: func(rawIn, rawOut json.RawMessage) error {
			var in I
			if err := json.Unmarshal(rawIn, &in); err != nil {
				return fmt.Errorf("decode input: %w", err)
			}
			var out O
			if err := json.Unmarshal(rawOut, &out); err != nil {
				return fmt.Errorf("decode output: %w", err)
			}
			return check(in, out)
		},
	})
}

func marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

func canonical(raw []byte) (string, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	out, err := marshal(normalizeNumbers(v))
	return string(out), err
}

// normalizeNumbers keeps integers exact and compares other numbers by value, because a harness that
// reserializes 0.000001 may spell it 1e-06. Spelling that matters is checked as strings or signed bytes.
func normalizeNumbers(v any) any {
	switch t := v.(type) {
	case json.Number:
		if strings.ContainsAny(string(t), ".eE") {
			if f, err := t.Float64(); err == nil {
				return strconv.FormatFloat(f, 'g', -1, 64)
			}
		}
		return t
	case []any:
		for i := range t {
			t[i] = normalizeNumbers(t[i])
		}
	case map[string]any:
		for k := range t {
			t[k] = normalizeNumbers(t[k])
		}
	}
	return v
}

func sameJSON(want any, rawGot json.RawMessage) error {
	wantRaw, err := marshal(want)
	if err != nil {
		return err
	}
	wantText, err := canonical(wantRaw)
	if err != nil {
		return err
	}
	gotText, err := canonical(rawGot)
	if err != nil {
		return err
	}
	if wantText != gotText {
		return fmt.Errorf("output differs\n  go:   %s\n  rust: %s", wantText, gotText)
	}
	return nil
}

type vectorCase struct {
	In  json.RawMessage `json:"in"`
	Out json.RawMessage `json:"out"`
}

type vectorFile struct {
	Family string       `json:"family"`
	Source string       `json:"source"`
	Cases  []vectorCase `json:"cases"`
}

// archSensitive families use floating point where the Go compiler may fuse x*y+z on arm64, so their
// bytes differ between architectures. The vectors pin amd64, from run.sh linux-gen.
var archSensitive = map[string]bool{"thumbhash": true}

// selected reports whether this run handles the family: CORE_ONLY names the families for a run in an
// amd64 container, and a native run on another architecture leaves arch-sensitive families to it.
func selected(name string) bool {
	if only := os.Getenv("CORE_ONLY"); only != "" {
		for _, n := range strings.Split(only, ",") {
			if n == name {
				return true
			}
		}
		return false
	}
	return !archSensitive[name] || runtime.GOARCH == "amd64"
}

func generate() error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	for _, f := range families {
		if !selected(f.name) {
			fmt.Printf("gen %-34s skipped, see run.sh linux-gen\n", f.name)
			continue
		}
		r := newRand(f.name)
		var b bytes.Buffer
		fmt.Fprintf(&b, "{\n\"family\": %q,\n\"source\": %q,\n\"cases\": [\n", f.name, f.source)
		for i := range f.cases {
			in, out, err := f.gen(r, i)
			if err != nil {
				return fmt.Errorf("%s case %d: %w", f.name, i, err)
			}
			inRaw, err := marshal(in)
			if err != nil {
				return fmt.Errorf("%s case %d: %w", f.name, i, err)
			}
			outRaw, err := marshal(out)
			if err != nil {
				return fmt.Errorf("%s case %d: %w", f.name, i, err)
			}
			sep := ","
			if i == f.cases-1 {
				sep = ""
			}
			fmt.Fprintf(&b, "{\"in\":%s,\"out\":%s}%s\n", inRaw, outRaw, sep)
		}
		b.WriteString("]\n}\n")
		if err := os.WriteFile(filepath.Join(outDir, f.name+".json"), b.Bytes(), 0o644); err != nil {
			return err
		}
		fmt.Printf("gen %-34s %5d cases\n", f.name, f.cases)
	}
	return nil
}

func verify(dir string) error {
	failed := 0
	missing := 0
	byName := map[string]family{}
	for _, f := range families {
		byName[f.name] = f
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		f := byName[name]
		if !selected(name) {
			fmt.Printf("verify %-34s skipped, see run.sh linux-verify\n", name)
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name+".json"))
		if err != nil {
			fmt.Printf("MISSING %s\n", name)
			missing++
			continue
		}
		var file vectorFile
		if err := json.Unmarshal(data, &file); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		bad := 0
		for i, c := range file.Cases {
			if err := runVerify(f, c); err != nil {
				bad++
				if bad <= 3 {
					fmt.Printf("FAIL %s case %d: %v\n  in: %s\n", name, i, err, c.In)
				}
			}
		}
		if bad > 0 {
			failed++
			fmt.Printf("verify %-34s %5d cases, %d FAILED\n", name, len(file.Cases), bad)
		} else {
			fmt.Printf("verify %-34s %5d cases, ok\n", name, len(file.Cases))
		}
	}
	if failed > 0 || missing > 0 {
		return fmt.Errorf("%d families failed, %d missing", failed, missing)
	}
	return nil
}

func runVerify(f family, c vectorCase) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return f.verify(c.In, c.Out)
}

func main() {
	registerAll()
	var err error
	switch {
	case len(os.Args) >= 2 && os.Args[1] == "gen":
		if os.Getenv("CORE_ONLY") == "" {
			err = writeLua("rust/crates/silo-core/src/redis_lua.rs")
		}
		if err == nil && os.Getenv("CORE_ONLY") == "" {
			err = writeLocks("rust/crates/silo-core/src/advisory_locks.rs")
		}
		if err == nil {
			err = generate()
		}
	case len(os.Args) >= 3 && os.Args[1] == "verify":
		err = verify(os.Args[2])
	case len(os.Args) >= 3 && os.Args[1] == "directplay":
		err = writeDirectPlay(os.Args[2])
	default:
		err = fmt.Errorf("usage: core gen | core verify <dir>")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
