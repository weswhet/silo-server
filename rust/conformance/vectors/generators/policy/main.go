// Command policy_vectors runs the vendored silo.scope/silo.permission/silo.action
// Rego policies through the real OPA rego library (github.com/open-policy-agent/opa/v1)
// over a large randomized input corpus, and writes {input, decision} pairs for each
// of the three decisions to JSON files that rust/crates/silo-gate's tests replay
// against regorus.
//
// Pin:
//
//	GOTOOLCHAIN=go1.26.10 go run ./rust/conformance/vectors/generators/policy \
//	  -vendor rust/crates/silo-gate/vendor -out rust/conformance/vectors/policy -n 2500 -seed 1
//
// This program only reads the vendored .rego module text (copied byte-for-byte from
// internal/policy/vendor) and the open-policy-agent/opa library already in go.sum. It
// does not import internal/policy, and it writes nothing under internal/.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/rego"
)

type moduleSource struct {
	path, source string
}

// stubByDomain names the vendor stub file providing silo_custom.<domain>.override
// when no override document is supplied for that domain.
var stubByDomain = map[string]string{
	"scope":      "custom_stub.rego",
	"permission": "custom_permission_stub.rego",
	"action":     "custom_action_stub.rego",
}

// loadModules loads the three decision modules plus the quality lib, and the
// real vendor stub for every domain in skipStubFor's complement (skipStubFor
// names domains whose stub is replaced by a synthetic override module instead).
func loadModules(dir string, skipStubFor map[string]bool) ([]moduleSource, error) {
	var out []moduleSource
	names := []string{
		"scope.rego", "permission.rego", "action.rego", "lib/quality.rego",
	}
	for _, domain := range []string{"scope", "permission", "action"} {
		if !skipStubFor[domain] {
			names = append(names, stubByDomain[domain])
		}
	}
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out = append(out, moduleSource{path: name, source: string(b)})
	}
	return out, nil
}

// --- randomized input generation, mirroring internal/policy/input.go field names ---

func randQuality(r *rand.Rand) string {
	opts := []string{"", "any", "ANY", "480p", "720P", "1080p", "STANDARD", "4K", "UHD", "2160p", "4320P", "bogus"}
	return opts[r.Intn(len(opts))]
}

func randRating(r *rand.Rand) string {
	opts := []string{"", "G", "PG", "PG-13", "R", "NC-17", "TV-MA"}
	return opts[r.Intn(len(opts))]
}

func randIDs(r *rand.Rand, n int) []int {
	if n == 0 {
		return []int{}
	}
	out := make([]int, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, r.Intn(50))
	}
	return out
}

func scopeInput(r *rand.Rand) map[string]any {
	return map[string]any{
		"schema_version":                     r.Intn(3),
		"user_id":                            r.Intn(10),
		"session_id":                         fmt.Sprintf("sess-%d", r.Intn(5)),
		"profile_id":                         fmt.Sprintf("prof-%d", r.Intn(5)),
		"account_library_ids":                randIDs(r, r.Intn(6)),
		"account_restricted":                 r.Intn(2) == 0,
		"account_max_playback_quality":       randQuality(r),
		"access_policy_revision":             int64(r.Intn(100)),
		"disabled_library_ids":               randIDs(r, r.Intn(4)),
		"profile_present":                    r.Intn(2) == 0,
		"profile_max_content_rating":         randRating(r),
		"profile_max_advisory_age":           r.Intn(25) - 2,
		"profile_max_playback_quality":       randQuality(r),
		"profile_library_restricted":         r.Intn(2) == 0,
		"profile_allowed_library_ids":        randIDs(r, r.Intn(6)),
		"profile_has_pin":                    r.Intn(2) == 0,
		"profile_verified":                   r.Intn(2) == 0,
		"profile_preferred_metadata_language": []string{"", "en", "en-US", "fr"}[r.Intn(4)],
		"request_time":                       "2026-01-01T00:00:00Z",
		"device_id":                          "dev-1",
		"client_ip":                          "127.0.0.1",
		"is_api_key":                         r.Intn(2) == 0,
	}
}

func scopeOverrideInput(r *rand.Rand) map[string]any {
	// A subset of fields a silo_custom.scope.override document might set;
	// loaded as `data` under silo_custom.scope so the stub is replaced.
	return map[string]any{
		"unrestricted":        r.Intn(2) == 0,
		"allowed_library_ids": randIDs(r, r.Intn(5)),
		"disabled_library_ids": randIDs(r, r.Intn(3)),
		"max_content_rating":  randRating(r),
		"max_advisory_age":    r.Intn(20) - 1,
		"max_playback_quality": randQuality(r),
		"profile_verified":    r.Intn(2) == 0,
	}
}

var permissions = []string{"acting_admin", "marker_edit", "metadata_curation", "unknown", ""}
var roles = []string{"admin", "user", ""}

func permissionInput(r *rand.Rand) map[string]any {
	return map[string]any{
		"schema_version":             r.Intn(3),
		"user_id":                    r.Intn(10),
		"role":                       roles[r.Intn(len(roles))],
		"user_enabled":               r.Intn(2) == 0,
		"assigned_permissions":       randPermSubset(r),
		"permission":                 permissions[r.Intn(len(permissions))],
		"declared_profile_id":        []string{"", "p1", "p2"}[r.Intn(3)],
		"acting_as_primary":          r.Intn(2) == 0,
		"household_requires_profile": r.Intn(2) == 0,
		"target_library_ids":         randIDs(r, r.Intn(5)),
		"user_library_ids":           randIDs(r, r.Intn(5)),
		"user_libraries_restricted":  r.Intn(2) == 0,
		"request_time":               "2026-01-01T00:00:00Z",
		"device_id":                  "dev-1",
		"client_ip":                  "127.0.0.1",
	}
}

func randPermSubset(r *rand.Rand) []string {
	all := []string{"marker_edit", "metadata_curation"}
	var out []string
	for _, p := range all {
		if r.Intn(2) == 0 {
			out = append(out, p)
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

var actions = []string{"download", "download_transcode", "playback_admission", "unknown", ""}
var requestedActions = []string{"direct_play", "transcode", "audio_transcode", ""}

func actionInput(r *rand.Rand) map[string]any {
	ratingOK := r.Intn(2) == 0
	maxRating := randRating(r)
	within := ratingOK
	if maxRating == "" {
		within = true
	}
	return map[string]any{
		"schema_version":                r.Intn(3),
		"action":                        actions[r.Intn(len(actions))],
		"user_id":                       r.Intn(10),
		"download_allowed":              r.Intn(2) == 0,
		"download_transcode_allowed":    r.Intn(2) == 0,
		"max_streams":                   r.Intn(5),
		"max_transcodes":                r.Intn(5),
		"transcode_allowed":             r.Intn(2) == 0,
		"audio_transcode_allowed":       r.Intn(2) == 0,
		"downloads_enabled":             r.Intn(2) == 0,
		"transcode_enabled":             r.Intn(2) == 0,
		"artifacts_available":           r.Intn(2) == 0,
		"current_active_streams":        r.Intn(6),
		"current_active_transcodes":     r.Intn(6),
		"requested_action":              requestedActions[r.Intn(len(requestedActions))],
		"requested_quality":             randQuality(r),
		"file_quality":                  randQuality(r),
		"max_playback_quality":          randQuality(r),
		"content_rating":                randRating(r),
		"max_content_rating":            maxRating,
		"content_rating_within_ceiling": within,
		"request_time":                  "2026-01-01T00:00:00Z",
		"device_id":                     "dev-1",
		"client_ip":                     "127.0.0.1",
	}
}

func actionOverrideInput(r *rand.Rand) map[string]any {
	return map[string]any{
		"allowed":         r.Intn(2) == 0,
		"reason":          []string{"", "custom reason"}[r.Intn(2)],
		"quality_ceiling": randQuality(r),
	}
}

func permissionOverrideInput(r *rand.Rand) map[string]any {
	return map[string]any{
		"allowed": r.Intn(2) == 0,
		"reason":  []string{"", "custom reason"}[r.Intn(2)],
	}
}

type caseRecord struct {
	Input    map[string]any `json:"input"`
	Override map[string]any `json:"override,omitempty"`
	Decision json.RawMessage `json:"decision"`
}

func evalDecision(ctx context.Context, vendorDir, query, domain string, input, overrideDoc map[string]any) (json.RawMessage, error) {
	skip := map[string]bool{}
	if overrideDoc != nil {
		skip[domain] = true
	}
	modules, err := loadModules(vendorDir, skip)
	if err != nil {
		return nil, fmt.Errorf("load modules: %w", err)
	}
	opts := []func(*rego.Rego){rego.Query(query)}
	for _, m := range modules {
		opts = append(opts, rego.Module(m.path, m.source))
	}
	// Supply the override document as `data.silo_custom.<domain>` via a
	// synthetic module that defines override() to return the fixed doc,
	// replacing the real always-false stub for that one domain.
	if overrideDoc != nil {
		raw, _ := json.Marshal(overrideDoc)
		synthetic := fmt.Sprintf("package silo_custom.%s\n\nimport rego.v1\n\noverride(_, _) := %s\n", domain, string(raw))
		opts = append(opts, rego.Module("custom/"+domain+"_synthetic.rego", synthetic))
	}
	opts = append(opts, rego.Input(input))
	r := rego.New(opts...)
	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare: %w", err)
	}
	rs, err := pq.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return json.RawMessage("null"), nil
	}
	return json.Marshal(rs[0].Expressions[0].Value)
}

func main() {
	vendorDir := flag.String("vendor", "rust/crates/silo-gate/vendor", "vendored rego module directory")
	outDir := flag.String("out", "rust/conformance/vectors/policy", "output directory")
	n := flag.Int("n", 2500, "cases per decision (base, no override)")
	nOverride := flag.Int("n-override", 1000, "additional cases per decision exercising a custom override")
	seed := flag.Int64("seed", 1, "PRNG seed")
	flag.Parse()

	ctx := context.Background()
	r := rand.New(rand.NewSource(*seed))

	type job struct {
		name, query, domain string
		gen                 func(*rand.Rand) map[string]any
		genOverride         func(*rand.Rand) map[string]any
	}
	jobs := []job{
		{"scope", "data.silo.scope.decision", "scope", scopeInput, scopeOverrideInput},
		{"permission", "data.silo.permission.decision", "permission", permissionInput, permissionOverrideInput},
		{"action", "data.silo.action.decision", "action", actionInput, actionOverrideInput},
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	total := 0
	for _, j := range jobs {
		var records []caseRecord
		for i := 0; i < *n; i++ {
			input := j.gen(r)
			dec, err := evalDecision(ctx, *vendorDir, j.query, j.domain, input, nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s case %d: %v\n", j.name, i, err)
				os.Exit(1)
			}
			records = append(records, caseRecord{Input: input, Decision: dec})
		}
		for i := 0; i < *nOverride; i++ {
			input := j.gen(r)
			override := j.genOverride(r)
			dec, err := evalDecision(ctx, *vendorDir, j.query, j.domain, input, override)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s override case %d: %v\n", j.name, i, err)
				os.Exit(1)
			}
			records = append(records, caseRecord{Input: input, Override: override, Decision: dec})
		}
		out, err := json.MarshalIndent(records, "", "  ")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		path := filepath.Join(*outDir, j.name+".json")
		if err := os.WriteFile(path, out, 0o644); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("%s: wrote %d cases to %s\n", j.name, len(records), path)
		total += len(records)
	}
	fmt.Printf("total cases: %d\n", total)
}
