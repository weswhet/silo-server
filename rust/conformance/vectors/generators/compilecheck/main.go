// Command compilecheck_vectors runs a battery of administrator-policy-source candidates through
// the real internal/policy.CompileCheck and records accept/reject for each, so
// rust/crates/silo-gate's tests can assert the Rust port's compile_check rejects at least
// everything Go rejects (fail-closed parity in the direction that matters: Rust must never accept
// what Go refuses).
//
// This program imports internal/policy as a read-only oracle; it writes nothing under internal/.
//
// Pin:
//
//	GOTOOLCHAIN=go1.26.10 go run ./rust/conformance/vectors/generators/compilecheck \
//	  -out rust/conformance/vectors/policy/compilecheck.json
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Silo-Server/silo-server/internal/policy"
)

type caseRecord struct {
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	Source  string `json:"source"`
	Rejected bool   `json:"rejected"`
	Error   string `json:"error,omitempty"`
}

func main() {
	out := flag.String("out", "rust/conformance/vectors/policy/compilecheck.json", "output file")
	flag.Parse()

	type candidate struct {
		name, domain, source string
	}
	cands := []candidate{
		{"valid_scope_override", "scope", `package silo_custom.scope
import rego.v1
override(base, i) := {"unrestricted": false} if { i.user_id == 1 } else := {}`},
		{"valid_permission_override", "permission", `package silo_custom.permission
import rego.v1
override(base, i) := {"allowed": false, "reason": "blocked"} if { i.role == "banned" } else := {}`},
		{"valid_action_override", "action", `package silo_custom.action
import rego.v1
override(base, i) := {"quality_ceiling": "720p"} if { i.file_quality == "4320p" } else := {}`},
		{"wrong_package", "scope", `package silo_custom.wrong
import rego.v1
override(_, _) := {}`},
		{"wrong_domain_package", "scope", `package silo_custom.permission
import rego.v1
override(_, _) := {}`},
		{"unsupported_domain", "bogus", `package silo_custom.bogus
import rego.v1
override(_, _) := {}`},
		{"empty_source", "scope", ``},
		{"syntax_error", "scope", `package silo_custom.scope
import rego.v1
override(base, i) := {{{`},
		{"undefined_function", "scope", `package silo_custom.scope
import rego.v1
override(base, i) := result if { result := totally_undefined_function(i) }`},
		{"wrong_arity_builtin", "scope", `package silo_custom.scope
import rego.v1
override(base, i) := result if { result := upper("a", "b", "c") }`},
		{"time_now_builtin", "scope", `package silo_custom.scope
import rego.v1
override(base, i) := {"max_advisory_age": time.now_ns()}`},
		{"http_send_builtin", "action", `package silo_custom.action
import rego.v1
override(base, i) := result if { resp := http.send({"method": "get", "url": "http://x"}); result := {"reason": resp.status} }`},
		{"rand_builtin", "scope", `package silo_custom.scope
import rego.v1
override(base, i) := {"max_advisory_age": rand.intn("x", 10)}`},
		{"uuid_builtin", "permission", `package silo_custom.permission
import rego.v1
override(base, i) := {"reason": uuid.rfc4122("x")}`},
		{"opa_runtime_builtin", "scope", `package silo_custom.scope
import rego.v1
override(base, i) := {"max_advisory_age": object.get(opa.runtime(), "x", 0)}`},
		{"type_mismatch_arith", "scope", `package silo_custom.scope
import rego.v1
override(base, i) := result if { result := {"max_advisory_age": i.account_library_ids + 1} }`},
		{"nested_valid_logic", "permission", `package silo_custom.permission
import rego.v1
override(base, i) := result if {
	i.role == "admin"
	i.user_id > 100
	result := {"allowed": true}
} else := {}`},
		{"oversized_source", "scope", "package silo_custom.scope\nimport rego.v1\n// " + strings.Repeat("x", 300000) + "\noverride(_, _) := {}"},
		{"reference_to_missing_vendor_rule", "action", `package silo_custom.action
import rego.v1
override(base, i) := result if { result := {"quality_ceiling": data.silo.action.nonexistent_helper(i)} }`},
	}

	var records []caseRecord
	for _, c := range cands {
		err := policy.CompileCheck(context.Background(), c.domain, c.source)
		rec := caseRecord{Name: c.name, Domain: c.domain, Source: c.source, Rejected: err != nil}
		if err != nil {
			rec.Error = err.Error()
		}
		records = append(records, rec)
		fmt.Printf("%-35s rejected=%v\n", c.name, rec.Rejected)
	}

	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
