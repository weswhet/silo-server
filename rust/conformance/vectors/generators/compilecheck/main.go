// Command compilecheck_vectors runs administrator-policy candidates through the real
// internal/policy.CompileCheck and records accept or reject for each, so rust/crates/silo-gate can
// assert compile_check never accepts what Go refuses. It also dumps LockedCapabilities, the builtin
// table compile_check is allowed to use. It imports internal/policy as a read-only oracle.
//
// Commands assume the repository root is the cwd:
//
//	GOTOOLCHAIN=go1.26.10 go run ./rust/conformance/vectors/generators/compilecheck
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"os"
	"sort"
	"strings"

	"github.com/Silo-Server/silo-server/internal/policy"
)

type caseRecord struct {
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Source   string `json:"source"`
	Rejected bool   `json:"rejected"`
	Error    string `json:"error,omitempty"`
}

type builtinRecord struct {
	Name       string          `json:"name"`
	Decl       json.RawMessage `json:"decl"`
	Deprecated bool            `json:"deprecated"`
}

var records []caseRecord

var randomSeed int64

func check(name, domain, source string) {
	err := policy.CompileCheck(context.Background(), domain, source)
	rec := caseRecord{Name: name, Domain: domain, Source: source, Rejected: err != nil}
	if err != nil {
		rec.Error = err.Error()
		if len(rec.Error) > 200 {
			rec.Error = rec.Error[:200]
		}
	}
	records = append(records, rec)
}

func header(domain string) string {
	return "package silo_custom." + domain + "\n\nimport rego.v1\n\n"
}

// body wraps statements as the override of a scope policy.
func body(statements ...string) string {
	return header("scope") + "override(base, i) := base if {\n\t" + strings.Join(statements, "\n\t") + "\n}\n"
}

// hidden places statements behind a branch no input takes.
func hidden(statements ...string) string {
	return body(append([]string{`i.never_set == "never"`, "false"}, statements...)...)
}

func values() map[string]string {
	return map[string]string{
		"null": "null", "true": "true", "num": "1", "neg": "-1", "float": "1.5", "str": `"s"`, "arr": "[1]", "arrs": `["a"]`,
		"mixed": `[1, "a"]`, "set": "{1}", "sets": `{"a"}`, "emptyset": "set()", "obj": `{"a": 1}`, "emptyobj": "{}", "emptyarr": "[]",
		"input": "i.x", "input2": "input.x", "count": "count(i.x)", "upper": `upper(i.x)`, "arrcomp": "[x | some x in i.x]",
		"setcomp": "{x | some x in i.x]", "local": "base.reason",
	}
}

func main() {
	vectors := flag.String("out", "rust/conformance/vectors/policy/compilecheck.json", "output vectors")
	caps := flag.String("caps", "rust/crates/silo-gate/src/locked_builtins.json", "output builtin table")
	seed := flag.Int64("seed", 20261101, "seed for the random programs; other seeds are for exploring")
	flag.Parse()
	randomSeed = *seed

	var builtins []builtinRecord
	for _, b := range policy.LockedCapabilities().Builtins {
		decl, err := json.Marshal(b.Decl)
		if err != nil {
			log.Fatal(err)
		}
		builtins = append(builtins, builtinRecord{Name: b.Name, Decl: decl, Deprecated: b.IsDeprecated()})
	}
	sort.Slice(builtins, func(i, j int) bool { return builtins[i].Name < builtins[j].Name })

	handWritten()
	statementMatrix()
	headMatrix()
	builtinMatrix(builtins)
	typeFlowMatrix()
	randomPrograms(12000)

	data, err := json.MarshalIndent(records, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*vectors, append(data, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	table, err := json.MarshalIndent(builtins, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*caps, append(table, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	rejected := 0
	for _, r := range records {
		if r.Rejected {
			rejected++
		}
	}
	log.Printf("wrote %d cases, %d rejected by Go; %d builtins", len(records), rejected, len(builtins))
}

func handWritten() {
	for _, c := range [][3]string{
		{"valid_scope_override", "scope", header("scope") + `override(base, i) := {"unrestricted": false} if { i.user_id == 1 } else := {}`},
		{"valid_permission_override", "permission", header("permission") + `override(base, i) := {"allowed": false, "reason": "blocked"} if { i.role == "banned" } else := {}`},
		{"valid_action_override", "action", header("action") + `override(base, i) := {"quality_ceiling": "720p"} if { i.file_quality == "4320p" } else := {}`},
		{"web_default_template", "scope", header("scope") + "override(base_decision, input) := base_decision if {\n  input.schema_version == 1\n}\n"},
		{"plain_base", "scope", header("scope") + "override(base, _) := base"},
		{"go_test_tightening", "scope", header("scope") + "override(_, _) := result if {\n\tresult := {\n\t\t\"unrestricted\": false,\n\t\t\"allowed_library_ids\": [2],\n\t}\n}"},
		{"stub", "scope", header("scope") + "override(_, _) := result if {\n\tresult := {}\n\tfalse\n}"},
		{"pure_net", "scope", header("scope") + "override(base, _) := base if {\n\tnet.cidr_contains(\"10.0.0.0/8\", \"10.0.0.1\")\n}"},
		{"no_import", "scope", "package silo_custom.scope\noverride(base, _) := base"},
		{"wrong_package", "scope", "package silo_custom.wrong\nimport rego.v1\noverride(_, _) := {}"},
		{"wrong_domain_package", "scope", "package silo_custom.permission\nimport rego.v1\noverride(_, _) := {}"},
		{"unsupported_domain", "bogus", "package silo_custom.bogus\nimport rego.v1\noverride(_, _) := {}"},
		{"empty_source", "scope", ""},
		{"whitespace_source", "scope", "  \n "},
		{"only_package", "scope", "package silo_custom.scope\n"},
		{"syntax_error", "scope", header("scope") + "override(base, i) := {{{"},
		{"oversized_source", "scope", header("scope") + "# " + strings.Repeat("x", 300000) + "\noverride(_, _) := {}"},
		{"missing_override", "scope", header("scope") + "helper := 1"},
		{"override_arity_one", "scope", header("scope") + "override(a) := {}"},
		{"override_arity_three", "scope", header("scope") + "override(a, b, c) := {}"},
		{"override_not_function", "scope", header("scope") + "override := {}"},
		{"override_bool", "scope", header("scope") + "override(_, _) if { true }"},
		{"override_returns_number", "scope", header("scope") + "override(_, _) := 1"},
		{"override_returns_string", "scope", header("scope") + `override(_, _) := "x"`},
		{"override_returns_array", "scope", header("scope") + "override(_, _) := [1]"},
		{"override_returns_set", "scope", header("scope") + "override(_, _) := {1}"},
		{"override_returns_null", "scope", header("scope") + "override(_, _) := null"},
		{"override_mixed_returns", "scope", header("scope") + "override(_, i) := 1 if { i.a }\noverride(_, i) := {} if { i.b }"},
		{"override_else_returns_number", "scope", header("scope") + "override(_, i) := {} if { i.a } else := 1"},
		{"override_bad_field_types", "scope", header("scope") + `override(_, _) := {"max_advisory_age": "x", "unrestricted": 1}`},
		{"override_shadow_input", "scope", header("scope") + "override(input, i) := {}"},
		{"override_shadow_data", "scope", header("scope") + "override(data, i) := {}"},
		{"override_duplicate_args", "scope", header("scope") + "override(a, a) := {}"},
		{"override_const_arg", "scope", header("scope") + "override(1, i) := {}"},
		{"override_recursive", "scope", header("scope") + "override(a, b) := override(a, b)"},
		{"override_recursive_hidden", "scope", hidden("x := override(base, i)", "x")},
		{"mutual_recursion", "scope", header("scope") + "override(a, b) := f(a)\nf(x) := g(x)\ng(x) := f(x)"},
		{"recursion_via_decision", "scope", hidden("x := data.silo.scope.decision", "x")},
		{"recursion_via_package", "scope", hidden("x := data.silo_custom.scope", "x")},
		{"unrelated_recursion", "scope", header("scope") + "override(base, _) := base\nh := k\nk := h"},
		{"print_space", "scope", hidden(`print ("x")`)},
		{"print", "scope", hidden(`print("x")`)},
		{"decode_verify", "scope", hidden(`io.jwt.decode_verify("a", {})`)},
		{"encode_sign", "scope", hidden(`io.jwt.encode_sign({}, {}, {})`)},
		{"encode_sign_raw", "scope", hidden(`io.jwt.encode_sign_raw("", "", "")`)},
		{"time_now", "scope", hidden("time.now_ns()")},
		{"time_now_comment_only", "scope", header("scope") + "# time.now_ns()\noverride(base, _) := base"},
		{"time_now_string_only", "scope", header("scope") + `override(base, _) := base if { base.x == "time.now_ns()" }`},
		{"http_send", "action", header("action") + `override(_, _) := r if { resp := http.send({"method": "get", "url": "http://x"}); r := {"reason": resp.status} }`},
		{"rand", "scope", hidden(`rand.intn("x", 10)`)},
		{"uuid", "scope", hidden(`uuid.rfc4122("x")`)},
		{"opa_runtime", "scope", hidden("opa.runtime()")},
		{"net_lookup", "scope", hidden(`net.lookup_ip_addr("x")`)},
		{"parse_module", "scope", hidden(`rego.parse_module("a", "b")`)},
		{"unknown_function", "scope", hidden("totally_undefined(i)")},
		{"unknown_dotted_function", "scope", hidden("nope.nope(i)")},
		{"missing_vendor_function", "action", header("action") + `override(base, i) := r if { r := {"quality_ceiling": data.silo.action.nonexistent_helper(i)} }`},
		{"vendor_function_wrong_arity", "action", hidden2("action", "data.silo.action.tighten(1)")},
		{"vendor_function_no_args", "action", hidden2("action", "x := data.silo.action.tighten")},
		{"vendor_ref_ok", "scope", hidden("x := data.silo.scope.base_decision", "x")},
		{"unsafe_var", "scope", hidden("x == 1")},
		{"unsafe_negation", "scope", hidden("not y")},
		{"unsafe_head", "scope", header("scope") + "override(_, _) := z if { true }"},
		{"unsafe_ref", "scope", hidden("i[q] == q.a.b", "not q")},
		{"reassign", "scope", hidden("x := 1", "x := 2")},
		{"shadow_arg", "scope", hidden("i := 1")},
		{"shadow_rule", "scope", hidden("override := 1")},
		{"shadow_builtin_local", "scope", hidden("count := 1", "count(i)")},
		{"local_as_function", "scope", hidden("f := 1", "f(1)")},
		{"rule_name_builtin", "scope", header("scope") + "override(base, _) := base\ncount(x) := 1"},
		{"rule_name_input", "scope", header("scope") + "override(base, _) := base\ninput := 1"},
		{"rule_name_data", "scope", header("scope") + "override(base, _) := base\ndata := 1"},
		{"rule_name_keyword", "scope", header("scope") + "override(base, _) := base\nnot := 1"},
		{"rule_arity_conflict", "scope", header("scope") + "override(base, _) := base\nf(x) := 1\nf(x, y) := 2"},
		{"rule_kind_conflict", "scope", header("scope") + "override(base, _) := base\nf := 1\nf(x) := 2"},
		{"rule_set_conflict", "scope", header("scope") + "override(base, _) := base\nf := 1\nf contains 2"},
		{"rule_values_differ", "scope", header("scope") + "override(base, _) := base\nf := 1\nf := 2"},
		{"default_rule", "scope", header("scope") + "override(base, _) := base\ndefault f := 1"},
		{"default_conflict", "scope", header("scope") + "override(base, _) := base\ndefault f := 1\ndefault f := 2"},
		{"default_override", "scope", header("scope") + "default override(_, _) := {}"},
		{"helper_call_bad_arg", "scope", header("scope") + "override(base, _) := base if { f(1) }\nf(x) if { upper(x) }"},
		{"helper_call_good_arg", "scope", header("scope") + `override(base, _) := base if { f("a") }` + "\nf(x) if { upper(x) }"},
		{"helper_call_any_arg", "scope", header("scope") + "override(base, i) := base if { f(i.x) }\nf(x) if { upper(x) }"},
		{"helper_call_wrong_arity", "scope", header("scope") + "override(base, _) := base if { f(1, 2) }\nf(x) := x"},
		{"helper_no_args", "scope", header("scope") + "override(base, _) := base if { f }\nf(x) := x"},
		{"helper_result_bad", "scope", header("scope") + "override(base, _) := base if { upper(f) }\nf := 1"},
		{"helper_result_good", "scope", header("scope") + `override(base, _) := base if { upper(f) }` + "\nf := \"a\""},
		{"helper_field_of_const", "scope", header("scope") + `override(base, _) := base if { f.x }` + "\nf := 1"},
		{"constrained_base", "scope", header("scope") + "override(base, _) := base if { upper(base) }"},
		{"constrained_base_hidden", "scope", hidden("upper(base)")},
		{"constrained_base_count", "scope", hidden("count(base)")},
		{"constrained_input_param", "scope", header("scope") + "override(base, i) := base if { upper(i) }"},
		{"constrained_twice", "scope", hidden("upper(i)", "abs(i)")},
		{"constrained_then_ref", "scope", hidden("upper(i)", "i.x")},
		{"ref_then_constrained", "scope", hidden("i.x", "upper(i)")},
		{"any_local_twice", "scope", hidden("x := i.y", "upper(x)", "abs(x)")},
		{"base_field_upper", "scope", hidden("upper(base.reason)", "abs(base.reason)")},
		{"field_of_string", "scope", hidden(`x := "a"`, "x.y")},
		{"index_of_number", "scope", hidden("x := 1", "x[0]")},
		{"field_of_object", "scope", hidden(`x := {"a": 1}`, "x.b")},
		{"field_of_object_ok", "scope", hidden(`x := {"a": 1}`, "x.a")},
		{"index_of_array", "scope", hidden("x := [1]", `x["a"]`)},
		{"typed_elem", "scope", hidden("some x in [1, 2]", "upper(x)")},
		{"typed_elem_ok", "scope", hidden(`some x in ["a"]`, "upper(x)")},
		{"typed_elem_mixed", "scope", hidden(`some x in [1, "a"]`, "upper(x)")},
		{"some_over_number", "scope", hidden("some x in 1", "x")},
		{"some_over_string", "scope", hidden(`some x in "a"`, "x")},
		{"some_key_value", "scope", hidden(`some k, v in {"a": 1}`, "upper(k)", "abs(v)")},
		{"some_key_value_bad", "scope", hidden(`some k, v in {"a": 1}`, "abs(k)")},
		{"some_decl", "scope", hidden("some x", "x := 1")},
		{"some_decl_then_ref", "scope", hidden("some x", "i[x]", "x")},
		{"some_shadow", "scope", hidden("some i in [1]", "i")},
		{"comp_unsafe", "scope", hidden("x := [y | z == 1]", "x")},
		{"comp_typed", "scope", hidden("x := [1 | true]", `upper(x[0])`)},
		{"comp_elem_bad", "scope", hidden("x := [y | y := 1]", `concat(",", x)`)},
		{"comp_leak", "scope", hidden("x := [y | y := i.a]", "y")},
		{"unify_mismatch", "scope", hidden(`1 = "a"`)},
		{"unify_var", "scope", hidden("x = 1", "x")},
		{"compare_mismatch", "scope", hidden(`1 == "a"`)},
		{"compare_order_mismatch", "scope", hidden(`1 < "a"`)},
		{"compare_local", "scope", hidden("x := 1", `x == "a"`)},
		{"in_scalar", "scope", hidden("1 in 2")},
		{"in_ok", "scope", hidden("1 in [1]")},
		{"not_in", "scope", hidden("not 1 in [2]")},
		{"arith_string", "scope", hidden(`1 + "a"`)},
		{"arith_array", "scope", hidden("i.account_library_ids + 1 > 0")},
		{"arith_const_array", "scope", hidden("[1] + 1 > 0")},
		{"minus_union", "scope", hidden("x := i.a - 1", "upper(x)")},
		{"plus_any", "scope", hidden("x := i.a + 1", "upper(x)")},
		{"set_and_num", "scope", hidden("x := 1 & 2", "x")},
		{"set_or_ok", "scope", hidden("x := {1} | {2}", "x")},
		{"div_zero", "scope", hidden("x := 1 / 0", "x")},
		{"with_input", "scope", hidden(`x := i.a with input as {}`, "x")},
		{"with_builtin", "scope", hidden(`count(i) with count as 1`)},
		{"every", "scope", hidden("every x in i.a { x > 0 }")},
		{"every_unsafe", "scope", hidden("every x in i.a { y > 0 }")},
		{"import_future", "scope", "package silo_custom.scope\nimport future.keywords\noverride(base, _) := base"},
		{"import_input", "scope", "package silo_custom.scope\nimport input.a\noverride(base, _) := base"},
		{"import_data_missing", "scope", "package silo_custom.scope\nimport data.nope\noverride(base, _) := base"},
		{"import_twice", "scope", "package silo_custom.scope\nimport rego.v1\nimport rego.v1\noverride(base, _) := base"},
		{"import_after_rule", "scope", "package silo_custom.scope\noverride(base, _) := base\nimport rego.v1"},
		{"v0_body", "scope", header("scope") + "override(base, _) = base { true }"},
		{"v0_partial_set", "scope", header("scope") + "override(base, _) := base\nf[x] { x := 1 }"},
		{"no_if", "scope", header("scope") + "override(base, _) := base { true }"},
		{"annotation", "scope", header("scope") + "# METADATA\n# title: x\noverride(base, _) := base"},
		{"bad_annotation", "scope", header("scope") + "# METADATA\n# scope: nonsense\noverride(base, _) := base"},
		{"dup_object_key", "scope", hidden(`x := {"a": 1, "a": 2}`, "x")},
		{"nested_too_deep", "scope", hidden("x := "+strings.Repeat("[", 3000)+strings.Repeat("]", 3000), "x")},
		{"deep_parens", "scope", hidden("x := "+strings.Repeat("(", 2000)+"1"+strings.Repeat(")", 2000), "x")},
		{"long_plus", "scope", hidden("x := 1"+strings.Repeat(" + 1", 5000), "x")},
		{"long_else", "scope", header("scope") + "override(_, i) := {} if { i.a }" + strings.Repeat(" else := {} if { i.b }", 2000)},
		{"long_ref", "scope", hidden("x := i"+strings.Repeat(".a", 5000), "x")},
		{"bad_string_escape", "scope", hidden(`x := "\q"`, "x")},
		{"newline_in_string", "scope", hidden("x := \"a\nb\"", "x")},
		{"unterminated_string", "scope", hidden(`x := "a`)},
		{"big_number", "scope", hidden("x := 1"+strings.Repeat("0", 400), "x")},
		{"exp_number", "scope", hidden("x := 1e999", "x")},
		{"octal_number", "scope", hidden("x := 007", "x")},
		{"hex_number", "scope", hidden("x := 0x10", "x")},
		{"multiline_binary", "scope", hidden("x := 1\n\t+ 1", "x")},
		{"dot_space", "scope", hidden("i . x")},
		{"bracket_space", "scope", hidden("i [0]")},
		{"call_space", "scope", hidden(`upper ("a")`)},
		{"trailing_garbage", "scope", header("scope") + "override(base, _) := base }"},
		{"semicolons", "scope", header("scope") + "override(base, i) := base if { i.a; i.b; i.c }"},
		{"inline_if", "scope", header("scope") + "override(base, i) := base if i.a"},
		{"nul_byte", "scope", header("scope") + "override(base, _) := base\x00"},
		{"replacement_character", "scope", header("scope") + "# \ufffd\noverride(base, _) := base"},
		{"non_ascii_ident", "scope", hidden("é := 1", "é")},
		{"non_ascii_string", "scope", hidden(`x := "é"`, "x")},
		{"partial_set_ok", "scope", header("scope") + "override(base, _) := base\nf contains 1"},
		{"partial_object", "scope", header("scope") + `override(base, _) := base` + "\nf[\"a\"] := 1"},
		{"ref_head", "scope", header("scope") + "override(base, _) := base\na.b.c := 1"},
		{"ref_head_conflict", "scope", header("scope") + "override(base, _) := base\na.b := 1\na := 2"},
		{"rule_named_override_extra", "scope", header("scope") + "override(base, _) := base\noverride.x := 1"},
		{"wildcard_value", "scope", hidden("x := _", "x")},
		{"wildcard_assign", "scope", hidden("_ := 1")},
		{"wildcard_head", "scope", header("scope") + "override(_, _) := _"},
		{"wildcard_ref_ok", "scope", hidden("i.a[_] == 1")},
		{"array_destructure", "scope", hidden("[a, b] := [1, 2]", "a", "b")},
		{"object_var_key", "scope", hidden("k := 1", "x := {k: 1}", "x")},
		{"object_number_key", "scope", hidden("x := {1: 1}", "x")},
		{"set_literal_of_arrays", "scope", hidden("x := {[1], [2]}", "x")},
		{"regex_bad_pattern", "scope", hidden(`regex.match("(", "a")`)},
		{"constant_true_stmt", "scope", hidden("1")},
		{"constant_composite_stmt", "scope", hidden("[1]")},
		{"void_call_assign", "scope", hidden("x := walk(i)", "x")},
		{"walk_relation", "scope", hidden("walk(i, [p, v])", "p", "v")},
		{"internal_builtin", "scope", hidden("internal.member_2(1, [1])")},
		{"rego_metadata", "scope", hidden("rego.metadata.rule()")},
		{"sprintf_nonarray", "scope", hidden(`sprintf("%d", 1)`)},
		{"sprintf_array", "scope", hidden(`sprintf("%d", [1])`)},
		{"concat_nums", "scope", hidden(`concat(",", [1])`)},
		{"concat_strs", "scope", hidden(`concat(",", ["a"])`)},
		{"object_get_num", "scope", hidden(`object.get(1, "a", 1)`)},
		{"numbers_range_big", "scope", hidden("x := numbers.range(1, 100000000)", "x")},
		{"count_number", "scope", hidden("count(1)")},
		{"count_string", "scope", hidden(`count("a")`)},
	} {
		check(c[0], c[1], c[2])
	}
}

func hidden2(domain string, statements ...string) string {
	return header(domain) + "override(base, i) := base if {\n\ti.never == 1\n\tfalse\n\t" + strings.Join(statements, "\n\t") + "\n}\n"
}

// statementMatrix runs each value through each statement shape, plainly and behind an untaken branch.
func statementMatrix() {
	var names []string
	vals := values()
	for name := range vals {
		names = append(names, name)
	}
	sort.Strings(names)
	shapes := map[string]string{
		"assign":   "q := %s",
		"stmt":     "%s",
		"not":      "not %s",
		"eq":       `%s == "s"`,
		"lt":       "%s < 1",
		"plus":     "q := %s + 1",
		"times":    "q := 2 * %s",
		"and":      "q := %s & {1}",
		"count":    "count(%s)",
		"upper":    "upper(%s)",
		"abs":      "abs(%s)",
		"concat":   `concat(",", %s)`,
		"objget":   `object.get(%s, "a", 0)`,
		"in":       "%s in [1]",
		"incoll":   "1 in %s",
		"some":     "some q in %s",
		"somekv":   "some k, q in %s",
		"field":    "%s.a",
		"index":    "%s[0]",
		"array":    "q := [%s]",
		"set":      "q := {%s}",
		"objval":   `q := {"k": %s}`,
		"compelem": "q := [%s | true]",
		"helper":   "h(%s)",
		"typedh":   "t(%s)",
		"parens":   "q := (%s)",
	}
	var shapeNames []string
	for name := range shapes {
		shapeNames = append(shapeNames, name)
	}
	sort.Strings(shapeNames)
	helpers := "\nh(x) := x\nt(x) if { upper(x) }\n"
	for _, shape := range shapeNames {
		for _, name := range names {
			statement := fmt.Sprintf(shapes[shape], vals[name])
			check("stmt_"+shape+"_"+name, "scope", body(statement)+helpers)
			check("hidden_"+shape+"_"+name, "scope", hidden(statement)+helpers)
		}
	}
}

// headMatrix runs each value through each head form.
func headMatrix() {
	vals := values()
	var names []string
	for name := range vals {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		v := vals[name]
		h := strings.ReplaceAll(v, "i.x", "input.x")
		h = strings.ReplaceAll(h, "base.reason", "input.reason")
		for shape, source := range map[string]string{
			"override":   "override(base, i) := " + v,
			"elsevalue":  "override(base, i) := base if { i.a } else := " + v,
			"rule":       "override(base, _) := base\nr := " + h,
			"ruleupper":  "override(base, _) := base if { upper(r) }\nr := " + h,
			"rulefield":  "override(base, _) := base if { r.a }\nr := " + h,
			"fn":         "override(base, _) := base if { f(1) }\nf(x) := " + h,
			"fnupper":    "override(base, _) := base if { upper(f(1)) }\nf(x) := " + h,
			"partialset": "override(base, _) := base\nr contains " + h,
		} {
			check("head_"+shape+"_"+name, "scope", header("scope")+source+"\n")
		}
	}
}

// builtinMatrix calls each builtin with the right arity, one too few and one too many arguments, a
// wrong scalar, and a wrong composite, always behind an untaken branch.
func builtinMatrix(builtins []builtinRecord) {
	for _, name := range []string{
		"http.send", "net.lookup_ip_addr", "opa.runtime", "time.now_ns", "rand.intn", "uuid.rfc4122", "uuid.parse", "rego.parse_module", "print",
		"trace", "io.jwt.decode_verify", "io.jwt.encode_sign", "io.jwt.encode_sign_raw", "crypto.x509.parse_and_verify_certificates",
	} {
		check("locked_"+name, "scope", hidden(name+"(i)"))
	}
	for _, b := range builtins {
		var decl struct {
			Args []json.RawMessage `json:"args"`
		}
		if err := json.Unmarshal(b.Decl, &decl); err != nil {
			log.Fatal(err)
		}
		n := len(decl.Args)
		call := func(args ...string) string { return "q := " + b.Name + "(" + strings.Join(args, ", ") + ")" }
		anys := make([]string, n)
		for i := range anys {
			anys[i] = fmt.Sprintf("i.a%d", i)
		}
		check("builtin_any_"+b.Name, "scope", hidden(call(anys...)))
		if n > 0 {
			check("builtin_few_"+b.Name, "scope", hidden(call(anys[:n-1]...)))
		}
		check("builtin_many_"+b.Name, "scope", hidden(call(append(append([]string{}, anys...), "i.z")...)))
		for slot := 0; slot < n; slot++ {
			for _, wrong := range []string{"null", "true", "1", `"s"`, "[1]", `["s"]`, "{1}", `{"a": 1}`} {
				args := append([]string{}, anys...)
				args[slot] = wrong
				check(fmt.Sprintf("builtin_slot%d_%s_%s", slot, wrong, b.Name), "scope", hidden(call(args...)))
			}
		}
		// Whatever it returns, misuse it as each of these.
		for _, use := range []string{"upper(q)", "abs(q)", "count(q)", "q.a", "q[0]", "some w in q", `concat(",", q)`} {
			check("builtin_result_"+use+"_"+b.Name, "scope", hidden(call(anys...), use))
		}
	}
}

// typeFlowMatrix checks that a known type survives each way of moving a value around.
func typeFlowMatrix() {
	sources := map[string]string{"num": "1", "str": `"s"`, "arr": "[1]", "obj": `{"a": 1}`, "set": "{1}", "any": "i.x", "cnt": "count(i.x)", "up": "upper(i.x)"}
	moves := map[string]string{
		"direct": "w := v",
		"array":  "z := [v]\n\tw := z[0]",
		"object": "z := {\"a\": v}\n\tw := z.a",
		"some":   "some w in [v]",
		"comp":   "z := [y | y := v]\n\tw := z[0]",
		"helper": "w := id(v)",
		"rule":   "w := k",
	}
	uses := []string{"upper(w)", "abs(w)", "count(w)", "w.a", "w[0]", "w + 1", "some u in w", "not w", `w == "x"`}
	var sourceNames, moveNames []string
	for name := range sources {
		sourceNames = append(sourceNames, name)
	}
	for name := range moves {
		moveNames = append(moveNames, name)
	}
	sort.Strings(sourceNames)
	sort.Strings(moveNames)
	for _, sourceName := range sourceNames {
		for _, moveName := range moveNames {
			for _, use := range uses {
				k := sources[sourceName]
				if strings.Contains(k, "i.x") {
					k = strings.ReplaceAll(k, "i.x", "input.x")
				}
				source := hidden("v := "+sources[sourceName], moves[moveName], use) + "\nid(x) := x\nk := " + k + "\n"
				check("flow_"+sourceName+"_"+moveName+"_"+use, "scope", source)
			}
		}
	}
}

// randomPrograms composes programs from the Rego subset compile_check accepts, so a wrong type or
// scope rule in the Rust checker shows up as a program it accepts and Go refuses. The fixed seed keeps
// the corpus stable.
func randomPrograms(n int) {
	r := rand.New(rand.NewSource(randomSeed))
	literals := []string{"null", "true", "false", "1", "-2", "1.5", `"s"`, `""`, "[]", "[1]", `["a"]`, `[1, "a"]`, "{}", `{"a": 1}`, `{"a": "b", "c": [1]}`, "set()", "{1}", `{"a"}`, "[[1]]", `[{"a": 1}]`}
	calls := []struct {
		name  string
		arity int
	}{
		{"count", 1}, {"upper", 1}, {"lower", 1}, {"abs", 1}, {"round", 1}, {"concat", 2}, {"contains", 2}, {"startswith", 2},
		{"split", 2}, {"sprintf", 2}, {"to_number", 1}, {"is_string", 1}, {"is_number", 1}, {"type_name", 1}, {"object.get", 3},
		{"object.keys", 1}, {"object.remove", 2}, {"object.union", 2}, {"array.concat", 2}, {"array.slice", 3}, {"sum", 1}, {"max", 1},
		{"sort", 1}, {"json.marshal", 1}, {"json.unmarshal", 1}, {"base64.encode", 1}, {"trim", 2}, {"replace", 3}, {"indexof", 2},
		{"substring", 3}, {"format_int", 2}, {"regex.match", 2}, {"net.cidr_contains", 2}, {"intersection", 1}, {"union", 1}, {"plus", 2},
	}
	for c := 0; c < n; c++ {
		var vars []string
		var term func(depth int) string
		term = func(depth int) string {
			choice := r.Intn(14)
			if depth > 2 && choice > 5 {
				choice = r.Intn(6)
			}
			switch choice {
			case 0, 1:
				return literals[r.Intn(len(literals))]
			case 2:
				return "i." + string(rune('a'+r.Intn(4)))
			case 3:
				return "base.reason"
			case 4, 5:
				if len(vars) > 0 {
					return vars[r.Intn(len(vars))]
				}
				return "i.x"
			case 6:
				return "input.y[_]"
			case 7, 8, 9:
				call := calls[r.Intn(len(calls))]
				args := make([]string, call.arity)
				for a := range args {
					args[a] = term(depth + 1)
				}
				return call.name + "(" + strings.Join(args, ", ") + ")"
			case 10:
				return []string{"h", "k", "any_rule"}[r.Intn(3)]
			case 11:
				return []string{"id", "use", "free"}[r.Intn(3)] + "(" + term(depth+1) + ")"
			case 12:
				return "[" + term(depth+1) + ", " + term(depth+1) + "]"
			default:
				ops := []string{"+", "-", "*", "/", "%", "&", "|"}
				return "(" + term(depth+1) + " " + ops[r.Intn(len(ops))] + " " + term(depth+1) + ")"
			}
		}
		var statements []string
		for s, count := 0, 1+r.Intn(5); s < count; s++ {
			name := fmt.Sprintf("v%d", s)
			switch r.Intn(10) {
			case 0, 1, 2:
				statements = append(statements, name+" := "+term(0))
				vars = append(vars, name)
			case 3:
				statements = append(statements, "some "+name+" in "+term(0))
				vars = append(vars, name)
			case 4:
				statements = append(statements, "some k"+name+", "+name+" in "+term(0))
				vars = append(vars, name, "k"+name)
			case 5:
				statements = append(statements, term(0)+" == "+term(0))
			case 6:
				statements = append(statements, term(0)+" < "+term(0))
			case 7:
				statements = append(statements, term(0)+" in "+term(0))
			case 8:
				statements = append(statements, "not "+term(1))
			default:
				statements = append(statements, name+" := [w | w := "+term(0)+"; "+term(1)+" != 1]")
				vars = append(vars, name)
			}
		}
		helpers := "\nid(x) := x\nuse(x) if { upper(x) }\nfree(_) := 1\nh := 1\nk := \"s\"\nany_rule := input.q\n"
		source := body(statements...) + helpers
		if c%2 == 0 {
			source = hidden(statements...) + helpers
		}
		check(fmt.Sprintf("random_%d", c), "scope", source)
	}
}
