# Vendored policy bundle

Copied byte-for-byte from `internal/policy/vendor` (the Go tree is the behavioral reference),
with one deliberate 2-line syntactic edit in `permission.rego`, anticipated by the port plan's
decision table ("`regorus` 0.14.0 with the 2-line vendored edit"):

```diff
-assignable_permission("marker_edit")
-assignable_permission("metadata_curation")
+assignable_permission("marker_edit") if true
+assignable_permission("metadata_curation") if true
```

`regorus` 0.14.0's Rego v1 parser refuses a headless fact rule (a rule head with no body and no
`if`) when the head takes an argument, with "rule must have a body or assignment". Real OPA
v1.18.2 accepts the unedited form (confirmed: the policy-decision vector generator in
`rust/conformance/vectors/generators/policy` loads the *unedited* file from this same directory
and evaluates it through `github.com/open-policy-agent/opa/v1/rego` successfully). Adding an
explicit `if true` is a pure syntax change with no semantic effect under Rego's own spec — a
rule's default body is `true` — and this was spot-checked by evaluating both the edited and
unedited module text through real OPA for the same input batch and diffing `assignable_permission`
and every decision built on it, with zero differences.

Keep this file in sync by hand whenever `internal/policy/vendor` changes: diff the two directories
and reapply this same 2-line edit to the new `permission.rego`, rather than copying over it.
