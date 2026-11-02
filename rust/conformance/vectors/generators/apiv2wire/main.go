//go:build apiv2wire_vectors

// Command apiv2wire writes the silo-api-v2 wire-kit vectors from the real internal/apiv2
// package: the RFC 9457 problem envelope, Huma's validation error mapping, HMAC-signed
// cursors, and RFC 9110 entity-tag preconditions. See run.sh for how to invoke it.
//
// internal/apiv2 is not modified: unexported functions needed for the Huma-mapping vectors
// are reached through a build overlay that adds one export-shim file to the package
// (overlay/apiv2.go.txt), and libvips is replaced with a stub through a temporary go.mod, the
// same two techniques rust/conformance/vectors/generators/core/run.sh uses, applied here in
// this generator's own, independent workspace so nothing under internal/ or that generator is
// touched.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	apiv2 "github.com/Silo-Server/silo-server/internal/apiv2"
	"github.com/danielgtaylor/huma/v2"
)

const outDir = "rust/conformance/vectors/apiv2wire"

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "apiv2wire:", err)
		os.Exit(1)
	}
}

func write(name string, v any) {
	b, err := json.MarshalIndent(v, "", "  ")
	must(err)
	must(os.MkdirAll(outDir, 0o755))
	must(os.WriteFile(filepath.Join(outDir, name+".json"), append(b, '\n'), 0o644))
}

// problemOut is the JSON shape a *apiv2.Problem is recorded in: its exported envelope fields
// plus the headers GetHeaders() exposes (the struct's own `headers` field is unexported).
type problemOut struct {
	Type     string               `json:"type"`
	Title    string               `json:"title"`
	Status   int                  `json:"status"`
	Detail   string               `json:"detail"`
	Instance string               `json:"instance"`
	Errors   []apiv2.ProblemError `json:"errors,omitempty"`
	Headers  map[string][]string  `json:"headers,omitempty"`
}

func ofProblem(p *apiv2.Problem) *problemOut {
	if p == nil {
		return nil
	}
	h := p.GetHeaders()
	var hm map[string][]string
	if len(h) > 0 {
		hm = map[string][]string{}
		for k, v := range h {
			hm[k] = v
		}
	}
	return &problemOut{Type: p.Type, Title: p.Title, Status: p.Status, Detail: p.Detail, Instance: p.Instance, Errors: p.Errors, Headers: hm}
}

func main() {
	genCatalog()
	genPrecondition()
	genCursor()
	genWire()
	genHumaMapping()
}

// --- catalog: every ProblemType the package declares, and the bare-status fallback. ---

type typeCase struct {
	ID     string `json:"id"`
	Status int    `json:"status"`
	Title  string `json:"title"`
	URI    string `json:"uri"`
}

func genCatalog() {
	cat := apiv2.Catalog()
	out := make([]typeCase, len(cat))
	for i, t := range cat {
		out[i] = typeCase{ID: t.ID, Status: t.Status, Title: t.Title, URI: t.URI()}
	}
	write("catalog", out)

	statuses := []int{200, 304, 400, 401, 403, 404, 405, 406, 408, 409, 410, 412, 413, 415, 422, 428, 429, 500, 501, 503, 999}
	type forStatus struct {
		Status int    `json:"status"`
		ID     string `json:"id"`
	}
	var fs []forStatus
	for _, s := range statuses {
		fs = append(fs, forStatus{Status: s, ID: apiv2.TypeForStatus(s).ID})
	}
	write("type_for_status", fs)
}

// --- precondition.go: fully exported, called directly. ---

type etagParseCase struct {
	Input string           `json:"input"`
	OK    bool             `json:"ok"`
	Tag   *apiv2.EntityTag `json:"tag,omitempty"`
}

type etagListCase struct {
	Input string            `json:"input"`
	OK    bool              `json:"ok"`
	Star  bool              `json:"star"`
	Tags  []apiv2.EntityTag `json:"tags,omitempty"`
}

func genPrecondition() {
	renderInputs := []struct {
		Scope, ID string
		Version   int64
	}{
		{"catalog.item", "1", 1},
		{"catalog.item", "1", 2},
		{"catalog.item", "2", 1},
		{"editor.revision", "42", 0},
		{"editor.revision", "42", 9223372036854775807},
		{"", "", 0},
	}
	type renderCase struct {
		Scope, ID string
		Version   int64
		Tag       string
	}
	var rendered []renderCase
	for _, in := range renderInputs {
		rendered = append(rendered, renderCase{in.Scope, in.ID, in.Version, apiv2.RenderETag(in.Scope, in.ID, in.Version).String()})
	}
	write("render_etag", rendered)

	parseInputs := []string{
		`"abc"`, `W/"abc"`, `""`, `W/""`, `"a\"b"`, `abc`, `"abc`, `W/abc"`, `"unterminated`,
	}
	var parsed []etagParseCase
	for _, in := range parseInputs {
		t, err := apiv2.ParseEntityTag(in)
		c := etagParseCase{Input: in, OK: err == nil}
		if err == nil {
			c.Tag = &t
		}
		parsed = append(parsed, c)
	}
	write("parse_entity_tag", parsed)

	listInputs := []string{
		``, `*`, ` * `, `"a"`, `"a", "b"`, `"a" , W/"b"`, `,`, `"a",,"b"`, `"a" "b"`, `*, "a"`, `"a`, `W/"a", *`,
	}
	var lists []etagListCase
	for _, in := range listInputs {
		tags, star, err := apiv2.ParseETagList(in)
		c := etagListCase{Input: in, OK: err == nil, Star: star}
		if err == nil {
			c.Tags = tags
		}
		lists = append(lists, c)
	}
	write("parse_etag_list", lists)

	strong := apiv2.EntityTag{Opaque: "abc"}
	strongB := apiv2.EntityTag{Opaque: "abc"}
	weak := apiv2.EntityTag{Opaque: "abc", Weak: true}
	diff := apiv2.EntityTag{Opaque: "xyz"}
	type matchCase struct {
		A, B   apiv2.EntityTag
		Strong bool
		Weak   bool
	}
	matches := []matchCase{
		{strong, strongB, apiv2.StrongMatch(strong, strongB), apiv2.WeakMatch(strong, strongB)},
		{strong, weak, apiv2.StrongMatch(strong, weak), apiv2.WeakMatch(strong, weak)},
		{weak, weak, apiv2.StrongMatch(weak, weak), apiv2.WeakMatch(weak, weak)},
		{strong, diff, apiv2.StrongMatch(strong, diff), apiv2.WeakMatch(strong, diff)},
	}
	write("match", matches)

	current := apiv2.EntityTag{Opaque: "cur1"}
	other := apiv2.EntityTag{Opaque: "cur2"}

	type ifMatchCase struct {
		IfMatch string          `json:"if_match"`
		Current apiv2.EntityTag `json:"current"`
		Problem *problemOut     `json:"problem,omitempty"`
	}
	var ifMatches []ifMatchCase
	for _, im := range []string{``, `*`, `"cur1"`, `W/"cur1"`, `"cur2"`, `not-a-tag`} {
		ifMatches = append(ifMatches, ifMatchCase{im, current, ofProblem(apiv2.EvaluateIfMatch(im, current))})
	}
	write("evaluate_if_match", ifMatches)

	type ifNoneMatchCase struct {
		IfNoneMatch string          `json:"if_none_match"`
		Current     apiv2.EntityTag `json:"current"`
		Matched     bool            `json:"matched"`
		Problem     *problemOut     `json:"problem,omitempty"`
	}
	var ifNoneMatches []ifNoneMatchCase
	for _, inm := range []string{``, `*`, `"cur1"`, `W/"cur1"`, `"cur2"`, `bad`} {
		matched, p := apiv2.EvaluateIfNoneMatch(inm, current)
		ifNoneMatches = append(ifNoneMatches, ifNoneMatchCase{inm, current, matched, ofProblem(p)})
	}
	write("evaluate_if_none_match", ifNoneMatches)

	type createOnlyCase struct {
		IfNoneMatch string           `json:"if_none_match"`
		Existing    *apiv2.EntityTag `json:"existing,omitempty"`
		Problem     *problemOut      `json:"problem,omitempty"`
	}
	var createOnly []createOnlyCase
	for _, existing := range []*apiv2.EntityTag{nil, &current} {
		for _, inm := range []string{``, `*`, `"cur1"`, `W/"cur1"`, `"cur2"`, `bad`} {
			createOnly = append(createOnly, createOnlyCase{inm, existing, ofProblem(apiv2.EvaluateCreateOnly(inm, existing))})
		}
	}
	write("evaluate_create_only", createOnly)

	type guardedCase struct {
		IfMatch, IfNoneMatch string
		Problem              *problemOut `json:"problem,omitempty"`
	}
	var guarded []guardedCase
	for _, im := range []string{`*`, `"cur1"`, `"cur2"`} {
		for _, inm := range []string{``, `*`, `"cur1"`, `W/"cur1"`} {
			guarded = append(guarded, guardedCase{im, inm, ofProblem(apiv2.EvaluateGuardedPreconditions(im, inm, current))})
		}
	}
	write("evaluate_guarded_preconditions", guarded)

	type readCase struct {
		IfMatch, IfNoneMatch string
		NotModified          bool
		Problem              *problemOut `json:"problem,omitempty"`
	}
	var reads []readCase
	for _, im := range []string{``, `"cur1"`, `"cur2"`} {
		for _, inm := range []string{``, `*`, `"cur1"`, `W/"cur1"`} {
			nm, p := apiv2.EvaluateReadPreconditions(im, inm, current)
			reads = append(reads, readCase{im, inm, nm, ofProblem(p)})
		}
	}
	write("evaluate_read_preconditions", reads)

	type createOnlyPreCase struct {
		IfMatch, IfNoneMatch string
		Existing             *apiv2.EntityTag `json:"existing,omitempty"`
		Problem              *problemOut      `json:"problem,omitempty"`
	}
	var createOnlyPre []createOnlyPreCase
	for _, existing := range []*apiv2.EntityTag{nil, &current} {
		for _, im := range []string{``, `*`, `"cur1"`, `"cur2"`} {
			for _, inm := range []string{``, `*`} {
				createOnlyPre = append(createOnlyPre, createOnlyPreCase{im, inm, existing, ofProblem(apiv2.EvaluateCreateOnlyPreconditions(im, inm, existing))})
			}
		}
	}
	write("evaluate_create_only_preconditions", createOnlyPre)

	type overwriteCase struct {
		IfMatch string
		Is      bool
	}
	var overwrites []overwriteCase
	for _, im := range []string{``, `*`, `"a"`, `bad`} {
		overwrites = append(overwrites, overwriteCase{im, apiv2.IsOverwrite(im)})
	}
	write("is_overwrite", overwrites)

	type staleCase struct {
		Current apiv2.EntityTag `json:"current"`
		Problem *problemOut     `json:"problem"`
	}
	write("stale_version_problem", []staleCase{
		{current, ofProblem(apiv2.StaleVersionProblem(current))},
		{apiv2.EntityTag{}, ofProblem(apiv2.StaleVersionProblem(apiv2.EntityTag{}))},
	})
	_ = other
}

// --- cursor.go: HMAC-signed cursors, exported Encode/Decode. ---

func genCursor() {
	secret := []byte("vector-secret-do-not-use-in-prod")
	c := apiv2.NewCursors(secret)
	scope := apiv2.CursorScope{OperationID: "list-items", Security: "acct:1/profile:2", Filter: "library=1", Sort: "name", Tiebreaker: "item_id"}

	type position struct {
		Name string `json:"name"`
		ID   int    `json:"id"`
	}
	type encodeCase struct {
		Scope    apiv2.CursorScope `json:"scope"`
		Position position          `json:"position"`
		Cursor   string            `json:"cursor"`
		Err      string            `json:"err,omitempty"`
	}
	pos := position{Name: "The Wire", ID: 7}
	cur, err := c.Encode(scope, pos)
	encCase := encodeCase{Scope: scope, Position: pos, Cursor: cur}
	if err != nil {
		encCase.Err = err.Error()
	}
	write("cursor_encode", []encodeCase{encCase})

	type decodeCase struct {
		Scope   apiv2.CursorScope `json:"scope"`
		Cursor  string            `json:"cursor"`
		OK      bool              `json:"ok"`
		Problem *problemOut       `json:"problem,omitempty"`
		Pos     *position         `json:"position,omitempty"`
	}
	run := func(scope apiv2.CursorScope, cursor string) decodeCase {
		var p position
		prob := c.Decode(scope, cursor, &p)
		dc := decodeCase{Scope: scope, Cursor: cursor, OK: prob == nil, Problem: ofProblem(prob)}
		if prob == nil {
			dc.Pos = &p
		}
		return dc
	}
	tampered := cur
	if len(tampered) > 0 {
		b := []byte(tampered)
		// flip a byte inside the signature half, after the '.' separator.
		for i := len(b) - 1; i >= 0; i-- {
			if b[i] != '.' {
				if b[i] == 'A' {
					b[i] = 'B'
				} else {
					b[i] = 'A'
				}
				break
			}
		}
		tampered = string(b)
	}
	otherScope := scope
	otherScope.Sort = "-name"
	write("cursor_decode", []decodeCase{
		run(scope, cur),
		run(scope, tampered),
		run(scope, "not-a-cursor"),
		run(scope, "not-a-cursor.either"),
		run(otherScope, cur),
		run(scope, ""),
	})

	empty := apiv2.NewCursors(nil)
	_, err2 := empty.Encode(scope, pos)
	var p position
	decProb := empty.Decode(scope, cur, &p)
	write("cursor_no_secret", struct {
		EncodeErr *problemOut `json:"encode_err,omitempty"`
		DecodeErr *problemOut `json:"decode_err,omitempty"`
	}{ofProblem(err2.(*apiv2.Problem)), ofProblem(decProb)})
}

// --- wire.go: Instant, NullableInstant, Patch, ParseSort. All exported. ---

func genWire() {
	type instantCase struct {
		Input string `json:"input"`
		OK    bool   `json:"ok"`
		Out   string `json:"out,omitempty"`
		Err   string `json:"err,omitempty"`
	}
	var instants []instantCase
	for _, in := range []string{
		`"2024-01-02T03:04:05.123Z"`,
		`"2024-01-02T03:04:05.1234567Z"`,
		`"2024-01-02T03:04:05Z"`,
		`"0001-01-01T00:00:00Z"`,
		`"not-a-time"`,
		`123`,
		`null`,
	} {
		var i apiv2.Instant
		err := json.Unmarshal([]byte(in), &i)
		c := instantCase{Input: in, OK: err == nil}
		if err != nil {
			c.Err = err.Error()
		} else {
			b, merr := json.Marshal(i)
			if merr != nil {
				c.OK = false
				c.Err = merr.Error()
			} else {
				c.Out = string(b)
			}
		}
		instants = append(instants, c)
	}
	write("instant", instants)

	var nullables []instantCase
	for _, in := range []string{`null`, `"2024-01-02T03:04:05.123Z"`, `"0001-01-01T00:00:00Z"`} {
		var n apiv2.NullableInstant
		err := json.Unmarshal([]byte(in), &n)
		c := instantCase{Input: in, OK: err == nil}
		if err != nil {
			c.Err = err.Error()
		} else {
			b, _ := json.Marshal(n)
			c.Out = string(b)
		}
		nullables = append(nullables, c)
	}
	write("nullable_instant", nullables)

	type patchCase struct {
		Input   string `json:"input"`
		Present bool   `json:"present"`
		Null    bool   `json:"null"`
		Value   string `json:"value,omitempty"`
		IsZero  bool   `json:"is_zero"`
		Out     string `json:"out"`
	}
	var patches []patchCase
	type withPatch struct {
		Field apiv2.Patch[string] `json:"field,omitzero"`
	}
	for _, in := range []string{`{}`, `{"field":null}`, `{"field":"hi"}`} {
		var w withPatch
		_ = json.Unmarshal([]byte(in), &w)
		out, _ := json.Marshal(w)
		patches = append(patches, patchCase{Input: in, Present: w.Field.Present, Null: w.Field.Null, Value: w.Field.Value, IsZero: w.Field.IsZero(), Out: string(out)})
	}
	write("patch", patches)

	// The cases a Patch decoded through an intermediate generic value gets wrong.
	type patchSub struct {
		A int `json:"a"`
		B int `json:"b"`
	}
	type withPatches struct {
		Big  apiv2.Patch[int64]    `json:"big,omitzero"`
		Sub  apiv2.Patch[patchSub] `json:"sub,omitzero"`
		IDs  apiv2.Patch[[]int]    `json:"ids,omitzero"`
		Name apiv2.Patch[string]   `json:"name,omitzero"`
		Flag apiv2.Patch[bool]     `json:"flag,omitzero"`
	}
	type patchValueCase struct {
		Input string `json:"input"`
		OK    bool   `json:"ok"`
		Out   string `json:"out"`
		State string `json:"state"`
	}
	var patchValues []patchValueCase
	for _, in := range []string{
		`{}`, `{"big":9007199254740993}`, `{"big":-9223372036854775808}`, `{"big":null}`, `{"big":1.5}`, `{"big":"1"}`,
		`{"sub":{"a":1}}`, `{"sub":{"A":1,"B":2}}`, `{"SUB":{"a":1}}`, `{"sub":null}`, `{"sub":{}}`, `{"sub":[]}`, `{"sub":{"a":1},"sub":{"b":2}}`,
		`{"sub":{"a":1},"sub":null}`, `{"sub":null,"sub":{"a":1}}`, `{"ids":[1,2]}`, `{"ids":[]}`, `{"ids":null}`, `{"ids":[1,2],"ids":[null]}`, `{"ids":[null,2]}`,
		`{"ids":"x"}`, `{"name":"a","name":"b"}`, `{"name":1}`, `{"name":"a","name":null}`, `{"flag":true}`, `{"flag":0}`, `null`,
	} {
		var w withPatches
		err := json.Unmarshal([]byte(in), &w)
		out, _ := json.Marshal(w)
		state := fmt.Sprintf("%v %v|%v %v|%v %v %v|%v %v|%v %v", w.Big.Present, w.Big.Null, w.Sub.Present, w.Sub.Null, w.IDs.Present, w.IDs.Null, w.IDs.Value == nil, w.Name.Present, w.Name.Null, w.Flag.Present, w.Flag.Null)
		patchValues = append(patchValues, patchValueCase{Input: in, OK: err == nil, Out: string(out), State: state})
	}
	write("patch_values", patchValues)

	type sortCase struct {
		Raw     string            `json:"raw"`
		Allowed []string          `json:"allowed"`
		Fields  []apiv2.SortField `json:"fields,omitempty"`
		Problem *problemOut       `json:"problem,omitempty"`
	}
	var sorts []sortCase
	allowed := []string{"name", "added_at"}
	for _, raw := range []string{``, `name`, `-name`, `name,-added_at`, `unknown`, `name,name`, `-`} {
		fields, p := apiv2.ParseSort(raw, allowed)
		sorts = append(sorts, sortCase{Raw: raw, Allowed: allowed, Fields: fields, Problem: ofProblem(p)})
	}
	write("parse_sort", sorts)
}

// --- Huma validation error mapping, reached through the overlay export shims. ---

func genHumaMapping() {
	type codeCase struct {
		Msg  string `json:"msg"`
		Code string `json:"code"`
	}
	var codes []codeCase
	for _, m := range []string{
		`unknown query parameter`,
		`unexpected property`,
		`expected required property name to be present`,
		`required query parameter is missing`,
		`required header parameter is missing`,
		`request body is required`,
		`expected value to be one of "a", "b"`,
		`expected number > 5`,
		`expected number < 5`,
		`expected length >= 3`,
		`expected array length >= 1`,
		`expected string`,
		`expected integer`,
		`invalid something`,
		`something else entirely`,
	} {
		codes = append(codes, codeCase{m, apiv2.VectorValidationCode(m)})
	}
	write("validation_code", codes)

	type detailCase struct {
		Msg string `json:"msg"`
		Out string `json:"out"`
	}
	var details []detailCase
	for _, m := range []string{
		`expected string to be RFC 3986 uri: parse "ht tp": net/url: invalid control character in URL`,
		`Invalid mime type: got text/plain, expected image/png,image/jpeg`,
		`expected required property name to be present`,
	} {
		details = append(details, detailCase{m, apiv2.VectorValidationDetail(m)})
	}
	write("validation_detail", details)

	type locationCase struct {
		Location, Message string
		Out               string
	}
	var locs []locationCase
	for _, lm := range [][2]string{
		{"form", "expected string"},
		{"form.name", "expected string"},
		{"body", "expected required property name to be present"},
		{"query.sort", "expected value to be one of \"a\""},
		{"name", "cannot read multipart form: boom"},
		{"body.items[0].name", "expected string"},
	} {
		locs = append(locs, locationCase{lm[0], lm[1], apiv2.VectorValidationLocation(lm[0], lm[1])})
	}
	write("validation_location", locs)

	type statusTypeCase struct {
		Status int    `json:"status"`
		Msg    string `json:"msg"`
		ID     string `json:"id"`
	}
	var sts []statusTypeCase
	for _, st := range []struct {
		Status int
		Msg    string
	}{
		{400, ""}, {422, ""}, {406, ""}, {408, ""}, {413, ""}, {415, ""}, {405, ""}, {409, ""},
	} {
		sts = append(sts, statusTypeCase{st.Status, st.Msg, apiv2.VectorHumaStatusType(st.Status, st.Msg).ID})
	}
	write("huma_status_type", sts)

	type detailByTypeCase struct {
		TypeID    string `json:"type_id"`
		Msg       string `json:"msg"`
		BodyLimit int64  `json:"body_limit"`
		Out       string `json:"out"`
	}
	var dbt []detailByTypeCase
	byID := map[string]apiv2.ProblemType{}
	for _, t := range apiv2.Catalog() {
		byID[t.ID] = t
	}
	for _, c := range []struct {
		ID        string
		Msg       string
		BodyLimit int64
	}{
		{"validation_failed", "framework message", 1 << 20},
		{"malformed_request", "framework message", 1 << 20},
		{"not_acceptable", "framework message", 1 << 20},
		{"request_timeout", "framework message", 1 << 20},
		{"payload_too_large", "framework message", 4096},
		{"unsupported_media_type", "framework message", 1 << 20},
		{"internal_error", "framework message", 1 << 20},
		{"conflict", "some other message", 1 << 20},
		{"conflict", "", 1 << 20},
	} {
		dbt = append(dbt, detailByTypeCase{c.ID, c.Msg, c.BodyLimit, apiv2.VectorHumaDetail(byID[c.ID], c.Msg, c.BodyLimit)})
	}
	write("huma_detail", dbt)

	// Full fromHumaError integration, covering the branches in problem.go's adapter.
	type fromHumaCase struct {
		Name      string      `json:"name"`
		RequestID string      `json:"request_id"`
		Status    int         `json:"status"`
		Msg       string      `json:"msg"`
		BodyLimit int64       `json:"body_limit"`
		Problem   *problemOut `json:"problem"`
	}
	maxBytesMsg := new(httpMaxBytesError).Error()
	cases := []fromHumaCase{
		{
			Name: "form_size_exceeded", RequestID: "req1", Status: 422, BodyLimit: 1024,
		},
		{
			Name: "form_parse_failure", RequestID: "req2", Status: 422, BodyLimit: 1 << 20,
		},
		{
			Name: "body_parse_failure", RequestID: "req3", Status: 400, BodyLimit: 1 << 20,
		},
		{
			Name: "validation_failure", RequestID: "req4", Status: 422, BodyLimit: 1 << 20,
		},
		{
			Name: "app_error_detail", RequestID: "req5", Status: 422, BodyLimit: 1 << 20,
		},
		{
			Name: "not_acceptable", RequestID: "req6", Status: 406, BodyLimit: 1 << 20,
		},
	}
	errsFor := func(name string) []error {
		switch name {
		case "form_size_exceeded":
			return []error{&huma.ErrorDetail{Message: "cannot read multipart form: " + maxBytesMsg, Location: "body"}}
		case "form_parse_failure":
			return []error{&huma.ErrorDetail{Message: "cannot read multipart form: multipart: NextPart: EOF", Location: "body"}}
		case "body_parse_failure":
			return []error{&huma.ErrorDetail{Message: "unexpected EOF", Location: "body"}}
		case "validation_failure":
			return []error{
				&huma.ErrorDetail{Message: "expected required property name to be present", Location: "body"},
				&huma.ErrorDetail{Message: "expected value to be one of \"a\", \"b\"", Location: "body.kind"},
			}
		case "app_error_detail":
			return []error{fmt.Errorf("library not found")}
		default:
			return nil
		}
	}
	for i, c := range cases {
		errs := errsFor(c.Name)
		p := apiv2.VectorFromHumaError(c.RequestID, c.Status, c.Msg, errs, c.BodyLimit)
		cases[i].Problem = ofProblem(p)
	}
	write("from_huma_error", cases)
}

// httpMaxBytesError mirrors the text *http.MaxBytesError.Error() produces
// ("http: request body too large"), without importing net/http just for this.
type httpMaxBytesError struct{}

func (*httpMaxBytesError) Error() string { return "http: request body too large" }
