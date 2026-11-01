//go:build gocompat_vectors

package main

import (
	"encoding/json"
	"math/rand/v2"
	"sort"
	"strings"
)

// Inner and Sink mirror the Rust structs the json_decode.json vector is tested against
// (crates/silo-gocompat/tests/vectors.rs). Keep the two in sync field for field.
type SinkInner struct {
	X int32  `json:"x"`
	Y string `json:"y"`
}

type Sink struct {
	Str string           `json:"str"`
	B   bool             `json:"b"`
	I8  int8             `json:"i8"`
	I16 int16            `json:"i16"`
	I32 int32            `json:"i32"`
	I64 int64            `json:"i64"`
	U8  uint8            `json:"u8"`
	U16 uint16           `json:"u16"`
	U32 uint32           `json:"u32"`
	U64 uint64           `json:"u64"`
	F32 float32          `json:"f32"`
	F64 float64          `json:"f64"`
	In  SinkInner        `json:"in"`
	Arr []int32          `json:"arr"`
	M   map[string]int32 `json:"m"`
	IM  map[int]string   `json:"im"`
	Ptr *int32           `json:"ptr"`
	Raw json.RawMessage  `json:"raw"`
	Num json.Number      `json:"num"`
}

// sinkObserved is what the generator and the Rust test both build from a decoded Sink, so the
// two sides compare one plain JSON shape instead of Sink's own (Go-specific) encoding.
type sinkObserved struct {
	Str string  `json:"str"`
	B   bool    `json:"b"`
	I8  int8    `json:"i8"`
	I16 int16   `json:"i16"`
	I32 int32   `json:"i32"`
	I64 int64   `json:"i64"`
	U8  uint8   `json:"u8"`
	U16 uint16  `json:"u16"`
	U32 uint32  `json:"u32"`
	U64 uint64  `json:"u64"`
	F32 float64 `json:"f32"` // widened so ±0 and precision compare the same way as Rust's f32-as-f64 dump
	F64 float64 `json:"f64"`
	InX int32   `json:"in_x"`
	InY string  `json:"in_y"`
	Arr []int32 `json:"arr"`
	M   []kv    `json:"m"`
	IM  []kv    `json:"im"`
	Ptr *int32  `json:"ptr"`
	Raw *string `json:"raw"`
	Num string  `json:"num"`
}

type kv struct {
	K string `json:"k"`
	V string `json:"v"`
}

func observe(s *Sink) sinkObserved {
	o := sinkObserved{
		Str: s.Str, B: s.B, I8: s.I8, I16: s.I16, I32: s.I32, I64: s.I64,
		U8: s.U8, U16: s.U16, U32: s.U32, U64: s.U64,
		F32: float64(s.F32), F64: s.F64,
		InX: s.In.X, InY: s.In.Y,
		Arr: s.Arr, Ptr: s.Ptr, Num: string(s.Num),
	}
	if s.Raw != nil {
		r := string(s.Raw)
		o.Raw = &r
	}
	mkeys := make([]string, 0, len(s.M))
	for k := range s.M {
		mkeys = append(mkeys, k)
	}
	sort.Strings(mkeys)
	for _, k := range mkeys {
		o.M = append(o.M, kv{k, formatInt32(s.M[k])})
	}
	ikeys := make([]int, 0, len(s.IM))
	for k := range s.IM {
		ikeys = append(ikeys, k)
	}
	sort.Ints(ikeys)
	for _, k := range ikeys {
		o.IM = append(o.IM, kv{formatInt(k), s.IM[k]})
	}
	return o
}

func formatInt32(n int32) string { return formatInt(int(n)) }
func formatInt(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

type decodeSinkCase struct {
	Doc      S             `json:"doc"`
	Disallow bool          `json:"disallow,omitempty"`
	Ok       *sinkObserved `json:"ok,omitempty"`
	Err      *S            `json:"err,omitempty"`
}

func sinkResult(doc string, disallow bool) decodeSinkCase {
	c := decodeSinkCase{Doc: S(doc), Disallow: disallow}
	var s Sink
	dec := json.NewDecoder(strings.NewReader(doc))
	if disallow {
		dec.DisallowUnknownFields()
	}
	err := dec.Decode(&s)
	if err != nil {
		e := S(err.Error())
		c.Err = &e
		return c
	}
	ob := observe(&s)
	c.Ok = &ob
	return c
}

type jsonDecodeVector struct {
	Meta
	Fold          []decodeSinkCase `json:"fold"`
	Duplicate     []decodeSinkCase `json:"duplicate"`
	Null          []decodeSinkCase `json:"null_noop"`
	UnknownFields []decodeSinkCase `json:"unknown_fields"`
	TypeErrors    []decodeSinkCase `json:"type_errors"`
	UTF8          []decodeSinkCase `json:"utf8"`
}

func genJSONDecode() jsonDecodeVector {
	r := newRand(9)
	v := jsonDecodeVector{Meta: newMeta()}
	populateFold(&v, r)
	populateDuplicate(&v, r)
	populateNull(&v, r)
	populateUnknownFields(&v, r)
	populateTypeErrors(&v, r)
	populateUTF8(&v, r)
	return v
}

// --- case folding: exact-match preference, fold-only matches, and ambiguous folds. ---

func populateFold(v *jsonDecodeVector, r *rand.Rand) {
	fields := []string{"str", "b", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64", "in", "arr", "m", "im", "ptr", "raw", "num"}
	caseVariants := func(s string) []string {
		return []string{s, strings.ToUpper(s), strings.ToTitle(s[:1]) + s[1:]}
	}
	valueFor := func(field string) string {
		switch field {
		case "str":
			return `"x"`
		case "b":
			return "true"
		case "in":
			return `{"x":1,"y":"z"}`
		case "arr":
			return "[1,2,3]"
		case "m":
			return `{"a":1}`
		case "im":
			return `{"1":"a"}`
		case "ptr":
			return "5"
		case "raw":
			return `{"a":1}`
		case "num":
			return "5"
		default:
			return "1"
		}
	}
	for _, f := range fields {
		for _, variant := range caseVariants(f) {
			doc := `{"` + variant + `":` + valueFor(f) + `}`
			v.Fold = append(v.Fold, sinkResult(doc, false))
		}
		// Exact lowercase plus an uppercase variant together: exact must win.
		doc := `{"` + strings.ToUpper(f) + `":` + valueFor(f) + `,"` + f + `":` + valueFor(f) + `}`
		v.Fold = append(v.Fold, sinkResult(doc, false))
		doc2 := `{"` + f + `":` + valueFor(f) + `,"` + strings.ToUpper(f) + `":` + valueFor(f) + `}`
		v.Fold = append(v.Fold, sinkResult(doc2, false))
	}
	// Sink's field names are distinct under folding; ambiguous folds are in the adversarial vector.
	for range 230 {
		f := fields[r.IntN(len(fields))]
		variant := caseVariants(f)[r.IntN(3)]
		doc := `{"` + variant + `":` + valueFor(f) + `,"extra` + variant + `":1}`
		v.Fold = append(v.Fold, sinkResult(doc, false))
	}
}

// --- duplicate keys: null no-op, object merge, scalar/array/map replace, chains. ---

func populateDuplicate(v *jsonDecodeVector, r *rand.Rand) {
	docs := []string{
		`{"i32": 1, "i32": 2}`,
		`{"i32": 1, "i32": 2, "i32": 3}`,
		`{"in": {"x": 1}, "in": {"y": "z"}}`,
		`{"in": {"x": 1, "y": "a"}, "in": {"x": 2}}`,
		`{"in": null, "in": {"x": 1}}`,
		`{"in": {"x": 1}, "in": null}`,
		`{"in": {"x": 1}, "in": null, "in": {"y": "q"}}`,
		`{"str": null, "str": "z"}`,
		`{"str": "z", "str": null}`,
		`{"arr": [1,2], "arr": [3]}`,
		`{"arr": [1,2], "arr": null}`,
		`{"arr": null, "arr": [9]}`,
		`{"m": {"a":1}, "m": {"b":2}}`,
		`{"m": {"a":1,"b":2}, "m": {"a":3}}`,
		`{"m": {"a":1}, "m": null}`,
		`{"m": null, "m": {"a":1}}`,
		`{"im": {"1":"a"}, "im": {"2":"b"}}`,
		`{"ptr": 1, "ptr": null}`,
		`{"ptr": null, "ptr": 1}`,
		`{"raw": {"a":1}, "raw": {"b":2}}`,
		`{"raw": {"a":1}, "raw": null}`,
		`{"num": 1, "num": 2}`,
		`{"in": {"x": 1}, "in": {"x": "bad"}}`,
		`{"b": true, "b": false}`,
		`{"u8": 1, "u8": 2, "u8": 3, "u8": 4}`,
	}
	for _, d := range docs {
		v.Duplicate = append(v.Duplicate, sinkResult(d, false))
	}
	keys := []string{"i32", "in", "str", "arr", "m", "im", "ptr", "raw", "num", "b"}
	vals := map[string][]string{
		"i32": {"1", "2", "null", `"x"`},
		"in":  {"{}", `{"x":1}`, `{"y":"a"}`, "null", `{"x":1,"y":"b"}`},
		"str": {`"a"`, `"b"`, "null", "1"},
		"arr": {"[1]", "[2,3]", "null", "[]"},
		"m":   {`{"a":1}`, `{"b":2}`, "null", "{}"},
		"im":  {`{"1":"a"}`, `{"2":"b"}`, "null"},
		"ptr": {"1", "null", "2"},
		"raw": {`{"a":1}`, `[1]`, "null", "5"},
		"num": {"1", "2.5", "null"},
		"b":   {"true", "false", "null"},
	}
	for range 210 {
		k := keys[r.IntN(len(keys))]
		n := 2 + r.IntN(3)
		var parts []string
		for range n {
			parts = append(parts, `"`+k+`":`+vals[k][r.IntN(len(vals[k]))])
		}
		doc := "{" + strings.Join(parts, ",") + "}"
		v.Duplicate = append(v.Duplicate, sinkResult(doc, false))
	}
}

// --- null into a non-pointer field: every scalar and container shape, fresh (no prior value). ---

func populateNull(v *jsonDecodeVector, r *rand.Rand) {
	fields := []string{"str", "b", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64", "in", "arr", "m", "im", "raw", "num"}
	for _, f := range fields {
		v.Null = append(v.Null, sinkResult(`{"`+f+`": null}`, false))
		v.Null = append(v.Null, sinkResult(`{"`+f+`": null, "str": "after"}`, false))
	}
	v.Null = append(v.Null, sinkResult(`{"ptr": null}`, false))
	v.Null = append(v.Null, sinkResult("null", false))
	v.Null = append(v.Null, sinkResult("{}", false))
	for range 260 {
		var parts []string
		for range 1 + r.IntN(len(fields)) {
			f := fields[r.IntN(len(fields))]
			if r.IntN(2) == 0 {
				parts = append(parts, `"`+f+`":null`)
			} else {
				parts = append(parts, `"`+f+`":`+map[string]string{
					"str": `"x"`, "b": "true", "in": `{"x":1}`, "arr": "[1]", "m": `{"a":1}`,
					"im": `{"1":"a"}`, "raw": "1", "num": "1",
				}[f])
				if parts[len(parts)-1] == `"`+f+`":` {
					parts[len(parts)-1] = `"` + f + `":1`
				}
			}
		}
		v.Null = append(v.Null, sinkResult("{"+strings.Join(parts, ",")+"}", false))
	}
}

// --- unknown fields: ignored by default, rejected under DisallowUnknownFields. ---

func populateUnknownFields(v *jsonDecodeVector, r *rand.Rand) {
	names := []string{"zzz", "extra", "unknown_thing", "Strr", "INN", "123", "", "a_b_c", "日本語", "ptrx"}
	for _, n := range names {
		doc := `{"str":"a","` + n + `":1,"i32":2}`
		v.UnknownFields = append(v.UnknownFields, sinkResult(doc, false))
		v.UnknownFields = append(v.UnknownFields, sinkResult(doc, true))
	}
	shapes := []string{"1", `"x"`, "true", "null", "[1,2]", `{"nested":1}`}
	for range 200 {
		n := names[r.IntN(len(names))] + formatInt(r.IntN(1000))
		shape := shapes[r.IntN(len(shapes))]
		doc := `{"` + n + `":` + shape + `,"i32":1}`
		v.UnknownFields = append(v.UnknownFields, sinkResult(doc, r.IntN(2) == 0))
	}
}

// --- type-mismatch error text, across every scalar kind and a nested field path. ---

func populateTypeErrors(v *jsonDecodeVector, r *rand.Rand) {
	scalarFields := []string{"str", "b", "i8", "i16", "i32", "i64", "u8", "u16", "u32", "u64", "f32", "f64"}
	shapes := map[string]string{
		"bool": "true", "number": "1", "string": `"x"`, "array": "[1]", "object": "{}",
	}
	shapeNames := []string{"bool", "number", "string", "array", "object"}
	for _, f := range scalarFields {
		for _, shapeName := range shapeNames {
			shape := shapes[shapeName]
			if (shapeName == "number" && (f == "i8" || f == "i16" || f == "i32" || f == "i64" || f == "u8" || f == "u16" || f == "u32" || f == "u64" || f == "f32" || f == "f64")) ||
				(shapeName == "string" && f == "str") ||
				(shapeName == "bool" && f == "b") {
				continue
			}
			v.TypeErrors = append(v.TypeErrors, sinkResult(`{"`+f+`":`+shape+`}`, false))
		}
	}
	// Numeric grammar/range failures.
	numericLiterals := []string{
		"1.5", "1e2", "-1", "256", "-129", "128", "65536", "32768", "-32769", "2147483648",
		"-2147483649", "4294967296", "18446744073709551616", "99999999999999999999", "1e400",
		"-1e400", "1e40", "-1e40", "0", "-0", "255", "127", "-128", "65535", "32767", "-32768",
	}
	for _, f := range scalarFields {
		if f == "str" || f == "b" {
			continue
		}
		for _, lit := range numericLiterals {
			v.TypeErrors = append(v.TypeErrors, sinkResult(`{"`+f+`":`+lit+`}`, false))
		}
	}
	// Nested field path.
	for _, shapeName := range shapeNames {
		shape := shapes[shapeName]
		if shapeName == "object" {
			continue
		}
		v.TypeErrors = append(v.TypeErrors, sinkResult(`{"in":{"x":`+shape+`}}`, false))
		v.TypeErrors = append(v.TypeErrors, sinkResult(`{"in":`+shape+`}`, false))
	}
	v.TypeErrors = append(v.TypeErrors, sinkResult(`{"arr":[1,true,3]}`, false))
	v.TypeErrors = append(v.TypeErrors, sinkResult(`{"arr":[1,"x",3]}`, false))
	v.TypeErrors = append(v.TypeErrors, sinkResult(`{"arr":"x"}`, false))
	v.TypeErrors = append(v.TypeErrors, sinkResult(`{"m":"x"}`, false))
	v.TypeErrors = append(v.TypeErrors, sinkResult(`{"m":{"a":true}}`, false))
	v.TypeErrors = append(v.TypeErrors, sinkResult(`"hello"`, false))
	v.TypeErrors = append(v.TypeErrors, sinkResult("5", false))
	v.TypeErrors = append(v.TypeErrors, sinkResult("[1,2]", false))
	v.TypeErrors = append(v.TypeErrors, sinkResult("true", false))
	for range 30 {
		f := scalarFields[r.IntN(len(scalarFields))]
		lit := numericLiterals[r.IntN(len(numericLiterals))]
		v.TypeErrors = append(v.TypeErrors, sinkResult(`{"in":{"x":1},"`+f+`":`+lit+`}`, false))
	}
}

// --- invalid UTF-8 and lone surrogates inside string literals. ---

func populateUTF8(v *jsonDecodeVector, r *rand.Rand) {
	badBytesStrings := []string{
		"a\xffb", "\xff", "\xfe", "\x80", "\xc0\x80", "\xc2", "\xe0\x80\x80", "\xe2\x82",
		"\xed\xa0\x80", "\xed\xbf\xbf", "\xf0\x80\x80\x80", "\xf0\x9f", "\xf4\x90\x80\x80",
		"ok\xffmore\xfeend", "\xff\xff\xff",
	}
	for _, s := range badBytesStrings {
		doc := []byte(`{"str":"` + s + `"}`)
		v.UTF8 = append(v.UTF8, sinkResult(string(doc), false))
	}
	surrogateEscapes := []string{
		`\ud800`, `\udc00`, `𐀀`, `􏿿`, `\ud800\ud800`, `\udc00\ud800`,
		`\ud800x`, `\ud800A`, `😀`, `\udead`,
	}
	for _, esc := range surrogateEscapes {
		doc := `{"str":"a` + esc + `b"}`
		v.UTF8 = append(v.UTF8, sinkResult(doc, false))
	}
	for range 180 {
		var b strings.Builder
		b.WriteString(`{"str":"`)
		for range 1 + r.IntN(4) {
			switch r.IntN(3) {
			case 0:
				b.WriteString(badBytesStrings[r.IntN(len(badBytesStrings))])
			case 1:
				b.WriteString(surrogateEscapes[r.IntN(len(surrogateEscapes))])
			default:
				b.WriteString("ok")
			}
		}
		b.WriteString(`"}`)
		v.UTF8 = append(v.UTF8, sinkResult(b.String(), false))
	}
}
