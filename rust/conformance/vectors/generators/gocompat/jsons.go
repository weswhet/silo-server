//go:build gocompat_vectors

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"
)

// Desc describes a value so the Rust test can rebuild it from the same input Go encoded.
type Desc struct {
	T    string     `json:"t"`
	Bool bool       `json:"b,omitempty"`
	Str  *S         `json:"s,omitempty"`
	Bits string     `json:"bits,omitempty"`
	Int  string     `json:"i,omitempty"`
	Arr  []Desc     `json:"a,omitempty"`
	Map  []DescPair `json:"m,omitempty"`
}

// DescPair is one map entry. Int keys carry their decimal text in K.
type DescPair struct {
	K S    `json:"k"`
	V Desc `json:"v"`
}

func strDesc(t, s string) Desc {
	v := S(s)
	return Desc{T: t, Str: &v}
}

// build turns a description into the Go value encoding/json sees.
func (d Desc) build() any {
	switch d.T {
	case "null":
		return nil
	case "bool":
		return d.Bool
	case "str":
		return string(*d.Str)
	case "f64":
		bits, _ := strconv.ParseUint(d.Bits, 16, 64)
		return math.Float64frombits(bits)
	case "f32":
		bits, _ := strconv.ParseUint(d.Bits, 16, 32)
		return math.Float32frombits(uint32(bits))
	case "int":
		n, _ := strconv.ParseInt(d.Int, 10, 64)
		return n
	case "uint":
		n, _ := strconv.ParseUint(d.Int, 10, 64)
		return n
	case "arr":
		out := make([]any, len(d.Arr))
		for i, e := range d.Arr {
			out[i] = e.build()
		}
		return out
	case "map":
		out := map[string]any{}
		for _, e := range d.Map {
			out[string(e.K)] = e.V.build()
		}
		return out
	case "imap":
		out := map[int64]any{}
		for _, e := range d.Map {
			n, _ := strconv.ParseInt(string(e.K), 10, 64)
			out[n] = e.V.build()
		}
		return out
	case "raw":
		return json.RawMessage(*d.Str)
	case "rawnil":
		return json.RawMessage(nil)
	case "num":
		return json.Number(*d.Str)
	case "bytes":
		b, _ := hex.DecodeString(string(*d.Str))
		return b
	case "bytesnil":
		return []byte(nil)
	}
	panic("unknown desc " + d.T)
}

type result struct {
	Ok  *S `json:"ok,omitempty"`
	Err *S `json:"err,omitempty"`
}

func newResult(b []byte, err error) result {
	if err != nil {
		e := S(err.Error())
		return result{Err: &e}
	}
	o := S(b)
	return result{Ok: &o}
}

type valueCase struct {
	In        Desc   `json:"in"`
	Marshal   result `json:"marshal"`
	NoHTML    result `json:"no_html"`
	Indent    result `json:"indent"`
	EncIndent result `json:"enc_indent"`
}

type floatJSONCase struct {
	Bits string `json:"bits"`
	Out  result `json:"out"`
}

type docCase struct {
	In        S      `json:"in"`
	Valid     bool   `json:"valid"`
	CheckErr  *S     `json:"check_err,omitempty"`
	Compact   result `json:"compact"`
	RawEscape result `json:"raw_escape"`
	Indent    result `json:"indent"`
	HTML      S      `json:"html"`
}

type jsonVector struct {
	Meta
	Values    []valueCase     `json:"values"`
	Float64   []floatJSONCase `json:"float64"`
	Float32   []floatJSONCase `json:"float32"`
	Strings   []valueCase     `json:"strings"`
	Numbers   []valueCase     `json:"numbers"`
	Documents []docCase       `json:"documents"`
	Structs   []structCase    `json:"structs"`
	// DeepDocuments has no input field: the test rebuilds it from the depth implied by Len.
	DeepDocuments []deepDocCase `json:"deep_documents"`
	Decode        []decodeCase  `json:"decode"`
}

type decodeOut struct {
	Raw  *S `json:"raw,omitempty"`
	Num  S  `json:"num"`
	Time S  `json:"time"`
}

type decodeCase struct {
	Doc S          `json:"doc"`
	Ok  *decodeOut `json:"ok,omitempty"`
}

// genDecode covers json.Unmarshal into the three types that keep literal text, with every key
// present so the mirror's other decoding differences stay out of it.
func genDecode() []decodeCase {
	var out []decodeCase
	raws := []string{"null", "1", `{ "a" : [ 1 ] }`, `"<x>"`, "[ ]", "true", "1.50"}
	nums := []string{"1", "-0", "1.50", "1e5", "1E+5", "0.1", "123456789012345678901234567890", `"1.5"`, `"abc"`, `""`, `"1"`, `"1"`, "null", "true", "[]", "{}"}
	times := []string{
		`"2024-02-29T12:30:45.12Z"`, `"2024-02-29T12:30:45+05:30"`, `"2024-02-29T12:30:45,5Z"`, `"2024-02-30T00:00:00Z"`, `"0001-01-01T00:00:00Z"`, `"2024-02-29T1:30:45Z"`,
		`"2024-02-29T12:30:45Z"`, `""`, `"x"`, "null", "1", "true", "[]", `"2024-02-29T12:30:45+24:00"`, `"2024-02-29"`,
	}
	add := func(raw, num, tm string) {
		doc := `{"raw":` + raw + `,"num":` + num + `,"time":` + tm + `}`
		c := decodeCase{Doc: S(doc)}
		var v struct {
			Raw  json.RawMessage `json:"raw"`
			Num  json.Number     `json:"num"`
			Time time.Time       `json:"time"`
		}
		if err := json.Unmarshal([]byte(doc), &v); err == nil {
			r := S(v.Raw)
			c.Ok = &decodeOut{Raw: &r, Num: S(v.Num), Time: S(v.Time.Format(time.RFC3339Nano))}
		}
		out = append(out, c)
	}
	for _, raw := range raws {
		add(raw, "1", `"2024-02-29T12:30:45Z"`)
	}
	for _, num := range nums {
		add("1", num, `"2024-02-29T12:30:45Z"`)
	}
	for _, tm := range times {
		add("1", "1", tm)
	}
	return out
}

type deepDocCase struct {
	Valid   bool   `json:"valid"`
	Compact result `json:"compact"`
	Len     int    `json:"len"`
}

func encodeValue(v any, html bool, prefix, indent string) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(html)
	enc.SetIndent(prefix, indent)
	err := enc.Encode(v)
	return b.Bytes(), err
}

func valueCaseFor(d Desc) valueCase {
	v := d.build()
	m, err := json.Marshal(v)
	c := valueCase{In: d, Marshal: newResult(m, err)}
	nh, err := encodeValue(v, false, "", "")
	c.NoHTML = newResult(nh, err)
	ind, err := json.MarshalIndent(v, ">", "  ")
	c.Indent = newResult(ind, err)
	ei, err := encodeValue(v, true, "", "\t")
	c.EncIndent = newResult(ei, err)
	return c
}

func randomDesc(r *rand.Rand, depth int) Desc {
	kinds := 12
	if depth <= 0 {
		kinds = 9
	}
	switch r.IntN(kinds) {
	case 0:
		return Desc{T: "null"}
	case 1:
		return Desc{T: "bool", Bool: r.IntN(2) == 0}
	case 2, 3:
		return strDesc("str", randomJSONString(r))
	case 4:
		return Desc{T: "f64", Bits: strconv.FormatUint(math.Float64bits(randomFloat(r)), 16)}
	case 5:
		return Desc{T: "f32", Bits: strconv.FormatUint(uint64(math.Float32bits(float32(randomFloat(r)))), 16)}
	case 6:
		return Desc{T: "int", Int: strconv.FormatInt(int64(r.Uint64())>>uint(r.IntN(64)), 10)}
	case 7:
		return Desc{T: "uint", Int: strconv.FormatUint(r.Uint64()>>uint(r.IntN(64)), 10)}
	case 8:
		switch r.IntN(4) {
		case 0:
			return strDesc("raw", rawDocs[r.IntN(len(rawDocs))])
		case 1:
			return strDesc("num", numberStrings[r.IntN(len(numberStrings))])
		case 2:
			return strDesc("bytes", hex.EncodeToString([]byte(randomBytes(r, 7))))
		}
		return Desc{T: []string{"rawnil", "bytesnil"}[r.IntN(2)]}
	case 9:
		d := Desc{T: "arr"}
		for range r.IntN(4) {
			d.Arr = append(d.Arr, randomDesc(r, depth-1))
		}
		return d
	case 10:
		d := Desc{T: "map"}
		seen := map[string]bool{}
		for range r.IntN(5) {
			k := randomJSONString(r)
			if !seen[k] {
				seen[k] = true
				d.Map = append(d.Map, DescPair{S(k), randomDesc(r, depth-1)})
			}
		}
		return d
	}
	d := Desc{T: "imap"}
	seen := map[int64]bool{}
	for range r.IntN(5) {
		k := int64(r.IntN(1000)) - 200
		if !seen[k] {
			seen[k] = true
			d.Map = append(d.Map, DescPair{S(strconv.FormatInt(k, 10)), randomDesc(r, depth-1)})
		}
	}
	return d
}

func randomJSONString(r *rand.Rand) string {
	switch r.IntN(6) {
	case 0:
		return randomAdversarial(r, 6)
	case 1:
		return randomBytes(r, 5)
	case 2:
		return invalidUTF8[r.IntN(len(invalidUTF8))]
	case 3:
		return mediaStrings[r.IntN(len(mediaStrings))]
	case 4:
		return "<a href=\"x&y\">" + string(adversarialRunes[r.IntN(len(adversarialRunes))]) + "</a>"
	}
	return string(rune('a'+r.IntN(26))) + strconv.Itoa(r.IntN(100))
}

var numberStrings = []string{
	"", "0", "-0", "1", "-1", "01", "1.0", "1.", ".5", "1e5", "1E5", "1e+5", "1e-5", "1e", "1e+", "-", "+1", "abc", "1 ", " 1", "0x10", "1.5e300", "123456789012345678901234567890", "NaN", "Infinity", "1_000", "٣", "1.2.3", "0e0", "0.0", "00", "-01", "1e5.5", "é",
}

var rawDocs = []string{
	"null", "true", "false", "0", "-0", "1.50", "1e5", `""`, `"a"`, `"<&>"`, `"\u003c"`, "{}", "[]", `{"a":1}`, `{ "a" : 1 , "b" : [ 1 , 2 ] }`, " [1, 2,\n3 ] ", `{"b":1,"a":2}`, `{"a":1,"a":2}`, `{"k<":"v>&"}`, "\"\u2028\"", "\"\u2029x\"", `"é"`, "\"\xff\"", `"\ud800"`,
	"", " ", "{", "}", "[", "]", `{"a"}`, `{"a":}`, `{"a":1,}`, "[1,]", "[,1]", "tru", "truex", "nul", "fals", "1.", ".5", "-", "+1", "01", "1e", "1e+", `"`, `"a`, "\"\n\"", `"\x"`, `"\u12"`, `"\u12g4"`, "\x00", "\xff", "é", "1 2", "{} {}", "'a'", `{a:1}`, `{1:1}`, "[1 2]", `{"a" 1}`, `{"a":1 "b":2}`, "nulll", "\t\r\n null \t\r\n",
	strings.Repeat("[", 100) + strings.Repeat("]", 100),
}

// deepDocs sit at the scanner's nesting limit. They only go through Valid and Compact, because
// indenting them would produce hundreds of megabytes.
var deepDocs = []string{strings.Repeat("[", 10001) + strings.Repeat("]", 10001), strings.Repeat("[", 10000) + strings.Repeat("]", 10000)}

func genJSON() jsonVector {
	r := newRand(6)
	v := jsonVector{Meta: newMeta()}
	for range 700 {
		v.Values = append(v.Values, valueCaseFor(randomDesc(r, 3)))
	}
	for _, d := range []Desc{
		{T: "null"}, {T: "arr"}, {T: "map"}, {T: "imap"}, {T: "rawnil"}, {T: "bytesnil"}, strDesc("bytes", ""),
		{T: "f64", Bits: strconv.FormatUint(math.Float64bits(math.NaN()), 16)}, {T: "f64", Bits: strconv.FormatUint(math.Float64bits(math.Inf(1)), 16)}, {T: "f64", Bits: strconv.FormatUint(math.Float64bits(math.Inf(-1)), 16)},
		{T: "f32", Bits: strconv.FormatUint(uint64(math.Float32bits(float32(math.Inf(1)))), 16)},
		{T: "imap", Map: []DescPair{{"10", Desc{T: "null"}}, {"9", Desc{T: "null"}}, {"-1", Desc{T: "null"}}, {"100", Desc{T: "null"}}}},
		{T: "map", Map: []DescPair{{"b", Desc{T: "null"}}, {"a", Desc{T: "null"}}, {"B", Desc{T: "null"}}, {"é", Desc{T: "null"}}, {"z", Desc{T: "null"}}, {"", Desc{T: "null"}}, {"<", Desc{T: "null"}}, {"\xff", Desc{T: "null"}}, {"\ufffd", Desc{T: "null"}}}},
	} {
		v.Values = append(v.Values, valueCaseFor(d))
	}
	add64 := func(f float64) {
		b, err := json.Marshal(f)
		v.Float64 = append(v.Float64, floatJSONCase{strconv.FormatUint(math.Float64bits(f), 16), newResult(b, err)})
	}
	add32 := func(f float32) {
		b, err := json.Marshal(f)
		v.Float32 = append(v.Float32, floatJSONCase{strconv.FormatUint(uint64(math.Float32bits(f)), 16), newResult(b, err)})
	}
	for _, f := range interestingFloats {
		add64(f)
		add32(float32(f))
	}
	for e := -30; e <= 30; e++ {
		add64(math.Pow(10, float64(e)))
		add64(math.Nextafter(math.Pow(10, float64(e)), 0))
		add64(math.Nextafter(math.Pow(10, float64(e)), math.Inf(1)))
		add32(float32(math.Pow(10, float64(e))))
		add32(math.Nextafter32(float32(math.Pow(10, float64(e))), 0))
		add32(math.Nextafter32(float32(math.Pow(10, float64(e))), float32(math.Inf(1))))
	}
	for range 5000 {
		add64(randomFloat(r))
	}
	for range 1500 {
		add64(tieFloat64(r))
		add32(tieFloat32(r))
	}
	for range 2500 {
		add32(float32(randomFloat(r)))
		add32(math.Float32frombits(r.Uint32()))
	}
	strInputs := []string{"", "<", ">", "&", "<&>", "\u2028", "\u2029", "\u2027", "\u202a", "\"", "\\", "/", "\x7f", "\ufffd", "\xef\xbf\xbd", "\xe2\x80", "\xe2\x80\xa8\xff"}
	for b := 0; b < 256; b++ {
		strInputs = append(strInputs, string([]byte{byte(b)}), "a"+string([]byte{byte(b)})+"b")
	}
	for _, c := range adversarialRunes {
		strInputs = append(strInputs, string(c))
	}
	strInputs = append(strInputs, invalidUTF8...)
	strInputs = append(strInputs, mediaStrings...)
	for range 300 {
		strInputs = append(strInputs, randomJSONString(r), randomBytes(r, 8))
	}
	for _, s := range strInputs {
		v.Strings = append(v.Strings, valueCaseFor(strDesc("str", s)))
	}
	for _, s := range numberStrings {
		v.Numbers = append(v.Numbers, valueCaseFor(strDesc("num", s)))
	}
	docs := append([]string{}, rawDocs...)
	for range 900 {
		base := rawDocs[r.IntN(len(rawDocs))]
		docs = append(docs, mutate(r, base), mutate(r, `{"a": [1, 2.5e3, "x<y", null, true], "b": {"c": "é\n", "d": -0.1}}`))
	}
	for _, s := range docs {
		c := docCase{In: S(s), Valid: json.Valid([]byte(s))}
		var parsed json.RawMessage
		if err := json.Unmarshal([]byte(s), &parsed); err != nil {
			e := S(err.Error())
			c.CheckErr = &e
		}
		var compact bytes.Buffer
		err := json.Compact(&compact, []byte(s))
		c.Compact = newResult(compact.Bytes(), err)
		raw, err := json.Marshal(json.RawMessage(s))
		c.RawEscape = newResult(raw, err)
		var ind bytes.Buffer
		err = json.Indent(&ind, []byte(s), "p", "  ")
		c.Indent = newResult(ind.Bytes(), err)
		var html bytes.Buffer
		json.HTMLEscape(&html, []byte(s))
		c.HTML = S(html.String())
		v.Documents = append(v.Documents, c)
	}
	for _, s := range deepDocs {
		var compact bytes.Buffer
		err := json.Compact(&compact, []byte(s))
		v.DeepDocuments = append(v.DeepDocuments, deepDocCase{json.Valid([]byte(s)), newResult(compact.Bytes(), err), len(s)})
	}
	v.Structs = genStructs()
	v.Decode = genDecode()
	return v
}

// Inner, Embedded, and All mirror structs in the crate's vector test, one for one.
type Inner struct {
	X int    `json:"x"`
	Y string `json:"y,omitempty"`
}

type Embedded struct {
	EA string `json:"ea"`
	EB int    `json:"eb,omitempty"`
}

type All struct {
	Embedded
	Str        string            `json:"str"`
	StrOE      string            `json:"str_oe,omitempty"`
	B          bool              `json:"b"`
	BOE        bool              `json:"b_oe,omitempty"`
	I          int               `json:"i"`
	IOE        int               `json:"i_oe,omitempty"`
	U64        uint64            `json:"u64"`
	F64        float64           `json:"f64"`
	F64OE      float64           `json:"f64_oe,omitempty"`
	F32        float32           `json:"f32"`
	Ptr        *string           `json:"ptr"`
	PtrOE      *string           `json:"ptr_oe,omitempty"`
	PtrInt     *int              `json:"ptr_int,omitempty"`
	Slice      []int             `json:"slice"`
	SliceOE    []string          `json:"slice_oe,omitempty"`
	Map        map[string]int    `json:"map"`
	MapOE      map[string]string `json:"map_oe,omitempty"`
	IntMap     map[int]string    `json:"int_map"`
	Bytes      []byte            `json:"bytes"`
	Raw        json.RawMessage   `json:"raw"`
	RawOE      json.RawMessage   `json:"raw_oe,omitempty"`
	Num        json.Number       `json:"num"`
	Time       time.Time         `json:"time"`
	TimeOE     time.Time         `json:"time_oe,omitempty"`
	TimeOZ     time.Time         `json:"time_oz,omitzero"`
	TimePtr    *time.Time        `json:"time_ptr,omitempty"`
	Dur        time.Duration     `json:"dur"`
	DurOE      time.Duration     `json:"dur_oe,omitempty"`
	Inner      Inner             `json:"inner"`
	InnerOE    Inner             `json:"inner_oe,omitempty"`
	InnerPtr   *Inner            `json:"inner_ptr,omitempty"`
	InnerOZ    Inner             `json:"inner_oz,omitzero"`
	Any        any               `json:"any"`
	Arr        [3]int            `json:"arr"`
	ByteArr    [2]byte           `json:"byte_arr"`
	Skipped    string            `json:"-"`
	Dash       string            `json:"-,"`
	HTML       string            `json:"<&>"`
	Inners     []Inner           `json:"inners"`
	MapOfInner map[string]*Inner `json:"map_of_inner"`
}

type structCase struct {
	Name string `json:"name"`
	Out  result `json:"out"`
}

func genStructs() []structCase {
	str := func(s string) *string { return &s }
	num := func(n int) *int { return &n }
	t := time.Date(2024, 2, 29, 12, 30, 45, 120000000, time.UTC)
	tz := t.In(time.FixedZone("", 19800))
	populated := All{
		Embedded: Embedded{EA: "ea<>", EB: 7}, Str: "s&", StrOE: "x", B: true, BOE: true, I: -5, IOE: 5, U64: math.MaxUint64, F64: 7200, F64OE: 120.5, F32: 3.14,
		Ptr: str("p"), PtrOE: str(""), PtrInt: num(0), Slice: []int{1, 2}, SliceOE: []string{""}, Map: map[string]int{"z": 1, "a": 2, "é": 3, "<": 4},
		MapOE: map[string]string{"k": "v"}, IntMap: map[int]string{10: "ten", 9: "nine", -1: "neg"}, Bytes: []byte("hello\xff"), Raw: json.RawMessage(`{ "b" : "<x>", "a" : [ 1 ] }`), RawOE: json.RawMessage(`1`),
		Num: "1.50", Time: t, TimeOE: tz, TimeOZ: t, TimePtr: &t, Dur: 1500 * time.Millisecond, DurOE: time.Second, Inner: Inner{1, "y"}, InnerOE: Inner{2, ""}, InnerPtr: &Inner{}, InnerOZ: Inner{3, ""},
		Any: map[string]any{"b": 1.0, "a": []any{"x", nil}}, Arr: [3]int{1, 2, 3}, ByteArr: [2]byte{1, 2}, Skipped: "no", Dash: "dash", HTML: "html", Inners: []Inner{{}, {1, "a"}},
		MapOfInner: map[string]*Inner{"n": nil, "m": {X: 1}},
	}
	zero := func(a All) All { return a }
	return []structCase{
		structResult("zero", zero(All{})),
		structResult("populated", populated),
		structResult("empty_containers", All{Slice: []int{}, SliceOE: []string{}, Map: map[string]int{}, MapOE: map[string]string{}, IntMap: map[int]string{}, Bytes: []byte{}, Raw: json.RawMessage(`[]`), RawOE: json.RawMessage{}, Inners: []Inner{}, MapOfInner: map[string]*Inner{}, Any: []any{}}),
		structResult("negative_zero", All{F64: math.Copysign(0, -1), F64OE: math.Copysign(0, -1), F32: float32(math.Copysign(0, -1))}),
		structResult("nan", All{F64: math.NaN()}),
		structResult("bad_raw", All{Raw: json.RawMessage(`{`)}),
		structResult("empty_raw", All{Raw: json.RawMessage{}}),
		structResult("bad_number", All{Num: "abc"}),
		structResult("bad_time", All{Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)}),
		structResult("zero_time_with_offset", All{TimeOZ: time.Time{}.In(time.FixedZone("", 3600)), TimeOE: time.Time{}.In(time.FixedZone("", 3600))}),
	}
}

func structResult(name string, v All) structCase {
	b, err := json.Marshal(v)
	return structCase{name, newResult(b, err)}
}
