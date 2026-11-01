//go:build gocompat_vectors

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
)

// These types mirror the ones in crates/silo-gocompat/tests/vectors.rs (mod decode_adversarial).
// Both sides compare json.Marshal's text, so nil and empty stay distinct.
type AdvSub struct {
	A int32 `json:"a"`
	B int32 `json:"b"`
}

type AdvInner struct {
	X  int32             `json:"x"`
	Y  string            `json:"y"`
	MS map[string]AdvSub `json:"ms"`
}

type Adv struct {
	N     int32            `json:"n"`
	S     string           `json:"s"`
	Nums  []int32          `json:"nums"`
	Ptr   *int32           `json:"ptr"`
	PP    *AdvSub          `json:"pp"`
	Inner AdvInner         `json:"inner"`
	List  []AdvSub         `json:"list"`
	T     time.Time        `json:"t"`
	TP    *time.Time       `json:"tp"`
	Raw   json.RawMessage  `json:"raw"`
	JN    json.Number      `json:"jn"`
	Any   any              `json:"any"`
	Arr   [2]int32         `json:"arr"`
	Bin   []byte           `json:"bin"`
	F32   float32          `json:"f32"`
	IM    map[int32]string `json:"im"`
	UM    map[uint8]string `json:"um"`
	Nest  [][]int32        `json:"nest"`
}

type AdvFold struct {
	Foo string `json:"foo"`
	FOO string `json:"FOO"`
	Bar string `json:"BAR"`
	BAR string `json:"bar"`
}

type advCase struct {
	Doc      S      `json:"doc"`
	Disallow bool   `json:"disallow,omitempty"`
	Ok       *S     `json:"ok,omitempty"`
	RawHex   string `json:"raw_hex,omitempty"`
	Err      *S     `json:"err,omitempty"`
}

func advOutcome(c *advCase, v any, raw json.RawMessage, err error) {
	if err != nil {
		e := S(err.Error())
		c.Err = &e
		return
	}
	b, merr := json.Marshal(v)
	if merr != nil {
		panic(merr)
	}
	ok := S(b)
	c.Ok = &ok
	c.RawHex = hex.EncodeToString(raw)
}

func advDecode(doc string, disallow bool) advCase {
	c := advCase{Doc: S(doc), Disallow: disallow}
	var v Adv
	dec := json.NewDecoder(strings.NewReader(doc))
	if disallow {
		dec.DisallowUnknownFields()
	}
	err := dec.Decode(&v)
	advOutcome(&c, &v, v.Raw, err)
	return c
}

func advUnmarshal(doc string) advCase {
	c := advCase{Doc: S(doc)}
	var v Adv
	err := json.Unmarshal([]byte(doc), &v)
	advOutcome(&c, &v, v.Raw, err)
	return c
}

func advFold(doc string, disallow bool) advCase {
	c := advCase{Doc: S(doc), Disallow: disallow}
	var v AdvFold
	dec := json.NewDecoder(strings.NewReader(doc))
	if disallow {
		dec.DisallowUnknownFields()
	}
	err := dec.Decode(&v)
	advOutcome(&c, &v, nil, err)
	return c
}

type streamStep struct {
	Ok       *S     `json:"ok,omitempty"`
	Err      *S     `json:"err,omitempty"`
	EOF      string `json:"eof,omitempty"`
	Buffered S      `json:"buffered"`
	Offset   int64  `json:"offset"`
	More     bool   `json:"more"`
}

type streamCase struct {
	Doc   S            `json:"doc"`
	Steps []streamStep `json:"steps"`
}

func advStream(doc string) streamCase {
	c := streamCase{Doc: S(doc)}
	dec := json.NewDecoder(strings.NewReader(doc))
	for range 5 {
		var v Adv
		err := dec.Decode(&v)
		var st streamStep
		if err != nil {
			e := S(err.Error())
			st.Err = &e
			if errors.Is(err, io.EOF) {
				st.EOF = "eof"
			} else if errors.Is(err, io.ErrUnexpectedEOF) {
				st.EOF = "unexpected"
			}
		} else {
			b, _ := json.Marshal(&v)
			ok := S(b)
			st.Ok = &ok
		}
		rest, _ := io.ReadAll(dec.Buffered())
		st.Buffered = S(rest)
		st.Offset = dec.InputOffset()
		c.Steps = append(c.Steps, st)
		if err != nil && st.EOF != "" {
			break
		}
	}
	return c
}

type AdvRec struct {
	N *AdvRec `json:"n"`
}

type AdvRawHolder struct {
	Raw json.RawMessage `json:"raw"`
}

type AdvKeep struct {
	Keep int32 `json:"keep"`
}

type depthCase struct {
	Shape string `json:"shape"`
	Depth int    `json:"depth"`
	Ok    bool   `json:"ok"`
	Err   *S     `json:"err,omitempty"`
}

// depthDoc is rebuilt by the Rust test from the shape and depth, to keep the vector small.
func depthDoc(shape string, depth int) string {
	switch shape {
	case "any_array", "unknown_array":
		d := strings.Repeat("[", depth) + strings.Repeat("]", depth)
		if shape == "unknown_array" {
			return `{"zzz":` + d[1:len(d)-1] + `}`
		}
		return d
	case "any_object":
		return strings.Repeat(`{"n":`, depth-1) + "{}" + strings.Repeat("}", depth-1)
	case "rec":
		return strings.Repeat(`{"n":`, depth-1) + "{}" + strings.Repeat("}", depth-1)
	case "raw":
		return `{"raw":` + strings.Repeat("[", depth-1) + strings.Repeat("]", depth-1) + `}`
	}
	panic(shape)
}

func advDepth(shape string, depth int) depthCase {
	doc := depthDoc(shape, depth)
	var err error
	switch shape {
	case "any_array", "any_object":
		var v any
		err = json.NewDecoder(strings.NewReader(doc)).Decode(&v)
	case "unknown_array":
		var v AdvKeep
		err = json.NewDecoder(strings.NewReader(doc)).Decode(&v)
	case "rec":
		var v AdvRec
		err = json.NewDecoder(strings.NewReader(doc)).Decode(&v)
	case "raw":
		var v AdvRawHolder
		err = json.NewDecoder(strings.NewReader(doc)).Decode(&v)
	}
	c := depthCase{Shape: shape, Depth: depth, Ok: err == nil}
	if err != nil {
		e := S(err.Error())
		c.Err = &e
	}
	return c
}

type jsonDecodeAdversarialVector struct {
	Meta
	Decode    []advCase    `json:"decode"`
	Unmarshal []advCase    `json:"unmarshal"`
	Fold      []advCase    `json:"fold"`
	Streams   []streamCase `json:"streams"`
	Depth     []depthCase  `json:"depth"`
}

func genJSONDecodeAdversarial() jsonDecodeAdversarialVector {
	v := jsonDecodeAdversarialVector{Meta: newMeta()}
	const ts = `"2020-01-02T03:04:05Z"`
	docs := []string{
		// H3: merging depends on the destination's kind.
		`{"inner":{"x":1,"y":"a"},"inner":{"x":null,"y":null}}`,
		`{"pp":{"a":1},"pp":null,"pp":{"b":2}}`,
		`{"pp":{"a":1},"pp":{"b":2}}`,
		`{"inner":{"ms":{"k":{"a":1}}},"inner":{"ms":{"k":{"b":2}}}}`,
		`{"list":[{"a":1,"b":2}],"list":[{"a":9}]}`,
		`{"list":[{"a":1,"b":2},{"a":3,"b":4}],"list":[{"a":9}],"list":[{},{}]}`,
		`{"list":[{"a":1,"b":2}],"list":[],"list":[{"a":9}]}`,
		`{"list":[{"a":1,"b":2}],"list":null,"list":[{"a":9}]}`,
		`{"nums":[1,2],"nums":[null]}`,
		`{"nums":[1,2],"nums":[]}`,
		`{"nums":[1,2],"nums":null}`,
		`{"nest":[[1,2]],"nest":[[null]]}`,
		// H3: an earlier occurrence's error survives a later good one.
		`{"nums":["bad"],"nums":[1]}`,
		`{"nums":"bad","nums":[1]}`,
		`{"nums":[1,"bad"],"nums":[1]}`,
		`{"ptr":"bad","ptr":1}`,
		`{"ptr":"bad","ptr":null}`,
		`{"pp":{"a":"bad"},"pp":null}`,
		`{"inner":{"x":"bad"},"inner":{"x":1}}`,
		`{"n":true,"n":1}`,
		`{"im":{"1":"a","x":"b"},"im":null}`,
		`{"list":[{},{"a":"bad"}],"list":[{}]}`,
		`{"arr":[1,"bad"],"arr":[1]}`,
		// H4: RawMessage is verbatim, last occurrence wins.
		`{"raw": {"a" : 1 } }`,
		`{"raw":"café\/x"}`,
		"{\"raw\":\"a\xffb\"}",
		`{"raw":"\ud83d"}`,
		`{"raw":{"a":1},"raw":null}`,
		`{"raw":null}`,
		`{"raw":{"a":1,"a":2}}`,
		`{"raw":[ 1 ],"raw":[ 2 ]}`,
		// H4: GoTime.
		`{"t":` + ts + `}`,
		`{"t":` + ts + `,"t":null}`,
		`{"t":"nope","t":` + ts + `}`,
		`{"t":` + ts + `,"t":"nope"}`,
		`{"t":"2020-01-02T03:04:05Z"}`,
		`{"t":5}`,
		`{"t":null}`,
		`{"tp":` + ts + `,"tp":null}`,
		`{"tp":null,"tp":` + ts + `}`,
		`{"tp":"nope","tp":null}`,
		`{"n":"bad","t":"nope"}`,
		`{"t":"nope","n":"bad"}`,
		// json.Number.
		`{"jn":1,"jn":null}`,
		`{"jn":"12"}`,
		`{"jn":"abc"}`,
		`{"jn":true}`,
		`{"jn":[1]}`,
		`{"jn":1.50}`,
		// M2: absent fields, null, arrays, []byte.
		`{}`,
		`null`,
		`{"arr":[1]}`,
		`{"arr":[1,2,3]}`,
		`{"arr":[1,2],"arr":[9]}`,
		`{"arr":[1,2],"arr":[]}`,
		`{"arr":[1,2],"arr":null}`,
		`{"arr":"x"}`,
		`{"bin":"aGVsbG8="}`,
		`{"bin":""}`,
		`{"bin":null}`,
		`{"bin":[1,2]}`,
		`{"bin":"!!!"}`,
		`{"bin":"aGVsbG8"}`,
		`{"bin":"aGVs\nbG8="}`,
		`{"bin":"aGVsbG8=x"}`,
		`{"bin":5}`,
		`{"bin":[1,2],"bin":"aA=="}`,
		`{"bin":"aA==","bin":[7,8]}`,
		`{"nums":"aGk="}`,
		`{"nums":""}`,
		// M3: any.
		`{"any":{"a":1},"any":{"b":2}}`,
		`{"any":1,"any":null}`,
		`{"any":9007199254740993}`,
		`{"any":-9007199254740993}`,
		`{"any":9007199254740992}`,
		`{"any":1e400}`,
		`{"any":[1e400],"any":1}`,
		`{"any":{"a":1,"a":2}}`,
		`{"any":{"a":1e400,"a":2}}`,
		`{"any":-0}`,
		`{"any":1.5e3}`,
		`{"any":[1,"x",null,true,{"k":[]}]}`,
		// M4: errors in document order, with Go's type spelling.
		`{"n":1,"s":5,"n":"bad"}`,
		`{"im":{"abc":"x"}}`,
		`{"um":{"+5":"x"}}`,
		`{"um":{"300":"x"}}`,
		`{"im":{"+5":"x"}}`,
		`{"nums":"x"}`,
		`{"list":"x"}`,
		`{"list":[5]}`,
		`{"pp":5}`,
		`{"inner":5}`,
		`{"nest":5}`,
		`{"nest":[5]}`,
		`{"inner":{"ms":5}}`,
		`{"im":5}`,
		`{"um":[]}`,
		`[1]`,
		`5`,
		// M5: f32 is parsed at its own width.
		`{"f32":1.00000017881393432617187499}`,
		`{"f32":3.4028235677973365e38}`,
		`{"f32":3.5e38}`,
		`{"f32":1e-60}`,
		// M6: shapes that used to be quadratic, small here.
		`{"inner":{"ms":{"a":{"a":1}}},"inner":{"ms":{"a":{"b":2},"b":{"a":3}}},"inner":{"ms":null}}`,
	}
	for _, d := range docs {
		v.Decode = append(v.Decode, advDecode(d, false))
	}
	for _, d := range []string{
		`{"n":"bad","zzz":1}`,
		`{"zzz":1,"n":"bad"}`,
		`{"zzz":1,"yyy":2}`,
		`{"inner":{"qqq":1}}`,
		`{"any":{"qqq":1}}`,
		`{"pp":{"qqq":1},"pp":null}`,
	} {
		v.Decode = append(v.Decode, advDecode(d, true))
	}
	for _, d := range []string{
		``, ` `, `{"n":1} {"n":2}`, `{"n":1} xyz`, `{"n":`, `null`, `{"n":1}`, ` {"n":1} `,
	} {
		v.Unmarshal = append(v.Unmarshal, advUnmarshal(d))
	}
	for _, d := range []string{
		`{"Foo":"x"}`, `{"foo":"x"}`, `{"FOO":"x"}`, `{"fOO":"x"}`,
		`{"Bar":"x"}`, `{"BAR":"x"}`, `{"bar":"x"}`,
		`{"Foo":"x","FOO":"y","foo":"z"}`,
	} {
		v.Fold = append(v.Fold, advFold(d, false))
		v.Fold = append(v.Fold, advFold(d, true))
	}
	for _, d := range []string{
		`{"n":1} {"n":2}`,
		`{"n":1}{"n":2}`,
		`{"n":1} xyz`,
		`{"n":1}xyz`,
		``,
		`   `,
		"\n\t ",
		`{"n":`,
		`{"n":1} {"n":`,
		`{"n":1}   `,
		`{"n":"bad"} {"n":2}`,
		`{"n":1} ]`,
		`1 2 3`,
		`null null`,
		`12`,
		`tru`,
		`[1,2]x`,
		`5x`,
		`"a" "b`,
		`{"n":1,}`,
	} {
		v.Streams = append(v.Streams, advStream(d))
	}
	for _, shape := range []string{"any_array", "any_object", "unknown_array", "rec", "raw"} {
		for _, depth := range []int{1000, 9999, 10000, 10001} {
			v.Depth = append(v.Depth, advDepth(shape, depth))
		}
	}
	return v
}
