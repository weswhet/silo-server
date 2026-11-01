//go:build gocompat_vectors

package main

import (
	"math/rand/v2"
	"net/url"
	"strings"
)

type unescapeCase struct {
	In  S  `json:"in"`
	Out *S `json:"out"`
	Err *S `json:"err"`
}

type valuesCase struct {
	Pairs [][2]S `json:"pairs"`
	Out   S      `json:"out"`
}

type urlVector struct {
	Meta
	QueryEscape   []mapCase      `json:"query_escape"`
	PathEscape    []mapCase      `json:"path_escape"`
	QueryUnescape []unescapeCase `json:"query_unescape"`
	PathUnescape  []unescapeCase `json:"path_unescape"`
	ValuesEncode  []valuesCase   `json:"values_encode"`
}

func randomBytes(r *rand.Rand, n int) string {
	b := make([]byte, r.IntN(n+1))
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	return string(b)
}

func unescapeResult(s string, f func(string) (string, error)) unescapeCase {
	c := unescapeCase{In: S(s)}
	out, err := f(s)
	if err != nil {
		e := S(err.Error())
		c.Err = &e
	} else {
		o := S(out)
		c.Out = &o
	}
	return c
}

func genURL() urlVector {
	r := newRand(4)
	v := urlVector{Meta: newMeta()}
	inputs := []string{"", "abc", "one two", "10%", " ?&=#+%!<>#\"{}|\\^[]`☺\t:/@$'()*,;", "a/b", "a+b", "a b+c", "~-_.", "é", "日本語", "🎬", "/media/tv/Show Name/ep 1.mkv", "user@example.com:8080"}
	for b := 0; b < 256; b++ {
		inputs = append(inputs, string([]byte{byte(b)}), "x"+string([]byte{byte(b)})+"y")
	}
	for _, c := range adversarialRunes {
		inputs = append(inputs, string(c), "a "+string(c))
	}
	inputs = append(inputs, invalidUTF8...)
	inputs = append(inputs, mediaStrings...)
	for range 300 {
		inputs = append(inputs, randomAdversarial(r, 6), randomBytes(r, 6))
	}
	for _, s := range inputs {
		q := url.QueryEscape(s)
		p := url.PathEscape(s)
		v.QueryEscape = append(v.QueryEscape, mapCase{S(s), S(q)})
		v.PathEscape = append(v.PathEscape, mapCase{S(s), S(p)})
		// Round trip: what Go wrote must read back through both directions.
		v.QueryUnescape = append(v.QueryUnescape, unescapeResult(q, url.QueryUnescape))
		v.PathUnescape = append(v.PathUnescape, unescapeResult(p, url.PathUnescape))
	}
	tokens := []string{"%", "%a", "%zz", "%AB", "%ab", "%aB", "+", "%2B", "%2b", "a", "a%", "%é", "é%", "%0", "%00", "%ff", "%FF", "%20", " ", "/", "%2F", "%2f", "%g0", "%0g", "\xff", "%\xff", "%2", "%%", "%%25", "%25", "日", "%E6%97%A5", "%E6", "%C3%28"}
	for range 800 {
		var b strings.Builder
		for range r.IntN(5) {
			b.WriteString(tokens[r.IntN(len(tokens))])
		}
		s := b.String()
		v.QueryUnescape = append(v.QueryUnescape, unescapeResult(s, url.QueryUnescape))
		v.PathUnescape = append(v.PathUnescape, unescapeResult(s, url.PathUnescape))
	}
	for _, s := range tokens {
		v.QueryUnescape = append(v.QueryUnescape, unescapeResult(s, url.QueryUnescape))
		v.PathUnescape = append(v.PathUnescape, unescapeResult(s, url.PathUnescape))
	}
	keyTokens := []string{"a", "b", "A", "z", "é", "a b", "a&b", "a=b", "", "日本", "k[]", "\xff", "10", "9", "api_key"}
	for range 300 {
		values := url.Values{}
		var pairs [][2]S
		for range r.IntN(7) {
			k := keyTokens[r.IntN(len(keyTokens))]
			val := inputs[r.IntN(len(inputs))]
			values.Add(k, val)
			pairs = append(pairs, [2]S{S(k), S(val)})
		}
		v.ValuesEncode = append(v.ValuesEncode, valuesCase{pairs, S(values.Encode())})
	}
	return v
}
