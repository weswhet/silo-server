//go:build gocompat_vectors

package main

import (
	"math/rand/v2"
	"net/url"
	"sort"
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
	QueryEscape      []mapCase      `json:"query_escape"`
	PathEscape       []mapCase      `json:"path_escape"`
	QueryUnescape    []unescapeCase `json:"query_unescape"`
	PathUnescape     []unescapeCase `json:"path_unescape"`
	ValuesEncode     []valuesCase   `json:"values_encode"`
	Parse            []parseCase    `json:"parse"`
	Query            []queryCase    `json:"query"`
	ResolveReference []resolveCase  `json:"resolve_reference"`
}

type userCase struct {
	Username S  `json:"username"`
	Password *S `json:"password,omitempty"`
}

type parseOk struct {
	Scheme      S         `json:"scheme"`
	Opaque      S         `json:"opaque"`
	User        *userCase `json:"user"`
	Host        S         `json:"host"`
	Path        S         `json:"path"`
	RawPath     S         `json:"raw_path"`
	OmitHost    bool      `json:"omit_host"`
	ForceQuery  bool      `json:"force_query"`
	RawQuery    S         `json:"raw_query"`
	Fragment    S         `json:"fragment"`
	RawFragment S         `json:"raw_fragment"`
	Str         S         `json:"str"`
}

type parseCase struct {
	In  S        `json:"in"`
	Ok  *parseOk `json:"ok,omitempty"`
	Err *S       `json:"err,omitempty"`
}

func parseResult(raw string) parseCase {
	c := parseCase{In: S(raw)}
	u, err := url.Parse(raw)
	if err != nil {
		e := S(err.Error())
		c.Err = &e
		return c
	}
	var uc *userCase
	if u.User != nil {
		username := S(u.User.Username())
		uc = &userCase{Username: username}
		if pw, ok := u.User.Password(); ok {
			p := S(pw)
			uc.Password = &p
		}
	}
	c.Ok = &parseOk{
		Scheme:      S(u.Scheme),
		Opaque:      S(u.Opaque),
		User:        uc,
		Host:        S(u.Host),
		Path:        S(u.Path),
		RawPath:     S(u.RawPath),
		OmitHost:    u.OmitHost,
		ForceQuery:  u.ForceQuery,
		RawQuery:    S(u.RawQuery),
		Fragment:    S(u.Fragment),
		RawFragment: S(u.RawFragment),
		Str:         S(u.String()),
	}
	return c
}

type queryPair struct {
	K S   `json:"k"`
	V []S `json:"v"`
}

type queryCase struct {
	RawQuery S           `json:"raw_query"`
	Pairs    []queryPair `json:"pairs"`
}

func queryResult(rawQuery string) queryCase {
	u := url.URL{RawQuery: rawQuery}
	values := u.Query()
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	c := queryCase{RawQuery: S(rawQuery)}
	for _, k := range keys {
		c.Pairs = append(c.Pairs, queryPair{K: S(k), V: strs(values[k])})
	}
	return c
}

type resolveCase struct {
	Base S `json:"base"`
	Ref  S `json:"ref"`
	Out  S `json:"out"`
}

func resolveResult(base, ref string) (resolveCase, bool) {
	b, err := url.Parse(base)
	if err != nil {
		return resolveCase{}, false
	}
	r, err := url.Parse(ref)
	if err != nil {
		return resolveCase{}, false
	}
	return resolveCase{Base: S(base), Ref: S(ref), Out: S(b.ResolveReference(r).String())}, true
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

	populateParse(&v, r)
	populateQuery(&v, r)
	populateResolve(&v, r)
	return v
}

// urlLiterals is a hand-picked set of raw URL strings covering Parse's branches: schemes,
// opaque vs hierarchical, authorities (userinfo, ports, IPv6 literals and zones), relative and
// dot-segment paths, queries, and fragments.
var urlLiterals = []string{
	"", "*", "http://example.com", "http://example.com/", "http://example.com/a/b?x=1#f",
	"HTTP://Example.COM/Path", "http://example.com:8080/p", "https://example.com:443/p",
	"ftp://example.com/p", "mailto:a@b.com", "mailto:a@b.com?subject=hi",
	"file:///etc/passwd", "file://host/etc/passwd", "cache_object:foo/bar",
	"cache_object://foo/bar", "a+b-9.c:opaque", "this:that", "ht!tp://x", "0http://x",
	"http://user:pass@host:80/p", "http://user@host/p", "http://user:@host/p",
	"http://:pass@host/p", "http://us%40er:p%40ss@host/p", "http://user:p@ssword@host/p",
	"http://user name@host/p", "http://a:b:c@host/p", "http://[::1]:80/p", "http://[::1]/p",
	"http://[fe80::1%25eth0]:80/p", "http://[fe80::1%eth0]/p", "http://[::1%25]/", "http://[::ffff:1.2.3.4]/p",
	"http://[1.2.3.4]/p", "http://[::1/p", "http://[::1]]/p", "http://host:/p",
	"http://host:abc/p", "http://host:65536/p", "postgres://a,b,c:5432/db",
	"http://a:b:c/p", "//example.com/p", "///p", "////p", "scheme:///p", "scheme://///p",
	"/a/b/../c", "/a/b/./c", "/a/../../b", "../a/b", "a/b/../../../c", "./a", "..", ".",
	"/a//b", "a:b/c", "/this:that", "foo/bar:baz", "foo:bar/baz", "?a=1", "?a=1&b=2",
	"??", "???", "#frag", "#frag#more", "/p#frag with space", "/p?q#frag",
	"/foo%2fbar", "/foo%2Fbar", "/%2e%2e/etc", "/a%20b", "/a b", "/a\tb", "http://host\x00/p",
	"http://host/p\x01", "/a?%zz", "http://[::1]:80?a=1#f", "http://%41:%42@host/p",
	"http://host/%", "http://host/%a", "http://host/%zz", "http://host/a%2", "http://üñïçodé.com/p",
	"http://例え.テスト/パス", "http://host/🎬", "data:text/plain;base64,SGVsbG8=",
	"http://host:80//p", "http://host//p", "http:path", "http:/path", "http:///path",
	"http://", "http://:80", "http://@", "http://@host", "scheme://", "a://b@c:1/d?e#f",
}

func populateParse(v *urlVector, r *rand.Rand) {
	for _, s := range urlLiterals {
		v.Parse = append(v.Parse, parseResult(s))
	}
	for _, c := range invalidUTF8 {
		v.Parse = append(v.Parse, parseResult(c), parseResult("/p/"+c))
	}
	schemes := []string{"", "http", "https", "a", "a1", "a+b", "a-b", "a.b", "0a", "a_b", "HTTP", "A"}
	authorities := []string{
		"", "//", "//host", "//host:80", "//host:", "//host:abc", "//user@host", "//user:pass@host",
		"//[::1]", "//[::1]:80", "//[fe80::1%25en0]", "//[1.2.3.4]", "//[::1",
	}
	paths := []string{"", "/", "/a", "/a/b", "a/b", "/a/../b", "/a%2fb", "/a b", "/a:b"}
	suffixes := []string{"", "?", "?a=1", "??", "#", "#f", "?a=1#f"}
	for range 400 {
		s := schemes[r.IntN(len(schemes))]
		a := authorities[r.IntN(len(authorities))]
		p := paths[r.IntN(len(paths))]
		suf := suffixes[r.IntN(len(suffixes))]
		raw := p + suf
		if s != "" {
			raw = s + ":" + a + raw
		} else if a != "" {
			raw = a + raw
		}
		v.Parse = append(v.Parse, parseResult(raw))
	}
}

func populateQuery(v *urlVector, r *rand.Rand) {
	queries := []string{
		"", "a=1", "a=1&b=2", "a=1&a=2", "a&b", "a=", "=1", "a=1&", "&a=1", "a;b=1",
		"a=1;b=2", "a=1&;b=2", "a=%zz", "a=1&b=%zz", "%zz=1", "a+b=c+d", "a%20b=c%20d",
		"a=b=c", "a==b", "a=1&a=1", "é=日本", "k[]=1&k[]=2", "a=1&b=2&c=3&d=4&e=5",
	}
	for _, q := range queries {
		v.Query = append(v.Query, queryResult(q))
	}
	keys := []string{"a", "b", "A", "", "k[]", "é", "日本", "a b", "a&b", "a=b", "10", "9"}
	vals := []string{"1", "", "x y", "é", "%zz", "a=b", "a&b", "🎬", "日本語"}
	for range 220 {
		var parts []string
		for range r.IntN(6) {
			if r.IntN(4) == 0 {
				parts = append(parts, keys[r.IntN(len(keys))])
				continue
			}
			parts = append(parts, keys[r.IntN(len(keys))]+"="+vals[r.IntN(len(vals))])
		}
		v.Query = append(v.Query, queryResult(strings.Join(parts, "&")))
	}
}

func populateResolve(v *urlVector, r *rand.Rand) {
	bases := []string{
		"http://example.com/a/b/c", "http://example.com/a/b/", "http://example.com/a/b",
		"http://example.com/", "http://example.com", "https://a.b/x/y?z=1#frag",
		"http://a:b@host:80/p/q", "mailto:a@b.com", "file:///a/b/c", "/a/b/c", "a/b/c",
		"http://example.com/a/b/c?q=1", "http://[::1]:80/a/b",
	}
	refs := []string{
		"", "d", "../d", "../../d", "./d", "d/e", "/d", "//other.com/d", "?q=2", "#frag2",
		"http://other.com/x", "https:d", "../..", "..", ".", "./", "../", "d/../e",
		"d/./e", "/../d", "mailto:c@d.com", "//user@other.com/d", "g?y/./x", "g?y/../x",
		";x", "g;x", "g;x?y#s",
	}
	for _, b := range bases {
		for _, ref := range refs {
			if c, ok := resolveResult(b, ref); ok {
				v.ResolveReference = append(v.ResolveReference, c)
			}
		}
	}
	for range 60 {
		b := bases[r.IntN(len(bases))]
		ref := refs[r.IntN(len(refs))] + urlLiterals[r.IntN(len(urlLiterals))]
		if c, ok := resolveResult(b, ref); ok {
			v.ResolveReference = append(v.ResolveReference, c)
		}
	}
}
