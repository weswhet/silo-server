//go:build silohttp_diff

package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
)

// writeVectors writes the pure-function vectors the Rust side checks without a Go toolchain:
//
//	GOTOOLCHAIN=go1.26.7 go run -tags silohttp_diff ./rust/conformance/vectors/generators/silohttp -vectors rust/conformance/vectors/silohttp/pure.json
func writeVectors(out string) {
	type sniff struct {
		Hex string `json:"hex"`
		CT  string `json:"ct"`
	}
	type key struct {
		In  string `json:"in"`
		Out string `json:"out"`
	}
	type status struct {
		Code int    `json:"code"`
		Text string `json:"text"`
	}
	type parsed struct {
		Raw      string `json:"raw"`
		Request  bool   `json:"request"`
		OK       bool   `json:"ok"`
		Scheme   string `json:"scheme,omitempty"`
		Host     string `json:"host,omitempty"`
		Path     string `json:"path_hex,omitempty"`
		RawPath  string `json:"raw_path_hex,omitempty"`
		RawQuery string `json:"raw_query_hex,omitempty"`
		Opaque   string `json:"opaque_hex,omitempty"`
		Escaped  string `json:"escaped,omitempty"`
		String   string `json:"string_hex,omitempty"`
	}
	var doc struct {
		Sniff  []sniff  `json:"sniff"`
		Keys   []key    `json:"keys"`
		Status []status `json:"status"`
		URLs   []parsed `json:"urls"`
	}

	var samples [][]byte
	sigs := []string{
		"<!DOCTYPE HTML", "<HTML", "<HEAD", "<SCRIPT", "<IFRAME", "<H1", "<DIV", "<FONT", "<TABLE", "<A", "<STYLE", "<TITLE", "<B", "<BODY", "<BR", "<P", "<!--",
		"<?xml", "%PDF-", "%!PS-Adobe-", "\xFE\xFF\x00\x00", "\xFF\xFE\x00\x00", "\xEF\xBB\xBF\x00", "\x00\x00\x01\x00", "\x00\x00\x02\x00", "BM", "GIF87a", "GIF89a",
		"RIFF\x00\x00\x00\x00WEBPVP", "\x89PNG\x0D\x0A\x1A\x0A", "\xFF\xD8\xFF", "FORM\x00\x00\x00\x00AIFF", "ID3", "OggS\x00", "MThd\x00\x00\x00\x06", "RIFF\x00\x00\x00\x00AVI ", "RIFF\x00\x00\x00\x00WAVE",
		"\x1A\x45\xDF\xA3", "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00LP",
		"\x00\x01\x00\x00", "OTTO", "ttcf", "wOFF", "wOF2", "\x1F\x8B\x08", "PK\x03\x04", "Rar!\x1A\x07\x00", "Rar!\x1A\x07\x01\x00", "\x00\x61\x73\x6D",
		"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom", "\x00\x00\x00\x18ftypisom\x00\x00\x00\x00isommp41", "\x00\x00\x00\x10ftypmp42\x00\x00\x00\x00", "\x00\x00\x00\x14ftypisom\x00\x00\x00\x00mp4", "\x00\x00\x00\x13ftypisom\x00\x00\x00\x00mp4",
	}
	for _, s := range sigs {
		samples = append(samples,
			[]byte(s),
			[]byte(s+" "),
			[]byte(s+">"),
			[]byte(s+"x"),
			[]byte(" \t\r\n"+s+" "),
			[]byte(s[:len(s)-1]),
			[]byte(s+"\x00\x01"),
		)
		lower := []byte(s)
		for i, c := range lower {
			if 'A' <= c && c <= 'Z' {
				lower[i] = c + 32
			}
		}
		samples = append(samples, append(lower, ' '))
	}
	for b := 0; b < 256; b++ {
		samples = append(samples, []byte{byte(b)}, []byte{'a', byte(b), 'b'})
	}
	samples = append(samples, nil, []byte(" \t\r\n\x0c"), make([]byte, 600))
	long := make([]byte, 511)
	for i := range long {
		long[i] = 'a'
	}
	samples = append(samples, long, append(append([]byte{}, long...), 0, 0), append(append([]byte{}, long...), 'b', 0))
	for _, s := range samples {
		doc.Sniff = append(doc.Sniff, sniff{hex.EncodeToString(s), http.DetectContentType(s)})
	}

	for _, s := range []string{
		"", "a", "A", "accept-encoding", "ACCEPT-ENCODING", "Accept-encoding", "x-ratelimit-limit", "etag", "www-authenticate", "a-b-c", "-a", "a-", "a--b", "1a", "a1b", "x_y", "x y", "x:y", "é", "a b-c", "ALREADY-Fine", "Trailer:foo", "content-MD5", "Sec-WebSocket-Key", "sec-websocket-key", "!#$%&'*+-.^_`|~",
	} {
		doc.Keys = append(doc.Keys, key{s, http.CanonicalHeaderKey(s)})
	}

	for c := 0; c < 1000; c++ {
		if t := http.StatusText(c); t != "" {
			doc.Status = append(doc.Status, status{c, t})
		}
	}

	raws := []string{
		"", "*", "/", "/a", "/a/b", "/a b", "/a%20b", "/a%2Fb", "/a%2fb/c", "/%zz", "/%", "/%2", "/a?b", "/a?", "/a??", "/a?b?c", "?x", "a", "a/b", "a:b", ":a", "1a:b", "a1:b", "/a#b", "/a;b", "/a,b", "/a=b", "/a@b", "/a:b", "/a+b", "/a$b", "/a&b", "/a!b", "/a'b", "/a(b)", "/a*b", "/a[b]", "/a<b>", "/a\"b", "/a`b", "/a{b}", "/a|b", "/a^b", "/a\\b", "/\xff", "/%ff", "/\xc3\xa9", "/%C3%A9", "/\x01", "/\x7f", "//a", "//a/b", "///a",
		"http://a", "http://a/", "http://a/b", "HTTP://A/B", "http://a:80/", "http://a:b/", "http://a:1:2/", "ftp://a:1:2/", "http://[::1]/", "http://[::1]:80/", "http://[::1]:b/", "http://[::1", "http://[bad]/", "http://[1.2.3.4]/", "http://[::ffff:1.2.3.4]/", "http://[fe80::1%25en0]/", "http://[fe80::1%en0]/", "http://x[::1]/", "http://u@a/", "http://u:p@a/", "http://u:p@ss@a/", "http://u%20:p%40@a/", "http://u^@a/", "http://%41/", "http://%C3%A9/", "http://a b/", "http://a%20b/", "http://a<b/", "http://a?q", "http://a#f", "http:", "http:/", "http:/a", "http:a", "mailto:x@y", "scheme:", "s+c.h-1://h/p", "1s://h", "a:/b", "/a?x=%zz",
	}
	add := func(raw string, request bool, u *url.URL, err error) {
		p := parsed{Raw: hex.EncodeToString([]byte(raw)), Request: request, OK: err == nil}
		if err == nil {
			p.Scheme = u.Scheme
			p.Host = hex.EncodeToString([]byte(u.Host))
			p.Path = hex.EncodeToString([]byte(u.Path))
			p.RawPath = hex.EncodeToString([]byte(u.RawPath))
			p.RawQuery = hex.EncodeToString([]byte(u.RawQuery))
			p.Opaque = hex.EncodeToString([]byte(u.Opaque))
			p.Escaped = u.EscapedPath()
			u.Fragment, u.RawFragment = "", ""
			p.String = hex.EncodeToString([]byte(u.String()))
		}
		doc.URLs = append(doc.URLs, p)
	}
	for _, raw := range raws {
		u, err := url.ParseRequestURI(raw)
		add(raw, true, u, err)
		u, err = url.Parse(raw)
		add(raw, false, u, err)
	}

	data, err := json.MarshalIndent(doc, "", " ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		panic(err)
	}
}
