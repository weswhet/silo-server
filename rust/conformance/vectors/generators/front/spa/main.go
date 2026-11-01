//go:build front_vectors

// Command spa writes the wire bytes of the real server.FrontendHandler, behind the same ServeMux entries
// as newRootMux, for a request matrix over a fixed file tree. rust/crates/silo-front replays the matrix
// and compares bytes.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"testing/fstest"
	"time"

	"github.com/Silo-Server/silo-server/internal/branding"
	"github.com/Silo-Server/silo-server/internal/server"
)

const index = `<!doctype html>
<html>
  <head>
    <title>Silo</title>
    <link rel="icon" href="/favicon.ico" sizes="any" />
  </head>
  <body><div id="root"></div></body>
</html>
`

var files = map[string]string{
	"index.html":          index,
	".well-known/x.txt":   "dotted\n",
	"assets/app.js":       "console.log('identity bytes of the app bundle');\n",
	"assets/app.js.br":    "brotli-sidecar-bytes",
	"assets/app.js.gz":    "gzip-sidecar-bytes",
	"assets/plain.js":     "no sidecars here\n",
	"assets/style.css":    "body { color: red }\n",
	"assets/style.css.gz": "gzip-css",
	"assets/fnt.woff2":    "wOF2 font bytes",
	"sw.js":               "self.addEventListener('install', () => {});\n",
	"icons/a.svg":         "<svg xmlns=\"http://www.w3.org/2000/svg\"/>\n",
	"nested/index.html":   "<p>nested</p>\n",
	"robots.txt":          "User-agent: *\n",
	"noext":               "binary?\x00\x01",
}

type settings map[string]string

func (s settings) Get(_ context.Context, key string) (string, error) { return s[key], nil }
func (s settings) Set(context.Context, string, string) error         { return nil }
func (s settings) GetMany(_ context.Context, keys ...string) (map[string]string, error) {
	out := map[string]string{}
	for _, k := range keys {
		if v, ok := s[k]; ok {
			out[k] = v
		}
	}
	return out, nil
}

type result struct {
	Variant  string `json:"variant"`
	Request  string `json:"request"`
	Response string `json:"response_base64"`
}

// requests is the matrix. Each entry is one complete request, closed with Connection: close so the
// response ends with the connection.
func requests() []string {
	req := func(method, target string, headers ...string) string {
		var b bytes.Buffer
		fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: spa.test\r\nConnection: close\r\n", method, target)
		for _, h := range headers {
			b.WriteString(h + "\r\n")
		}
		b.WriteString("\r\n")
		return b.String()
	}
	var out []string
	for _, m := range []string{"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "QUERY", "TRACE"} {
		out = append(out, req(m, "/"), req(m, "/metrics"), req(m, "/some/app/route"))
	}
	out = append(out,
		"POST / HTTP/1.1\r\nHost: spa.test\r\nConnection: close\r\nContent-Length: 5\r\n\r\nhello",
		req("GET", "/index.html"),
		req("GET", "/library/ebooks?x=1"),
		req("GET", "/trailing/"),
		req("GET", "/", `If-None-Match: "nope"`),
		req("GET", "/", "If-None-Match: *"),
		req("GET", "/", "Range: bytes=0-4"),
		req("GET", "/", "Range: bytes=9999-"),
		req("HEAD", "/", "Range: bytes=0-4"),
		req("GET", "/assets/app.js"),
		req("GET", "/assets/app.js", "Accept-Encoding: br, gzip"),
		req("GET", "/assets/app.js", "Accept-Encoding: gzip"),
		req("GET", "/assets/app.js", "Accept-Encoding: br;q=0.5, gzip;q=0.9"),
		req("GET", "/assets/app.js", "Accept-Encoding: GZIP;q=0"),
		req("GET", "/assets/app.js", "Accept-Encoding: identity;q=0"),
		req("GET", "/assets/app.js", "Accept-Encoding: *;q=0"),
		req("GET", "/assets/app.js", "Accept-Encoding: *;q=0, gzip"),
		req("GET", "/assets/app.js", "Accept-Encoding: br;q=abc, gzip;q=2"),
		req("GET", "/assets/app.js", "Accept-Encoding: *"),
		req("GET", "/assets/app.js", "Accept-Encoding: br", "Range: bytes=0-3"),
		req("GET", "/assets/app.js", "Accept-Encoding: identity;q=0, br", "Range: bytes=0-3"),
		req("HEAD", "/assets/app.js", "Accept-Encoding: br"),
		req("HEAD", "/assets/app.js", "Accept-Encoding: br", "Range: bytes=0-3"),
		req("POST", "/assets/app.js", "Accept-Encoding: br"),
		req("GET", "/assets/plain.js", "Accept-Encoding: br, gzip"),
		req("GET", "/assets/plain.js", "Accept-Encoding: identity;q=0, gzip"),
		req("GET", "/assets/style.css", "Accept-Encoding: br, gzip"),
		req("GET", "/assets/fnt.woff2", "Accept-Encoding: br, gzip"),
		req("GET", "/assets/app.js.br"),
		req("GET", "/assets/app.js.gz"),
		req("GET", "/assets/missing.js"),
		req("GET", "/assets"),
		req("GET", "/assets?q=1"),
		req("GET", "/assets/"),
		req("GET", "/assets/app.js", `If-None-Match: "x"`),
		req("GET", "/sw.js"),
		req("HEAD", "/sw.js"),
		req("POST", "/sw.js"),
		req("GET", "/robots.txt", "Range: bytes=0-3"),
		req("GET", "/noext"),
		req("GET", "/.well-known/x.txt"),
		req("GET", "/.well-known"),
		req("GET", "/icons"),
		req("GET", "/icons?a=b"),
		req("GET", "/icons/"),
		req("GET", "/icons/a.svg"),
		req("GET", "/nested"),
		req("GET", "/nested/"),
		req("GET", "/nested/index.html"),
		req("GET", "/nested/index.html?z=1"),
		req("GET", "/metrics/"),
	)
	return out
}

func wire(addr, request string) ([]byte, error) {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := c.Write([]byte(request)); err != nil {
		return nil, err
	}
	return io.ReadAll(bufio.NewReader(c))
}

func run(variant string, svc *branding.Service) []result {
	server.Branding = svc
	mux := http.NewServeMux()
	mux.Handle("/metrics", http.NotFoundHandler())
	mux.Handle("/", server.FrontendHandler())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()
	var out []result
	for _, r := range requests() {
		raw, err := wire(ln.Addr().String(), r)
		if err != nil {
			log.Fatal(err)
		}
		out = append(out, result{Variant: variant, Request: r, Response: base64.StdEncoding.EncodeToString(raw)})
	}
	return out
}

func main() {
	fsys := fstest.MapFS{}
	for name, body := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(body)}
	}
	server.WebDistFS = fsys

	branded := map[string]string{
		branding.KeyServerName:  `Bob's <Silo> & "Co"`,
		branding.KeyAccentColor: "#ff00aa",
		"branding.favicon_ref":  "abc123.ico",
	}
	var out []result
	out = append(out, run("no_settings", branding.NewService(settings{}, nil))...)
	out = append(out, run("branded", branding.NewService(settings(branded), nil))...)
	doc, err := json.MarshalIndent(map[string]any{
		"files":    files,
		"branding": branded,
		"cases":    out,
	}, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(os.Args[1], append(doc, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
}
