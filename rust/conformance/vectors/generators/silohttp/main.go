//go:build silohttp_diff

// Command silohttp is the Go side of the silo-http wire differential. It serves real net/http,
// real chi, and the real internal/httpstream compressor on loopback ports, and the Rust test in
// rust/crates/silo-http/tests/differential.rs builds the same routers from the same inputs and
// compares bytes on the wire. The test builds and starts this program itself:
//
//	GOTOOLCHAIN=go1.26.10 go build -tags silohttp_diff -o <bin> ./rust/conformance/vectors/generators/silohttp
//
// It prints one JSON object mapping listener names to ports, then serves until killed.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/Silo-Server/silo-server/internal/httpstream"
)

var (
	sideMu sync.Mutex
	side   = map[string]string{}
)

func record(id, value string) {
	sideMu.Lock()
	defer sideMu.Unlock()
	side[id] += value + "\n"
}

// echo writes everything the handler can see of the request, in a form the Rust side reproduces
// byte for byte. strconv.Quote keeps non-UTF-8 bytes visible.
func echo(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	q := strconv.Quote
	fmt.Fprintf(&b, "method=%s\nuri=%s\nproto=%s\nhost=%s\n", q(r.Method), q(r.RequestURI), q(r.Proto), q(r.Host))
	fmt.Fprintf(&b, "path=%s\nrawpath=%s\nrawquery=%s\nescaped=%s\n", q(r.URL.Path), q(r.URL.RawPath), q(r.URL.RawQuery), q(r.URL.EscapedPath()))
	fmt.Fprintf(&b, "scheme=%s\nurlhost=%s\nstring=%s\n", q(r.URL.Scheme), q(r.URL.Host), q(r.URL.String()))
	fmt.Fprintf(&b, "cl=%d\nte=%s\nclose=%t\npattern=%s\n", r.ContentLength, q(strings.Join(r.TransferEncoding, ",")), r.Close, q(r.Pattern))
	if rctx := chi.RouteContext(r.Context()); rctx != nil {
		fmt.Fprintf(&b, "routepath=%s\nroutemethod=%s\nroutepattern=%s\n", q(rctx.RoutePath), q(rctx.RouteMethod), q(rctx.RoutePattern()))
		for _, p := range rctx.RoutePatterns {
			fmt.Fprintf(&b, "stack=%s\n", q(p))
		}
		for i, k := range rctx.URLParams.Keys {
			fmt.Fprintf(&b, "param=%s:%s\n", q(k), q(rctx.URLParams.Values[i]))
			fmt.Fprintf(&b, "lookup=%s pathvalue=%s\n", q(chi.URLParam(r, k)), q(r.PathValue(k)))
		}
	}
	for _, name := range strings.Split(r.Header.Get("X-Path-Values"), ",") {
		if name != "" {
			fmt.Fprintf(&b, "pathvalue=%s:%s\n", q(name), q(r.PathValue(name)))
		}
	}
	keys := make([]string, 0, len(r.Header))
	for k := range r.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range r.Header[k] {
			fmt.Fprintf(&b, "hdr=%s:%s\n", q(k), q(v))
		}
	}
	body, err := io.ReadAll(r.Body)
	fmt.Fprintf(&b, "body=%s\n", q(string(body)))
	if err != nil {
		fmt.Fprintf(&b, "bodyerr=%s\n", q(err.Error()))
	}
	if r.Trailer != nil {
		tk := make([]string, 0, len(r.Trailer))
		for k := range r.Trailer {
			tk = append(tk, k)
		}
		sort.Strings(tk)
		for _, k := range tk {
			fmt.Fprintf(&b, "trailer=%s:%s\n", q(k), q(strings.Join(r.Trailer[k], ",")))
		}
	}
	w.Write([]byte(b.String()))
}

func field(parts []string, i int) string {
	if i >= len(parts) {
		return ""
	}
	s, err := url.PathUnescape(parts[i])
	if err != nil {
		return parts[i]
	}
	return s
}

func repeat(n, c string) string {
	count, _ := strconv.Atoi(n)
	return strings.Repeat(c, count)
}

type onlyReader struct{ io.Reader }

// ops runs the script in the X-Ops header, one call to the response writer per op. Fields are
// comma-separated and path-escaped, ops are separated by "|".
func ops(w http.ResponseWriter, r *http.Request) {
	id := r.Header.Get("X-Id")
	note := func(err error) {
		if id == "" {
			return
		}
		if err != nil {
			record(id, err.Error())
		} else {
			record(id, "nil")
		}
	}
	for _, op := range strings.Split(r.Header.Get("X-Ops"), "|") {
		p := strings.Split(op, ",")
		switch p[0] {
		case "h":
			w.Header().Set(field(p, 1), field(p, 2))
		case "a":
			w.Header().Add(field(p, 1), field(p, 2))
		case "raw":
			w.Header()[field(p, 1)] = []string{field(p, 2)}
		case "nil":
			w.Header()[field(p, 1)] = nil
		case "d":
			w.Header().Del(field(p, 1))
		case "wh":
			code, _ := strconv.Atoi(field(p, 1))
			w.WriteHeader(code)
		case "w":
			_, err := w.Write([]byte(repeat(field(p, 1), field(p, 2))))
			note(err)
		case "ws":
			_, err := io.WriteString(w, repeat(field(p, 1), field(p, 2)))
			note(err)
		case "rf":
			n, err := io.Copy(w, onlyReader{strings.NewReader(repeat(field(p, 1), field(p, 2)))})
			note(err)
			if id != "" {
				record(id, strconv.FormatInt(n, 10))
			}
		case "f":
			err := http.NewResponseController(w).Flush()
			note(err)
		case "rb":
			data, err := io.ReadAll(r.Body)
			if id != "" {
				record(id, fmt.Sprintf("read %d", len(data)))
			}
			note(err)
		case "rn":
			n, _ := strconv.Atoi(field(p, 1))
			buf := make([]byte, n)
			got, err := io.ReadFull(r.Body, buf)
			if id != "" {
				record(id, fmt.Sprintf("read %d", got))
			}
			note(err)
		case "cb":
			note(r.Body.Close())
		case "mb":
			n, _ := strconv.ParseInt(field(p, 1), 10, 64)
			r.Body = http.MaxBytesReader(w, r.Body, n)
		case "fd":
			note(http.NewResponseController(w).EnableFullDuplex())
		case "e":
			code, _ := strconv.Atoi(field(p, 1))
			http.Error(w, field(p, 2), code)
		case "nf":
			http.NotFound(w, r)
		case "rd":
			code, _ := strconv.Atoi(field(p, 1))
			http.Redirect(w, r, field(p, 2), code)
		case "panic":
			panic("boom")
		case "abort":
			panic(http.ErrAbortHandler)
		case "hj":
			conn, buf, err := http.NewResponseController(w).Hijack()
			if err != nil {
				note(err)
				return
			}
			data := make([]byte, buf.Reader.Buffered())
			io.ReadFull(buf.Reader, data)
			fmt.Fprintf(conn, "hijacked %q %s", data, field(p, 1))
			conn.Close()
			return
		case "waitctx":
			<-r.Context().Done()
			record(id, "canceled")
		case "sleep":
			ms, _ := strconv.Atoi(field(p, 1))
			time.Sleep(time.Duration(ms) * time.Millisecond)
		case "echo":
			echo(w, r)
		}
	}
}

func content(root string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		for _, p := range [][2]string{{"etag", "Etag"}, {"ct", "Content-Type"}, {"ce", "Content-Encoding"}, {"cc", "Cache-Control"}, {"lm", "Last-Modified"}} {
			if q.Has(p[0]) {
				w.Header().Set(p[1], q.Get(p[0]))
			}
		}
		if q.Has("noct") {
			w.Header()["Content-Type"] = nil
		}
		f, err := os.Open(filepath.Join(root, q.Get("f")))
		if err != nil {
			http.Error(w, "missing fixture", 500)
			return
		}
		defer f.Close()
		var mod time.Time
		switch q.Get("mod") {
		case "":
			mod = time.Unix(1700000000, 0)
		case "zero":
		case "epoch":
			mod = time.Unix(0, 0)
		case "nanos":
			mod = time.Unix(1700000000, 123456789)
		}
		name := q.Get("name")
		if !q.Has("name") {
			name = q.Get("f")
		}
		http.ServeContent(w, r, name, mod, f)
	})
}

func walk(r chi.Routes) string {
	var lines []string
	chi.Walk(r, func(method, route string, _ http.Handler, mws ...func(http.Handler) http.Handler) error {
		lines = append(lines, fmt.Sprintf("%s %s %d", method, route, len(mws)))
		return nil
	})
	sort.Strings(lines)
	return strings.Join(lines, "\n") + "\n"
}

func mw(name string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("X-Mw", name)
			next.ServeHTTP(w, r)
		})
	}
}

func text(s string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", s)
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte(s))
	}
}

// adversarial is the router with every chi feature the server's routers use, in shapes the route
// inventory does not reach.
func adversarial() *chi.Mux {
	h := http.HandlerFunc(echo)
	r := chi.NewRouter()
	r.Get("/s/static", h)
	r.Get("/s/{id}", h)
	r.Get("/s/{id}/x", h)
	r.Get("/s/*", h)
	r.Get("/m/{a}.{b}", h)
	r.Get("/m/{a}-{b}.{c}", h)
	r.Get("/m/{name}.jpg", h)
	r.Get("/m/pre-{x}", h)
	r.Get("/m/pre-{x}/post", h)
	r.Get("/m/{x}-suf", h)
	r.Get("/Videos/{id}/hls/{playlistId}/{segmentId}.{segmentContainer}", h)
	r.Get("/Videos/{itemId}/Trickplay/{width}/{index}.jpg", h)
	r.Get("/feed/{slug}.xml", h)
	r.Get("/r/{id:[0-9]+}", h)
	r.Get("/r/{id:[a-z]+}", h)
	r.Get(`/r/{slug:[a-z-]+}/{n:\d+}`, h)
	r.Get(`/r/{date:\d{4}-\d{2}-\d{2}}`, h)
	r.Get(`/r/{any:.*}/end`, h)
	r.Get(`/r/{u:\p{L}+}x`, h)
	r.Get(`/r/{e:}/empty`, h)
	r.Get("/mm", h)
	r.Post("/mm", h)
	r.Put("/mm/{x}", h)
	r.Delete("/mm/{x}", h)
	r.Head("/h", h)
	r.Method("QUERY", "/q", h)
	r.Connect("/c", h)
	r.Trace("/t", h)
	r.Options("/o", h)
	r.Patch("/p", h)
	r.Handle("/all", h)
	r.Handle("GET /spaced", h)
	r.Handle("POST\t/tabbed", h)
	r.Route("/sub", func(s chi.Router) {
		s.Get("/", h)
		s.Get("/a", h)
		s.Get("/{p}", h)
		s.Route("/deep", func(d chi.Router) {
			d.Get("/", h)
			d.Get("/{q}", h)
			d.Post("/*", h)
		})
	})
	r.Mount("/mnt", h)
	own := chi.NewRouter()
	own.NotFound(text("own-404"))
	own.MethodNotAllowed(text("own-405"))
	own.Get("/x", h)
	r.Mount("/own", own)
	inherit := chi.NewRouter()
	inherit.Get("/x", h)
	r.Mount("/inherit", inherit)
	r.With(mw("with")).Get("/with", h)
	r.With(mw("with1"), mw("with2")).With(mw("with3")).Post("/with", h)
	r.Group(func(g chi.Router) {
		g.Use(mw("grp"))
		g.Get("/grp", h)
		g.Group(func(gg chi.Router) {
			gg.Use(mw("grp2"))
			gg.Get("/grp2", h)
		})
	})
	r.Route("/{tenant}/v", func(s chi.Router) {
		s.Use(mw("tenant"))
		s.Get("/{id}", h)
		s.Get("/", h)
	})
	return r
}

// withHandlers is the router whose 404 and 405 are custom, set after mounting so they propagate.
func withHandlers() *chi.Mux {
	h := http.HandlerFunc(echo)
	r := chi.NewRouter()
	r.Use(mw("root"))
	sub := chi.NewRouter()
	sub.Get("/x", h)
	r.Mount("/sub", sub)
	r.Get("/only-get", h)
	r.NotFound(text("custom-404"))
	r.MethodNotAllowed(text("custom-405"))
	late := chi.NewRouter()
	late.Get("/x", h)
	r.Mount("/late", late)
	r.With(mw("inline")).NotFound(text("inline-404"))
	return r
}

// canonicalize is a small stand-in for internal/jellycompat's canonicalizeCompatPath: it uppercases
// known first segments, the rewrite that makes the route path differ from the request path.
func canonicalize(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		switch strings.ToLower(part) {
		case "items":
			parts[i] = "Items"
		case "users":
			parts[i] = "Users"
		case "system":
			parts[i] = "System"
		}
	}
	return strings.Join(parts, "/")
}

// rewriting has the same stack as internal/jellycompat/router.go: StripSlashes except under /web,
// then path normalization that rewrites RoutePath and, on a clone, r.URL.
func rewriting() *chi.Mux {
	h := http.HandlerFunc(echo)
	r := chi.NewRouter()
	r.Use(func(next http.Handler) http.Handler {
		stripped := middleware.StripSlashes(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/web" || strings.HasPrefix(r.URL.Path, "/web/") {
				next.ServeHTTP(w, r)
				return
			}
			stripped.ServeHTTP(w, r)
		})
	})
	r.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if rctx := chi.RouteContext(r.Context()); rctx != nil && rctx.RoutePath != "" {
				rctx.RoutePath = canonicalize(rctx.RoutePath)
			}
			normalized := canonicalize(r.URL.Path)
			if normalized == r.URL.Path {
				next.ServeHTTP(w, r)
				return
			}
			clone := r.Clone(r.Context())
			urlCopy := *clone.URL
			urlCopy.Path = normalized
			urlCopy.RawPath = normalized
			clone.URL = &urlCopy
			next.ServeHTTP(w, clone)
		})
	})
	r.Get("/Items", h)
	r.Get("/Items/{id}", h)
	r.Get("/Users/{id}/Items", h)
	r.Get("/System/Info/Public", h)
	r.Get("/web", h)
	r.Get("/web/", h)
	r.Get("/web/*", h)
	return r
}

// redirecting exercises middleware.RedirectSlashes in front of a router.
func redirecting() *chi.Mux {
	h := http.HandlerFunc(echo)
	r := chi.NewRouter()
	r.Use(middleware.RedirectSlashes)
	r.Get("/a", h)
	r.Get("/a/b", h)
	return r
}

// bridge is what an axum handler behind the chi mux comes to: the Rust side uses a real axum handler
// through Handler::with_state, with its header names lowercased by the http crate.
func bridge() *chi.Mux {
	r := chi.NewRouter()
	r.Get("/b/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/x")
		w.Header().Set("X-State", "state")
		w.WriteHeader(201)
		w.Write([]byte("id=" + chi.URLParam(r, "id")))
	})
	r.Post("/b/{id}", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "text/x")
		w.Write([]byte(r.Method + " " + string(body)))
	})
	return r
}

type route struct{ method, path string }

func inventory(repo, listener string) []route {
	data, err := os.ReadFile(filepath.Join(repo, "contracts/api/v2/route-inventory.json"))
	if err != nil {
		panic(err)
	}
	var doc struct {
		Routes []struct {
			Listener, Method, Path string
		} `json:"routes"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		panic(err)
	}
	var out []route
	for _, r := range doc.Routes {
		if r.Listener == listener {
			out = append(out, route{r.Method, r.Path})
		}
	}
	return out
}

func mediaRoutes(repo, rel string) []route {
	data, err := os.ReadFile(filepath.Join(repo, rel))
	if err != nil {
		panic(err)
	}
	var out []route
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		first, _, _ := strings.Cut(line, "\t")
		method, path, ok := strings.Cut(first, " ")
		if ok {
			out = append(out, route{method, path})
		}
	}
	return out
}

func chiFrom(routes []route) *chi.Mux {
	r := chi.NewRouter()
	h := http.HandlerFunc(echo)
	for _, rt := range routes {
		r.Method(rt.method, rt.path, h)
	}
	return r
}

func muxFrom(routes []route) *http.ServeMux {
	m := http.NewServeMux()
	seen := map[string]bool{}
	for _, rt := range routes {
		if !seen[rt.path] {
			seen[rt.path] = true
			m.HandleFunc(rt.path, echo)
		}
	}
	return m
}

func rootMux(api http.Handler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/metrics", http.NotFoundHandler())
	mux.Handle("/api/", api)
	mux.HandleFunc("/", echo)
	return mux
}

func patternMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /static/", echo)
	m.HandleFunc("POST /items/{id}", echo)
	m.HandleFunc("PUT /items/{id}", echo)
	m.HandleFunc("/files/{path...}", echo)
	m.HandleFunc("/exact/{$}", echo)
	m.HandleFunc("example.com/hosted/", echo)
	m.HandleFunc("/hosted/", echo)
	m.HandleFunc("/a%2fb/", echo)
	m.HandleFunc("CONNECT /conn", echo)
	m.HandleFunc("HEAD /headonly", echo)
	m.HandleFunc("/tree/", echo)
	m.HandleFunc("GET /w/{a}/seg/{b}", echo)
	return m
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-vectors" {
		writeVectors(os.Args[2])
		return
	}
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: silohttp <repo-root> <fixture-dir> | silohttp -vectors <out-file>")
		os.Exit(2)
	}
	repo, files := os.Args[1], os.Args[2]

	mediaAPI := "internal/api/testdata/media_routes.txt"
	mediaJelly := "internal/jellycompat/testdata/media_routes.txt"
	mediaABS := "internal/audiobooks/abs/testdata/media_routes.txt"
	mediaProxy := "internal/proxy/testdata/media_routes.txt"
	mediaNode := "internal/transcodenode/testdata/media_routes.txt"

	chiAPI := chiFrom(inventory(repo, "api"))
	adv := adversarial()
	handlers := withHandlers()
	rewrite := rewriting()
	redirects := redirecting()

	compressAll := httpstream.CompressWithExclusions(nil, nil)(http.HandlerFunc(ops))
	skipResponse := httpstream.CompressWithExclusions(nil, func(_ *http.Request, h http.Header) bool {
		return h.Get("X-No-Compress") != ""
	}, "text/custom")(http.HandlerFunc(ops))

	listeners := map[string]*http.Server{
		"chi-api":         {Handler: chiAPI},
		"chi-proxy":       {Handler: chiFrom(inventory(repo, "proxy"))},
		"chi-transcode":   {Handler: chiFrom(inventory(repo, "transcode_node"))},
		"chi-media-api":   {Handler: chiFrom(mediaRoutes(repo, mediaAPI))},
		"chi-media-jelly": {Handler: chiFrom(mediaRoutes(repo, mediaJelly))},
		"chi-media-abs":   {Handler: chiFrom(mediaRoutes(repo, mediaABS))},
		"chi-media-proxy": {Handler: chiFrom(mediaRoutes(repo, mediaProxy))},
		"chi-media-node":  {Handler: chiFrom(mediaRoutes(repo, mediaNode))},
		"chi-adv":         {Handler: adv},
		"chi-handlers":    {Handler: handlers},
		"chi-rewrite":     {Handler: rewrite},
		"chi-redirect":    {Handler: redirects},
		"mux-root":        {Handler: rootMux(chiAPI)},
		"mux-debug":       {Handler: muxFrom(inventory(repo, "operational_debug"))},
		"mux-metrics":     {Handler: muxFrom(inventory(repo, "operational_metrics"))},
		"mux-patterns":    {Handler: patternMux()},
		"ops":             {Handler: http.HandlerFunc(ops)},
		"content":         {Handler: content(files)},
		"servefile": {Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.ServeFile(w, r, filepath.Join(files, r.URL.Query().Get("f")))
		})},
		"fileserver":     {Handler: http.StripPrefix("/pub", http.FileServer(http.Dir(files)))},
		"compress":       {Handler: compressAll},
		"compress-types": {Handler: skipResponse},
		"opts-off":       {Handler: http.HandlerFunc(ops), DisableGeneralOptionsHandler: true},
		"timeouts": {
			Handler:           http.HandlerFunc(ops),
			ReadHeaderTimeout: 200 * time.Millisecond,
			IdleTimeout:       200 * time.Millisecond,
		},
		"smallheaders":   {Handler: http.HandlerFunc(echo), MaxHeaderBytes: 1024},
		"timeouts-write": {Handler: http.HandlerFunc(ops), WriteTimeout: 150 * time.Millisecond},
		"timeouts-read":  {Handler: http.HandlerFunc(ops), ReadTimeout: 150 * time.Millisecond},
		"bridge":         {Handler: bridge()},
	}

	control := http.NewServeMux()
	control.HandleFunc("/side", func(w http.ResponseWriter, r *http.Request) {
		sideMu.Lock()
		defer sideMu.Unlock()
		io.WriteString(w, side[r.URL.Query().Get("id")])
	})
	walked := map[string]chi.Routes{"chi-adv": adv, "chi-handlers": handlers, "chi-rewrite": rewrite, "chi-api": chiAPI}
	control.HandleFunc("/mime", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, mime.TypeByExtension(r.URL.Query().Get("e")))
	})
	control.HandleFunc("/walk", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, walk(walked[r.URL.Query().Get("l")]))
	})
	control.HandleFunc("/find", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		rctx := chi.NewRouteContext()
		mx := walked[q.Get("l")].(*chi.Mux)
		fmt.Fprintf(w, "%q %t\n", mx.Find(rctx, q.Get("m"), q.Get("p")), mx.Match(chi.NewRouteContext(), q.Get("m"), q.Get("p")))
	})
	listeners["control"] = &http.Server{Handler: control}

	ports := map[string]int{}
	for name, srv := range listeners {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		ports[name] = ln.Addr().(*net.TCPAddr).Port
		go srv.Serve(ln)
	}
	data, err := json.Marshal(ports)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(data))
	select {}
}
