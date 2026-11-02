// Command clientip_vectors drives the real internal/clientip.Middleware over a deterministic corpus
// and records every value it stores in the request context, plus the exported helpers that read them.
// rust/crates/silo-gate/tests/clientip_differential.rs replays the result against the Rust port.
//
// Commands assume the repository root is the cwd:
//
//	GOTOOLCHAIN=go1.26.10 go run ./rust/conformance/vectors/generators/clientip \
//	  -out rust/conformance/vectors/clientip/middleware.json
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"log"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	"github.com/Silo-Server/silo-server/internal/clientip"
)

type record struct {
	Name          string              `json:"name"`
	Trusted       string              `json:"trusted"`
	RemoteAddr    string              `json:"remote_addr"`
	Host          string              `json:"host"`
	TLS           bool                `json:"tls"`
	Headers       map[string][]string `json:"headers"`
	ClientIP      string              `json:"client_ip"`
	RemoteAfter   string              `json:"remote_after"`
	Unknown       bool                `json:"unknown"`
	Scheme        string              `json:"scheme"`
	RequestHost   string              `json:"request_host"`
	Peer          string              `json:"peer"`
	PeerIP        string              `json:"peer_ip"`
	Origin        string              `json:"origin"`
	HasForwarding bool                `json:"has_forwarding"`
}

type cidrRecord struct {
	Raw        string `json:"raw"`
	Err        bool   `json:"err"`
	Normalized string `json:"normalized"`
	NormErr    bool   `json:"norm_err"`
}

type output struct {
	Middleware []record     `json:"middleware"`
	CIDRs      []cidrRecord `json:"cidrs"`
}

var trustedLists = []string{
	"10.0.0.0/8,127.0.0.0/8,::1/128",
	clientip.DefaultTrustedProxies,
	"",
	"::ffff:10.0.0.0/104",
	"::ffff:0:0/96",
	"::/0",
	"0.0.0.0/0",
	"fd00::/8,192.168.1.1/32",
	"::ffff:0:0/90",
	"10.0.0.1/008",
}

var peers = []string{
	"10.0.0.1:443", "10.0.0.1", "8.8.8.8:1234", "127.0.0.1:1", "[::1]:80", "::1", "[::ffff:10.0.0.1]:9",
	"::ffff:10.0.0.1", "[fd00::1]:1", "[fe80::1%eth0]:5", "junk", "", "[::1]", "1.2.3.4:5:6", "[1.2.3.4]:80",
	"192.168.1.1:2", "[::1]:80]", "[[::1]]:80", "2001:db8::1", "10.0.0.1:", ":80", "010.0.0.1:1",
}

var addressValues = []string{
	"1.2.3.4", "junk", "::ffff:1.2.3.4", "[::ffff:1.2.3.4]", "1.2.3.4:80", "[2001:db8::1]:443", "2001:db8::1",
	"10.0.0.2", "fd00::2", "::1", "fe80::1%eth0", "[fe80::1%eth0]:9", "1.2.3.4%x", "::ffff:10.0.0.2", "unknown",
	"0.0.0.0", "256.1.1.1", "01.2.3.4", "2001:DB8::A", "::", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7::", "::1.2.3.4",
	"[1.2.3.4]", "[]", "[", "]", ":", "1.2.3.4:", ":80", "[::1", "::1]", " 1.2.3.4 ", "　1.2.3.4",
}

var xffShapes = []func(a, b string) []string{
	func(a, b string) []string { return nil },
	func(a, b string) []string { return []string{a} },
	func(a, b string) []string { return []string{a + ", " + b} },
	func(a, b string) []string { return []string{a, b} },
	func(a, b string) []string { return []string{b + ",,", " , " + a + " ,"} },
	func(a, b string) []string { return []string{""} },
	func(a, b string) []string { return []string{" , ,"} },
}

var protos = [][]string{nil, {"https"}, {"http"}, {"wss"}, {"ws"}, {"HTTPS"}, {"https", "http"}, {"https,http"}, {""}, {" https"}}
var forwardedHosts = [][]string{nil, {"app.example.com"}, {"App.Example.com:443"}, {"a,b"}, {"a", "b"}, {" spaced.example "}, {""}, {"evil/x"}, {"u@h"}, {"[::1]:8443"}, {"h\tx"}, {"H:80"}}
var hosts = []string{"silo.test", "SILO.test:443", "silo.test:80", "[::1]:8096", "[FE80::1]", "::1", "silo.test:", "ÄB.test", "a:b:c"}
var forwardeds = [][]string{nil, {"for=1.1.1.1"}, {""}, {" , "}, {"for=1.1.1.1", "for=2.2.2.2"}}
var realIPs = [][]string{nil, {"5.6.7.8"}, {"junk"}, {" 5.6.7.8 "}, {"5.6.7.8", "9.9.9.9"}, {"[::ffff:5.6.7.8]:1"}, {""}, {"::ffff:5.6.7.8"}}
var upgrades = [][]string{nil, {"websocket"}, {" WebSocket "}, {"h2c"}, {"h2c", "websocket"}, {"websocket", "h2c"}}
var connections = [][]string{nil, {"Upgrade"}, {"keep-alive, upgrade"}, {"keep-alive"}, {"close", "UPGRADE"}}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.Intn(len(xs))] }

func run(trustedRaw, remote, host string, useTLS bool, headers map[string][]string) record {
	nets, err := clientip.ParseCIDRs(trustedRaw)
	if err != nil {
		log.Fatalf("parse %q: %v", trustedRaw, err)
	}
	resolver := clientip.NewResolver(nets)
	req := httptest.NewRequest(http.MethodGet, "http://placeholder/", nil)
	req.RemoteAddr = remote
	req.Host = host
	if useTLS {
		req.TLS = &tls.ConnectionState{}
	} else {
		req.TLS = nil
	}
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	rec := record{Trusted: trustedRaw, RemoteAddr: remote, Host: host, TLS: useTLS, Headers: headers}
	rec.HasForwarding = clientip.HasForwardingHeaders(req.Header)
	clientip.Middleware(resolver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rec.ClientIP = clientip.FromContext(ctx)
		rec.RemoteAfter = r.RemoteAddr
		rec.Unknown = clientip.ForwardedClientUnknown(ctx)
		rec.Scheme = clientip.RequestScheme(r)
		rec.RequestHost = clientip.RequestHost(r)
		rec.Peer = clientip.PeerFromContext(ctx)
		rec.PeerIP = clientip.PeerIP(ctx)
		rec.Origin = clientip.RequestOrigin(r)
	})).ServeHTTP(httptest.NewRecorder(), req)
	return rec
}

func main() {
	out := flag.String("out", "rust/conformance/vectors/clientip/middleware.json", "output file")
	flag.Parse()

	var result output
	add := func(name string, rec record) {
		rec.Name = name
		result.Middleware = append(result.Middleware, rec)
	}

	// Structured sweep over peer, X-Forwarded-For and X-Real-IP, with every trust list.
	for _, trusted := range trustedLists[:6] {
		for _, peer := range []string{"10.0.0.1:443", "8.8.8.8:1234", "[::ffff:10.0.0.1]:9", "[::1]:80"} {
			for _, a := range addressValues {
				for i, shape := range xffShapes[1:4] {
					headers := map[string][]string{"X-Forwarded-For": shape(a, "10.0.0.9")}
					add("xff_sweep_"+string(rune('a'+i)), run(trusted, peer, "silo.test", false, headers))
				}
			}
		}
	}

	// Randomized sweep across every field. The fixed seed keeps the corpus stable.
	r := rand.New(rand.NewSource(20261101))
	for i := 0; i < 6000; i++ {
		headers := map[string][]string{}
		set := func(name string, values []string) {
			if values != nil {
				headers[name] = values
			}
		}
		set("X-Forwarded-For", pick(r, xffShapes)(pick(r, addressValues), pick(r, addressValues)))
		set("X-Real-Ip", pick(r, realIPs))
		set("Forwarded", pick(r, forwardeds))
		set("X-Forwarded-Proto", pick(r, protos))
		set("X-Forwarded-Host", pick(r, forwardedHosts))
		set("Upgrade", pick(r, upgrades))
		set("Connection", pick(r, connections))
		add("random", run(pick(r, trustedLists), pick(r, peers), pick(r, hosts), r.Intn(4) == 0, headers))
	}

	for _, raw := range []string{
		"", "10.0.0.0/8", "10.0.0.1/8, ::1/128", " , 10.0.0.0/8 ,", "junk", "10.0.0.0", "10.0.0.0/33", "::/129", "10.0.0.0/+8",
		"10.0.0.0/08", "10.0.0.0/-1", "10.0.0.0/8/9", "::ffff:1.2.3.4/120", "fe80::1%eth0/64", "1.2.3.4/99999999999999999999", "01.2.3.4/8",
		"10.0.0.0/", "/8", strings.Repeat("9", 40),
	} {
		rec := cidrRecord{Raw: raw}
		if _, err := clientip.ParseCIDRs(raw); err != nil {
			rec.Err = true
		}
		normalized, err := clientip.NormalizeCIDRList(raw)
		rec.Normalized, rec.NormErr = normalized, err != nil
		result.CIDRs = append(result.CIDRs, rec)
	}

	data, err := json.MarshalIndent(result, "", " ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d middleware and %d CIDR cases", len(result.Middleware), len(result.CIDRs))
}
