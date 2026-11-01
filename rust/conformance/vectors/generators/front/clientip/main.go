//go:build front_vectors

// Command clientip serves what the real internal/clientip middleware resolves for each request, so a
// test can compare a client's direct connection with the same client through the Rust front.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/Silo-Server/silo-server/internal/clientip"
)

func main() {
	trusted := flag.String("trusted", "", "comma-separated trusted CIDRs")
	flag.Parse()
	cidrs, err := clientip.ParseCIDRs(*trusted)
	if err != nil {
		log.Fatal(err)
	}
	handler := clientip.Middleware(clientip.NewResolver(cidrs))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"client_ip": clientip.FromContext(r.Context()),
			"unknown":   clientip.ForwardedClientUnknown(r.Context()),
			"scheme":    clientip.RequestScheme(r),
			"host":      clientip.RequestHost(r),
			"origin":    clientip.RequestOrigin(r),
		})
	}))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(ln.Addr().String())
	log.Fatal(http.Serve(ln, handler))
}
