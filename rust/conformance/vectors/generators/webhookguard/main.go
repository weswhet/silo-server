// Command webhookguard writes the lookup vectors for the webhook destination guard
// (internal/notifications validateWebhookURL): for each host, whether netip.ParseAddr reads it,
// and otherwise what net.DefaultResolver.LookupNetIP(ctx, "ip", host) answers inside the Go
// server's container. Every host is decided offline: numeric spellings that Go's resolver sends
// to DNS as names, localhost spellings answered from /etc/hosts, and reserved names.
package main

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"time"
)

var hosts = []string{
	"0177.0.0.1", "010.8.8.8", "0x7f000001", "2130706433", "127.1", "127.0.1", "1.2.3.04",
	"0x08.0x08.0x08.0x08", "0X7F.1", "134744072", "08.8.8.8", "017700000001", "0x7f.0.0.1",
	"0", "0x", "00", "1.2.3", "1.2.3.4.5", "4294967296", "99999999999", "256.1.1.1", "1e2",
	"0xg", "-1", "8.8.8.8.", "127.0.0.1.", "LOCALHOST.", "localhost", "localhost.", "LocalHost",
	"LOCALHOST", "foo.localhost", "ip6-localhost", "a.invalid", "example.test", "0177.0.0.1.",
}

type vector struct {
	Host     string   `json:"host"`
	ParsedIP bool     `json:"parsed_ip"`
	Resolved bool     `json:"resolved"`
	Addrs    []string `json:"addrs,omitempty"`
}

func main() {
	out := make([]vector, 0, len(hosts))
	for _, h := range hosts {
		v := vector{Host: h}
		if _, err := netip.ParseAddr(h); err == nil {
			v.ParsedIP = true
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
			cancel()
			if err == nil && len(addrs) > 0 {
				v.Resolved = true
				for _, a := range addrs {
					v.Addrs = append(v.Addrs, a.String())
				}
			}
		}
		out = append(out, v)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
