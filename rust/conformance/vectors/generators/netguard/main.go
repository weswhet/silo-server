// Command netguard writes the outbound address guard vectors from the real internal/netguard package:
// each address, how netip.ParseAddr reads it, and Classify's answer.
package main

import (
	"encoding/json"
	"net/netip"
	"os"

	"github.com/Silo-Server/silo-server/internal/netguard"
)

var addresses = []string{
	"8.8.8.8", "1.1.1.1", "93.184.215.14", "10.1.2.3", "100.64.0.1", "100.127.255.255", "100.128.0.1",
	"127.0.0.1", "172.16.0.1", "172.31.255.255", "172.32.0.1", "192.0.0.8", "192.0.2.1", "192.88.99.1",
	"192.168.1.1", "198.18.0.1", "198.19.255.255", "198.20.0.1", "198.51.100.7", "203.0.113.9",
	"169.254.169.254", "0.0.0.0", "0.1.2.3", "100.100.100.200", "100.100.100.201", "224.0.0.1",
	"239.255.255.250", "240.0.0.1", "255.255.255.255", "::", "::1", "::2", "::7f00:1", "::a9fe:a9fe",
	"::ffff:127.0.0.1", "::ffff:169.254.1.1", "::ffff:8.8.8.8", "fe80::1", "fe80::1%eth0", "febf::1",
	"fec0::1", "ff02::1", "fd00:ec2::254", "fd00:ec2::253", "fd00::1", "fc00::1", "64:ff9b::a9fe:a9fe",
	"64:ff9b::808:808", "64:ff9b::a00:1", "64:ff9b:1::1", "2001:db8::1", "2606:4700::1111",
	"2001:4860:4860::8888", "01.2.3.4", "1.2.3", "256.1.1.1", "fe80::1%", "example.com", "",
}

type vector struct {
	Input string `json:"input"`
	Valid bool   `json:"valid"`
	Class string `json:"class,omitempty"`
}

func main() {
	names := map[netguard.Class]string{netguard.Public: "public", netguard.Private: "private", netguard.Blocked: "blocked"}
	out := make([]vector, 0, len(addresses))
	for _, a := range addresses {
		v := vector{Input: a}
		if addr, err := netip.ParseAddr(a); err == nil {
			v.Valid = true
			v.Class = names[netguard.Classify(addr)]
		}
		out = append(out, v)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
