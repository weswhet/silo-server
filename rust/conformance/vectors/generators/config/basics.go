//go:build silo_config_vectors

package main

import (
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"strconv"
)

type parseVector struct {
	In    string  `json:"in"`
	Atoi  result  `json:"atoi"`
	Bool  result  `json:"bool"`
	Int0  result  `json:"int0"`
	Uint3 result  `json:"uint30"`
	Float result  `json:"float"`
	Bits  *uint64 `json:"float_bits,omitempty"`
}

func errResult(v any, err error) result {
	if err != nil {
		return result{Error: err.Error()}
	}
	return result{Ok: v}
}

func writeParseVectors() {
	in := []string{
		"", " ", "0", "00", "1", "-1", "+1", "-0", "+0", "007", "12a", "a12", "1_000", "0x1f", "0X1F", "0o17", "0b101", "0x", "0b", "0o", "017", "08",
		"9223372036854775807", "9223372036854775808", "-9223372036854775808", "-9223372036854775809", "18446744073709551615", "18446744073709551616",
		"1073741823", "1073741824", "t", "T", "true", "TRUE", "True", "tRuE", "f", "F", "false", "FALSE", "False", "yes", "no",
		"1.5", "-1.5", "+1.5", ".5", "5.", ".", "-.", "1e5", "1E5", "1e+5", "1e-5", "1e", "1e+", "e5", "1.2.3", "1e400", "-1e400", "1e-400", "5e-324", "1.7976931348623157e308", "1.797693134862315807937e+308",
		"inf", "Inf", "INF", "+inf", "-inf", "infinity", "Infinity", "+INFINITY", "-Infinity", "infin", "nan", "NaN", "NAN", "+nan", "-nan",
		"0x1p-2", "0X1P2", "0x1.8p1", "-0x1p0", "0x_1p0", "0x1_0p0", "0x1p", "0x1", "0xp1", "0x1.fffffffffffffp1023", "0x1p1024", "0x1p-1074", "0x1p-1075", "1_0", "1_0.5", "0.1", "0.2", "0.30000000000000004",
		"123456789012345678901234567890", "0.000000000000000000000000000000000000001",
	}
	out := make([]parseVector, 0, len(in))
	for _, v := range in {
		a, ea := strconv.Atoi(v)
		b, eb := strconv.ParseBool(v)
		i, ei := strconv.ParseInt(v, 0, 64)
		u, eu := strconv.ParseUint(v, 10, 30)
		f, ef := strconv.ParseFloat(v, 64)
		vec := parseVector{In: v, Atoi: errResult(a, ea), Bool: errResult(b, eb), Int0: errResult(strconv.FormatInt(i, 10), ei), Uint3: errResult(u, eu)}
		if ef != nil {
			vec.Float = result{Error: ef.Error()}
		} else {
			vec.Float = result{Ok: strconv.FormatFloat(f, 'g', -1, 64)}
			bits := bitsOf(f)
			vec.Bits = &bits
		}
		out = append(out, vec)
	}
	write("strconv.json", out)
}

type urlVector struct {
	In       string  `json:"in"`
	Error    string  `json:"error,omitempty"`
	Scheme   string  `json:"scheme"`
	Opaque   string  `json:"opaque"`
	Username *string `json:"username"`
	Password *string `json:"password"`
	Host     string  `json:"host"`
	Hostname string  `json:"hostname"`
	Port     string  `json:"port"`
	Path     string  `json:"path"`
	RawQuery string  `json:"raw_query"`
	Fragment string  `json:"fragment"`
}

type hostPortVector struct {
	In    string `json:"in"`
	Host  string `json:"host"`
	Port  string `json:"port"`
	Error string `json:"error,omitempty"`
}

type addrVector struct {
	In       string `json:"in"`
	Valid    bool   `json:"valid"`
	Loopback bool   `json:"loopback"`
	Zone     string `json:"zone"`
	CIDR     bool   `json:"cidr"`
}

type mailVector struct {
	In    string `json:"in"`
	Equal bool   `json:"equal"`
}

func writeNetVectors() {
	urls := []string{
		"", "*", "/", "/a/b", "a/b", "a:b/c", "http://example.com", "HTTP://EXAMPLE.com:80/Path?q=1#frag", "https://user:pass@host:443/x", "https://user@host", "https://u%40ser:p%3Ass@host/",
		"http://[::1]:8080/", "http://[::1]", "http://[fe80::1%25en0]:80/", "http://[1.2.3.4]/", "http://[::1", "http://::1/", "http://a:b:c/", "postgres://a:1,b:2/db", "redis://a:1,b:2/db", "http://a:1,b:2/db",
		"http://host:port/", "http://host:80a/", "http://ho st/", "http://ho%20st/", "http://ho%zzst/", "http://ex%41mple.com/", "http://exämple.com/", "http://user:p@ss@host/", "http://us er@host/", "http://host/%zz", "http://host/?%zz", "http://host/#%zz",
		"mailto:a@b.com", "http:opaque", "scheme:", "1http://x", ":foo", "http://x\x7f", "http://x\n", "//host/path", "///path", "?q=1", "#f", "http://host?", "http://host/?a=1&b=2;c", "unix:///var/run/redis.sock", "unix:/x.sock?db=1", "unix://",
		"redis://localhost", "redis://:pw@localhost:6379/3", "rediss://user:pw@h/0?a=b", "http://host:/", "http://[::1]:/", "http://[::1]x/", "http://host#a#b",
	}
	uout := make([]urlVector, 0, len(urls))
	for _, v := range urls {
		u, err := url.Parse(v)
		if err != nil {
			uout = append(uout, urlVector{In: v, Error: err.Error()})
			continue
		}
		vec := urlVector{In: v, Scheme: u.Scheme, Opaque: u.Opaque, Host: u.Host, Hostname: u.Hostname(), Port: u.Port(), Path: u.Path, RawQuery: u.RawQuery, Fragment: u.Fragment}
		if u.User != nil {
			name := u.User.Username()
			vec.Username = &name
			if p, ok := u.User.Password(); ok {
				vec.Password = &p
			}
		}
		uout = append(uout, vec)
	}
	hps := []string{"", ":", "a", "a:1", ":1", "a:", "[::1]:80", "[::1]", "::1", "::1:80", "[a]:b:c", "[a]b:1", "a]:1", "[a:1", "a[b:1", "a:1]", "[[a]]:1", "[]:1"}
	hout := make([]hostPortVector, 0, len(hps))
	for _, v := range hps {
		h, p, err := net.SplitHostPort(v)
		vec := hostPortVector{In: v, Host: h, Port: p}
		if err != nil {
			vec.Error = err.Error()
		}
		hout = append(hout, vec)
	}
	addrs := []string{"", "1.2.3.4", "01.2.3.4", "1.2.3", "1.2.3.256", "127.0.0.1", "127.1.2.3", "128.0.0.1", "::1", "::2", "::", "1::", "::ffff:127.0.0.1", "::ffff:1.2.3.4", "fe80::1%en0", "fe80::1%", "%en0", "::1%lo", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "abcd::12345", "::1.2.3.4", "0:0:0:0:0:0:0:1", "localhost", "1.2.3.4/8"}
	cidrs := map[string]bool{}
	aout := make([]addrVector, 0, len(addrs))
	for _, v := range addrs {
		a, err := netip.ParseAddr(v)
		vec := addrVector{In: v, Valid: err == nil}
		if err == nil {
			vec.Loopback = a.IsLoopback()
			vec.Zone = a.Zone()
		}
		_, _, cerr := net.ParseCIDR(v)
		vec.CIDR = cerr == nil
		cidrs[v] = true
		aout = append(aout, vec)
	}
	for _, v := range []string{"10.0.0.0/8", "10.0.0.0/33", "10.0.0.0/0", "10.0.0.0/-1", "10.0.0.0/+8", "10.0.0.0/", "10.0.0.0/08", "::1/128", "::1/129", "::ffff:1.2.3.4/120", "fe80::1%en0/64", "/8", "1.2.3.4/99999999999999999999", "::/0", "010.0.0.0/8"} {
		_, _, cerr := net.ParseCIDR(v)
		vec := addrVector{In: v, CIDR: cerr == nil}
		if a, err := netip.ParseAddr(v); err == nil {
			vec.Valid, vec.Loopback, vec.Zone = true, a.IsLoopback(), a.Zone()
		}
		aout = append(aout, vec)
	}
	mails := []string{"", "a@b", "a@b.com", "a.b@c.com", ".a@b.com", "a.@b.com", "a..b@c.com", "a@.b.com", "a@b..com", "a@b.com.", "a b@c.com", "a@b c.com", "a @b.com", "a@ b.com", "A <a@b.com>", "<a@b.com>", "a@b.com (x)", "\"a\"@b.com", "\"a b\"@c.com", "a@[1.2.3.4]", "a@[::1]", "a@[bad]", "a@[1.2.3.4", "a@b@c", "@b.com", "a@", "日本@例.jp", "a+b@c.com", "a!#$%&'*+/=?^_`{|}~@c.com", "a(b@c.com", "a,b@c.com", "group: a@b.com;", "a@b.com,c@d.com", "a@[::1%lo]", "a\\b@c.com"}
	mout := make([]mailVector, 0, len(mails))
	for _, v := range mails {
		address, err := mail.ParseAddress(v)
		mout = append(mout, mailVector{In: v, Equal: err == nil && address.Address == v})
	}
	write("net.json", map[string]any{"urls": uout, "host_ports": hout, "addrs": aout, "mails": mout})
}
