//go:build gocompat_vectors

package main

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type parseDurationCase struct {
	In  S       `json:"in"`
	Out *string `json:"out"` // nanoseconds as a decimal string
	Err *S      `json:"err"`
}

type durationCase struct {
	Nanos   string `json:"nanos"`
	String  S      `json:"string"`
	Seconds string `json:"seconds_bits"`
	Minutes string `json:"minutes_bits"`
	Hours   string `json:"hours_bits"`
	Millis  int64  `json:"millis"`
	Micros  int64  `json:"micros"`
}

type formatCase struct {
	Secs   int64  `json:"secs"`
	Nanos  int    `json:"nanos"`
	Offset int    `json:"offset"`
	UTC    bool   `json:"utc"`
	Layout string `json:"layout"`
	Out    S      `json:"out"`
}

type marshalTimeCase struct {
	Secs   int64  `json:"secs"`
	Nanos  int    `json:"nanos"`
	Offset int    `json:"offset"`
	UTC    bool   `json:"utc"`
	Out    *S     `json:"out"`
	Err    *S     `json:"err"`
	IsZero bool   `json:"is_zero"`
	Date   [3]int `json:"date"`
	Clock  [3]int `json:"clock"`
}

type parseTimeCase struct {
	Layout string `json:"layout"`
	Value  S      `json:"value"`
	Secs   *int64 `json:"secs,omitempty"`
	Nanos  int    `json:"nanos,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Nano   *S     `json:"nano,omitempty"`
	Err    *S     `json:"err,omitempty"`
}

type timeVector struct {
	Meta
	ParseDuration []parseDurationCase `json:"parse_duration"`
	Durations     []durationCase      `json:"durations"`
	Format        []formatCase        `json:"format"`
	MarshalJSON   []marshalTimeCase   `json:"marshal_json"`
	Parse         []parseTimeCase     `json:"parse"`
}

// usedLayouts are the layouts the server formats and parses with, plus every other element the
// layout language has, so a new caller is covered too. Zone abbreviations (MST) are format-only.
var usedLayouts = []string{
	time.RFC3339, time.RFC3339Nano, time.DateOnly, time.DateTime, time.TimeOnly, "2006-01-02T15:04:05Z", "2006-01-02T15:04:05.000Z",
	"20060102T150405Z", "20060102150405", "20060102", "2006/01/02 15:04:05", "2006", "2006-01-02T15:04:05.0000000Z", "2006-01-02 15:04:05-07",
	"02", "01", "-07:00", "15:04", time.RFC1123Z, time.RubyDate, time.RFC822Z, time.ANSIC, time.Kitchen, time.Stamp, time.StampMilli, time.StampMicro, time.StampNano, http.TimeFormat,
	"Jan _2 __2 002 Mon Monday January 3 03 4 5 PM pm 06 1 2", "15:04:05,000", "15:04:05,999", "15:04:05.9", "15:04:05.00", "Z07", "Z0700", "Z070000", "Z07:00:00", "-07", "-0700", "-070000", "-07:00:00",
	"_2006", "x_2006y", "Month", "Mondays", "Janet", "Jan", "January", "Mon", "PM", "pm", ".000", ".999", "5.000", ".0005", "0102", "literal", "", "2006-002", "2006 __2", "06",
}

var formatOnlyLayouts = []string{time.RFC1123, time.RFC850, time.RFC822, time.UnixDate, "MST", "2006 MST"}

func randomDurationBits(r *rand.Rand) int64 {
	switch r.IntN(4) {
	case 0:
		return r.Int64N(2000)
	case 1:
		return r.Int64N(int64(time.Hour))
	case 2:
		v := int64(r.Uint64() >> uint(r.IntN(64)))
		if r.IntN(2) == 0 {
			return -v
		}
		return v
	}
	return r.Int64N(1000) * []int64{1, 1000, 1e6, 1e9, 6e10, 36e11, 864e11}[r.IntN(7)]
}

func floatBits(f float64) string { return strconv.FormatUint(math.Float64bits(f), 16) }

func randomUnix(r *rand.Rand) int64 {
	switch r.IntN(6) {
	case 0:
		return r.Int64N(4e9)
	case 1:
		return -r.Int64N(1 << 37)
	case 2:
		return r.Int64N(253402300799+62135596800+1) - 62135596800 // years 1..9999
	case 3:
		return r.Int64N(1<<42) - (1 << 41) // beyond the four-digit years
	case 4:
		return []int64{0, -1, 1, 951782400, 951868799, 1709164800, 4107542399, 253402300799, 253402300800, -62135596800, -62135596801, -62167219200, -62167219201}[r.IntN(13)]
	}
	return int64(1700000000 + r.IntN(1e8))
}

func randomNanos(r *rand.Rand) int {
	switch r.IntN(4) {
	case 0:
		return 0
	case 1:
		return []int{1, 10, 100, 1000, 120000000, 500000000, 999999999, 100000000, 123456789, 123456000, 123000000}[r.IntN(11)]
	}
	return r.IntN(1e9)
}

func randomOffset(r *rand.Rand) (int, bool) {
	switch r.IntN(5) {
	case 0, 1:
		return 0, true
	case 2:
		return 0, false
	}
	return []int{3600, -3600, 19800, -12600, 20700, 43200, -43200, 50400, 86399, -86399, 86400, -86400, 90000, 1, -1, 59, -59, 60, -60, 3599, -3599, 3601, 5400, -5400, 360000}[r.IntN(25)], false
}

func makeTime(secs int64, nanos, offset int, utc bool) time.Time {
	t := time.Unix(secs, int64(nanos))
	if utc {
		return t.UTC()
	}
	return t.In(time.FixedZone("", offset))
}

func genTime() timeVector {
	r := newRand(3)
	v := timeVector{Meta: newMeta()}

	addParseDuration := func(s string) {
		c := parseDurationCase{In: S(s)}
		d, err := time.ParseDuration(s)
		if err != nil {
			e := S(err.Error())
			c.Err = &e
		} else {
			o := strconv.FormatInt(int64(d), 10)
			c.Out = &o
		}
		v.ParseDuration = append(v.ParseDuration, c)
	}
	for _, s := range []string{
		"0", "5s", "30s", "1478s", "-5s", "+5s", "-0", "+0", "5.0s", "5.6s", "5.s", ".5s", "1.0s", "1.00s", "1.004s", "1.0040s", "100.00100s", "10ns", "11us", "12µs", "12μs", "13ms", "14s", "15m", "16h",
		"3h30m", "10.5s4m", "-2m3.4s", "1h2m3s4ms5us6ns", "39h9m14.425s", "52763797000ns", "0.3333333333333333333h", "9007199254740993ns", "9223372036854775807ns", "9223372036854775.807us",
		"9223372036s854ms775us807ns", "-9223372036854775808ns", "-9223372036854775.808us", "-9223372036s854ms775us808ns", "-2562047h47m16.854775808s", "0.100000000000000000000h", "0.830103483285477580700h",
		"", "3", "-", "s", ".", "-.", ".s", "+.s", "1d", "\x85\x85", "\xffff", "hello \xffff world", "\uFFFD", "\uFFFD hello \uFFFD world", "9223372036854775810ns", "9223372036854775808ns", "-9223372036854775809ns",
		"9223372036854776us", "3000000h", "9223372036854775.808us", "9223372036854ms775us808ns", "1h1", "1h1.", "h", "1h ", " 1h", "1 h", "1H", "1Ms", "1MS", "1µ", "1μ", "1µs2μs", "1.5.5s", "1..5s", "--1s", "++1s", "-+1s", "1e3s", "0x10s",
		"٣s", "３s", "1s\n", "1\ts", "0s", "00s", "-00s", "000", "00", "0.0", "0.", ".0", "1e", "1s1", "1s-1s", "2562047h47m16.854775807s", "2562047h47m16.854775808s", "2562048h", "18446744073709551616ns", "99999999999999999999ns",
		"0.00000000000000000001h", "1.00000000000000000000000000000000000000001h", "1.9999999999999999999999s", "0.000000001s", "0.0000000001s", "0.0000000005s", "1.0000000005s", "3.141592653589793238s", "1h0.5m", "0.5h0.5m0.5s",
	} {
		addParseDuration(s)
	}
	units := []string{"ns", "us", "µs", "μs", "ms", "s", "m", "h", "d", "", "S", "x", "é", "ns ", "min"}
	for range 500 {
		var b strings.Builder
		if r.IntN(3) == 0 {
			b.WriteString([]string{"-", "+"}[r.IntN(2)])
		}
		for range 1 + r.IntN(3) {
			switch r.IntN(3) {
			case 0:
				b.WriteString(strconv.FormatInt(r.Int64N(1000), 10))
			case 1:
				fmt.Fprintf(&b, "%d.%d", r.Int64N(100000), r.Int64N(1000000))
			case 2:
				b.WriteString(strconv.FormatUint(r.Uint64()>>uint(r.IntN(64)), 10))
			}
			b.WriteString(units[r.IntN(len(units))])
		}
		addParseDuration(b.String())
	}

	addDuration := func(n int64) {
		d := time.Duration(n)
		v.Durations = append(v.Durations, durationCase{
			Nanos: strconv.FormatInt(n, 10), String: S(d.String()), Seconds: floatBits(d.Seconds()), Minutes: floatBits(d.Minutes()), Hours: floatBits(d.Hours()),
			Millis: d.Milliseconds(), Micros: d.Microseconds(),
		})
	}
	for _, n := range []int64{0, 1, -1, 999, 1000, 1001, 999999, 1000000, 1000001, 999999999, 1000000000, 1000000001, 59999999999, 60000000000, 3599999999999, 3600000000000, 3600000000001, 5400000000000, 7200000000000, math.MaxInt64, math.MinInt64, math.MinInt64 + 1, 1100, 1500, 1500000, 1500000000, 90000000000} {
		addDuration(n)
		addDuration(-n)
	}
	for range 500 {
		addDuration(randomDurationBits(r))
	}

	layouts := append(append([]string{}, usedLayouts...), formatOnlyLayouts...)
	for range 4000 {
		secs, nanos := randomUnix(r), randomNanos(r)
		offset, utc := randomOffset(r)
		layout := layouts[r.IntN(len(layouts))]
		if r.IntN(3) == 0 {
			layout = time.RFC3339Nano
		}
		v.Format = append(v.Format, formatCase{secs, nanos, offset, utc, layout, S(makeTime(secs, nanos, offset, utc).Format(layout))})
	}
	for range 1200 {
		secs, nanos := randomUnix(r), randomNanos(r)
		offset, utc := randomOffset(r)
		t := makeTime(secs, nanos, offset, utc)
		c := marshalTimeCase{Secs: secs, Nanos: nanos, Offset: offset, UTC: utc, IsZero: t.IsZero()}
		b, err := json.Marshal(t)
		if err != nil {
			e := S(err.Error())
			c.Err = &e
		} else {
			o := S(b)
			c.Out = &o
		}
		y, m, d := t.Date()
		hh, mm, ss := t.Clock()
		c.Date = [3]int{y, int(m), d}
		c.Clock = [3]int{hh, mm, ss}
		v.MarshalJSON = append(v.MarshalJSON, c)
	}
	v.MarshalJSON = append(v.MarshalJSON, func() marshalTimeCase {
		t := time.Time{}
		b, _ := json.Marshal(t)
		o := S(b)
		y, m, d := t.Date()
		return marshalTimeCase{Secs: t.Unix(), UTC: true, Out: &o, IsZero: true, Date: [3]int{y, int(m), d}}
	}())

	addParse := func(layout, value string) {
		c := parseTimeCase{Layout: layout, Value: S(value)}
		t, err := time.Parse(layout, value)
		if err != nil {
			e := S(err.Error())
			c.Err = &e
		} else {
			secs := t.Unix()
			_, off := t.Zone()
			n := S(t.Format(time.RFC3339Nano))
			c.Secs, c.Nanos, c.Offset, c.Nano = &secs, t.Nanosecond(), off, &n
		}
		v.Parse = append(v.Parse, c)
	}
	for _, value := range []string{
		"2010-02-04T21:00:57.012345678+08:00", "2010-02-04T21:00:57,012345678+08:00", "2010-02-04T21:00:57+08:00", "2010-02-04T21:00:57Z", "2010-02-04T21:00:57.0Z", "2010-02-04T21:00:57.Z", "2010-02-04t21:00:57z", "2010-02-04 21:00:57Z",
		"2010-02-04T1:00:57Z", "2010-02-04T21:0:57Z", "2010-02-04T21:00:7Z", "2010-2-04T21:00:57Z", "2010-02-4T21:00:57Z", "10-02-04T21:00:57Z", "2000-02-29T00:00:00Z", "2001-02-29T00:00:00Z", "1900-02-29T00:00:00Z", "2024-02-30T00:00:00Z", "2024-04-31T00:00:00Z",
		"2024-13-01T00:00:00Z", "2024-00-01T00:00:00Z", "2024-01-00T00:00:00Z", "2024-01-32T00:00:00Z", "2024-01-01T24:00:00Z", "2024-01-01T25:00:00Z", "2024-01-01T00:60:00Z", "2024-01-01T00:00:60Z", "2024-01-01T23:59:59.999999999Z", "2024-01-01T23:59:59.9999999999Z",
		"2024-01-01T23:59:59.99999999999999999999Z", "2024-01-01T00:00:00+24:00", "2024-01-01T00:00:00+25:00", "2024-01-01T00:00:00+23:60", "2024-01-01T00:00:00+23:61", "2024-01-01T00:00:00-24:00", "2024-01-01T00:00:00+00:00", "2024-01-01T00:00:00-00:00", "2024-01-01T00:00:00+0000",
		"2024-01-01T00:00:00+00", "2024-01-01T00:00:00", "2024-01-01T00:00:00ZZ", "2024-01-01T00:00:00Z ", " 2024-01-01T00:00:00Z", "2024-01-01", "0000-01-01T00:00:00Z", "0001-01-01T00:00:00Z", "9999-12-31T23:59:59Z", "10000-01-01T00:00:00Z", "-001-01-01T00:00:00Z",
		"٢٠٢٤-01-01T00:00:00Z", "２０２４-01-01T00:00:00Z", "2024-01-01T00:00:00\u2028", "2024-01-01T00:00:00é", "\xff024-01-01T00:00:00Z", "2024-01-01T00:00:00\xff", "", "T", "Z", "null", "2024", "2024-", "2024-01-", "2024-01-01T", "2024-01-01T00", "2024-01-01T00:", "2024-01-01T00:00", "2024-01-01T00:00:",
		"2024-01-01T00:00:00+", "2024-01-01T00:00:00+01", "2024-01-01T00:00:00+01:", "2024-01-01T00:00:00+01:0", "2024-01-01T00:00:00+1:00", "2024-01-01T00:00:00+01:00:00", "2024-01-01T00:00:00.5+01:00", "2024-01-01T00:00:00,5+01:00", "2024-01-01T00:00:00.+01:00", "2024-01-01T00:00:00.a+01:00",
		"20240101", "20240101T000000Z", "20240101T246060Z", "20241301", "20240230", "00:00", "24:00", "23:59", "12:60", "1:00", "01:0", "2024-1-1", "2024-001", "2024-366", "2023-366", "2024-060", "2024-061", "2024-000", "2024 __2", "2024  60", "2024   6", "12", "13", "00", "31", "32",
		"Mon, 02 Jan 2006 15:04:05 GMT", "mon, 02 jan 2006 15:04:05 GMT", "MON, 02 JAN 2006 15:04:05 GMT", "Tue, 02 Jan 2006 15:04:05 GMT", "Mon, 2 Jan 2006 15:04:05 GMT", "Mon, 02 Foo 2006 15:04:05 GMT", "3:04PM", "03:04PM", "13:04PM", "12:00AM", "12:00PM", "0:00AM", "3:04pm", "3:04 PM", "-07:00", "+07:00", "Z", "+24:00", "+25:00", "07:00",
		"-0700", "-07", "+070000", "-07:00:00", "+07:00:60", "+07:00:61", "-00:00:01", "+00:00:01", "x2006y", "x2006", "_2006", "January", "january", "JANUARY", "Janu", "Jan", "Feb", "Monday", "monday", "Mon", "Foo", "2006-01-02T15:04:05.1234567Z", "2006-01-02T15:04:05.12345678Z", "2006-01-02T15:04:05.000Z", "2006-01-02T15:04:05.00Z",
		"15:04:05", "15:04:05.5", "15:04:05,5", "15:04:05.123456789123", "15:04:05.", "15:04:05.x", "15:04:05 ", "2006-01-02 15:04:05-07", "2006-01-02 15:04:05+0700", "2006-01-02 15:04:05", "2006-01-02  15:04:05", "2006/01/02 15:04:05", "2006/1/2 15:04:05",
	} {
		for _, layout := range []string{time.RFC3339, time.RFC3339Nano} {
			addParse(layout, value)
		}
		addParse(usedLayouts[r.IntN(len(usedLayouts))], value)
	}
	parseLayouts := []string{}
	for _, layout := range usedLayouts {
		parseLayouts = append(parseLayouts, layout)
	}
	for _, layout := range parseLayouts {
		for range 12 {
			secs, nanos := randomUnix(r), randomNanos(r)
			offset, utc := randomOffset(r)
			valid := makeTime(secs, nanos, offset, utc).Format(layout)
			addParse(layout, valid)
			addParse(layout, mutate(r, valid))
		}
	}
	for range 2500 {
		secs, nanos := randomUnix(r), randomNanos(r)
		offset, utc := randomOffset(r)
		valid := makeTime(secs, nanos, offset, utc).Format(time.RFC3339Nano)
		addParse(time.RFC3339, mutate(r, valid))
		if r.IntN(2) == 0 {
			addParse(time.RFC3339Nano, valid)
		}
	}
	return v
}

func mutate(r *rand.Rand, s string) string {
	if s == "" {
		return "x"
	}
	b := []byte(s)
	i := r.IntN(len(b))
	alphabet := "0123456789-+:.,TZtz x"
	switch r.IntN(5) {
	case 0:
		b[i] = alphabet[r.IntN(len(alphabet))]
	case 1:
		b = append(b[:i], b[i+1:]...)
	case 2:
		b = append(b[:i], append([]byte{alphabet[r.IntN(len(alphabet))]}, b[i:]...)...)
	case 3:
		b = b[:i]
	case 4:
		b = append(b, alphabet[r.IntN(len(alphabet))])
	}
	return string(b)
}
