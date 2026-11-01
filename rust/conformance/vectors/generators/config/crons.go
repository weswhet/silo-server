//go:build silo_config_vectors

package main

import (
	"fmt"
	"math"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

func bitsOf(f float64) uint64 { return math.Float64bits(f) }

var (
	secondParser    = cron.NewParser(cron.Second | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.DowOptional | cron.Descriptor)
	standardParser  = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	optSecondParser = cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow | cron.Descriptor)
	noDescParser    = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	subsetParser    = cron.NewParser(cron.Hour | cron.Dom | cron.Month | cron.DowOptional)
)

var parsers = map[string]cron.Parser{
	"second": secondParser, "standard": standardParser, "optsecond": optSecondParser, "nodesc": noDescParser, "subset": subsetParser,
}

type cronSchedule struct {
	Second   string `json:"second,omitempty"`
	Minute   string `json:"minute,omitempty"`
	Hour     string `json:"hour,omitempty"`
	Dom      string `json:"dom,omitempty"`
	Month    string `json:"month,omitempty"`
	Dow      string `json:"dow,omitempty"`
	Location string `json:"location,omitempty"`
	Delay    int64  `json:"delay,omitempty"`
}

type cronParse struct {
	Parser string `json:"parser"`
	Spec   string `json:"spec"`
	result
}

type cronTime struct {
	Unix  int64  `json:"unix"`
	Nanos int    `json:"nanos"`
	Loc   string `json:"loc"`
}

type cronNext struct {
	Parser string    `json:"parser"`
	Spec   string    `json:"spec"`
	From   cronTime  `json:"from"`
	Next   *cronTime `json:"next"`
	Offset int       `json:"offset"`
	Year   int       `json:"year"`
	Text   string    `json:"text"`
	Hang   bool      `json:"-"`
}

func locName(l *time.Location) string {
	switch l {
	case time.Local:
		return "Local"
	case time.UTC:
		return "UTC"
	}
	return l.String()
}

func describe(s cron.Schedule) cronSchedule {
	switch v := s.(type) {
	case *cron.SpecSchedule:
		return cronSchedule{
			Second: fmt.Sprintf("%x", v.Second), Minute: fmt.Sprintf("%x", v.Minute), Hour: fmt.Sprintf("%x", v.Hour),
			Dom: fmt.Sprintf("%x", v.Dom), Month: fmt.Sprintf("%x", v.Month), Dow: fmt.Sprintf("%x", v.Dow), Location: locName(v.Location),
		}
	case cron.ConstantDelaySchedule:
		return cronSchedule{Delay: int64(v.Delay)}
	}
	panic("unknown schedule")
}

// getTime is robfig's own test helper from spec_test.go, with Local being UTC under TZ=UTC.
func getTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	location := time.Local
	if strings.HasPrefix(value, "TZ=") {
		parts := strings.Fields(value)
		loc, err := time.LoadLocation(parts[0][len("TZ="):])
		if err != nil {
			panic(err)
		}
		location = loc
		value = parts[1]
	}
	for _, layout := range []string{"Mon Jan 2 15:04 2006", "Mon Jan 2 15:04:05 2006"} {
		if t, err := time.ParseInLocation(layout, value, location); err == nil {
			return t
		}
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04:05-0700", value, location); err == nil {
		return t
	}
	panic("could not parse time value " + value)
}

func encodeTime(t time.Time) cronTime {
	name := t.Location().String()
	_, off := t.Zone()
	if t.Location() == time.UTC || t.Location() == time.Local {
		name = "UTC"
	} else if name == "" {
		name = fmt.Sprintf("fixed:%d", off)
	}
	return cronTime{Unix: t.Unix(), Nanos: t.Nanosecond(), Loc: name}
}

// cronHangs records inputs on which robfig's Next never returns. A vector cannot hold an answer for
// them, and each one leaves a goroutine spinning until this process exits.
var cronHangs []cronNext

func nextVector(parser, spec string, from time.Time) cronNext {
	sched, err := parsers[parser].Parse(spec)
	if err != nil {
		panic(fmt.Sprintf("%s: %v", spec, err))
	}
	vec := cronNext{Parser: parser, Spec: spec, From: encodeTime(from)}
	done := make(chan time.Time, 1)
	go func() { done <- sched.Next(from) }()
	var next time.Time
	select {
	case next = <-done:
	case <-time.After(3 * time.Second):
		cronHangs = append(cronHangs, vec)
		vec.Hang = true
		return vec
	}
	if !next.IsZero() {
		enc := encodeTime(next)
		vec.Next = &enc
		_, vec.Offset = next.Zone()
		vec.Year = next.Year()
		vec.Text = next.Format("2006-01-02T15:04:05.999999999Z07:00 Mon")
	}
	return vec
}

// The cases from robfig/cron v3.0.1's spec_test.go, parser_test.go, and constantdelay_test.go.
var robfigNext = [][2]string{
	{"Mon Jul 9 14:45 2012", "0 0/15 * * * *"}, {"Mon Jul 9 14:59 2012", "0 0/15 * * * *"}, {"Mon Jul 9 14:59:59 2012", "0 0/15 * * * *"},
	{"Mon Jul 9 15:45 2012", "0 20-35/15 * * * *"}, {"Mon Jul 9 23:46 2012", "0 */15 * * * *"}, {"Mon Jul 9 23:45 2012", "0 20-35/15 * * * *"},
	{"Mon Jul 9 23:35:51 2012", "15/35 20-35/15 * * * *"}, {"Mon Jul 9 23:35:51 2012", "15/35 20-35/15 1/2 * * *"}, {"Mon Jul 9 23:35:51 2012", "15/35 20-35/15 10-12 * * *"},
	{"Mon Jul 9 23:35:51 2012", "15/35 20-35/15 1/2 */2 * *"}, {"Mon Jul 9 23:35:51 2012", "15/35 20-35/15 * 9-20 * *"}, {"Mon Jul 9 23:35:51 2012", "15/35 20-35/15 * 9-20 Jul *"},
	{"Mon Jul 9 23:35 2012", "0 0 0 9 Apr-Oct ?"}, {"Mon Jul 9 23:35 2012", "0 0 0 */5 Apr,Aug,Oct Mon"}, {"Mon Jul 9 23:35 2012", "0 0 0 */5 Oct Mon"},
	{"Mon Jul 9 23:35 2012", "0 0 0 * Feb Mon"}, {"Mon Jul 9 23:35 2012", "0 0 0 * Feb Mon/2"}, {"Mon Dec 31 23:59:45 2012", "0 * * * * *"},
	{"Mon Jul 9 23:35 2012", "0 0 0 29 Feb ?"}, {"2012-03-11T00:00:00-0500", "TZ=America/New_York 0 30 2 11 Mar ?"},
	{"2012-03-11T00:00:00-0500", "TZ=America/New_York 0 0 * * * ?"}, {"2012-03-11T01:00:00-0500", "TZ=America/New_York 0 0 * * * ?"}, {"2012-03-11T03:00:00-0400", "TZ=America/New_York 0 0 * * * ?"}, {"2012-03-11T04:00:00-0400", "TZ=America/New_York 0 0 * * * ?"},
	{"2012-03-11T00:00:00-0500", "CRON_TZ=America/New_York 0 0 * * * ?"}, {"2012-03-11T01:00:00-0500", "CRON_TZ=America/New_York 0 0 * * * ?"}, {"2012-03-11T03:00:00-0400", "CRON_TZ=America/New_York 0 0 * * * ?"}, {"2012-03-11T04:00:00-0400", "CRON_TZ=America/New_York 0 0 * * * ?"},
	{"2012-03-11T00:00:00-0500", "TZ=America/New_York 0 0 1 * * ?"}, {"2012-03-11T01:00:00-0500", "TZ=America/New_York 0 0 1 * * ?"}, {"2012-03-11T00:00:00-0500", "TZ=America/New_York 0 0 2 * * ?"},
	{"2012-11-04T00:00:00-0400", "TZ=America/New_York 0 30 2 04 Nov ?"}, {"2012-11-04T01:45:00-0400", "TZ=America/New_York 0 30 1 04 Nov ?"},
	{"2012-11-04T00:00:00-0400", "TZ=America/New_York 0 0 * * * ?"}, {"2012-11-04T01:00:00-0400", "TZ=America/New_York 0 0 * * * ?"}, {"2012-11-04T01:00:00-0500", "TZ=America/New_York 0 0 * * * ?"},
	{"2012-11-04T00:00:00-0400", "TZ=America/New_York 0 0 1 * * ?"}, {"2012-11-04T01:00:00-0400", "TZ=America/New_York 0 0 1 * * ?"}, {"2012-11-04T01:00:00-0500", "TZ=America/New_York 0 0 1 * * ?"},
	{"2012-11-04T00:00:00-0400", "TZ=America/New_York 0 0 2 * * ?"}, {"2012-11-04T02:00:00-0500", "TZ=America/New_York 0 0 2 * * ?"},
	{"2012-11-04T00:00:00-0400", "TZ=America/New_York 0 0 3 * * ?"}, {"2012-11-04T03:00:00-0500", "TZ=America/New_York 0 0 3 * * ?"},
	{"TZ=America/New_York 2012-11-04T00:00:00-0400", "0 0 * * * ?"}, {"TZ=America/New_York 2012-11-04T01:00:00-0400", "0 0 * * * ?"}, {"TZ=America/New_York 2012-11-04T01:00:00-0500", "0 0 * * * ?"},
	{"TZ=America/New_York 2012-11-04T00:00:00-0400", "0 0 1 * * ?"}, {"TZ=America/New_York 2012-11-04T01:00:00-0400", "0 0 1 * * ?"}, {"TZ=America/New_York 2012-11-04T01:00:00-0500", "0 0 1 * * ?"},
	{"TZ=America/New_York 2012-11-04T00:00:00-0400", "0 0 2 * * ?"}, {"TZ=America/New_York 2012-11-04T02:00:00-0500", "0 0 2 * * ?"},
	{"TZ=America/New_York 2012-11-04T00:00:00-0400", "0 0 3 * * ?"}, {"TZ=America/New_York 2012-11-04T03:00:00-0500", "0 0 3 * * ?"},
	{"Mon Jul 9 23:35 2012", "0 0 0 30 Feb ?"}, {"Mon Jul 9 23:35 2012", "0 0 0 31 Apr ?"},
	{"TZ=America/New_York 2012-11-04T00:00:00-0400", "0 0 3 3 * ?"},
	{"2018-10-17T05:00:00-0400", "TZ=America/Sao_Paulo 0 0 9 10 * ?"}, {"2018-02-14T05:00:00-0500", "TZ=America/Sao_Paulo 0 0 9 22 * ?"},
}

var robfigActivation = [][2]string{
	{"Mon Jul 9 15:00 2012", "0/15 * * * *"}, {"Mon Jul 9 15:45 2012", "0/15 * * * *"}, {"Mon Jul 9 15:40 2012", "0/15 * * * *"},
	{"Mon Jul 9 15:05 2012", "5/15 * * * *"}, {"Mon Jul 9 15:20 2012", "5/15 * * * *"}, {"Mon Jul 9 15:50 2012", "5/15 * * * *"},
	{"Sun Jul 15 15:00 2012", "0/15 * * Jul *"}, {"Sun Jul 15 15:00 2012", "0/15 * * Jun *"}, {"Sun Jul 15 08:30 2012", "30 08 ? Jul Sun"}, {"Sun Jul 15 08:30 2012", "30 08 15 Jul ?"},
	{"Mon Jul 16 08:30 2012", "30 08 ? Jul Sun"}, {"Mon Jul 16 08:30 2012", "30 08 15 Jul ?"}, {"Mon Jul 9 15:00 2012", "@hourly"}, {"Mon Jul 9 15:04 2012", "@hourly"},
	{"Mon Jul 9 15:00 2012", "@daily"}, {"Mon Jul 9 00:00 2012", "@daily"}, {"Mon Jul 9 00:00 2012", "@weekly"}, {"Sun Jul 8 00:00 2012", "@weekly"}, {"Sun Jul 8 01:00 2012", "@weekly"},
	{"Sun Jul 8 00:00 2012", "@monthly"}, {"Sun Jul 1 00:00 2012", "@monthly"}, {"Sun Jul 15 00:00 2012", "* * 1,15 * Sun"}, {"Fri Jun 15 00:00 2012", "* * 1,15 * Sun"}, {"Wed Aug 1 00:00 2012", "* * 1,15 * Sun"},
	{"Sun Jul 15 00:00 2012", "* * */10 * Sun"}, {"Sun Jul 15 00:00 2012", "* * * * Mon"}, {"Mon Jul 9 00:00 2012", "* * 1,15 * *"}, {"Sun Jul 15 00:00 2012", "* * 1,15 * *"}, {"Sun Jul 15 00:00 2012", "* * */2 * Sun"},
}

var robfigWithTZ = [][2]string{
	{"2016-01-03T13:09:03+0530", "14 14 * * *"}, {"2016-01-03T04:09:03+0530", "14 14 * * ?"}, {"2016-01-03T14:09:03+0530", "14 14 * * *"}, {"2016-01-03T14:00:00+0530", "14 14 * * ?"},
}

var robfigDelays = []struct {
	time  string
	delay string
}{
	{"Mon Jul 9 14:45 2012", "15m0.00000005s"}, {"Mon Jul 9 14:59 2012", "15m"}, {"Mon Jul 9 14:59:59 2012", "15m"}, {"Mon Jul 9 15:45 2012", "35m"}, {"Mon Jul 9 23:46 2012", "14m"}, {"Mon Jul 9 23:45 2012", "35m"},
	{"Mon Jul 9 23:35:51 2012", "44m24s"}, {"Mon Jul 9 23:35:51 2012", "25h44m24s"}, {"Mon Jul 9 23:35 2012", "2184h25m"}, {"Mon Dec 31 23:59:45 2012", "15s"}, {"Mon Jul 9 14:45:00 2012", "15ms"}, {"Mon Jul 9 14:45:00.005 2012", "15m"}, {"Mon Jul 9 14:45:00.005 2012", "15m0.00000005s"},
}

func writeCronVectors() {
	specs := []struct{ parser, spec string }{}
	add := func(parser string, list ...string) {
		for _, s := range list {
			specs = append(specs, struct{ parser, spec string }{parser, s})
		}
	}
	add("second", "0 5 * * * *", "CRON_TZ=UTC  0 5 * * * *", "CRON_TZ=Asia/Tokyo 0 5 * * * *", "@every 5m", "@midnight", "TZ=UTC  @midnight", "TZ=Asia/Tokyo @midnight", "@yearly", "@annually", "* 5 * * * *",
		"* 5 j * * *", "@every Xm", "@unrecognized", "* * * *", "", "0 0 15 */3 *", "5 5", "TZ=America/New_York 0 30 2 11 Mar ?")
	add("standard", "5 * * * *", "CRON_TZ=UTC  5 * * * *", "@every 5m", "5 j * * *", "* * * *", "xyz", "60 0 * * *", "0 60 * * *", "0 0 * * XYZ", "TZ=America/New_York 15/0 * * * *",
		"0 0 32 * *", "0 0 0 * *", "0 0 * 13 *", "0 0 * 0 *", "0 0 * * 7", "0 24 * * *", "* * * * ?", "? ? ? ? ?", "*/2 */3 */4 */5 */6", "1,2,3 4 5 6 0", "1-5 * * * *", "5-1 * * * *", "5--7 * * * *", "1/2/3 * * * *", "*/0 * * * *", "*/-1 * * * *", "-1 * * * *", "+5 * * * *", "1_0 * * * *", "99999999999999999999 * * * *",
		", * * * *", ",,1,, * * * *", "1, * * * *", " 1 2 3 4 5 ", "\t1\t2\t3\t4\t5", "1 2 3 jan sun", "1 2 3 JAN SUN", "1 2 3 Jan-Mar Mon-Fri", "1 2 3 jan-dec sun-sat", "1 2 3 foo *", "1 2 3 * foo", "1 2 3 4", "1 2 3 4 5 6",
		"@hourly", "@daily", "@weekly", "@monthly", "@yearly", "@annually", "@midnight", "@every", "@every ", "@every 1h30m", "@every 500ms", "@every 1m30.5s", "@every 0s", "@every -5m", "@every 1d", "@HOURLY", "@ hourly", " @hourly",
		"TZ=UTC 5 * * * *", "TZ=UTC\t5 * * * *", "TZ=Nope/Nope 5 * * * *", "TZ=../etc/passwd 5 * * * *", "TZ=/etc/localtime 5 * * * *", "TZ=\\x 5 * * * *", "TZ= 5 * * * *", "TZ=Local 5 * * * *", "CRON_TZ=Local 5 * * * *", "CRON_TZ=UTC", "TZ=UTC", "TZ=America/New_York", "CRON_TZ=Asia/Tokyo @every 5m", "CRON_TZ=Asia/Tokyo  @daily", "CRON_TZ=Europe/London 0 3 * * *",
		"0 3 * * *", "0 4 * * *", "30 4 * * *", "0 5 * * *", "59 23 31 12 6", "0/1 * * * *", "0-59/1 * * * *", "0-59/60 * * * *", "59/1 * * * *", "*/1 * * * *", "*/100 * * * *", "?/2 * * * *", "1-2-3 * * * *", "a-b * * * *", "jan * * * *", "* * * mon *", "* * * * jan")
	add("optsecond", "0 5 * * * *", "5 5 * * * *", "5 * * * *", "* * * *", "* * * * * * *", "@daily")
	add("nodesc", "@every 1m", "@hourly", "5 * * * *", "TZ=UTC @daily")
	add("subset", "5 15 * 4", "5 15 *", "5 15", "5 15 * * *", "@daily")

	parses := make([]cronParse, 0, len(specs))
	for _, s := range specs {
		s := s
		parses = append(parses, cronParse{Parser: s.parser, Spec: s.spec, result: catch(func() result {
			sched, err := parsers[s.parser].Parse(s.spec)
			if err != nil {
				return result{Error: err.Error()}
			}
			return result{Ok: describe(sched)}
		})})
	}

	nexts := []cronNext{}
	add2 := func(v cronNext) {
		if !v.Hang {
			nexts = append(nexts, v)
		}
	}
	for _, c := range robfigNext {
		add2(nextVector("second", c[1], getTime(c[0])))
	}
	for _, c := range robfigActivation {
		add2(nextVector("standard", c[1], getTime(c[0]).Add(-time.Second)))
	}
	for _, c := range robfigWithTZ {
		t, err := time.Parse("2006-01-02T15:04:05-0700", c[0])
		if err != nil {
			panic(err)
		}
		add2(nextVector("standard", c[1], t))
	}
	for _, c := range robfigDelays {
		from, err := time.ParseInLocation("Mon Jan 2 15:04:05.000 2006", c.time, time.UTC)
		if err != nil {
			from = getTime(c.time)
		}
		add2(nextVector("standard", "@every "+c.delay, from))
	}

	// A seeded sweep through DST rules: gaps at midnight, half-hour shifts, whole-day zone changes.
	zones := []string{"UTC", "America/New_York", "America/Sao_Paulo", "Asia/Tokyo", "Asia/Kathmandu", "Australia/Lord_Howe", "Europe/London", "Africa/Casablanca", "Pacific/Apia", "America/St_Johns", "Asia/Gaza", "America/Havana"}
	sweepSpecs := []string{
		"0 0 * * * *", "0 30 * * * *", "0 0 0 * * *", "0 30 0 * * *", "0 0 1 * * *", "0 30 1 * * *", "0 0 2 * * *", "0 30 2 * * *", "0 0 3 * * *", "0 0 12 * * *", "0 0 23 * * *", "0 59 23 * * *",
		"15 */7 */3 * * *", "0 0 0 1 * *", "0 0 0 31 * *", "0 0 0 29 2 *", "0 0 0 * * 0", "0 0 6 * * 1-5", "0 0 0 1 1 *", "0 0 0 13 * 5", "* * * * * *", "0 * * * * *", "30 15 10 15 * ?", "0 0 0 ? * sat",
	}
	rng := rand.New(rand.NewPCG(14, 27))
	starts := []string{"2012-03-11T06:30:00Z", "2012-11-04T05:30:00Z", "2018-10-14T02:30:00Z", "2018-11-03T23:30:00Z", "2021-03-28T00:30:00Z", "2021-10-31T00:30:00Z", "2011-12-29T09:30:00Z", "2023-03-26T01:30:00Z", "2023-04-23T02:30:00Z", "2024-02-28T23:59:59Z", "2024-12-31T23:59:59Z", "2025-10-05T15:30:00Z", "2026-11-01T05:59:30Z"}
	for _, zone := range zones {
		loc, err := time.LoadLocation(zone)
		if err != nil {
			panic(err)
		}
		for _, spec := range sweepSpecs {
			for _, start := range starts {
				base, err := time.Parse(time.RFC3339, start)
				if err != nil {
					panic(err)
				}
				if rng.IntN(3) != 0 {
					continue
				}
				from := base.Add(time.Duration(rng.IntN(7200)) * time.Second).Add(time.Duration(rng.IntN(2)) * 500 * time.Millisecond)
				add2(nextVector("second", "TZ="+zone+" "+spec, from))
				add2(nextVector("second", spec, from.In(loc)))
				add2(nextVector("second", "CRON_TZ="+zone+" "+spec, from.In(time.FixedZone("", 19800))))
			}
		}
	}
	write("cron.json", map[string]any{"parse": parses, "next": nexts, "hangs": cronHangs})
}
