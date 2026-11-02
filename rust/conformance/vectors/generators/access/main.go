//go:build access_vectors

// Command access writes vectors for the rating ceilings, the metadata language normalization, and the
// decision log digest, from the real packages. Run it from the repository root:
//
//	GOTOOLCHAIN=go1.26.10 go run -tags access_vectors ./rust/conformance/vectors/generators/access
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	_ "unsafe" // go:linkname

	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/Silo-Server/silo-server/internal/access"
	"github.com/Silo-Server/silo-server/internal/lang"
	"github.com/Silo-Server/silo-server/internal/policy"
)

var ratings = []string{
	"", " ", "G", "PG", "pg-13", "PG 13", "PG.13", "R", "NC-17", "TV-Y", "TV-G", "TV-Y7", "TV-Y7-FV", "TV-PG", "TV-14", "TV-MA",
	"tv-ma", "MA", "MA15+", "MA 15+", "M", "US:M", "AU:M", "DE:16", "gb:15", "de: 12", "FSK 16", "FSK16", "12A", "U", "UC",
	"Rated R", "RATED PG-13", "Rated R for strong language", "Rated", "RatedR", "Unrated", "Not Rated", "NR", "NOT YET RATED",
	"16", "16+", "+16", "+16+", "21", "22", "100", "0", "1999", "AL", "ATP", "SAM 16", "B-15", "AA", "ALL", "M/12", "M/18",
	"UA", "UA 7+", "UA13+", "R15+", "PG12", "APTA", "L", "X", "X18+", "TP", "Tous publics", "junk", "XX:PG", "xyzw:PG", ":PG",
	"1:PG", "é", "PG-13 ", "ſ", "ı", "KR:ALL", "MX:A",
}

type overridesCase struct {
	Stored string            `json:"stored"`
	Out    map[string]string `json:"out"`
}

func main() {
	type ceiling struct {
		Raw    string `json:"raw"`
		System string `json:"system"`
		Age    *int   `json:"age"`
		OK     bool   `json:"ok"`
		CAge   *int   `json:"ceiling_age"`
		COK    bool   `json:"ceiling_ok"`
	}
	type stricter struct {
		A, B, Out string
	}
	out := map[string]any{}
	var cs []ceiling
	for _, raw := range ratings {
		system, age, ok := access.Normalize(raw)
		cage, cok := access.AgeForCeiling(raw)
		cs = append(cs, ceiling{Raw: raw, System: system, Age: age, OK: ok, CAge: cage, COK: cok})
	}
	out["ceilings"] = cs
	var ss []stricter
	for _, a := range ratings {
		for _, b := range ratings {
			ss = append(ss, stricter{a, b, access.StricterCeiling(a, b)})
		}
	}
	out["stricter"] = ss

	// parseMetadataLanguageOverrides is unexported, so it is linked by name below.
	stored := []string{
		`{"en":"de"}`, `{"eng":"de","en":"fr"}`, `{"EN":"pt-br"}`, `{"":"de"}`, `{" ":"de"}`, `{"en":""}`, `{"en":null}`,
		`{"en":null,"fr":"de"}`, `{"zz-not-a-lang":"de"}`, `{"en":"not a tag"}`, `{"ja":"x-silo-original"}`, `{}`, `null`,
		`[]`, `"x"`, `{"en":1}`, `{"fil":"EN-us"}`, `{"en":"de","eng":"fr","ENG":"it"}`, `{"zh-hant":"zh-hans"}`,
	}
	var os_ []overridesCase
	for _, s := range stored {
		os_ = append(os_, overridesCase{s, overrides(s)})
	}
	out["overrides"] = os_

	var canon [][2]string
	for _, v := range []string{"", "en", "EN", " eng ", "fil", "zh-Hant", "pt-BR", "not a tag", "zz", "und", "x-silo-original", "é"} {
		canon = append(canon, [2]string{v, lang.Canonical(v)})
	}
	out["canonical"] = canon

	// DecisionLogger's digest and shape are the exported marshal of the input.
	raw, err := json.Marshal(policy.ScopeInput{SchemaVersion: 1, UserID: 2, SessionID: "s", ProfileID: "p", RequestTime: "2026-01-02T03:04:05Z"})
	check(err)
	out["scope_input"] = string(raw)

	// chi's Recoverer, for the listener's answer to a panic.
	type recovered struct {
		Connection string `json:"connection"`
		Status     int    `json:"status"`
		Body       string `json:"body"`
		Written    bool   `json:"written"`
	}
	var rec []recovered
	for _, c := range []string{"", "close", "Upgrade", "upgrade"} {
		w := httptest.NewRecorder()
		h := chimw.Recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if c != "" {
			r.Header.Set("Connection", c)
		}
		stderr := os.Stderr
		os.Stderr, _ = os.Open(os.DevNull)
		h.ServeHTTP(w, r)
		os.Stderr = stderr
		wrote := w.Result().StatusCode != 200 || w.Body.Len() > 0
		rec = append(rec, recovered{c, w.Code, w.Body.String(), wrote})
	}
	out["recoverer"] = rec

	data, err := json.MarshalIndent(out, "", " ")
	check(err)
	check(os.WriteFile("rust/conformance/vectors/access/access.json", append(data, '\n'), 0o644))
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}

//go:linkname parseMetadataLanguageOverrides github.com/Silo-Server/silo-server/internal/access.parseMetadataLanguageOverrides
func parseMetadataLanguageOverrides(raw json.RawMessage) map[string]string

func overrides(value string) map[string]string {
	return parseMetadataLanguageOverrides(json.RawMessage(value))
}
