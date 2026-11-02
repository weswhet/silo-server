//go:build access_vectors

// Command access writes vectors for the rating ceilings, the metadata language normalization, and the
// decision log digest, from the real packages. Run it from the repository root:
//
//	GOTOOLCHAIN=go1.26.10 go run -tags access_vectors ./rust/conformance/vectors/generators/access
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"unsafe" // go:linkname, and reading the decision logger's queue

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/Silo-Server/silo-server/internal/access"
	apimw "github.com/Silo-Server/silo-server/internal/api/middleware"
	"github.com/Silo-Server/silo-server/internal/auth"
	"github.com/Silo-Server/silo-server/internal/lang"
	"github.com/Silo-Server/silo-server/internal/models"
	"github.com/Silo-Server/silo-server/internal/userstore"
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

	out["scope_input_nil"] = scopeInputNil()
	out["permission_input_nil"] = permissionInputNil()

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

//go:linkname parseLibraryIDList github.com/Silo-Server/silo-server/internal/access.parseLibraryIDList
func parseLibraryIDList(raw json.RawMessage) []int

type scopeNilCase struct {
	Name              string          `json:"name"`
	UserLibraryIDs    []int           `json:"user_library_ids"`
	GroupLibraryIDs   *[]int          `json:"group_library_ids,omitempty"`
	ProfileRows       *[]int          `json:"profile_rows"`
	DisabledRaw       string          `json:"disabled_raw"`
	ContentAccessOnly bool            `json:"content_access_only"`
	Input             json.RawMessage `json:"input"`
}

// scopeInputNil runs the real ViewerResolver.ResolveFacts with the real vendor engine and reads the input off
// the decision logger, so nothing here is a hand-built ScopeInput. The logger is never started; its queue is
// read directly. A profile's list goes through AttachAllowedLibraries, as every store read does.
func scopeInputNil() []scopeNilCase {
	ctx := context.Background()
	engine, err := policy.NewEngine(ctx)
	check(err)
	logger := policy.NewDecisionLogger(nil, "vectors")
	logger.SetVerbosity("verbose")
	logger.SetScopeSampleRate(1)
	field := reflect.ValueOf(logger).Elem().FieldByName("ch")
	queue := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem().Interface().(chan policy.Entry)
	resolver := policy.NewViewerResolver(nil, nil, nil, policy.NewPDP(engine, policy.WithDecisionLogger(logger)))

	empty, some, unsorted := []int{}, []int{3}, []int{5, 3, 3}
	type userCase struct {
		name  string
		ids   []int
		group *[]int
	}
	users := []userCase{
		{"account-nil", nil, nil}, {"account-empty", []int{}, nil}, {"account-some", unsorted, nil},
		{"group-nil", nil, new([]int)}, {"group-empty", nil, &empty}, {"group-some", nil, &some},
		{"account-over-group", []int{}, &some},
	}
	*users[3].group = nil
	profiles := []struct {
		name string
		rows *[]int
	}{{"no-profile", nil}, {"profile-no-rows", &empty}, {"profile-rows", &some}}
	disabled := []string{"", "null", "[]", "[1]", "[-1,0]", "[1,-1]", "[null,2]", `"x"`, "{}", "[1.5]", "[1e2]", "[9223372036854775808]"}

	var out []scopeNilCase
	for _, u := range users {
		for _, p := range profiles {
			for _, raw := range disabled {
				for _, contentOnly := range []bool{false, true} {
					user := &models.User{ID: 2, Role: "user", Enabled: true, LibraryIDs: u.ids}
					var group *access.GroupPolicy
					if u.group != nil {
						g := access.NoGroupPolicy()
						g.LibraryIDs = *u.group
						group = &g
					}
					effective := access.ApplyGroupPolicy(user, group)
					input := access.ResolveInput{UserID: 2, SkipPINVerification: true, ContentAccessOnly: contentOnly}
					var profile *userstore.Profile
					if p.rows != nil {
						input.ProfileID = "p"
						list := []userstore.Profile{{ID: "p"}}
						var rows []userstore.ProfileAllowedLibrary
						for _, id := range *p.rows {
							rows = append(rows, userstore.ProfileAllowedLibrary{ProfileID: "p", LibraryID: id})
						}
						userstore.AttachAllowedLibraries(list, rows)
						profile = &list[0]
					}
					prefs := access.ViewerPreferences{}
					if raw != "" {
						prefs.DisabledLibraryIDs = parseLibraryIDList(json.RawMessage(raw))
					}
					_, err := resolver.ResolveFacts(ctx, input, user, profile, effective, prefs)
					check(err)
					entry := <-queue
					rawOut := raw
					if rawOut == "" {
						rawOut = "null" // no row reads as the contract default, which is null
					}
					out = append(out, scopeNilCase{
						Name: u.name + "/" + p.name + "/" + raw, UserLibraryIDs: u.ids, GroupLibraryIDs: u.group,
						ProfileRows: p.rows, DisabledRaw: rawOut, ContentAccessOnly: contentOnly, Input: entry.InputSample,
					})
				}
			}
		}
	}
	return out
}

type permissionNilCase struct {
	Name        string          `json:"name"`
	Gate        string          `json:"gate"`
	Permissions []string        `json:"permissions"`
	LibraryIDs  []int           `json:"library_ids"`
	Mask        []string        `json:"mask"`
	Targets     []int           `json:"targets"`
	Input       json.RawMessage `json:"input"`
}

type capturingDecider struct{ seen []policy.PermissionInput }

func (d *capturingDecider) CheckPermission(_ context.Context, in policy.PermissionInput) (policy.PermissionDecision, policy.Meta, error) {
	d.seen = append(d.seen, in)
	return policy.PermissionDecision{Allowed: true}, policy.Meta{}, nil
}

type fixedUser struct{ user *models.User }

func (f fixedUser) GetByID(context.Context, int) (*models.User, error) { return f.user, nil }

type fixedLibraries []int

func (f fixedLibraries) ResolveMetadataTargetLibraryIDs(context.Context, string) ([]int, error) {
	return f, nil
}

type fixedGroup struct{ policy *access.GroupPolicy }

func (f fixedGroup) GetPolicyForUser(context.Context, int) (*access.GroupPolicy, error) {
	return f.policy, nil
}

// permissionInputNil runs the real gates with a decider that records what they send. users.permissions is NOT
// NULL, so the account's list is never nil from the store.
func permissionInputNil() []permissionNilCase {
	groupID := int64(1)
	var out []permissionNilCase
	run := func(name string, perms []string, libs []int, mask []string, hasMask bool, targets []int) {
		user := &models.User{ID: 2, Role: "user", Enabled: true, Permissions: perms, LibraryIDs: libs}
		var groups access.GroupPolicyProvider
		if hasMask {
			user.AccessGroupID = &groupID
			g := access.NoGroupPolicy()
			g.AllowedPermissions = mask
			groups = fixedGroup{&g}
		}
		decider := &capturingDecider{}
		gates := apimw.NewPolicyPermissionMiddleware(fixedUser{user}, fixedLibraries(targets), nil, nil, decider, groups)
		claims := &auth.Claims{UserID: 2, Role: "user"}
		next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})

		req := func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			rc := chi.NewRouteContext()
			rc.URLParams.Add("id", "c")
			ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
			return r.WithContext(apimw.SetClaims(ctx, claims))
		}
		gates.RequireMarkerEdit(next).ServeHTTP(httptest.NewRecorder(), req())
		out = append(out, permissionNilCase{Name: name + "/marker", Gate: "marker_edit", Permissions: perms, LibraryIDs: libs, Mask: mask, Input: mustJSON(decider.seen[0])})
		decider.seen = nil
		gates.RequireMetadataCurationForItem(next).ServeHTTP(httptest.NewRecorder(), req())
		out = append(out, permissionNilCase{Name: name + "/curation-only", Gate: "curation_only", Permissions: perms, LibraryIDs: libs, Mask: mask, Input: mustJSON(decider.seen[0])})
		out = append(out, permissionNilCase{Name: name + "/curation", Gate: "curation", Permissions: perms, LibraryIDs: libs, Mask: mask, Targets: targets, Input: mustJSON(decider.seen[1])})
	}
	for _, c := range []struct {
		name  string
		perms []string
		libs  []int
		mask  []string
		has   bool
	}{
		{"empty-perms-nil-libs", []string{}, nil, nil, false},
		{"perms-nil-libs", []string{"metadata_curation"}, nil, nil, false},
		{"perms-empty-libs", []string{"metadata_curation"}, []int{}, nil, false},
		{"perms-some-libs", []string{"metadata_curation"}, []int{4, 3}, nil, false},
		{"empty-mask", []string{"metadata_curation"}, nil, []string{}, true},
		{"nil-mask", []string{"metadata_curation"}, nil, nil, true},
		{"mask-miss", []string{"metadata_curation"}, nil, []string{"marker_edit"}, true},
		{"mask-hit", []string{"metadata_curation"}, nil, []string{"metadata_curation"}, true},
	} {
		run(c.name, c.perms, c.libs, c.mask, c.has, []int{7})
	}

	decider := &capturingDecider{}
	_, err := apimw.NewPolicyActingAdminDecider(decider, nil, nil)(context.Background(), apimw.ActingAdminRequest{Claims: &auth.Claims{UserID: 2, Role: "admin"}})
	check(err)
	out = append(out, permissionNilCase{Name: "acting-admin", Gate: "acting_admin", Permissions: []string{}, Input: mustJSON(decider.seen[0])})
	return out
}

func mustJSON(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	check(err)
	return raw
}

func overrides(value string) map[string]string {
	return parseMetadataLanguageOverrides(json.RawMessage(value))
}
