//go:build silo_config_vectors

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"

	settingsv1 "github.com/Silo-Server/silo-server/contracts/settings/v1"
	"github.com/Silo-Server/silo-server/internal/settingscontract"
	"github.com/Silo-Server/silo-server/internal/settingskeys"
	"github.com/Silo-Server/silo-server/internal/settingsresolve"
	"github.com/Silo-Server/silo-server/internal/userstore"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

type valueVector struct {
	Key      string `json:"key"`
	Value    string `json:"value"`
	ValueHex string `json:"value_hex"`
	Error    string `json:"error,omitempty"`
	Normal   string `json:"normalized,omitempty"`
}

func normalizeError(msg string) string {
	cwd := must(os.Getwd())
	msg = strings.ReplaceAll(msg, cwd, "<CWD>")
	lines := strings.Split(msg, "\n")
	// Validator errors over a Go map come in random order, so compare them as a set.
	sort.Strings(lines[min(1, len(lines)):])
	for i, line := range lines {
		if before, list, ok := strings.Cut(line, "additional properties "); ok {
			names, after, _ := strings.Cut(list, " not allowed")
			parts := strings.Split(names, ", ")
			sort.Strings(parts)
			lines[i] = before + "additional properties " + strings.Join(parts, ", ") + " not allowed" + after
		}
	}
	return strings.Join(lines, "\n")
}

func writeContractVectors() {
	manifest := settingscontract.MustLoad()
	schemas := settingscontract.ObjectSchemas()
	canonical := must(settingscontract.CanonicalBytes())
	public := must(settingscontract.PublicBytes())

	type defInfo struct {
		Key     string   `json:"key"`
		Remote  bool     `json:"remote"`
		Scopes  []string `json:"scopes_r1"`
		Admin   bool     `json:"admin_default"`
		Default string   `json:"default_value"`
	}
	defs := []defInfo{}
	for _, k := range manifest.Keys() {
		d, _ := manifest.Lookup(k)
		scopes := []string{}
		for _, s := range d.ScopesAtRevision(1) {
			scopes = append(scopes, string(s))
		}
		defs = append(defs, defInfo{Key: k, Remote: d.IsRemote(), Scopes: scopes, Admin: d.AdminDefault, Default: string(d.DefaultValue)})
	}

	values := []string{
		"", " ", "null", " null ", "true", "false", "True", "1", "0", "-1", "1.0", "1.5", "5", "10", "15", "30", "60", "100", "1000", "1e2", "1e999", "99999999999999999999", `"1.5"`, `"5"`, `"abc"`, `""`, `"true"`, `"en"`, `"EN-us"`, `"eng"`, `"x"`, `"not a language"`, "[]", "{}", `[1]`, `["a"]`, `{"a":1}`, `true]`, `true x`, `1 2`, `"a" "b"`, "[", "{", `"unterminated`, `"\ud800"`, `"\udc00"`, `"\ud83d\ude00"`, "\"\xff\"", "\u00a0true\u00a0",
		`{"a":1,"a":2}`, `[{"a":1,"a":2}]`, strings.Repeat("[", 70) + strings.Repeat("]", 70),
		`"never"`, `"ask"`, `"always"`, `"combined"`, `"separate"`, `"auto"`, `"12h"`, `"24h"`, `"system"`,
		`{"fontSize":"small"}`, `{"fontSize":"nope"}`, `{"nope":1}`, `{"fontColor":"#ffffff","backgroundOpacity":50}`, `{"backgroundOpacity":101}`, `{"textOpacity":0}`, `{"fontFamily":"a(b"}`, `{"fontFamily":""}`, `{"fontFamily":"ヒラギノ角ゴ ProN"}`, `{"textOutline":"x"}`,
		`{"items":[]}`, `{"items":[{"type":"builtin","destination":"home"}]}`, `{"items":[{"type":"builtin","destination":"home"},{"type":"builtin","destination":"home"}]}`, `{"items":[{"type":"library","library_id":1},{"type":"library","library_id":1,"label":"x"}]}`, `{"items":[{"type":"library","library_id":1.0}]}`, `{"items":[{"type":"section","library_id":1,"section_id":"s"}]}`, `{"items":[{"type":"collection","collection_id":"c"}]}`, `{"items":[{"type":"nope"}]}`, `{"items":[{"type":"library"}]}`,
		`[1,2,3]`, `[1,1]`, `[0]`, `[-1]`, `["1"]`, `{"en":"fr"}`, `{"EN":"fr"}`, `{"en":"x y"}`, `{"--color":"#fff"}`, `{"bad key":"x"}`, `{"sort":"name"}`, `{"size":"large"}`,
	}
	vectors := []valueVector{}
	for _, k := range manifest.Keys() {
		d, _ := manifest.Lookup(k)
		cases := append([]string{string(d.DefaultValue)}, values...)
		for _, m := range d.ValueSchema.Values {
			cases = append(cases, string(must(json.Marshal(m.Value))))
		}
		for _, v := range cases {
			vec := valueVector{Key: k, Value: v, ValueHex: hex.EncodeToString([]byte(v))}
			if n, err := d.ValueSchema.NormalizeValue(json.RawMessage(v), schemas); err != nil {
				vec.Error = normalizeError(err.Error())
			} else {
				vec.Normal = string(n)
			}
			vectors = append(vectors, vec)
		}
	}

	type compareVector struct {
		Key string `json:"key"`
		A   string `json:"a"`
		B   string `json:"b"`
		Out int    `json:"out"`
	}
	compares := []compareVector{}
	for _, k := range manifest.Keys() {
		d, _ := manifest.Lookup(k)
		if d.ValueSchema.Type == settingscontract.TypeObject {
			continue
		}
		cands := []string{string(d.DefaultValue), "1", "5", "null", `"x"`, "true", " 2 ", `"1.5"`}
		for _, m := range d.ValueSchema.Values {
			cands = append(cands, string(must(json.Marshal(m.Value))))
		}
		for _, a := range cands {
			for _, b := range cands {
				compares = append(compares, compareVector{k, a, b, d.ValueSchema.CompareValues(json.RawMessage(a), json.RawMessage(b))})
			}
		}
	}

	type mirrorVector struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Mirror  string `json:"mirror,omitempty"`
		Logical string `json:"logical"`
		Write   string `json:"write,omitempty"`
		Has     bool   `json:"has"`
		Error   string `json:"error,omitempty"`
	}
	mirrors := []mirrorVector{}
	for _, k := range []string{settingskeys.PlaybackAutoSkipIntro, settingskeys.PlaybackIntroSkipMode, "ui.theme", "nope"} {
		for _, v := range []string{"true", "false", "null", `"never"`, `"ask"`, `"always"`, `"bogus"`, "1", "{"} {
			vec := mirrorVector{Key: k, Value: v, Logical: settingscontract.LogicalKey(k)}
			if m, ok := settingscontract.MirrorKey(k); ok {
				vec.Mirror = m
			}
			w, has, err := settingscontract.MirrorWrite(k, json.RawMessage(v))
			vec.Has = has
			if err != nil {
				vec.Error = err.Error()
			} else if has {
				vec.Write = w.Key + "=" + string(w.Value)
			}
			mirrors = append(mirrors, vec)
		}
	}

	type manifestVector struct {
		Doc         string `json:"doc"`
		Error       string `json:"error,omitempty"`
		SchemaError string `json:"schema_error,omitempty"`
	}
	manifestSchema := func() *jsonschema.Schema {
		raw := must(settingsv1.FS.ReadFile("manifest.schema.json"))
		doc := must(jsonschema.UnmarshalJSON(strings.NewReader(string(raw))))
		compiler := jsonschema.NewCompiler()
		if err := compiler.AddResource("manifest.schema.json", doc); err != nil {
			panic(err)
		}
		return must(compiler.Compile("manifest.schema.json"))
	}()
	ok := `{"key":"a.b","introduced_in":1,"persistence":"remote","allowed_scopes":["profile"],"resolution_order":["profile","default"],"value_schema":{"type":"boolean"},"default_value":true,"category":"c","label":"l","description":"d"}`
	wrap := func(d string) string { return `{"api_version":1,"revision":3,"definitions":[` + d + `]}` }
	rep := func(from, to string) string { return wrap(strings.Replace(ok, from, to, 1)) }
	schemaDef := func(schema, def string) string {
		return wrap(strings.Replace(strings.Replace(ok, `{"type":"boolean"}`, schema, 1), `"default_value":true`, `"default_value":`+def, 1))
	}
	docs := []string{
		wrap(ok), `{"api_version":0,"revision":0,"definitions":[]}`, wrap(ok + "," + ok), rep(`"introduced_in":1`, `"introduced_in":0`), rep(`"introduced_in":1`, `"introduced_in":9`),
		rep(`"persistence":"remote"`, `"persistence":"x"`), rep(`"allowed_scopes":["profile"]`, `"allowed_scopes":[]`), rep(`"allowed_scopes":["profile"]`, `"allowed_scopes":["profile","profile"]`), rep(`"allowed_scopes":["profile"]`, `"allowed_scopes":["client_local"]`),
		rep(`"allowed_scopes":["profile"]`, `"allowed_scopes":[{"scope":"profile","introduced_in":9}]`), rep(`"resolution_order":["profile","default"]`, `"resolution_order":[]`), rep(`"resolution_order":["profile","default"]`, `"resolution_order":["profile"]`), rep(`"resolution_order":["profile","default"]`, `"resolution_order":["default","profile","default"]`), rep(`"resolution_order":["profile","default"]`, `"resolution_order":["profile_device","default"]`), rep(`"resolution_order":["profile","default"]`, `"resolution_order":["default"]`),
		schemaDef(`{"type":"nope"}`, "true"), schemaDef(`{"type":"integer"}`, "1"), schemaDef(`{"type":"integer","minimum":5,"maximum":1}`, "3"), schemaDef(`{"type":"integer","minimum":0,"maximum":9,"step":0}`, "3"), schemaDef(`{"type":"integer","minimum":0,"maximum":9}`, "30"),
		schemaDef(`{"type":"integer","minimum":0,"maximum":[{"value":9},{"value":5,"introduced_in":2}]}`, "3"), schemaDef(`{"type":"integer","minimum":[{"value":0},{"value":1}],"maximum":9}`, "3"), schemaDef(`{"type":"integer","minimum":[{"value":0,"introduced_in":2}],"maximum":9}`, "3"), schemaDef(`{"type":"integer","minimum":[{"value":1},{"value":0,"introduced_in":9}],"maximum":9}`, "3"), schemaDef(`{"type":"integer","minimum":[{"value":1},{"value":0,"introduced_in":1}],"maximum":9}`, "3"), schemaDef(`{"type":"integer","minimum":[],"maximum":9}`, "3"),
		schemaDef(`{"type":"string"}`, `"a"`), schemaDef(`{"type":"string","max_length":0}`, `"a"`), schemaDef(`{"type":"string","min_length":5,"max_length":1}`, `"a"`), schemaDef(`{"type":"string","max_length":5,"pattern":"("}`, `"a"`), schemaDef(`{"type":"string","max_length":5,"pattern":"^b$"}`, `"a"`),
		schemaDef(`{"type":"enum"}`, `"a"`), schemaDef(`{"type":"enum","values":[{"value":"a"},{"value":"a"}]}`, `"a"`), schemaDef(`{"type":"enum","values":[{"value":"a","introduced_in":9}]}`, `"a"`), schemaDef(`{"type":"enum","values":[{"value":1},{"value":1.0}]}`, `1`), schemaDef(`{"type":"enum","values":[{"value":"a"}]}`, `"b"`),
		schemaDef(`{"type":"object"}`, `{}`), schemaDef(`{"type":"object","schema_ref":"nope.json"}`, `{}`), schemaDef(`{"type":"boolean"}`, "null"), schemaDef(`{"type":"boolean","nullable":true}`, "null"), strings.Replace(wrap(ok), `"default_value":true,`, "", 1),
		rep(`"category":"c"`, `"constrained_by":{"policy_input":"p","constraint":"ceiling"},"category":"c"`), rep(`"category":"c"`, `"constrained_by":{"policy_input":" ","constraint":"locked"},"category":"c"`), rep(`"category":"c"`, `"constrained_by":{"policy_input":"p","constraint":"nope"},"category":"c"`), rep(`"category":"c"`, `"admin_default":true,"category":"c"`), rep(`"category":"c"`, `"unset_label":"u","category":"c"`), rep(`"category":"c"`, `"suggested_options":"nope","category":"c"`),
		`{"api_version":1,"revision":3,"option_sets":{"s":{"type":"string","options":[]}},"definitions":[` + ok + `]}`,
		`{"api_version":1,"revision":3,"option_sets":{"s":{"type":"language_tag","options":[{"value":"EN","introduced_in":1},{"value":"en","introduced_in":1},{"value":"en","introduced_in":9},{"value":"not a tag","introduced_in":1}]}},"definitions":[` + ok + `]}`,
	}
	manifests := make([]manifestVector, 0, len(docs))
	for _, doc := range docs {
		var m settingscontract.Manifest
		vec := manifestVector{Doc: doc}
		if err := manifestSchema.Validate(must(jsonschema.UnmarshalJSON(strings.NewReader(doc)))); err != nil {
			vec.SchemaError = normalizeError(err.Error())
		}
		if err := json.Unmarshal([]byte(doc), &m); err != nil {
			vec.Error = "decode: " + err.Error()
		} else if err := m.Validate(schemas); err != nil {
			vec.Error = normalizeError(err.Error())
		}
		manifests = append(manifests, vec)
	}

	type revisionVector struct {
		Key     string   `json:"key"`
		Rev     int      `json:"revision"`
		Visible bool     `json:"visible"`
		Scopes  []string `json:"scopes"`
		Enum    []string `json:"enum"`
		Minimum *float64 `json:"minimum"`
		Maximum *float64 `json:"maximum"`
	}
	revisions := []revisionVector{}
	for _, rev := range []int{0, 1, 3, 7, 14, 20, manifest.Revision} {
		for _, k := range manifest.Keys() {
			d, _ := manifest.Lookup(k)
			vec := revisionVector{Key: k, Rev: rev, Visible: d.VisibleAtRevision(rev), Scopes: []string{}, Enum: []string{}}
			for _, sc := range d.ScopesAtRevision(rev) {
				vec.Scopes = append(vec.Scopes, string(sc))
			}
			for _, m := range d.EnumValuesAtRevision(rev) {
				vec.Enum = append(vec.Enum, string(must(json.Marshal(m.Value))))
			}
			if v, ok := d.ValueSchema.Minimum.AtRevision(rev); ok {
				vec.Minimum = &v
			}
			if v, ok := d.ValueSchema.Maximum.AtRevision(rev); ok {
				vec.Maximum = &v
			}
			revisions = append(revisions, vec)
		}
	}
	options := map[string][]settingscontract.SuggestedOption{}
	for name, set := range manifest.OptionSets {
		for _, rev := range []int{1, 14, manifest.Revision} {
			options[fmt.Sprintf("%s@%d", name, rev)] = set.OptionsAtRevision(rev)
		}
	}

	steps := []map[string]any{}
	for _, c := range [][3]float64{{0.15, 0, 0.05}, {0.17, 0, 0.05}, {1, 0, 0}, {3, 1, 2}, {4, 1, 2}, {0.1 + 0.2, 0, 0.1}, {2.5, 0, 0.5}, {-3, 0, 1.5}} {
		steps = append(steps, map[string]any{"value": c[0], "base": c[1], "step": c[2], "out": settingscontract.StepAligned(c[0], c[1], c[2])})
	}

	write("settings_contract.json", map[string]any{
		"revision":      manifest.Revision,
		"api_version":   manifest.APIVersion,
		"etag":          must(settingscontract.ETag()),
		"public_etag":   must(settingscontract.PublicETag()),
		"canonical_sha": sum(canonical),
		"public_sha":    sum(public),
		"definitions":   defs,
		"values":        vectors,
		"compares":      compares,
		"mirrors":       mirrors,
		"manifests":     manifests,
		"steps":         steps,
		"revisions":     revisions,
		"options":       options,
		"remote":        settingskeys.Remote,
		"client_local":  settingskeys.ClientLocal,
		"deprecated":    settingskeys.Deprecated,
	})
}

type fakeStore struct {
	rows  []userstore.SettingValue
	query *userstore.SettingResolutionQuery
}

func (f *fakeStore) ListSettingValuesForResolution(_ context.Context, q userstore.SettingResolutionQuery) ([]userstore.SettingValue, error) {
	f.query = &q
	out := []userstore.SettingValue{}
	for _, r := range f.rows {
		for _, k := range q.Keys {
			if r.Key == k {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

type fakeSettings map[string]string

func (f fakeSettings) Get(_ context.Context, key string) (string, error) { return f[key], nil }

type resolverRow struct {
	Key          string          `json:"key"`
	Scope        string          `json:"scope"`
	ProfileID    string          `json:"profile_id,omitempty"`
	ClientFamily string          `json:"client_family,omitempty"`
	DeviceID     string          `json:"device_id,omitempty"`
	LibraryID    int             `json:"library_id,omitempty"`
	SeriesID     string          `json:"series_id,omitempty"`
	UpdatedAt    string          `json:"updated_at,omitempty"`
	Value        json.RawMessage `json:"value"`
	ValueText    string          `json:"value_text"`
}

type resolverContext struct {
	ProfileID    string   `json:"profile_id,omitempty"`
	ClientFamily string   `json:"client_family,omitempty"`
	DeviceID     string   `json:"device_id,omitempty"`
	LibraryIDs   []int    `json:"library_ids,omitempty"`
	SeriesIDs    []string `json:"series_ids,omitempty"`
}

type resolverCase struct {
	Name          string                     `json:"name"`
	Keys          []string                   `json:"keys"`
	Context       resolverContext            `json:"context"`
	Stored        []resolverRow              `json:"stored"`
	Constraints   map[string]json.RawMessage `json:"constraints,omitempty"`
	AdminDefaults map[string]string          `json:"admin_defaults,omitempty"`
	Bindings      []map[string]string        `json:"constraint_bindings,omitempty"`
	Result        string                     `json:"result"`
	Identities    []string                   `json:"identities"`
	// Several of the same keys for ResolveContexts and ResolveProfiles.
	Contexts []resolverContext `json:"contexts,omitempty"`
	Profiles []string          `json:"profiles,omitempty"`
}

func rowsOf(in []resolverRow) []userstore.SettingValue {
	out := make([]userstore.SettingValue, 0, len(in))
	for _, r := range in {
		out = append(out, userstore.SettingValue{
			SettingIdentity: userstore.SettingIdentity{Key: r.Key, Scope: settingscontract.Scope(r.Scope), ProfileID: r.ProfileID, ClientFamily: settingscontract.ClientFamily(r.ClientFamily), DeviceID: r.DeviceID, LibraryID: r.LibraryID, SeriesID: r.SeriesID},
			Value:           r.Value, UpdatedAt: r.UpdatedAt,
		})
	}
	return out
}

func ctxOf(c resolverContext) settingsresolve.Context {
	return settingsresolve.Context{ProfileID: c.ProfileID, ClientFamily: settingscontract.ClientFamily(c.ClientFamily), DeviceID: c.DeviceID, LibraryIDs: c.LibraryIDs, SeriesIDs: c.SeriesIDs}
}

func runResolver(c *resolverCase) {
	for i := range c.Stored {
		c.Stored[i].ValueText = string(c.Stored[i].Value)
	}
	manifest := settingscontract.MustLoad()
	if c.Contexts != nil {
		contexts := make([]settingsresolve.Context, 0, len(c.Contexts))
		for _, rc := range c.Contexts {
			contexts = append(contexts, ctxOf(rc))
		}
		out, err := settingsresolve.New(manifest).ResolveContexts(context.Background(), &fakeStore{rows: rowsOf(c.Stored)}, contexts, c.Keys, settingsresolve.Constraints(c.Constraints))
		if err != nil {
			panic(err)
		}
		c.Result = goJSON(out)
		return
	}
	if c.Profiles != nil {
		out, err := settingsresolve.New(manifest).ResolveProfiles(context.Background(), &fakeStore{rows: rowsOf(c.Stored)}, c.Profiles, c.Keys, settingsresolve.Constraints(c.Constraints))
		if err != nil {
			panic(err)
		}
		c.Result = goJSON(out)
		return
	}
	var resolver *settingsresolve.Resolver = settingsresolve.New(manifest)
	if c.AdminDefaults != nil {
		resolver = resolver.WithAdminDefaults(fakeSettings(c.AdminDefaults))
	}
	effs, err := resolver.Resolve(context.Background(), &fakeStore{rows: rowsOf(c.Stored)}, ctxOf(c.Context), c.Keys, settingsresolve.Constraints(c.Constraints))
	if err != nil {
		panic(err)
	}
	c.Result = goJSON(effs)
	c.Identities = []string{}
	for _, e := range effs {
		if e.Identity != nil {
			c.Identities = append(c.Identities, goJSON(e.Identity))
		} else {
			c.Identities = append(c.Identities, "")
		}
	}
}

func writeResolverVectors() {
	raw := must(os.ReadFile("contracts/settings/v1/conformance.json"))
	var fixture struct {
		Cases []struct {
			Name               string                     `json:"name"`
			Keys               []string                   `json:"keys"`
			Context            *resolverContext           `json:"context"`
			Stored             []resolverRow              `json:"stored"`
			Constraints        map[string]json.RawMessage `json:"constraints"`
			ConstraintBindings []map[string]string        `json:"constraint_bindings"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		panic(err)
	}
	cases := []resolverCase{}
	for _, fc := range fixture.Cases {
		if len(fc.ConstraintBindings) > 0 {
			// A binding needs the unexported applyConstraint; the fixture's own expectations check those.
			continue
		}
		c := resolverCase{Name: fc.Name, Keys: fc.Keys, Stored: fc.Stored, Constraints: fc.Constraints}
		if fc.Context != nil {
			c.Context = *fc.Context
		}
		cases = append(cases, c)
	}
	titleArt := settingskeys.UiTitleArt
	nextUp := settingskeys.UiNextUpMode
	profile := func(v string) resolverRow {
		return resolverRow{Key: titleArt, Scope: "profile", ProfileID: "p1", UpdatedAt: "2026-01-01T00:00:00Z", Value: json.RawMessage(v)}
	}
	device := func(v string) resolverRow {
		return resolverRow{Key: titleArt, Scope: "profile_device", ProfileID: "p1", DeviceID: "phone", UpdatedAt: "2026-01-02T00:00:00Z", Value: json.RawMessage(v)}
	}
	cases = append(cases,
		resolverCase{Name: "admin default inherited", Keys: []string{titleArt}, Context: resolverContext{ProfileID: "p1", DeviceID: "phone"}, AdminDefaults: map[string]string{"defaults." + titleArt: "false"}},
		resolverCase{Name: "admin default whitespace", Keys: []string{titleArt}, Context: resolverContext{ProfileID: "p1"}, AdminDefaults: map[string]string{"defaults." + titleArt: "  false  "}},
		resolverCase{Name: "admin default empty", Keys: []string{titleArt}, Context: resolverContext{ProfileID: "p1"}, AdminDefaults: map[string]string{"defaults." + titleArt: "   "}},
		resolverCase{Name: "admin default invalid", Keys: []string{titleArt}, Context: resolverContext{ProfileID: "p1"}, AdminDefaults: map[string]string{"defaults." + titleArt: `"nope"`}},
		resolverCase{Name: "stored beats admin default", Keys: []string{titleArt}, Context: resolverContext{ProfileID: "p1", DeviceID: "phone"}, Stored: []resolverRow{device("true")}, AdminDefaults: map[string]string{"defaults." + titleArt: "false"}},
		resolverCase{Name: "profile before device", Keys: []string{titleArt}, Context: resolverContext{ProfileID: "p1", DeviceID: "phone"}, Stored: []resolverRow{device("true"), profile("false")}},
		resolverCase{Name: "next up admin default", Keys: []string{nextUp, titleArt, "nope.key", nextUp}, Context: resolverContext{ProfileID: "p1"}, AdminDefaults: map[string]string{"defaults." + nextUp: `"separate"`}},
		resolverCase{Name: "client local keys are dropped", Keys: []string{settingskeys.DownloadsWifiOnly}, Context: resolverContext{ProfileID: "p1"}},
		resolverCase{Name: "no keys", Keys: []string{}, Context: resolverContext{ProfileID: "p1"}},
		resolverCase{Name: "stored values keep their bytes", Keys: []string{settingskeys.PlaybackSubtitleAppearance}, Context: resolverContext{ProfileID: "p1"},
			Stored: []resolverRow{{Key: settingskeys.PlaybackSubtitleAppearance, Scope: "profile", ProfileID: "p1", Value: json.RawMessage(`{ "textOpacity" : 5, "fontSize":"small", "backgroundStyle":"box" }`)}}},
		resolverCase{Name: "contexts batch", Keys: []string{titleArt, settingskeys.PlaybackSubtitleMode}, Contexts: []resolverContext{{ProfileID: "p1", DeviceID: "phone"}, {ProfileID: "p2", DeviceID: "phone"}, {DeviceID: "phone"}},
			Stored: []resolverRow{device("true"), {Key: titleArt, Scope: "profile", ProfileID: "p2", Value: json.RawMessage("false")}}},
		resolverCase{Name: "contexts nothing known", Keys: []string{"nope"}, Contexts: []resolverContext{{ProfileID: "p1"}, {ProfileID: "p2"}}},
		resolverCase{Name: "profiles batch", Keys: []string{titleArt}, Profiles: []string{"p1", "p2", "p1"},
			Stored: []resolverRow{profile("false"), device("true")}},
		resolverCase{Name: "library tie break", Keys: []string{settingskeys.PlaybackSubtitleMode}, Contexts: []resolverContext{{ProfileID: "p1", LibraryIDs: []int{9, 3}}, {ProfileID: "p1", SeriesIDs: []string{"z", "a"}}},
			Stored: []resolverRow{
				{Key: settingskeys.PlaybackSubtitleMode, Scope: "profile_library", ProfileID: "p1", LibraryID: 9, Value: json.RawMessage(`"off"`)},
				{Key: settingskeys.PlaybackSubtitleMode, Scope: "profile_library", ProfileID: "p1", LibraryID: 3, Value: json.RawMessage(`"always"`)},
				{Key: settingskeys.PlaybackSubtitleMode, Scope: "profile_series", ProfileID: "p1", SeriesID: "z", Value: json.RawMessage(`"off"`)},
				{Key: settingskeys.PlaybackSubtitleMode, Scope: "profile_series", ProfileID: "p1", SeriesID: "a", Value: json.RawMessage(`"auto"`)},
			}},
	)
	for i := range cases {
		runResolver(&cases[i])
	}
	write("resolver.json", cases)
}
