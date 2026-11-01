//go:build settings_vectors

// Command settings writes differential vectors for the settings contract's ValidateValue and the
// settingsmigrate planner, from the real packages. Run it from the repository root:
//
//	GOTOOLCHAIN=go1.26.7 go run -tags settings_vectors ./rust/conformance/vectors/generators/settings
//
// jsonschema errors embed the working directory, which is written here as {CWD}.
package main

import (
	"bytes"
	"encoding/json"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Silo-Server/silo-server/internal/settingscontract"
	"github.com/Silo-Server/silo-server/internal/settingsmigrate"
)

const outDir = "rust/conformance/vectors/settings"

type validateCase struct {
	Key string `json:"key"`
	Raw string `json:"raw"`
	Err string `json:"err"`
}

type rowOut struct {
	Key       string `json:"key"`
	Scope     string `json:"scope"`
	ProfileID string `json:"profile_id"`
	DeviceID  string `json:"device_id"`
	LibraryID int    `json:"library_id"`
	SeriesID  string `json:"series_id"`
	Value     string `json:"value"`
}

type rejectOut struct {
	SourceTable string `json:"source_table"`
	SourceKey   string `json:"source_key"`
	Identity    string `json:"identity"`
	Value       string `json:"value"`
	Reason      string `json:"reason"`
}

type planCase struct {
	Name    string      `json:"name"`
	Input   inputOut    `json:"input"`
	Rows    []rowOut    `json:"rows"`
	Rejects []rejectOut `json:"rejects"`
}

type inputOut struct {
	Settings       []settingsmigrate.LegacySetting           `json:"settings"`
	DeviceSettings []settingsmigrate.LegacyDeviceSetting     `json:"device_settings"`
	Profiles       []settingsmigrate.LegacyProfile           `json:"profiles"`
	SeriesPrefs    []settingsmigrate.LegacySeriesPreference  `json:"series_prefs"`
	LibraryPrefs   []settingsmigrate.LegacyLibraryPreference `json:"library_prefs"`
}

func main() {
	cwd, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	contract := settingscontract.MustLoad()
	schemas := settingscontract.ObjectSchemas()
	r := rand.New(rand.NewPCG(0x51100, 3))

	scrub := func(s string) string { return strings.ReplaceAll(s, "file://"+cwd+"/", "file://{CWD}/") }

	scalars := []string{
		`true`, `false`, `null`, `0`, `1`, `-1`, `5`, `15`, `100`, `120`, `121`, `5000`, `5001`, `-5001`, `1.5`, `0.25`, `0.3`, `0.26`, `3`, `3.05`,
		`1e3`, `1E2`, `1.0`, `-0`, `99999999999`, `9223372036854775808`, `1e999`, `"text"`, `""`, `" "`, `"true"`, `"15"`, `"en"`, `"EN"`, `"eng"`, `"pt-BR"`,
		`"not a tag"`, `"auto"`, `"always"`, `"ask"`, `"never"`, `"1080p"`, `"<b>&"`, `"é"`, `"😀"`, `"\ud83d"`, `"\ude00"`, `"\ud83dx"`, `"\ud83dA"`,
		`[]`, `[1]`, `[1,2,2]`, `{}`, `{"a":1}`, `{"a":1,"a":2}`, ` true `, `true]`, `true x`, `tru`, `"unterminated`, `{`, `[`, `{"a"`, `[1,`, `01`, `1.`, `-`, `1e`,
		`nul`, "\"a\nb\"", `"\q"`, `"\u12"`, `"\uZZZZ"`,
	}
	objects := map[string][]string{
		"card-overlays.json": {
			`{"version":2,"preset":"classic","order":[],"items":{}}`,
			`{"version":2,"preset":"classic","order":["hdr","year"],"items":{"hdr":{"enabled":true,"position":"top-left"},"year":{"enabled":false,"position":"bottom-right","accentColor":"#aabbcc","showIcon":true}}}`,
			`{"version":3,"preset":"classic","order":[],"items":{}}`,
			`{"version":2,"preset":"nope","order":[],"items":{}}`,
			`{"version":2,"preset":"classic","order":["hdr","hdr"],"items":{}}`,
			`{"version":2,"preset":"classic","order":["bad"],"items":{}}`,
			`{"version":2,"preset":"classic","order":[],"items":{"bad":{"enabled":true,"position":"top-left"}}}`,
			`{"version":2,"preset":"classic","order":[],"items":{"hdr":{"enabled":"x","position":"top-left"}}}`,
			`{"version":2,"preset":"classic","order":[],"items":{"hdr":{"enabled":true,"position":"middle"}}}`,
			`{"version":2,"preset":"classic","order":[],"items":{"hdr":{"enabled":true,"position":"top-left","accentColor":"red"}}}`,
			`{"version":2,"preset":"classic","order":[],"items":{"hdr":{"position":"top-left"}}}`,
			`{"version":2,"preset":"classic","order":[],"items":{"hdr":{"enabled":true,"position":"top-left","extra":1}}}`,
			`{"version":2.0,"preset":"classic","order":[],"items":{}}`,
			`{"preset":"classic","items":{}}`,
			`{"version":2}`,
			`{"extra":1,"version":2,"preset":"classic","order":[],"items":{}}`,
		},
		"library-id-list.json": {`[]`, `[1,2,3]`, `[0]`, `[-1]`, `[1,1]`, `[1.5]`, `[1.0]`, `["x"]`, `[null]`, `[1e2]`, `[1e400]`, `{"a":1}`, `"x"`, `1`, `[1000000]`, `[0.5,0.5]`},
		"sidebar-pins.json": {
			`{}`, `{"1":[{"type":"section","id":"a","label":"b"}]}`, `{"1":[{"type":"bad","id":"a","label":"b"}]}`, `{"1":[{"type":"section"}]}`, `{"1":[{"type":"section","id":"","label":"b"}]}`,
			`{"1":{}}`, `{"1":[1]}`, `{"1":[{"type":"section","id":"a","label":"b","x":1}]}`, `[]`,
			`{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":[]}`,
		},
		"theme-var-overrides.json": {`{}`, `{"accent":"#fff"}`, `{"Bad":"x"}`, `{"accent":""}`, `{"accent":1}`, `{"a-b":"x","c9":"y"}`, `{"9a":"x"}`, `[]`},
		"primary-menu.json": {
			`{"items":[{"type":"builtin","destination":"home"}]}`,
			`{"items":[{"type":"builtin","destination":"movies"}]}`,
			`{"items":[]}`, `{}`, `{"items":[{"type":"builtin","destination":"home"},{"type":"builtin","destination":"home"}]}`,
			`{"items":[{"type":"builtin","destination":"home"},{"type":"library","library_id":1,"label":"a"},{"type":"library","library_id":1,"label":"b"}]}`,
			`{"items":[{"type":"builtin","destination":"home"},{"type":"library","library_id":1.0,"label":"a"}]}`,
			`{"items":[{"type":"builtin","destination":"home"},{"type":"library","library_id":0,"label":"a"}]}`,
			`{"items":[{"type":"builtin","destination":"home"},{"type":"library","library_id":1,"label":" "}]}`,
			`{"items":[{"type":"builtin","destination":"home"},{"type":"nope"}]}`,
			`{"items":[{"type":"builtin","destination":"home"},{"type":"section","library_id":1,"section_id":"s","label":"a"},{"type":"collection","library_id":1,"collection_id":"c","label":"a"},{"type":"collection","collection_id":"c","label":"a"}]}`,
			`{"items":[{"type":"builtin","destination":"home"},1]}`,
		},
		"navigation-shortcuts.json": {`{"items":[]}`, `{"items":[{"type":"builtin","destination":"movies"}]}`, `{"items":[{"type":"builtin","destination":"movies"},{"type":"builtin","destination":"movies"}]}`, `{}`, `{"x":1}`},
		"subtitle-appearance.json":  {`{}`, `{"fontSize":"large"}`, `{"fontSize":"nope"}`, `{"fontSize":"small","fontSize":"large"}`, `{"textOpacity":0.5}`, `{"textOpacity":5}`, `{"backgroundOpacity":-1}`, `{"fontColor":"#fff"}`, `{"fontColor":"#ffffff"}`, `{"nope":1}`},
		"card-presentation.json":    {`{}`, `{"nope":1}`},
		"library-page-state.json":   {`{}`, `{"libraries":{}}`, `{"libraries":{"1":{}}}`, `{"nope":1}`, `{"libraries":[]}`},
		"metadata-language-overrides.json": {`{}`, `{"libraries":{}}`, `{"nope":1}`, `{"libraries":{"1":"en"}}`},
	}
	mutate := func(doc string) string {
		b := []byte(doc)
		switch r.IntN(4) {
		case 0:
			if len(b) > 0 {
				i := r.IntN(len(b))
				b = append(b[:i], b[i+1:]...)
			}
		case 1:
			if len(b) > 0 {
				b = b[:r.IntN(len(b))]
			}
		case 2:
			chars := `{}[],:"0a -\`
			i := r.IntN(len(b) + 1)
			b = append(b[:i], append([]byte{chars[r.IntN(len(chars))]}, b[i:]...)...)
		case 3:
			if len(b) > 0 {
				chars := `{}[],:"0a -\`
				b[r.IntN(len(b))] = chars[r.IntN(len(chars))]
			}
		}
		return string(b)
	}

	var validates []validateCase
	seen := map[string]bool{}
	addValidate := func(key, raw string) {
		id := key + "\x00" + raw
		if seen[id] {
			return
		}
		seen[id] = true
		def, _ := contract.Lookup(key)
		msg := ""
		if err := def.ValueSchema.ValidateValue(json.RawMessage(raw), schemas); err != nil {
			msg = scrub(err.Error())
		}
		validates = append(validates, validateCase{key, raw, msg})
	}
	for _, key := range contract.Keys() {
		def, _ := contract.Lookup(key)
		for _, raw := range scalars {
			addValidate(key, raw)
		}
		if def.ValueSchema.Type == settingscontract.TypeObject {
			docs := objects[def.ValueSchema.SchemaRef]
			if len(docs) == 0 {
				panic("no documents for " + def.ValueSchema.SchemaRef)
			}
			for _, doc := range docs {
				addValidate(key, doc)
			}
			for i := 0; i < 250; i++ {
				addValidate(key, mutate(docs[r.IntN(len(docs))]))
			}
		}
	}
	writeJSON("validate", map[string]any{"cases": validates})

	// Planner cases. The legacy store holds strings, so raw values cover what coerce handles.
	rawValues := []string{
		"", "  ", "true", "false", "TRUE", "True", "t", "F", "1", "0", "yes", "2", "15", "30", " 30 ", "-1", "120", "121", "5000", "99999999999", "9223372036854775808",
		"1.5", "0.25", "0.26", "0.3", "1", "3", "3.1", "1e0", "NaN", "nan", "inf", "+Inf", "-Inf", "Infinity", "0x10", "0x1p-2", "1_000", "0x_1p0", "1e999", "1e-999", ".5", "5.", "+.5e1",
		"en", "EN", "eng", "English", "pt_br", "not a tag", "x-private", "i-klingon", "<b>&", "auto", "always", "ask", "never", "dark", "light", "1080p", "null", "[]", "{}", "[1,2]",
		"text more", "\"quoted\"", "é", "日本語",
	}
	profiles := []settingsmigrate.LegacyProfile{{ID: "p1"}, {ID: "p2"}}
	var plans []planCase
	planner := settingsmigrate.New(contract, schemas)
	addPlan := func(name string, in settingsmigrate.Input) {
		result := planner.Plan(in)
		c := planCase{Name: name, Input: inputOut{in.Settings, in.DeviceSettings, in.Profiles, in.SeriesPrefs, in.LibraryPrefs}}
		for _, row := range result.Rows {
			c.Rows = append(c.Rows, rowOut{row.Key, string(row.Scope), row.ProfileID, row.DeviceID, row.LibraryID, row.SeriesID, string(row.Value)})
		}
		for _, rej := range result.Rejects {
			c.Rejects = append(c.Rejects, rejectOut{rej.SourceTable, rej.SourceKey, string(rej.Identity), rej.Value, scrub(rej.Reason)})
		}
		plans = append(plans, c)
	}

	legacyKeys := append(contract.Keys(), "subtitle_appearance", "player.next_up_prompt_seconds", "ui_theme", "ui_text_scale", "ui_text_weight", "ui_high_contrast", "ui_custom_theme_vars", "ui_custom_css",
		"card_overlays", "next_up_mode", "sidebar_pins", "disabled_library_ids", "library_order", "unknown.key", "jellycompat:displayprefs:a:b")
	// Every raw value against the first key of each value type, and a short list against the rest.
	seenType := map[string]bool{}
	shortValues := []string{"", " dark ", "true", "15", "en", "[]", "{}", "<b>"}
	for _, key := range legacyKeys {
		var settings []settingsmigrate.LegacySetting
		var device []settingsmigrate.LegacyDeviceSetting
		values := shortValues
		typeKey := "unknown"
		if def, ok := contract.Lookup(settingsmigrate.CanonicalKey(key)); ok {
			typeKey = string(def.ValueSchema.Type) + def.ValueSchema.SchemaRef
		}
		if !seenType[typeKey] || key == "player.playback_speed" {
			seenType[typeKey] = true
			values = rawValues
		}
		for _, value := range values {
			settings = append(settings[:0], settingsmigrate.LegacySetting{Key: key, Value: value})
			device = append(device[:0], settingsmigrate.LegacyDeviceSetting{ProfileID: "p1", DeviceID: "d1", Key: key, Value: value})
			addPlan("account "+key, settingsmigrate.Input{Settings: append([]settingsmigrate.LegacySetting(nil), settings...), Profiles: profiles})
			addPlan("device "+key, settingsmigrate.Input{DeviceSettings: append([]settingsmigrate.LegacyDeviceSetting(nil), device...), Profiles: profiles})
		}
	}
	// Object documents through coerce, including the card overlay upgrade.
	for _, key := range legacyKeys {
		canonical := settingsmigrate.CanonicalKey(key)
		def, ok := contract.Lookup(canonical)
		if !ok || def.ValueSchema.Type != settingscontract.TypeObject {
			continue
		}
		docs := append([]string(nil), objects[def.ValueSchema.SchemaRef]...)
		if def.ValueSchema.SchemaRef == "card-overlays.json" {
			docs = append(docs,
				`null`, `[]`, `1`, `{}`,
				`{"hdr":{"enabled":true,"position":"top-left"}}`,
				`{"hdr":{"enabled":true,"position":"top-left","accentColor":"#ABCDEF","showIcon":false,"junk":1},"bad":{"enabled":true,"position":"top-left"},"year":{"enabled":false},"rating_rt":{"enabled":true,"position":"nowhere"},"studio":{"enabled":false,"position":"bottom-left","accentColor":"red"},"runtime":5}`,
				`{"version":1,"hdr":{"enabled":true,"position":"top-left"}}`,
				`{"version":"2","hdr":{"enabled":true,"position":"top-left"}}`,
				`{"preset":"x","hdr":{"enabled":true,"position":"top-left"}}`,
				`{"items":{},"hdr":{"enabled":true,"position":"top-left"}}`,
				`{"n":1e999,"hdr":{"enabled":true,"position":"top-left"}}`,
				`{"hdr":{"enabled":true,"position":"top-left"},"hdr":{"enabled":false,"position":"top-right"}}`,
				`{"hdr":{"enabled":true,"position":"top-left"}} trailing`,
			)
		}
		for _, doc := range docs {
			addPlan("object account "+key, settingsmigrate.Input{Settings: []settingsmigrate.LegacySetting{{Key: key, Value: doc}}, Profiles: profiles})
			addPlan("object device "+key, settingsmigrate.Input{DeviceSettings: []settingsmigrate.LegacyDeviceSetting{{ProfileID: "p1", DeviceID: "d1", Key: key, Value: doc}}, Profiles: profiles})
		}
		for i := 0; i < 60; i++ {
			doc := mutate(docs[r.IntN(len(docs))])
			addPlan("mutated "+key, settingsmigrate.Input{Settings: []settingsmigrate.LegacySetting{{Key: key, Value: doc}}, Profiles: profiles})
		}
	}

	str := func(s string) *string { return &s }
	yes, no := true, false
	qualities := []string{"", "auto", "original", "2160p", "1080p-high", "1080p", "1080p-medium", "1080p-8", "720p-high", "720p-medium", "720p", "480p", "420p", "328p", "360p", " 720p ", "AUTO"}
	for _, q := range qualities {
		addPlan("profile quality "+q, settingsmigrate.Input{Profiles: []settingsmigrate.LegacyProfile{{ID: "p1", QualityPreference: str(q)}}})
		addPlan("device quality "+q, settingsmigrate.Input{Profiles: []settingsmigrate.LegacyProfile{{ID: "p1"}}, DeviceSettings: []settingsmigrate.LegacyDeviceSetting{{ProfileID: "p1", DeviceID: "d", Key: "playback.preferred_quality", Value: q}}})
	}
	languages := []string{"", " ", "en", "eng", "English", "ENGLISH", "fre", "pt_BR", "zh-hant", "not a tag", "x-foo", "qaa", "Монгол", "i-klingon"}
	modes := []string{"", "auto", "always", "forced", "off", "none", "bad", "<x>"}
	for _, l := range languages {
		addPlan("profile languages "+l, settingsmigrate.Input{Profiles: []settingsmigrate.LegacyProfile{{ID: "p1", Language: str(l), SubtitleLanguage: str(l), PreferredMetadataLanguage: str(l)}}})
		addPlan("series language "+l, settingsmigrate.Input{Profiles: profiles, SeriesPrefs: []settingsmigrate.LegacySeriesPreference{{ProfileID: "p1", SeriesID: "s1", AudioLanguage: str(l), SubtitleLanguage: str(l), AudioSourceTable: "user_audio_preferences", SubtitleSourceTable: "user_subtitle_preferences"}}})
		addPlan("library language "+l, settingsmigrate.Input{Profiles: profiles, LibraryPrefs: []settingsmigrate.LegacyLibraryPreference{{ProfileID: "p1", LibraryID: 7, AudioLanguage: str(l), SubtitleLanguage: str(l), SourceTable: "user_library_playback_preferences"}}})
	}
	for _, m := range modes {
		addPlan("profile mode "+m, settingsmigrate.Input{Profiles: []settingsmigrate.LegacyProfile{{ID: "p1", SubtitleMode: str(m)}}})
		addPlan("series mode "+m, settingsmigrate.Input{Profiles: profiles, SeriesPrefs: []settingsmigrate.LegacySeriesPreference{{ProfileID: "p1", SeriesID: "s1", SubtitleMode: str(m)}}})
		addPlan("library mode "+m, settingsmigrate.Input{Profiles: profiles, LibraryPrefs: []settingsmigrate.LegacyLibraryPreference{{ProfileID: "p1", LibraryID: 7, SubtitleMode: str(m)}}})
	}
	addPlan("profile flags true", settingsmigrate.Input{Profiles: []settingsmigrate.LegacyProfile{{ID: "p1", ShowForcedSubtitles: &yes, AutoSkipIntro: &yes, AutoSkipCredits: &yes, AutoSkipRecap: &yes, AutoPlayNextPreview: &yes}}})
	addPlan("profile flags false", settingsmigrate.Input{Profiles: []settingsmigrate.LegacyProfile{{ID: "p1", ShowForcedSubtitles: &no, AutoSkipIntro: &no, AutoSkipCredits: &no, AutoSkipRecap: &no, AutoPlayNextPreview: &no}}})
	addPlan("series forced", settingsmigrate.Input{Profiles: profiles, SeriesPrefs: []settingsmigrate.LegacySeriesPreference{{ProfileID: "p1", SeriesID: "a", ShowForcedSubtitles: &yes}, {ProfileID: "p2", SeriesID: "b", ShowForcedSubtitles: &no}}})
	addPlan("library forced", settingsmigrate.Input{Profiles: profiles, LibraryPrefs: []settingsmigrate.LegacyLibraryPreference{{ProfileID: "p1", LibraryID: 1, ShowForcedSubtitles: &yes}, {ProfileID: "p2", LibraryID: 2, ShowForcedSubtitles: &no}}})
	addPlan("default sources", settingsmigrate.Input{Profiles: profiles, SeriesPrefs: []settingsmigrate.LegacySeriesPreference{{ProfileID: "p1", SeriesID: "a", AudioLanguage: str("bad tag"), SubtitleLanguage: str("bad tag"), SubtitleMode: str("nope")}}, LibraryPrefs: []settingsmigrate.LegacyLibraryPreference{{ProfileID: "p1", LibraryID: 1, AudioLanguage: str("bad tag"), SubtitleMode: str("nope")}}})
	addPlan("orphans with loaded empty profiles", settingsmigrate.Input{Profiles: []settingsmigrate.LegacyProfile{}, Settings: []settingsmigrate.LegacySetting{{Key: "ui.theme", Value: "dark"}}, DeviceSettings: []settingsmigrate.LegacyDeviceSetting{{ProfileID: "gone", DeviceID: "d", Key: "ui.theme", Value: "dark"}, {ProfileID: "gone", DeviceID: "d", Key: "playback.preferred_quality", Value: "720p"}}, SeriesPrefs: []settingsmigrate.LegacySeriesPreference{{ProfileID: "gone", SeriesID: "s", AudioLanguage: str("en")}}, LibraryPrefs: []settingsmigrate.LegacyLibraryPreference{{ProfileID: "gone", LibraryID: 3, SubtitleMode: str("always")}}})
	addPlan("orphans with nil profiles", settingsmigrate.Input{DeviceSettings: []settingsmigrate.LegacyDeviceSetting{{ProfileID: "gone", DeviceID: "d", Key: "ui.theme", Value: "dark"}}})
	addPlan("rename dedupe alias first", settingsmigrate.Input{Profiles: profiles, DeviceSettings: []settingsmigrate.LegacyDeviceSetting{{ProfileID: "p1", DeviceID: "d", Key: "player.next_up_prompt_seconds", Value: "10"}, {ProfileID: "p1", DeviceID: "d", Key: "playback.next_up_prompt_seconds", Value: "20"}}})
	addPlan("rename dedupe canonical first", settingsmigrate.Input{Profiles: profiles, DeviceSettings: []settingsmigrate.LegacyDeviceSetting{{ProfileID: "p1", DeviceID: "d", Key: "playback.next_up_prompt_seconds", Value: "20"}, {ProfileID: "p1", DeviceID: "d", Key: "player.next_up_prompt_seconds", Value: "10"}}})
	addPlan("dedupe equal provenance", settingsmigrate.Input{Profiles: profiles, Settings: []settingsmigrate.LegacySetting{{Key: "ui_theme", Value: "dark"}, {Key: "ui.theme", Value: "light"}}})
	addPlan("mirror auto skip", settingsmigrate.Input{Profiles: []settingsmigrate.LegacyProfile{{ID: "p1", AutoSkipIntro: &yes}}})
	addPlan("mirror device both agree", settingsmigrate.Input{Profiles: profiles, DeviceSettings: []settingsmigrate.LegacyDeviceSetting{{ProfileID: "p1", DeviceID: "d", Key: "playback.auto_skip_intro", Value: "true"}, {ProfileID: "p1", DeviceID: "d", Key: "playback.intro_skip_mode", Value: "always"}}})
	addPlan("mirror device both disagree", settingsmigrate.Input{Profiles: profiles, DeviceSettings: []settingsmigrate.LegacyDeviceSetting{{ProfileID: "p1", DeviceID: "d", Key: "playback.auto_skip_intro", Value: "true"}, {ProfileID: "p1", DeviceID: "d", Key: "playback.intro_skip_mode", Value: "never"}}})
	addPlan("mirror account enum", settingsmigrate.Input{Profiles: profiles, Settings: []settingsmigrate.LegacySetting{{Key: "playback.intro_skip_mode", Value: "ask"}}})
	addPlan("device audio quarantine", settingsmigrate.Input{Profiles: profiles, DeviceSettings: []settingsmigrate.LegacyDeviceSetting{{ProfileID: "p1", DeviceID: "d", Key: "playback.audio_language", Value: "en"}, {ProfileID: "p1", DeviceID: "e", Key: "playback.audio_language", Value: "  "}}})
	addPlan("no profiles fans out to nothing", settingsmigrate.Input{Profiles: []settingsmigrate.LegacyProfile{}, Settings: []settingsmigrate.LegacySetting{{Key: "ui.theme", Value: "dark"}, {Key: "ui_theme", Value: "nope"}}})
	writeJSON("plan", map[string]any{"goarch": runtime.GOARCH, "cases": plans})
}

func writeJSON(name string, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, name+".json"), b.Bytes(), 0o644); err != nil {
		panic(err)
	}
}
