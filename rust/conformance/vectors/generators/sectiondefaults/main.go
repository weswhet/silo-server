// Command sectiondefaults writes rust/conformance/vectors/sections/defaults.json from the
// real internal/sections package: the default home and library section sets, the
// generated home library rows, and the continue-type config helpers.
// Run with rust/conformance/vectors/generators/sectiondefaults/run.sh.
package main

import (
	"encoding/json"
	"os"

	"github.com/Silo-Server/silo-server/internal/models"
	"github.com/Silo-Server/silo-server/internal/sections"
)

type lib struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

func main() {
	out := map[string]any{}

	libSets := [][]lib{
		{},
		{{1, "Movies", "movies"}, {2, "TV", "series"}},
		{{3, "Mixed", "mixed"}, {4, "Books", "audiobooks"}},
		{{5, "Novels", "ebook"}, {6, "Comics", "manga"}, {7, "Pods", "podcasts"}},
		{{8, "Shows", "series"}, {9, " Audio ", "Audiobook"}, {10, "Films", "Movie"}, {11, "Other", ""}},
	}
	var home []map[string]any
	for _, set := range libSets {
		var folders []*models.MediaFolder
		for _, l := range set {
			folders = append(folders, &models.MediaFolder{ID: l.ID, Name: l.Name, Type: l.Type})
		}
		folders = append(folders, nil)
		home = append(home, map[string]any{"libraries": set, "sections": sections.DefaultHomeSections(folders)})
	}
	out["home"] = home

	seven := 7
	var library []map[string]any
	for _, typ := range []string{"movies", "movie", "series", "audiobooks", "audiobook", "ebooks", "ebook", "manga", "podcasts", "mixed", "tv", "", "Movies"} {
		for _, id := range []*int{nil, &seven} {
			library = append(library, map[string]any{"type": typ, "library_id": id, "sections": sections.DefaultLibrarySectionsForType(id, typ)})
		}
	}
	out["library"] = library
	out["library_fallback"] = sections.DefaultLibrarySections(&seven)

	var clamp [][2]int
	for _, n := range []int{-1, 0, 1, 100, 499, 500, 501, 100000} {
		clamp = append(clamp, [2]int{n, sections.ClampItemLimit(n)})
	}
	out["clamp"] = clamp

	var cont []map[string]any
	for _, cfg := range []string{"", `{}`, `{"continue_type":"listening"}`, `{"continue_type":" READING "}`, `{"continue_type":"bogus"}`,
		`{"filter_type":"audiobook"}`, `{"filter_type":"Ebook"}`, `{"media_scope":"audiobook"}`, `{"media_scope":" ebook"}`,
		`{"filter_type":"movie","media_scope":"ebook"}`, `not json`, `{"continue_type":5}`, `null`, `{"continue_type":"","filter_type":"ebook"}`} {
		typ, err := sections.ParseContinueType(json.RawMessage(cfg))
		cont = append(cont, map[string]any{"config": cfg, "type": typ, "error": err != nil, "from_config": sections.ContinueTypeFromConfig(json.RawMessage(cfg))})
	}
	out["continue_parse"] = cont
	var contCfg []map[string]any
	for _, t := range []string{"watching", "listening", "reading", "bogus", ""} {
		var matches []string
		for _, it := range []string{"movie", "episode", "series", "audiobook", "ebook", "manga"} {
			if sections.ContinueTypeMatchesItem(sections.ContinueType(t), it) {
				matches = append(matches, it)
			}
		}
		contCfg = append(contCfg, map[string]any{"type": t, "config": string(sections.ContinueTypeConfig(sections.ContinueType(t))), "valid": sections.IsValidContinueType(sections.ContinueType(t)), "matches": matches, "next_up": sections.ContinueTypeAllowsNextUp(sections.ContinueType(t))})
	}
	out["continue_types"] = contCfg
	var kinds []map[string]any
	for _, t := range []string{"movies", "movie", "series", "tv", "show", "tvshows", "mixed", " Mixed ", "audiobook", "Audiobooks ", "ebook", "manga", "", "podcasts"} {
		kinds = append(kinds, map[string]any{"type": t, "video": sections.IsVideoLibraryType(t), "audiobook": sections.IsAudiobookLibraryType(t)})
	}
	out["library_kinds"] = kinds

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
