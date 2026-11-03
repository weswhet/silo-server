// Writes the bundled collection template bodies each surface answers with, so silo-front serves Go's own
// catalog. Run from the repository root:
//
//	go run ./rust/conformance/vectors/generators/collections rust/crates/silo-front/src/native/collection_templates
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/Silo-Server/silo-server/internal/collections/templates"
)

func write(dir, name string, value any, escape bool) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(escape)
	if err := enc.Encode(value); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), buf.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

// creatable is apiv2.creatableCollectionTemplates.
func creatable(catalog templates.Catalog) templates.Catalog {
	sources := []string{"mdblist", "tmdb", "tmdb_list"}
	out := templates.Catalog{Categories: make([]templates.CategoryGroup, 0, len(catalog.Categories))}
	for _, group := range catalog.Categories {
		kept := make([]templates.Template, 0, len(group.Templates))
		for _, template := range group.Templates {
			if slices.Contains(sources, string(template.Source)) {
				kept = append(kept, template)
			}
		}
		if len(kept) > 0 {
			group.Templates = kept
			out.Categories = append(out.Categories, group)
		}
	}
	return out
}

// summary and bundle are apiv2.CollectionTemplateSummary and CollectionTemplateBundle.
type summary struct {
	ID         string              `json:"id"`
	Title      string              `json:"title"`
	Source     templates.Source    `json:"source"`
	MediaKind  templates.MediaKind `json:"media_kind"`
	Featured   bool                `json:"featured"`
	PosterPath string              `json:"poster_path,omitempty"`
	NeedsSetup bool                `json:"needs_setup"`
}

type bundle struct {
	templates.Bundle
	Templates []summary `json:"templates"`
}

func main() {
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0o755); err != nil {
		panic(err)
	}
	catalog := templates.Default.Catalog()
	write(dir, "v1_catalog.json", catalog, true)
	write(dir, "v1_bundles.json", templates.Default.BundleCatalog(), true)
	write(dir, "v2_catalog.json", creatable(catalog), false)
	listed := templates.Default.BundlesWithTemplates()
	bundles := make([]bundle, 0, len(listed))
	for _, b := range listed {
		summaries := make([]summary, 0, len(b.Templates))
		for _, t := range b.Templates {
			summaries = append(summaries, summary{t.ID, t.Title, t.Source, t.MediaKind, t.Featured, t.PosterPath, t.NeedsSetup()})
		}
		bundles = append(bundles, bundle{b.Bundle, summaries})
	}
	write(dir, "v2_bundles.json", struct {
		Bundles []bundle `json:"bundles"`
	}{bundles}, false)
	fmt.Println("wrote", dir)
}
