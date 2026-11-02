// Prints every registered section recipe's presets from the real internal/sections/recipes, which
// silo-store embeds for readableTitle. Run from the repository root:
//
//	go run ./rust/conformance/vectors/generators/recipes > rust/crates/silo-store/src/catalog/recipe_presets.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Silo-Server/silo-server/internal/sections/recipes"
)

type preset struct {
	DisplayName   string          `json:"display_name"`
	DefaultParams json.RawMessage `json:"default_params"`
}

func main() {
	out := map[string][]preset{}
	for _, rec := range recipes.List() {
		presets := []preset{}
		for _, p := range rec.Definition().Presets {
			presets = append(presets, preset{DisplayName: p.DisplayName, DefaultParams: p.DefaultParams})
		}
		out[rec.Type()] = presets
	}
	data, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(data))
}
