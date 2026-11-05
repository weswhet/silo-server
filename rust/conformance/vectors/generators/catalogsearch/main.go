//go:build catalogsearch_vectors

// Command catalogsearch writes the search query parser vectors from the real internal/catalog
// package (search_query.go, search_fold.go). See run.sh.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Silo-Server/silo-server/internal/catalog"
)

var inputs = []string{
	"", "   ", "the matrix", "The Matrix 1999", "1999", "\"star wars\" 1977", "\"star wars\"",
	"\"unbalanced star", "star \"wars", "a vengers", "the m", "\"the\" m", "\"the matrix\" re",
	"Amélie", "Ærøskøbing", "Straße", "Łódź", "Œuvre ßtraße", "İstanbul", "ı", "Fast and Furious",
	"Rocky Two", "21st century", "first blood", "2nd 3rd 4th 11th 1st", "x1st", "ninth gate 2100",
	"blade runner 2049", "1899 film", "year 2101", "+999", "Pokémon: The First Movie",
	"spider-man: no way home", "ｆｕｌｌ ｗｉｄｔｈ", "日本語 タイトル", "١٢٣ arabic digits",
	"Ⅻ roman", "café́", "éclair", "tab\tsep\nnew", " nbsp ", " line",
	"o'brien's", "AND and And", "ab", "abcd", "abc def", "\"\"", "\"a\" \"b\"", "Dž digraph",
	"ǅ title", "ΣΊΣΥΦΟΣ", "Ꮳherokee", "ǰ", "Å", "Ω ohm", "ﬁ ligature", "Ø ø Đ đ Ð ð Ħ ħ Ŧ ŧ Ŀ ŀ ẞ",
}

func main() {
	out := make([]catalog.VecSearchQuery, 0, len(inputs))
	for _, in := range inputs {
		out = append(out, catalog.VecParseSearchQuery(in))
	}
	b, err := json.Marshal(out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile("rust/conformance/vectors/catalog/search_query.json", append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
