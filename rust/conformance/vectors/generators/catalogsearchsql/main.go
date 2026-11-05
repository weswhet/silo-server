//go:build catalogsearchsql_vectors

// The full query and item type corpus runs unrestricted; every other access filter runs a few
// queries, which is enough to cover where its predicates land.
//
// Command catalogsearchsql writes the Postgres search SQL vectors (the mixed FTS builder, the
// trigram fuzzy builder, GetByIDsWithAccess and personal-collection member counts) and the fuzzy
// rerank vectors from the real internal/catalog package. See run.sh.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Silo-Server/silo-server/internal/access"
	"github.com/Silo-Server/silo-server/internal/catalog"
)

type arg struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

func args(values []any) []arg {
	out := make([]arg, len(values))
	for i, v := range values {
		out[i] = arg{Type: fmt.Sprintf("%T", v), Value: v}
	}
	return out
}

type accessIn struct {
	Name               string   `json:"name"`
	Allowed            []int    `json:"allowed"`
	Disabled           []int    `json:"disabled"`
	MaxContentRating   string   `json:"max_content_rating"`
	AllowUnrated       bool     `json:"allow_unrated_content"`
	MaxAdvisoryAge     int      `json:"max_advisory_age"`
	RequireAdvisoryAge bool     `json:"require_advisory_age"`
	Excluded           []string `json:"excluded_media_types"`
}

func (a accessIn) filter() catalog.AccessFilter {
	return catalog.AccessFilter{
		AllowedLibraryIDs:  a.Allowed,
		DisabledLibraryIDs: a.Disabled,
		MaturityLimits: access.MaturityLimits{
			MaxContentRating: a.MaxContentRating, AllowUnratedContent: a.AllowUnrated,
			MaxAdvisoryAge: a.MaxAdvisoryAge, RequireAdvisoryAge: a.RequireAdvisoryAge,
		},
		ExcludedMediaTypes: a.Excluded,
	}
}

var accesses = []accessIn{
	{Name: "unrestricted"},
	{Name: "one_library", Allowed: []int{1}},
	{Name: "allowed", Allowed: []int{1, 2}},
	{Name: "none_allowed", Allowed: []int{}},
	{Name: "disabled", Disabled: []int{2}},
	{Name: "allowed+disabled", Allowed: []int{1, 2}, Disabled: []int{2}},
	{Name: "kid", MaxContentRating: "PG", AllowUnrated: true, MaxAdvisoryAge: 12},
	{Name: "kid_strict", MaxContentRating: "TV-Y7", RequireAdvisoryAge: true, MaxAdvisoryAge: 7},
	{Name: "excluded", Excluded: []string{"ebook", "audiobook"}},
	{Name: "kid+one_library+excluded", Allowed: []int{2}, MaxContentRating: "PG-13", MaxAdvisoryAge: 13, Excluded: []string{"ebook"}},
}

var queries = []string{
	"", "   ", "\"\"", "matrix", "the matrix", "The Matrix 1999", "1999", "\"star wars\" 1977",
	"\"star wars\"", "\"star wars\" empire", "ab", "it", "the m", "castle", "Amélie", "spider-man: no way home",
	"avegners endgame", "gane of throns", "the god place", "from up", "o'brien", "日本語", "a",
}

var typeSets = [][]string{nil, {}, {"movie"}, {"series"}, {"episode"}, {"Movie", " series ", ""}, {"movie", "episode"}, {"series", "episode", "movie"}, {"ebook"}}

type sqlCase struct {
	Kind     string   `json:"kind"`
	Query    string   `json:"query,omitempty"`
	Types    []string `json:"types"`
	Limit    int      `json:"limit"`
	Offset   int      `json:"offset"`
	Total    bool     `json:"total"`
	Exclude  []string `json:"exclude"`
	MinSim   float64  `json:"min_sim"`
	UserID   int      `json:"user_id"`
	IDs      []string `json:"ids"`
	Access   accessIn `json:"access"`
	DataSQL  string   `json:"data_sql"`
	CountSQL string   `json:"count_sql"`
	Args     []arg    `json:"args"`
}

type rerankCase struct {
	Search    string     `json:"search"`
	Titles    []string   `json:"titles"`
	Aliases   [][]string `json:"aliases"`
	ExactHits bool       `json:"exact_hits"`
	Admitted  []string   `json:"admitted"`
	Required  int        `json:"required"`
	Candidate string     `json:"candidate_text"`
}

type textCase struct {
	Query      string   `json:"query"`
	SearchText string   `json:"search_text"`
	Types      []string `json:"types"`
	MediaTypes []string `json:"media_types"`
	Episodes   bool     `json:"episodes"`
}

type levCase struct {
	A   string `json:"a"`
	B   string `json:"b"`
	Max int    `json:"max"`
	D   int    `json:"d"`
}

type out struct {
	SQL    []sqlCase    `json:"sql"`
	Rerank []rerankCase `json:"rerank"`
	Text   []textCase   `json:"text"`
	Lev    []levCase    `json:"levenshtein"`
}

func main() {
	var o out
	for _, a := range accesses {
		f := a.filter()
		for _, ids := range [][]string{{"m1"}, {"m2", "m1", "e3"}} {
			s, as := catalog.VecGetByIDsWithAccessSQL(ids, f)
			o.SQL = append(o.SQL, sqlCase{Kind: "get_by_ids", IDs: ids, Access: a, DataSQL: s, Args: args(as)})
			s, as = catalog.VecCountVisiblePersonalSQL(7, ids, f)
			o.SQL = append(o.SQL, sqlCase{Kind: "count_personal", UserID: 7, IDs: ids, Access: a, DataSQL: s, Args: args(as)})
		}
		qs, tss := queries, typeSets
		if a.Name != "unrestricted" {
			qs, tss = []string{"the matrix", "\"star wars\" 1977", "castle"}, [][]string{nil, {"movie", "episode"}}
		}
		for _, q := range qs {
			for _, ts := range tss {
				for _, page := range [][2]int{{20, 0}, {21, 40}} {
					for _, total := range []bool{true, false} {
						d, c, as := catalog.VecMixedSearchSQL(q, ts, page[0], page[1], f, total)
						o.SQL = append(o.SQL, sqlCase{Kind: "mixed", Query: q, Types: ts, Limit: page[0], Offset: page[1], Total: total, Access: a, DataSQL: d, CountSQL: c, Args: args(as)})
					}
				}
				for _, ex := range []struct {
					ids []string
					min float64
				}{{nil, 0}, {[]string{"m1", "m2"}, 0.45}} {
					d, c, as := catalog.VecFuzzySearchSQL(q, ts, 20, 0, f, ex.min == 0, ex.ids, ex.min)
					o.SQL = append(o.SQL, sqlCase{Kind: "fuzzy", Query: q, Types: ts, Limit: 20, Total: ex.min == 0, Exclude: ex.ids, MinSim: ex.min, Access: a, DataSQL: d, CountSQL: c, Args: args(as)})
				}
			}
		}
	}
	titles := []string{"The Good Place", "The Bad Place", "A Quiet Place", "Quiet Place", "Game of Thrones",
		"Justice League: Throne of Atlantis", "Avengers: Endgame", "Harry Potter and the Philosopher's Stone",
		"Miss Potter", "Live Stream From Hell", "Livestream from Hell", "Up", "From Up on Poppy Hill",
		"The Godfather", "The Godfather Part II", "Godfather", "Amélie", "Spider-Man: No Way Home", ""}
	aliases := make([][]string, len(titles))
	aliases[4] = []string{"GoT", "Juego de Tronos"}
	aliases[16] = []string{"Le Fabuleux Destin d'Amélie Poulain"}
	searches := []string{"the god place", "gane of throns", "avegners", "hary poter", "livestream from hel",
		"live stream from hell", "from up", "the godfathr", "godfather", "a quiet place", "the the", "juego tronos",
		"amelie", "spidr man no way hom", "zzzzzzz", "", "a b c d e f g h i j k l m n o p q r s"}
	for _, s := range searches {
		for _, exact := range []bool{false, true} {
			adm, req := catalog.VecFuzzyRerank(s, titles, aliases, exact)
			o.Rerank = append(o.Rerank, rerankCase{s, titles, aliases, exact, adm, req, catalog.VecFuzzyCandidateText(s)})
		}
	}
	for _, q := range queries {
		for _, ts := range typeSets {
			mt, ep := catalog.VecSplitSearchItemTypes(ts)
			o.Text = append(o.Text, textCase{q, catalog.VecSearchText(q), ts, mt, ep})
		}
	}
	words := []string{"", "a", "ab", "kitten", "sitting", "godfathr", "godfather", "flaw", "lawn", "amélie", "amelie", "日本", "日本語"}
	for _, a := range words {
		for _, b := range words {
			for _, m := range []int{0, 1, 2} {
				o.Lev = append(o.Lev, levCase{a, b, m, catalog.VecLevenshtein(a, b, m)})
			}
		}
	}
	b, err := json.Marshal(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := os.WriteFile("rust/conformance/vectors/catalog/search_sql.json", append(b, '\n'), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
