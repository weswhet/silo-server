//go:build catalogquery_vectors

// Command catalogquery writes the silo-catalog query engine vectors from the real
// internal/catalog package: QueryBuilder.Build and BuildSortPlan, buildPreviewPagePlan's
// statements, buildCountQuery, cursorSeekSQL, parseDuration, and definition validation. Every
// argument is recorded with its Go type, because the type decides how pgx binds it. See run.sh.
//
// With `db <url>` it also runs a corpus of preview pages through QueryExecutor.PreviewPage
// against that database (the scratch clone run.sh prepares) and records the ordered content
// IDs, for the Rust Postgres test to compare against.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Silo-Server/silo-server/internal/access"
	"github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/models"
)

const outDir = "rust/conformance/vectors/catalog"

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "catalogquery:", err)
		os.Exit(1)
	}
}

func write(name string, v any) {
	b, err := json.Marshal(v)
	must(err)
	must(os.MkdirAll(outDir, 0o755))
	must(os.WriteFile(filepath.Join(outDir, name+".json"), append(b, '\n'), 0o644))
}

// arg is one bound argument with its Go type.
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

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// accessIn is the JSON form of an AccessFilter both sides decode.
type accessIn struct {
	Name               string   `json:"name"`
	Allowed            []int    `json:"allowed"`
	Disabled           []int    `json:"disabled"`
	MaxContentRating   string   `json:"max_content_rating"`
	AllowUnrated       bool     `json:"allow_unrated_content"`
	MaxAdvisoryAge     int      `json:"max_advisory_age"`
	RequireAdvisoryAge bool     `json:"require_advisory_age"`
	AllowedContentIDs  []string `json:"allowed_content_ids"`
	UserID             int      `json:"user_id"`
	ProfileID          string   `json:"profile_id"`
	NamePrefix         string   `json:"name_prefix"`
	Excluded           []string `json:"excluded_media_types"`
}

func (a accessIn) filter() catalog.AccessFilter {
	return catalog.AccessFilter{
		AllowedLibraryIDs:  a.Allowed,
		DisabledLibraryIDs: a.Disabled,
		AllowedContentIDs:  a.AllowedContentIDs,
		MaturityLimits: access.MaturityLimits{
			MaxContentRating: a.MaxContentRating, AllowUnratedContent: a.AllowUnrated,
			MaxAdvisoryAge: a.MaxAdvisoryAge, RequireAdvisoryAge: a.RequireAdvisoryAge,
		},
		UserID: a.UserID, ProfileID: a.ProfileID, NamePrefix: a.NamePrefix, ExcludedMediaTypes: a.Excluded,
	}
}

// The library IDs here are the seeded conformance libraries (1 movies, 2 series).
var accesses = []accessIn{
	{Name: "unrestricted"},
	{Name: "allowed", Allowed: []int{1, 2}},
	{Name: "disabled", Disabled: []int{2}},
	{Name: "kid", MaxContentRating: "PG", AllowUnrated: true, MaxAdvisoryAge: 12},
}

// profiled is an access with a viewer, for personalized rules and sorts.
func profiled(a accessIn) accessIn {
	a.Name += "+profile"
	a.UserID, a.ProfileID = 2, "c0f00000-0000-4000-8000-000000000002"
	return a
}

// kidProfile is the seeded kid profile (Conf Kid, rated PG) on the seeded user.
var kidProfile = accessIn{Name: "kid-profile", MaxContentRating: "PG", UserID: 2, ProfileID: "c0f00000-0000-4000-8000-000000000003"}

func defJSON(def string) catalog.QueryDefinition {
	var d catalog.QueryDefinition
	must(json.Unmarshal([]byte(def), &d))
	return d
}

// ruleValues lists the values a rule corpus tries for a field and operator.
func ruleValues(field, op string) []any {
	switch op {
	case "in_last", "not_in_last":
		return []any{"30d", "2w", " 12H ", "6m", "1y", "0d", "x", "5q", 3.0}
	case "between":
		switch field {
		case "latest_episode_added", "last_air_date", "added_at", "release_date", "last_watched":
			return []any{[]any{"2020-01-01", "2024-12-31T00:00:00Z"}, []any{"2020-01-01"}, "nope", []any{"2020-13-01", "2021-01-01"}}
		case "year":
			return []any{[]any{1990.0, 1999.0}}
		default:
			return []any{[]any{5.0, 8.5}, []any{"5", "x"}, []any{1.0}}
		}
	}
	switch field {
	case "type":
		return []any{"movie"}
	case "genre", "studio", "network", "country":
		return []any{"Drama"}
	case "year":
		return []any{2001.0}
	case "rating_imdb", "runtime", "rating_tmdb", "rating_rt_critic", "rating_rt_audience", "bitrate":
		return []any{7.5, "8", "abc"}
	case "original_language", "audio_language", "subtitle_language":
		return []any{"EN"}
	case "content_rating":
		return []any{"PG-13"}
	case "added_at", "release_date", "last_watched":
		return []any{"2020-06-01"}
	case "latest_episode_added", "last_air_date":
		return []any{"2020-06-01", "06/01/2020", 5.0}
	case "status":
		return []any{"matched"}
	case "actor", "director", "writer", "producer", "author", "narrator", "series":
		return []any{"Tom Hanks"}
	case "watched", "favorited", "in_watchlist", "in_progress", "hdr", "dolby_vision":
		return []any{true, false, "true", "1"}
	case "resolution":
		return []any{" 4K ", "1080p", 1.0}
	case "show_title", "title":
		return []any{"Star 100%_x", "  ", 3.0}
	case "decade":
		return []any{1995.0, "1980", 5.0, 10000.0}
	}
	return []any{"x"}
}

var ruleFields = []string{
	"type", "genre", "year", "rating_imdb", "rating", "studio", "network", "country", "original_language",
	"content_rating", "added_at", "release_date", "status", "actor", "director", "writer", "producer",
	"author", "narrator", "series", "watched", "favorited", "in_watchlist", "in_progress", "last_watched",
	"resolution", "hdr", "dolby_vision", "bitrate", "audio_language", "subtitle_language", "show_title",
	"title", "decade", "runtime", "rating_tmdb", "rating_rt_critic", "rating_rt_audience",
	"latest_episode_added", "last_air_date", "nope",
}

var allOps = []string{"is", "is_not", "contains", "not_contains", "begins_with", "ends_with", "gt", "gte", "lt", "lte", "between", "in_last", "not_in_last"}

type buildCase struct {
	Builder catalog.VecBuilder `json:"builder"`
	Def     string             `json:"def"`
	SQL     string             `json:"sql"`
	Args    []arg              `json:"args"`
	CTE     bool               `json:"history_cte"`
	ArgIdx  int                `json:"arg_idx"`
	V1Error string             `json:"v1_error"`
	Error   string             `json:"error"`
}

func ruleDefs() []string {
	var defs []string
	for _, field := range ruleFields {
		for _, op := range allOps {
			for _, value := range ruleValues(field, op) {
				rule := map[string]any{"field": field, "op": op, "value": value}
				b, _ := json.Marshal(map[string]any{"groups": []any{map[string]any{"rules": []any{rule}}}})
				defs = append(defs, string(b))
			}
		}
	}
	defs = append(defs,
		`{}`,
		`{"groups":[]}`,
		`{"groups":[{"rules":[]}]}`,
		`{"match":"ANY","groups":[{"rules":[{"field":"genre","op":"is","value":"Drama"}]},{"match":"any","rules":[{"field":"year","op":"gt","value":2000},{"field":"type","op":"is_not","value":"series"}]}]}`,
		`{"groups":[{"rules":[{"field":"resolution","op":"is","value":"4k"},{"field":"hdr","op":"is","value":true},{"field":"bitrate","op":"between","value":[1000,9000]},{"field":"audio_language","op":"is","value":"en"},{"field":"subtitle_language","op":"is","value":"FR"},{"field":"dolby_vision","op":"is","value":false}]}]}`,
		`{"groups":[{"rules":[{"field":"resolution","op":"is","value":"4k"},{"field":"bitrate","op":"gte","value":5}]}]}`,
		`{"groups":[{"match":"any","rules":[{"field":"resolution","op":"is","value":"4k"},{"field":"hdr","op":"is","value":true}]}]}`,
		`{"groups":[{"rules":[{"field":"resolution","op":"is","value":"4k"},{"field":"resolution","op":"is_not","value":"720p"},{"field":"hdr","op":"is","value":"true"}]}]}`,
		`{"groups":[{"rules":[{"field":"last_watched","op":"in_last","value":"30d"},{"field":"watched","op":"is","value":true}]},{"rules":[{"field":"in_progress","op":"is","value":false}]}]}`,
		`{"match":"some","groups":[]}`,
		`{"groups":[{"match":"x","rules":[]}]}`,
		`{"library_ids":[0,3],"groups":[]}`,
		`{"media_scope":"podcast","groups":[]}`,
		`{"sort":{"field":"nope"}}`,
		`{"sort":{"order":"up"}}`,
		`{"limit":0}`,
		`{"media_scope":"ebook","groups":[{"rules":[{"field":"narrator","op":"is","value":"A"}]}]}`,
		`{"media_scope":"ebook","sort":{"field":"narrator"}}`,
	)
	return defs
}

var builderScopes = []string{"", "episode", "ebook", "series", "movie"}

func buildVectors() []buildCase {
	var cases []buildCase
	for _, def := range ruleDefs() {
		for _, scope := range builderScopes {
			for _, user := range []bool{true, false} {
				if !user && scope != "" {
					continue
				}
				for _, libs := range [][]int{nil, {3}, {1, 2}} {
					if libs != nil && (scope != "" || !user) {
						continue
					}
					b := catalog.VecBuilder{Alias: "mi", MediaScope: scope, LibraryIDs: libs, MediaItems: scope != "episode", ArgIdx: 4}
					if user {
						b.UserID, b.ProfileID = 2, "p2"
					}
					sql, a, cte, idx, err := catalog.VecBuild(b, defJSON(def))
					c := buildCase{Builder: b, Def: def, SQL: sql, Args: args(a), CTE: cte, ArgIdx: idx, Error: errText(err)}
					c.V1Error = errText(catalog.ValidateV1Rules(defJSON(def)))
					cases = append(cases, c)
				}
			}
		}
	}
	return cases
}

type sortPlanOut struct {
	Terms   []catalog.VecTerm `json:"terms"`
	Joins   []string          `json:"joins"`
	OrderBy string            `json:"order_by"`
	Args    []arg             `json:"args"`
}

type sortCase struct {
	Builder catalog.VecBuilder `json:"builder"`
	Sort    catalog.QuerySort  `json:"sort"`
	Plan    *sortPlanOut       `json:"plan"`
	Error   string             `json:"error"`
}

func sortVectors() []sortCase {
	fields := []string{"", "sort_title", "recently_added", "rating", "random", "nope"}
	for f := range catalog.QuerySortFieldSet(true) {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	var cases []sortCase
	for _, field := range fields {
		for _, order := range []string{"", "ASC", "desc", "sideways"} {
			for _, scope := range builderScopes {
				for _, libs := range [][]int{nil, {3}, {1, 2}} {
					for _, user := range []bool{true, false} {
						for _, alias := range []string{"mi", "x"} {
							if alias == "x" && (libs != nil || !user || scope != "") {
								continue
							}
							b := catalog.VecBuilder{Alias: alias, MediaScope: scope, LibraryIDs: libs, MediaItems: scope != "episode" && alias == "mi", ArgIdx: 7}
							if user {
								b.UserID, b.ProfileID = 2, "p2"
							}
							s := catalog.QuerySort{Field: field, Order: order}
							plan, err := catalog.VecSort(b, s)
							c := sortCase{Builder: b, Sort: s, Error: errText(err)}
							if plan != nil {
								c.Plan = &sortPlanOut{plan.Terms, plan.Joins, plan.OrderBy, args(plan.Args)}
							}
							cases = append(cases, c)
						}
					}
				}
			}
		}
	}
	return cases
}

type planOut struct {
	Terms         []catalog.VecTerm `json:"terms"`
	PagedSQL      string            `json:"paged_sql"`
	PagedArgs     []arg             `json:"paged_args"`
	PagedTotalSQL string            `json:"paged_total_sql"`
	CountSQL      string            `json:"count_sql"`
	CountArgs     []arg             `json:"count_args"`
	CursorSQL     string            `json:"cursor_sql"`
	CursorArgs    []arg             `json:"cursor_args"`
	AfterSQL      string            `json:"after_sql"`
	AfterArgs     []arg             `json:"after_args"`
	AfterError    string            `json:"after_error"`
	TupleSQL      string            `json:"tuple_sql"`
	TupleArgs     []arg             `json:"tuple_args"`
	TitleKey      string            `json:"title_key"`
	AnchorSQL     string            `json:"anchor_sql"`
	AnchorArgs    []arg             `json:"anchor_args"`
}

type planCaseOut struct {
	Executor catalog.VecExecutor `json:"executor"`
	Def      string              `json:"def"`
	Access   accessIn            `json:"access"`
	Limit    int                 `json:"limit"`
	Offset   int                 `json:"offset"`
	After    *string             `json:"after"`
	Plan     *planOut            `json:"plan"`
	Error    string              `json:"error"`
	CountSQL string              `json:"count_sql"`
	CountArg []arg               `json:"count_args"`
	CountErr string              `json:"count_error"`
}

var planDefs = []string{
	`{}`,
	`{"media_scope":"movie"}`,
	`{"media_scope":"video","sort":{"field":"title"}}`,
	`{"media_scope":"series","sort":{"field":"last_air_date"},"limit":5}`,
	`{"media_scope":"episode","sort":{"field":"title"}}`,
	`{"media_scope":"episode","sort":{"field":"release_date","order":"asc"}}`,
	`{"media_scope":"ebook","sort":{"field":"progress"}}`,
	`{"library_ids":[2,1,1],"sort":{"field":"added_at"}}`,
	`{"library_ids":[1],"sort":{"field":"added_at","order":"asc"}}`,
	`{"library_ids":[1],"media_scope":"episode","sort":{"field":"added_at"}}`,
	`{"sort":{"field":"resolution"},"limit":3}`,
	`{"sort":{"field":"content_rating"}}`,
	`{"sort":{"field":"series"}}`,
	`{"sort":{"field":"date_viewed"}}`,
	`{"sort":{"field":"plays"}}`,
	`{"groups":[{"rules":[{"field":"last_watched","op":"in_last","value":"30d"}]}],"sort":{"field":"progress"}}`,
	`{"groups":[{"rules":[{"field":"watched","op":"is","value":false},{"field":"genre","op":"is","value":"Drama"}]}]}`,
	`{"match":"any","groups":[{"rules":[{"field":"year","op":"gte","value":2000}]},{"rules":[{"field":"rating","op":"gt","value":7}]}],"sort":{"field":"year"}}`,
	`{"groups":[{"rules":[{"field":"resolution","op":"is","value":"4k"},{"field":"hdr","op":"is","value":true}]}],"library_ids":[1]}`,
	`{"groups":[{"rules":[{"field":"nope","op":"is","value":1}]}]}`,
}

var snapshot = time.Date(2024, 5, 6, 7, 8, 9, 123000000, time.FixedZone("", 7200))

func executors() []catalog.VecExecutor {
	return []catalog.VecExecutor{
		{},
		{GroupByWork: true},
		{SourceWhere: "mi.content_id IN (SELECT content_id FROM media_item_libraries WHERE media_folder_id = $1)", SourceArgs: []any{1}},
		{SourceCTE: "src AS (SELECT content_id AS id, created_at AS pos FROM media_items WHERE year > $1)", SourceJoin: "JOIN src s ON s.id = mi.content_id", SourceArgs: []any{1990},
			SourceOrder: []catalog.VecTerm{{Expression: "s.pos", Kind: "timestamp", Descending: true}, {Expression: "mi.content_id", Kind: "text", NullsLast: true}}},
		{Scope: "episode"},
		{BaseRelationSQL: "(SELECT * FROM media_items) mi"},
		{SnapshotAt: &snapshot},
	}
}

func planVectors() []planCaseOut {
	var out []planCaseOut
	value := "2021-01-01"
	for ei, ex := range executors() {
		for _, def := range planDefs {
			list := accesses
			if ei == 0 {
				list = append([]accessIn{}, accesses...)
				for _, a := range accesses {
					list = append(list, profiled(a))
				}
				list = append(list,
					accessIn{Name: "content-ids", AllowedContentIDs: []string{"a", "b"}, NamePrefix: " The_% ", Excluded: []string{"audiobook", "podcast"}},
					accessIn{Name: "no-content", AllowedContentIDs: []string{}, Allowed: []int{}},
					accessIn{Name: "strict", MaxContentRating: "PG-13", MaxAdvisoryAge: 10, RequireAdvisoryAge: true, Allowed: []int{1}, Disabled: []int{1}},
					accessIn{Name: "bad-ceiling", MaxContentRating: "zzz"},
					kidProfile,
				)
			}
			for _, a := range list {
				for _, page := range [][2]int{{20, 0}, {5, 10}, {0, -1}} {
					if page != [2]int{20, 0} && (ei != 0 || (a.Name != "unrestricted" && a.Name != "kid+profile")) {
						continue
					}
					for _, after := range []*string{&value, nil} {
						if after == nil && page != [2]int{20, 0} {
							continue
						}
						d := defJSON(def)
						plan, err := catalog.VecPlan(ex, d, a.filter(), page[0], page[1], after)
						c := planCaseOut{Executor: ex, Def: def, Access: a, Limit: page[0], Offset: page[1], After: after, Error: errText(err)}
						if plan != nil {
							q := squeeze
							c.Plan = &planOut{plan.Terms, q(plan.PagedSQL), args(plan.PagedArgs), q(plan.PagedTotalSQL), q(plan.CountSQL), args(plan.CountArgs),
								q(plan.CursorSQL), args(plan.CursorArgs), q(plan.AfterSQL), args(plan.AfterArgs), plan.AfterError, q(plan.TupleSQL), args(plan.TupleArgs), plan.TitleKey, q(plan.AnchorSQL), args(plan.AnchorArgs)}
						}
						countSQL, countArgs, cerr := catalog.VecCount(ex, d, a.filter())
						c.CountSQL, c.CountArg, c.CountErr = squeeze(countSQL), args(countArgs), errText(cerr)
						out = append(out, c)
					}
				}
			}
		}
	}
	return out
}

type seekCase struct {
	Terms []catalog.VecTerm    `json:"terms"`
	After *catalog.QueryCursor `json:"after"`
	Start int                  `json:"start"`
	SQL   string               `json:"sql"`
	Args  []arg                `json:"args"`
	Error string               `json:"error"`
}

func seekVectors() []seekCase {
	v := func(s string) *string { return &s }
	termSets := [][]catalog.VecTerm{
		{{Expression: "a", Kind: "text", NotNull: true}, {Expression: "b", Kind: "text", NullsLast: true, NotNull: true}},
		{{Expression: "x", Kind: "number", Descending: true, NullsLast: true}, {Expression: "t", Kind: "text", NullsLast: true}, {Expression: "id", Kind: "text", NullsLast: true}},
		{{Expression: "d", Kind: "date", Descending: true}, {Expression: "n", Kind: "number", SQLType: "int"}, {Expression: "ts", Kind: "timestamp", Descending: true, NotNull: true}},
	}
	var out []seekCase
	for _, terms := range termSets {
		variants := []*catalog.QueryCursor{nil}
		for mask := 0; mask < 1<<len(terms); mask++ {
			c := &catalog.QueryCursor{}
			for i, t := range terms {
				key := catalog.QueryCursorValue{Kind: t.Kind}
				if mask&(1<<i) != 0 {
					key.Value = v(fmt.Sprintf("v%d", i))
				}
				c.Keys = append(c.Keys, key)
			}
			variants = append(variants, c)
		}
		variants = append(variants, &catalog.QueryCursor{Keys: []catalog.QueryCursorValue{{Kind: "text"}}})
		bad := &catalog.QueryCursor{}
		for range terms {
			bad.Keys = append(bad.Keys, catalog.QueryCursorValue{Kind: "bogus"})
		}
		variants = append(variants, bad)
		for _, after := range variants {
			sql, a, err := catalog.VecSeek(terms, after, 5)
			out = append(out, seekCase{Terms: terms, After: after, Start: 5, SQL: sql, Args: args(a), Error: errText(err)})
		}
	}
	return out
}

type durationCase struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Error  string `json:"error"`
}

func durationVectors() []durationCase {
	var out []durationCase
	for _, in := range []string{"30d", " 2W", "12h", "6m", "1y", "0d", "-3d", "+3d", "d", "", "x", "5q", "5é", "3 d", "100000001d", "99999999h", "7000y", "6000y", "1_0d", "07d", "9223372036854775808d", "'d"} {
		o, err := catalog.VecParseDuration(in)
		out = append(out, durationCase{in, o, errText(err)})
	}
	return out
}

type cursorJSONCase struct {
	Cursor catalog.QueryCursor `json:"cursor"`
	JSON   string              `json:"json"`
}

func cursorJSONVectors() []cursorJSONCase {
	v := "2024-01-01T00:00:00Z"
	var out []cursorJSONCase
	for _, c := range []catalog.QueryCursor{
		{},
		{Keys: []catalog.QueryCursorValue{{Kind: "timestamp", Value: &v}, {Kind: "text"}}, Consumed: 40},
	} {
		b, err := json.Marshal(c)
		must(err)
		out = append(out, cursorJSONCase{c, string(b)})
	}
	return out
}

type libraryScopeCase struct {
	Access    accessIn `json:"access"`
	Requested []int    `json:"requested"`
	IDs       []int    `json:"ids"`
	None      bool     `json:"none"`
}

func libraryScopeVectors() []libraryScopeCase {
	var out []libraryScopeCase
	for _, a := range []accessIn{{}, {Allowed: []int{}}, {Allowed: []int{1, 2, 3}}, {Disabled: []int{2}}, {Allowed: []int{2, 1}, Disabled: []int{1}}} {
		for _, req := range [][]int{nil, {2}, {3, 2, 2}, {5}} {
			ids, none := catalog.VecLibraryScope(a.filter(), req)
			out = append(out, libraryScopeCase{a, req, ids, none})
		}
	}
	return out
}

// cursorCase walks a definition two cursor pages deep, then seeks.
type cursorCase struct {
	Def    string               `json:"def"`
	Access accessIn             `json:"access"`
	Limit  int                  `json:"limit"`
	Page1  []string             `json:"page1"`
	Next1  *catalog.QueryCursor `json:"next1"`
	Total  int                  `json:"total"`
	Page2  []string             `json:"page2"`
	Next2  *catalog.QueryCursor `json:"next2"`
	Error  string               `json:"error"`
	Seeks  []seekOut            `json:"seeks"`
}

type seekOut struct {
	Index  int                  `json:"index"`
	Cursor *catalog.QueryCursor `json:"cursor"`
	Error  string               `json:"error"`
}

func ids(items []*models.MediaItem) []string {
	out := []string{}
	for _, it := range items {
		out = append(out, it.ContentID)
	}
	return out
}

func cursorVectors(pool *pgxpool.Pool) []cursorCase {
	ctx := context.Background()
	var out []cursorCase
	defs := []string{
		`{"sort":{"field":"title"}}`,
		`{"sort":{"field":"title","order":"desc"},"limit":250}`,
		`{"sort":{"field":"added_at"}}`,
		`{"library_ids":[1],"sort":{"field":"added_at","order":"asc"}}`,
		`{"sort":{"field":"release_date"}}`,
		`{"sort":{"field":"year","order":"asc"}}`,
		`{"sort":{"field":"rating_imdb"}}`,
		`{"sort":{"field":"content_rating"}}`,
		`{"sort":{"field":"resolution"}}`,
		`{"sort":{"field":"progress"}}`,
		`{"sort":{"field":"date_viewed"}}`,
		`{"sort":{"field":"plays"}}`,
		`{"sort":{"field":"last_air_date"},"media_scope":"series"}`,
		`{"sort":{"field":"latest_episode_added"}}`,
		`{"media_scope":"episode","sort":{"field":"release_date"}}`,
		`{"media_scope":"episode","sort":{"field":"title"}}`,
		`{"groups":[{"rules":[{"field":"watched","op":"is","value":false}]}],"sort":{"field":"runtime"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"title"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"added_at"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"release_date","order":"asc"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"date_viewed"}}`,
		`{"media_scope":"episode","library_ids":[2],"groups":[{"rules":[{"field":"watched","op":"is","value":false}]}],"sort":{"field":"title"}}`,
	}
	for _, def := range defs {
		for _, a := range []accessIn{profiled(accesses[0]), kidProfile, profiled(accesses[2])} {
			ex := catalog.VecWithSeekAnchors(&catalog.QueryExecutor{Pool: pool})
			c := cursorCase{Def: def, Access: a, Limit: 40, Seeks: []seekOut{}}
			p1, err := ex.PreviewCursorPage(ctx, defJSON(def), a.filter(), 40, nil, true)
			if err != nil {
				c.Error = err.Error()
				out = append(out, c)
				continue
			}
			c.Page1, c.Next1, c.Total = ids(p1.Items), p1.Next, p1.Total
			if p1.Next != nil {
				p2, err := ex.PreviewCursorPage(ctx, defJSON(def), a.filter(), 40, p1.Next, false)
				must(err)
				c.Page2, c.Next2 = ids(p2.Items), p2.Next
			}
			for _, index := range []int{0, 1, 39, 100, 255, 256, 257, 270, 299, 5000} {
				key, err := ex.SeekCursor(ctx, defJSON(def), a.filter(), index)
				c.Seeks = append(c.Seeks, seekOut{index, key, errText(err)})
			}
			out = append(out, c)
		}
	}
	return out
}

// dbCase is one PreviewPage run against the scratch database.
type dbCase struct {
	Def     string   `json:"def"`
	Access  accessIn `json:"access"`
	Limit   int      `json:"limit"`
	Offset  int      `json:"offset"`
	IDs     []string `json:"ids"`
	Total   int      `json:"total"`
	HasMore bool     `json:"has_more"`
	Error   string   `json:"error"`
}

func dbVectors(url string) []dbCase {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	must(err)
	defer pool.Close()
	var out []dbCase
	list := append([]accessIn{}, accesses...)
	for _, a := range accesses {
		list = append(list, profiled(a))
	}
	list = append(list, kidProfile)
	defs := append(append([]string{}, planDefs...),
		`{"groups":[{"rules":[{"field":"genre","op":"contains","value":"Drama"}]}],"sort":{"field":"title"}}`,
		`{"groups":[{"rules":[{"field":"year","op":"between","value":[1990,2005]}]}],"sort":{"field":"year","order":"asc"}}`,
		`{"groups":[{"rules":[{"field":"rating_tmdb","op":"gte","value":"6.5"}]}],"sort":{"field":"rating_tmdb"}}`,
		`{"groups":[{"rules":[{"field":"decade","op":"is","value":1990}]}]}`,
		`{"groups":[{"rules":[{"field":"title","op":"contains","value":"the"}]}],"sort":{"field":"title","order":"desc"}}`,
		`{"groups":[{"rules":[{"field":"added_at","op":"in_last","value":"100y"}]}]}`,
		`{"groups":[{"rules":[{"field":"release_date","op":"between","value":["1990-01-01","2010-12-31"]}]}],"sort":{"field":"release_date"}}`,
		`{"groups":[{"rules":[{"field":"content_rating","op":"is","value":"PG"}]}]}`,
		`{"groups":[{"rules":[{"field":"favorited","op":"is","value":true}]}]}`,
		`{"groups":[{"rules":[{"field":"in_watchlist","op":"is","value":false}]}]}`,
		`{"groups":[{"rules":[{"field":"in_progress","op":"is","value":true}]}],"sort":{"field":"progress"}}`,
		`{"groups":[{"rules":[{"field":"last_watched","op":"lt","value":"2100-01-01"}]}],"sort":{"field":"date_viewed"}}`,
		`{"groups":[{"rules":[{"field":"actor","op":"is_not","value":"Nobody"}]}],"sort":{"field":"runtime"}}`,
		`{"groups":[{"rules":[{"field":"bitrate","op":"gt","value":1}]}],"sort":{"field":"bitrate"}}`,
		`{"groups":[{"rules":[{"field":"type","op":"is","value":"series"},{"field":"last_air_date","op":"in_last","value":"50y"}]}],"sort":{"field":"latest_episode_added"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"title"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"added_at","order":"asc"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"release_date"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"year"},"groups":[{"rules":[{"field":"genre","op":"contains","value":"Drama"}]}]}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"progress"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"date_viewed"}}`,
		`{"media_scope":"episode","library_ids":[2],"sort":{"field":"plays","order":"asc"}}`,
		`{"media_scope":"episode","library_ids":[2],"groups":[{"rules":[{"field":"watched","op":"is","value":false}]}]}`,
		`{"media_scope":"episode","library_ids":[2],"groups":[{"rules":[{"field":"watched","op":"is","value":true}]}],"sort":{"field":"date_viewed"}}`,
		`{"media_scope":"episode","library_ids":[2],"groups":[{"rules":[{"field":"in_progress","op":"is","value":true}]}]}`,
		`{"media_scope":"episode","library_ids":[2],"groups":[{"rules":[{"field":"last_watched","op":"in_last","value":"30y"}]}]}`,
		`{"media_scope":"episode","library_ids":[2],"limit":13,"sort":{"field":"content_rating"}}`,
	)
	for _, def := range defs {
		for _, a := range list {
			for _, page := range [][2]int{{7, 0}, {7, 7}, {500, 0}} {
				ex := &catalog.QueryExecutor{Pool: pool}
				items, total, more, err := ex.PreviewPage(ctx, defJSON(def), a.filter(), page[0], page[1], true)
				c := dbCase{Def: def, Access: a, Limit: page[0], Offset: page[1], Total: total, HasMore: more, Error: errText(err), IDs: []string{}}
				for _, it := range items {
					c.IDs = append(c.IDs, it.ContentID)
				}
				out = append(out, c)
			}
		}
	}
	return out
}

// The select list and the unscoped episode relation recur in every statement; the plan vectors
// carry them as these tokens, and query_columns records them once.
const (
	listColumnsToken = "<list_columns>"
	episodeBaseToken = "<episode_base_relation>"
)

func squeeze(sql string) string {
	sql = strings.ReplaceAll(sql, catalog.VecListColumns(), listColumnsToken)
	return strings.ReplaceAll(sql, catalog.VecEpisodeBaseRelation(), episodeBaseToken)
}

type ruleOut struct {
	Field     string   `json:"field"`
	Op        string   `json:"op"`
	Type      string   `json:"type"`
	ElemTypes []string `json:"elem_types"`
	Value     any      `json:"value"`
}

type groupOut struct {
	Match string    `json:"match"`
	Rules []ruleOut `json:"rules"`
}

type requestOut struct {
	Source           string            `json:"source"`
	Scope            string            `json:"scope"`
	SectionID        string            `json:"section_id"`
	LibraryID        int               `json:"library_id"`
	CollectionID     string            `json:"collection_id"`
	PersonID         int64             `json:"person_id"`
	NamePrefix       string            `json:"name_prefix"`
	SearchQuery      string            `json:"search_query"`
	LibraryIDs       []int             `json:"library_ids"`
	MediaScope       string            `json:"media_scope"`
	Match            string            `json:"match"`
	Groups           []groupOut        `json:"groups"`
	Sort             catalog.QuerySort `json:"sort"`
	QueryLimit       *int              `json:"query_limit"`
	Limit            int               `json:"limit"`
	Offset           int               `json:"offset"`
	UseSourceOrder   bool              `json:"use_source_order"`
	SkipTotal        bool              `json:"skip_total"`
	SnapshotAt       string            `json:"snapshot_at"`
	SearchMediaScope string            `json:"search_media_scope"`
	V1Rules          bool              `json:"v1_rules"`
	ValidateError    string            `json:"validate_error"`
}

type parseCase struct {
	Query         string      `json:"query"`
	SearchScopes  bool        `json:"search_media_scopes"`
	ExtendedRules bool        `json:"extended_rules"`
	Request       *requestOut `json:"request"`
	Error         string      `json:"error"`
}

var parseQueries = []string{
	"",
	"source=QUERY&limit=500&offset=-3&include_total=false",
	"limit=0&offset=12&include_total=TRUE",
	"limit=abc&include_total=nope",
	"q=%20star%20wars%20&name_prefix=%20Th%20",
	"q=x&sort=title",
	"sort=RELEVANCE",
	"sort=relevance&order=asc&q=a",
	"order=asc",
	"sort=sort_title&order=DESC",
	"sort=rating",
	"type=Movie&library_id=3&query_limit=9&match=ANY",
	"type=podcast&library_id=-1&query_limit=-2",
	"type=video_with_episodes",
	"type=video_with_episodes&source=favorites",
	"type=video_with_episodes&source=bogus",
	"type=video_with_episodes&source=section&section_id=x&scope=home",
	"genre=%20Drama%20&status=matched&year_min=1990&year_max=1999",
	"year_min=2000",
	"year_max=2010",
	"content_rating=PG",
	"content_rating=PG,%20R,,PG-13",
	"groups[0][match]=any&groups[0][rules][0][field]=year&groups[0][rules][0][op]=between&groups[0][rules][0][value][1]=2000&groups[0][rules][0][value][0]=1990",
	"groups[1][rules][2][field]=title&groups[1][rules][2][op]=is&groups[1][rules][2][value]=%201917%20&groups[0][rules][5][field]=watched&groups[0][rules][5][op]=is&groups[0][rules][5][value]=TRUE",
	"groups[0][rules][0][field]=rating&groups[0][rules][0][op]=gt&groups[0][rules][0][value]=7.5",
	"groups[0][rules][0][field]=genre&groups[0][rules][0][op]=is&groups[0][rules][0][value]=a&groups[0][rules][0][value]=b",
	"groups[0][rules][0][field]=year&groups[0][rules][0][op]=is&groups[0][rules][0][value]=%2B42&groups[0][rules][1][field]=year&groups[0][rules][1][op]=gt&groups[0][rules][1][value]=1e3",
	"groups[0][rules][0][field]=show_title&groups[0][rules][0][op]=contains&groups[0][rules][0][value][0]=12&groups[0][rules][0][value][3]=true",
	"groups[0][rules][0][op]=is&groups[x][match]=any&groups[0][rules][0][bogus]=1",
	"groups[2][match]=ANY",
	"groups[99999999999999999999][match]=any",
	"source=favorites",
	"source=watchlist&sort=added_at",
	"source=history&sort=added_at",
	"source=favorites&sort=year",
	"source=person",
	"source=person&person_id=abc",
	"source=person&person_id=9223372036854775807&sort=year",
	"source=section",
	"source=section&scope=other&section_id=s",
	"source=section&section_id=%20s1%20",
	"source=section&section_id=s1&library_id=4",
	"source=section&section_id=s1&scope=home&library_id=4",
	"source=section&section_id=s1&library_id=4&title=x&limit=5&snapshot=2024-01-01T00:00:00Z",
	"source=section&section_id=s1&library_id=4&sort=year",
	"source=section&section_id=s1&library_id=4&groups[0][match]=any",
	"source=library_collection",
	"source=user_collection&collection_id=c1&q=x",
	"source=library_collection&collection_id=c1&sort=title",
	"snapshot=2024-05-06T07:08:09.123456789%2B02:00",
	"snapshot=yesterday",
	"source=nope",
	"groups[0][rules][0][field]=not_in_last&groups[0][rules][0][op]=x",
	"groups[0][rules][0][field]=last_air_date&groups[0][rules][0][op]=not_in_last&groups[0][rules][0][value]=30d",
}

func ruleOutOf(r catalog.QueryRule) ruleOut {
	o := ruleOut{Field: r.Field, Op: r.Op, Type: fmt.Sprintf("%T", r.Value), Value: r.Value}
	if items, ok := r.Value.([]any); ok {
		for _, it := range items {
			o.ElemTypes = append(o.ElemTypes, fmt.Sprintf("%T", it))
		}
	}
	return o
}

func parseVectors() []parseCase {
	var out []parseCase
	for _, raw := range parseQueries {
		values, err := url.ParseQuery(raw)
		must(err)
		for _, opts := range []catalog.CatalogRequestOptions{{}, {SearchMediaScopes: true, ExtendedRules: true}} {
			req, err := catalog.ParseCatalogRequestWithOptions(values, opts)
			c := parseCase{Query: raw, SearchScopes: opts.SearchMediaScopes, ExtendedRules: opts.ExtendedRules, Error: errText(err)}
			if err == nil {
				r := &requestOut{Source: string(req.Source), Scope: req.Scope, SectionID: req.SectionID, LibraryID: req.LibraryID,
					CollectionID: req.CollectionID, PersonID: req.PersonID, NamePrefix: req.NamePrefix, SearchQuery: req.SearchQuery,
					LibraryIDs: req.Query.LibraryIDs, MediaScope: req.Query.MediaScope, Match: req.Query.Match, Sort: req.Query.Sort,
					QueryLimit: req.Query.Limit, Limit: req.Limit, Offset: req.Offset, UseSourceOrder: req.UseSourceOrder,
					SkipTotal: req.SkipTotal, SearchMediaScope: req.SearchMediaScope, V1Rules: req.V1Rules,
					Groups: []groupOut{}}
				if req.SnapshotAt != nil {
					r.SnapshotAt = req.SnapshotAt.Format(time.RFC3339Nano)
				}
				for _, g := range req.Query.Groups {
					gro := groupOut{Match: g.Match, Rules: []ruleOut{}}
					for _, rule := range g.Rules {
						gro.Rules = append(gro.Rules, ruleOutOf(rule))
					}
					r.Groups = append(r.Groups, gro)
				}
				// Validate last: Normalize writes through the shared Groups slice.
				r.ValidateError = errText(req.ValidateQueryDefinition())
				c.Request = r
			}
			out = append(out, c)
		}
	}
	return out
}

type fragmentCase struct {
	Input  string `json:"input"`
	Output string `json:"output"`
	Error  string `json:"error"`
}

func fragmentVectors() []fragmentCase {
	var out []fragmentCase
	for _, in := range []string{
		"", "  ", "null", "{}", "[]", "{bad", `{"groups":[]}`,
		`{"match":"ANY","groups":[{"match":"Any","rules":[{"field":" Watched ","op":"is","value":true},{"field":"TYPE","op":"is","value":" Movie "}]}]}`,
		`{"groups":[{"rules":[{"field":"type","op":"is","value":"all"}]},{"rules":[{"field":"watched","op":"is","value":false}]}]}`,
		`{"groups":[{"rules":[{"field":"type","op":"is","value":"all"}]}]}`,
		`{"groups":[{"rules":[{"field":"type","op":"is","value":"ebook"}]}]}`,
		`{"groups":[{"rules":[{"field":"type","op":"is","value":""}]}]}`,
		`{"groups":[{"rules":[{"field":"type","op":"is","value":3}]}]}`,
		`{"groups":[{"rules":[{"field":"watched","op":"is","value":"true"}]}]}`,
		`{"groups":[{"rules":[{"field":"watched","op":"gt","value":true}]}]}`,
		`{"groups":[{"rules":[{"field":"year","op":"is","value":1}]}]}`,
		`{"library_ids":[1]}`, `{"media_scope":" "}`, `{"media_scope":"movie"}`, `{"limit":3}`, `{"sort":{"field":"title"}}`, `{"sort":{"order":""}}`,
		`{"match":"bogus","groups":[{"rules":[{"field":"watched","op":"is","value":true}]}]}`,
		`{"groups":[{"rules":[{"field":"type","op":"is_not","value":"series"}]}],"extra":1}`,
	} {
		o, err := catalog.NormalizeDisplayQueryFragment([]byte(in))
		out = append(out, fragmentCase{in, o, errText(err)})
	}
	return out
}

type episodeQueryOut struct {
	Empty    bool   `json:"empty"`
	WithCTEs string `json:"with_ctes"`
	From     string `json:"from"`
	SortJoin string `json:"sort_join"`
	Where    string `json:"where"`
	OrderBy  string `json:"order_by"`
	Args     []arg  `json:"args"`
	Gate     bool   `json:"requires_full_page_gate"`
	PageSQL  string `json:"page_sql"`
	PageArgs []arg  `json:"page_args"`
	SeekSQL  string `json:"seek_sql"`
	SeekArgs []arg  `json:"seek_args"`
}

func episodeQueryOf(q *catalog.VecEpisodeQuery) *episodeQueryOut {
	if q == nil {
		return nil
	}
	return &episodeQueryOut{q.Empty, q.WithCTEs, q.From, q.SortJoin, q.Where, q.OrderBy, args(q.Args), q.Gate, q.PageSQL, args(q.PageArgs), q.SeekSQL, args(q.SeekArgs)}
}

type episodeCase struct {
	Executor   catalog.VecExecutor `json:"executor"`
	Def        string              `json:"def"`
	Access     accessIn            `json:"access"`
	Limit      int                 `json:"limit"`
	Offset     int                 `json:"offset"`
	UserState  *episodeQueryOut    `json:"user_state"`
	UserOK     bool                `json:"user_ok"`
	UserErr    string              `json:"user_error"`
	Entries    *episodeQueryOut    `json:"entries"`
	EntriesOK  bool                `json:"entries_ok"`
	EntriesErr string              `json:"entries_error"`
}

func episodeVectors() []episodeCase {
	var defs []string
	for _, sort := range []string{"", "title", "added_at", "release_date", "last_air_date", "year", "content_rating", "runtime", "rating_imdb", "rating_tmdb", "rating_rt_critic", "resolution", "bitrate", "progress", "date_viewed", "plays", "author"} {
		for _, order := range []string{"", "asc"} {
			defs = append(defs, fmt.Sprintf(`{"media_scope":"episode","library_ids":[2],"sort":{"field":%q,"order":%q}}`, sort, order))
		}
	}
	rules := []string{
		`{"field":"type","op":"is","value":"episode"}`, `{"field":"type","op":"is_not","value":"episode"}`, `{"field":"type","op":"is","value":"movie"}`,
		`{"field":"genre","op":"contains","value":"Drama"}`, `{"field":"studio","op":"is_not","value":"S"}`, `{"field":"network","op":"is","value":"N"}`, `{"field":"country","op":"is","value":"US"}`,
		`{"field":"year","op":"between","value":[1990,2000]}`, `{"field":"year","op":"is","value":2000}`, `{"field":"rating","op":"gte","value":7}`,
		`{"field":"original_language","op":"is_not","value":"en"}`, `{"field":"content_rating","op":"is","value":"PG"}`, `{"field":"status","op":"is","value":"matched"}`,
		`{"field":"added_at","op":"in_last","value":"30d"}`, `{"field":"added_at","op":"gt","value":"2020-01-01"}`, `{"field":"release_date","op":"not_in_last","value":"1y"}`, `{"field":"release_date","op":"between","value":["2020-01-01","2021-01-01"]}`,
		`{"field":"resolution","op":"is","value":"4K"}`, `{"field":"resolution","op":"is_not","value":"720p"}`, `{"field":"hdr","op":"is","value":true}`, `{"field":"dolby_vision","op":"is","value":false}`,
		`{"field":"bitrate","op":"gt","value":5}`, `{"field":"bitrate","op":"lte","value":5}`, `{"field":"bitrate","op":"between","value":[1,2]}`,
		`{"field":"audio_language","op":"is","value":"EN"}`, `{"field":"subtitle_language","op":"is_not","value":"Fr"}`, `{"field":"actor","op":"is","value":"A"}`,
		`{"field":"watched","op":"is","value":true}`, `{"field":"watched","op":"is","value":false}`, `{"field":"in_progress","op":"is","value":true}`, `{"field":"in_progress","op":"is","value":false}`,
		`{"field":"last_watched","op":"gt","value":"2020-01-01"}`, `{"field":"last_watched","op":"between","value":["2020-01-01","2021-01-01"]}`, `{"field":"last_watched","op":"in_last","value":"7d"}`, `{"field":"last_watched","op":"lt","value":"2020-01-01"}`,
		`{"field":"title","op":"contains","value":"x"}`,
	}
	for _, r := range rules {
		defs = append(defs, `{"media_scope":"episode","groups":[{"rules":[`+r+`]}]}`)
		defs = append(defs, `{"media_scope":"episode","sort":{"field":"date_viewed"},"groups":[{"rules":[`+r+`,{"field":"genre","op":"is","value":"Drama"}]}]}`)
	}
	defs = append(defs,
		`{"media_scope":"episode","match":"any","groups":[{"rules":[{"field":"year","op":"gt","value":1}]},{"match":"any","rules":[{"field":"genre","op":"is","value":"a"},{"field":"status","op":"is","value":"b"}]}]}`,
		`{"media_scope":"episode","groups":[{"match":"any","rules":[{"field":"watched","op":"is","value":true}]}]}`,
		`{"media_scope":"episode","groups":[{"rules":[{"field":"watched","op":"is","value":true},{"field":"in_progress","op":"is","value":true}]}]}`,
		`{"media_scope":"episode","groups":[{"rules":[{"field":"resolution","op":"is","value":"4k"},{"field":"hdr","op":"is","value":true}]}]}`,
		`{"media_scope":"episode","limit":5,"sort":{"field":"title"}}`,
		`{"media_scope":"episode","library_ids":[1,2]}`,
		`{"media_scope":"movie"}`,
	)
	list := []accessIn{
		{Name: "unrestricted"},
		profiled(accessIn{Name: "lib2", Allowed: []int{2}}),
		profiled(accessIn{Name: "disabled1", Disabled: []int{1}}),
		kidProfile,
		profiled(accessIn{Name: "kid-strict", MaxContentRating: "PG", MaxAdvisoryAge: 10, RequireAdvisoryAge: true, Excluded: []string{"podcast"}, NamePrefix: "Ep"}),
		profiled(accessIn{Name: "content", AllowedContentIDs: []string{"e1"}, Excluded: []string{"episode"}}),
		profiled(accessIn{Name: "none", AllowedContentIDs: []string{}}),
		profiled(accessIn{Name: "empty", Allowed: []int{}}),
	}
	var out []episodeCase
	for _, def := range defs {
		for _, a := range list {
			for _, page := range [][2]int{{20, 0}, {5, 15}} {
				for _, ex := range []catalog.VecExecutor{{}, {Scope: "episode"}, {SnapshotAt: &snapshot}} {
					if (ex.Scope != "" || ex.SnapshotAt != nil) && (page[1] != 0 || a.Name != "lib2+profile") {
						continue
					}
					us, uok, uerr, en, eok, eerr := catalog.VecEpisodeQueries(ex, defJSON(def), a.filter(), page[0], page[1])
					out = append(out, episodeCase{ex, def, a, page[0], page[1], episodeQueryOf(us), uok, errText(uerr), episodeQueryOf(en), eok, errText(eerr)})
				}
			}
		}
	}
	return out
}

type sortHelperCase struct {
	Fn     string            `json:"fn"`
	Field  string            `json:"field"`
	Order  string            `json:"order"`
	Flag   bool              `json:"flag"`
	Sort   catalog.QuerySort `json:"sort"`
	OK     bool              `json:"ok"`
	Output string            `json:"output"`
}

type legacyCase struct {
	Input string `json:"input"`
	Def   string `json:"def"`
	Error string `json:"error"`
}

func sortHelperVectors() []sortHelperCase {
	var out []sortHelperCase
	fields := []string{"", " Title ", "added_at", "release_date", "year", "rating_imdb", "rating", "progress", "plays", "relevance", "random", "nope", "series", "SORT_TITLE"}
	for _, f := range fields {
		for _, o := range []string{"", " ASC ", "desc", "up"} {
			s, ok := catalog.NormalizePersonalListSort(f, o)
			out = append(out, sortHelperCase{Fn: "personal_list", Field: f, Order: o, Sort: s, OK: ok})
			s, ok = catalog.NormalizePersonalSourceSort(f, o)
			out = append(out, sortHelperCase{Fn: "personal_source", Field: f, Order: o, Sort: s, OK: ok})
			for _, flag := range []bool{false, true} {
				s, ok = catalog.NormalizeCollectionSort(f, o, flag)
				out = append(out, sortHelperCase{Fn: "collection", Field: f, Order: o, Flag: flag, Sort: s, OK: ok})
			}
			enc, err := catalog.EncodeCollectionDefaultSort(catalog.QuerySort{Field: f, Order: o}, o != "up")
			must(err)
			out = append(out, sortHelperCase{Fn: "encode", Field: f, Order: o, Flag: o != "up", Output: enc})
		}
	}
	for _, raw := range []string{"", " ", "{}", "null", "[]", "{bad", `{"field":"Year"}`, `{"field":"plays","order":"asc"}`, `{"field":"title","order":"x"}`, `{"mode":"manual"}`} {
		for _, flag := range []bool{false, true} {
			s, ok := catalog.ParseCollectionDefaultSort([]byte(raw), flag)
			out = append(out, sortHelperCase{Fn: "parse_default", Field: raw, Flag: flag, Sort: s, OK: ok})
		}
	}
	return out
}

func legacyVectors() []legacyCase {
	var out []legacyCase
	for _, in := range []string{
		"", "null", "{}", "[]", `{"filter_type":" Movie ","filter_library_id":3,"filter_library_ids":[5,3,1],"match":"ANY","sort":"Rating","order":"","limit":4}`,
		`{"groups":[{"rules":[{"field":"genre","op":"is","value":"Drama"}]}],"sort":"title","order":"DESC"}`,
		`{"filter_library_ids":[0]}`, `{"filter_type":"podcast"}`, `{"limit":0}`, `{"sort":"bogus"}`, `{"filter_library_id":"x"}`,
	} {
		def, err := catalog.NormalizeLegacySectionFilter(json.RawMessage(in))
		c := legacyCase{Input: in, Error: errText(err)}
		if err == nil {
			b, _ := json.Marshal(def)
			c.Def = string(b)
		}
		out = append(out, c)
	}
	return out
}

func main() {
	if len(os.Args) > 2 && os.Args[1] == "db" {
		write("query_db", dbVectors(os.Args[2]))
		pool, err := pgxpool.New(context.Background(), os.Args[2])
		must(err)
		write("query_db_cursor", cursorVectors(pool))
		pool.Close()
		return
	}
	write("query_columns", map[string]any{"list_columns": catalog.VecListColumns(), "episode_base_relation": catalog.VecEpisodeBaseRelation(), "item_columns": catalog.VecItemColumns(), "episode_hydrate": catalog.VecEpisodeHydrateSQL()})
	write("query_parse", parseVectors())
	write("query_sort_helpers", sortHelperVectors())
	write("query_legacy_section", legacyVectors())
	write("query_episode", episodeVectors())
	write("query_display_fragment", fragmentVectors())
	write("query_build", buildVectors())
	write("query_sort", sortVectors())
	write("query_plan", planVectors())
	write("query_seek", seekVectors())
	write("query_duration", durationVectors())
	write("query_cursor_json", cursorJSONVectors())
	write("query_library_scope", libraryScopeVectors())
}
