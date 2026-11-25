package apiv2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/Silo-Server/silo-server/internal/api/handlers"
	"github.com/Silo-Server/silo-server/internal/playlists"
)

type playlistTestStore struct {
	p          playlists.Playlist
	owner      string
	applied    int
	stale      bool
	afterApply func()
}

func (s *playlistTestStore) List(_ context.Context, owner playlists.Owner) ([]playlists.Playlist, error) {
	if owner.ProfileID != s.owner {
		return []playlists.Playlist{}, nil
	}
	return []playlists.Playlist{s.p}, nil
}
func (s *playlistTestStore) Get(_ context.Context, owner playlists.Owner, id string) (playlists.Playlist, error) {
	if owner.ProfileID != s.owner || id != s.p.ID {
		return playlists.Playlist{}, playlists.ErrNotFound
	}
	return s.p, nil
}
func (s *playlistTestStore) Create(context.Context, playlists.Owner, string) (playlists.Playlist, error) {
	return s.p, nil
}
func (s *playlistTestStore) Apply(_ context.Context, owner playlists.Owner, id string, revision int64, _ playlists.Mutation) (playlists.Playlist, error) {
	s.applied++
	if s.stale || revision != s.p.Revision {
		return playlists.Playlist{}, playlists.ErrStale
	}
	if s.afterApply != nil {
		s.afterApply()
	}
	s.p.Revision++
	return s.p, nil
}

type playlistCatalog struct {
	fakeCatalog
	calls int
	ids   []string
}

func (f *playlistCatalog) PlaylistCards(_ context.Context, _ handlers.ItemViewer, ids []string) (map[string]handlers.CollectionItemView, error) {
	f.calls++
	f.ids = ids
	if f.err != nil {
		return nil, f.err
	}
	cards := map[string]handlers.CollectionItemView{}
	for _, id := range ids {
		if id == "restricted" || id == "unreadable" {
			continue
		}
		card := fakeListingCard(id)
		if id == "episode:other-series" {
			card.Type = "episode"
		}
		cards[id] = card
	}
	return cards, nil
}
func TestPlaylistRedactionAndPlaybackOrder(t *testing.T) {
	deps, _ := catalogDeps(t)
	store := &playlistTestStore{owner: "p-owner", p: playlists.Playlist{ID: "list", Name: "Evening", Revision: 3, Entries: []playlists.Entry{{ID: "a", ItemID: "movie"}, {ID: "b", ItemID: "restricted"}, {ID: "c", ItemID: "unreadable"}, {ID: "d", ItemID: "episode:other-series"}, {ID: "e", ItemID: "movie"}}}}
	deps.Playlists = store
	catalog := &playlistCatalog{}
	deps.CatalogItems = catalog
	h := newTestHandler(t, deps)
	rec := do(t, h, http.MethodGet, "/api/v2/playlists/list", "", viewerHeaders())
	if rec.Code != 200 {
		t.Fatalf("get %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "private, no-store" {
		t.Fatal("playlist detail can be cached")
	}
	var p Playlist
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 5 || p.Entries[1].Available || p.Entries[1].ItemID != "" || p.Entries[1].Item != nil || p.Entries[2].Available {
		t.Fatalf("redaction failed: %+v", p.Entries)
	}
	for _, tc := range []struct{ query, want string }{{"entry_id=a", "a"}, {"entry_id=a&after=true", "d"}, {"entry_id=d&after=true", "e"}, {"entry_id=e&after=true", ""}, {"entry_id=b", "d"}} {
		rec := do(t, h, http.MethodGet, "/api/v2/playlists/list/playback?"+tc.query, "", viewerHeaders())
		if rec.Code != 200 {
			t.Fatalf("resolve: %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Entry *PlaylistEntry `json:"entry"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		got := ""
		if body.Entry != nil {
			got = body.Entry.ID
		}
		if got != tc.want {
			t.Fatalf("%s got %q want %q", tc.query, got, tc.want)
		}
	}
	requireProblem(t, do(t, h, http.MethodPatch, "/api/v2/playlists/list", `{"name":"New"}`, viewerHeaders()), TypePreconditionRequired)
	requireProblem(t, do(t, h, http.MethodPatch, "/api/v2/playlists/list", `{"name":"New"}`, with(viewerHeaders(), "If-Match", `"stale"`)), TypePreconditionFailed)
	if store.applied != 0 {
		t.Fatal("unguarded edit reached store")
	}
	store.stale = true
	requireProblem(t, do(t, h, http.MethodPatch, "/api/v2/playlists/list", `{"name":"New"}`, with(viewerHeaders(), "If-Match", rec.Header().Get("ETag"))), TypePreconditionFailed)
	store.stale = false
	catalog.err = errors.New("catalog unavailable")
	removed := do(t, h, http.MethodDelete, "/api/v2/playlists/list/entries/a", "", with(viewerHeaders(), "If-Match", rec.Header().Get("ETag")))
	if removed.Code != http.StatusNoContent {
		t.Fatalf("removal depends on catalog after commit: %d %s", removed.Code, removed.Body.String())
	}

}

func TestPlaylistMutationReceiptsDoNotReadAfterCommit(t *testing.T) {
	for _, tc := range []struct {
		method, path, body string
		reads              int
	}{
		{http.MethodPatch, "/api/v2/playlists/list", `{"name":"New"}`, 0},
		{http.MethodPost, "/api/v2/playlists/list/entries", `{"item_id":"movie"}`, 1},
		{http.MethodPut, "/api/v2/playlists/list/entries/order", `{"entry_ids":["a"]}`, 0},
	} {
		t.Run(tc.method, func(t *testing.T) {
			deps, _ := catalogDeps(t)
			cat := &playlistCatalog{}
			store := &playlistTestStore{owner: "p-owner", p: playlists.Playlist{ID: "list", Revision: 3, Entries: []playlists.Entry{{ID: "a", ItemID: "movie"}}}}
			store.afterApply = func() { cat.err = errors.New("catalog failed after commit") }
			deps.Playlists, deps.CatalogItems = store, cat
			h := newTestHandler(t, deps)
			before := do(t, h, http.MethodGet, "/api/v2/playlists/list", "", viewerHeaders())
			cat.calls = 0
			result := do(t, h, tc.method, tc.path, tc.body, with(viewerHeaders(), "If-Match", before.Header().Get("ETag")))
			if result.Code != 200 {
				t.Fatalf("committed mutation: %d %s", result.Code, result.Body.String())
			}
			var receipt map[string]any
			if err := json.Unmarshal(result.Body.Bytes(), &receipt); err != nil {
				t.Fatal(err)
			}
			if len(receipt) != 2 || receipt["id"] != "list" || receipt["revision"] != float64(4) {
				t.Fatalf("receipt: %v", receipt)
			}
			if cat.calls != tc.reads {
				t.Fatalf("catalog calls=%d want%d", cat.calls, tc.reads)
			}
			if result.Header().Get("ETag") == before.Header().Get("ETag") || result.Header().Get("ETag") == "" {
				t.Fatal("missing committed ETag")
			}
			if result.Header().Get("Cache-Control") != playlistCacheControl {
				t.Fatal("receipt can be cached")
			}
		})
	}
}

func TestPlaylistReadsBatchDistinctItems(t *testing.T) {
	deps, _ := catalogDeps(t)
	cat := &playlistCatalog{}
	store := &playlistTestStore{owner: "p-owner", p: playlists.Playlist{ID: "list", Revision: 1}}
	for i := range 500 {
		store.p.Entries = append(store.p.Entries, playlists.Entry{ID: strconv.Itoa(i), ItemID: fmt.Sprintf("movie-%d", i%499)})
	}
	deps.Playlists, deps.CatalogItems = store, cat
	h := newTestHandler(t, deps)
	for _, path := range []string{"/api/v2/playlists/list", "/api/v2/playlists/list/playback?entry_id=0"} {
		cat.calls = 0
		result := do(t, h, http.MethodGet, path, "", viewerHeaders())
		if result.Code != 200 {
			t.Fatalf("%d %s", result.Code, result.Body.String())
		}
		if cat.calls != 1 || len(cat.ids) != 499 {
			t.Fatalf("calls=%d IDs=%d", cat.calls, len(cat.ids))
		}
	}
}
