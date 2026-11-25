package apiv2

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/Silo-Server/silo-server/internal/api/handlers"
	catalogpkg "github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/playlists"
)

type playlistTestStore struct {
	p       playlists.Playlist
	owner   string
	applied int
	stale   bool
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
	return s.p, nil
}

type playlistCatalog struct{ fakeCatalog }

func (f *playlistCatalog) ItemDetail(ctx context.Context, v handlers.ItemViewer, id string) (*catalogpkg.ItemDetail, error) {
	if id == "restricted" {
		return nil, &handlers.APIError{Status: 404, Code: "not_found"}
	}
	if id == "unreadable" {
		return &catalogpkg.ItemDetail{ContentID: id, Title: "Hidden title", Type: "movie", Versions: []catalogpkg.FileVersion{{Unreadable: true}}}, nil
	}
	d, err := f.fakeCatalog.ItemDetail(ctx, v, "movie:heat-1995")
	if d != nil {
		d.ContentID = id
		if strings.HasPrefix(id, "episode") {
			d.Type = "episode"
		}
	}
	return d, err
}
func TestPlaylistRedactionAndPlaybackOrder(t *testing.T) {
	deps, _ := catalogDeps(t)
	store := &playlistTestStore{owner: "p-owner", p: playlists.Playlist{ID: "list", Name: "Evening", Revision: 3, Entries: []playlists.Entry{{ID: "a", ItemID: "movie"}, {ID: "b", ItemID: "restricted"}, {ID: "c", ItemID: "unreadable"}, {ID: "d", ItemID: "episode:other-series"}, {ID: "e", ItemID: "movie"}}}}
	deps.Playlists = store
	deps.CatalogItems = &playlistCatalog{}
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
	deps.CatalogItems.(*playlistCatalog).err = errors.New("catalog unavailable")
	removed := do(t, h, http.MethodDelete, "/api/v2/playlists/list/entries/a", "", with(viewerHeaders(), "If-Match", rec.Header().Get("ETag")))
	if removed.Code != http.StatusNoContent {
		t.Fatalf("removal depends on catalog after commit: %d %s", removed.Code, removed.Body.String())
	}

}
