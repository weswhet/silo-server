package playlists

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestPlaylistIsolationConcurrencyDB catches lost updates, cross-profile access,
// and accidental title de-duplication in the persisted store.
func TestPlaylistIsolationConcurrencyDB(t *testing.T) {
	dsn := os.Getenv("SILO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SILO_TEST_DATABASE_URL is not set")
	}
	ctx := t.Context()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	suffix := uuid.NewString()
	var user int
	if err := pool.QueryRow(ctx, `INSERT INTO users(username,email,password_hash,role,permissions) VALUES($1::text,$1::text||'@example.test','h','user','{}') RETURNING id`, suffix).Scan(&user); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, user) }()
	a, b := "a-"+suffix, "b-"+suffix
	for _, id := range []string{a, b} {
		if _, err := pool.Exec(ctx, `INSERT INTO user_profiles(id,user_id,name) VALUES($1,$2,'Test')`, id, user); err != nil {
			t.Fatal(err)
		}
	}
	owner := Owner{UserID: user, ProfileID: a}
	other := Owner{UserID: user, ProfileID: b}
	s := &Store{Pool: pool}
	p, err := s.Create(ctx, owner, "Movie night")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, Owner{UserID: user + 1, ProfileID: a}, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other account reused profile ID: %v", err)
	}
	if _, err := s.Get(ctx, other, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other profile read: %v", err)
	}
	if _, err := s.Apply(ctx, other, p.ID, p.Revision, Mutation{Delete: true}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other profile deleted: %v", err)
	}
	for range 2 {
		p, err = s.Apply(ctx, owner, p.ID, p.Revision, Mutation{AddItem: "movie:one"})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(p.Entries) != 2 || p.Entries[0].ID == p.Entries[1].ID {
		t.Fatal("duplicates not independent")
	}
	revision := p.Revision
	order := []string{p.Entries[1].ID, p.Entries[0].ID}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Go(func() { _, err := s.Apply(ctx, owner, p.ID, revision, Mutation{Order: order}); results <- err })
	}
	wg.Wait()
	close(results)
	success, stale := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrStale) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || stale != 1 {
		t.Fatalf("concurrent results success=%d stale=%d", success, stale)
	}
	// A fresh repository instance must see committed order, not process state.
	restarted := &Store{Pool: pool}
	persisted, err := restarted.Get(ctx, owner, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Entries[0].ID != order[0] || persisted.Revision != revision+1 {
		t.Fatalf("lost persisted order: %+v", persisted)
	}
	if _, err := s.Apply(ctx, owner, p.ID, persisted.Revision, Mutation{Order: []string{order[0], order[0]}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad permutation: %v", err)
	}
	after, err := s.Get(ctx, owner, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != persisted.Revision || after.Entries[0].ID != persisted.Entries[0].ID {
		t.Fatal("failed reorder partially committed")
	}
	name := "Renamed"
	renamed, err := s.Apply(ctx, owner, p.ID, after.Revision, Mutation{Name: &name})
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Entries[0].ID != after.Entries[0].ID || renamed.Name != name {
		t.Fatal("rename changed entries")
	}
	if err := s.PurgeProfile(ctx, user, b); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, owner, p.ID); err != nil {
		t.Fatalf("other profile purge removed playlist: %v", err)
	}
	if err := s.PurgeProfile(ctx, user, a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, owner, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("purge retained playlist: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM profile_playlist_entries WHERE playlist_id=$1`, p.ID).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("purge retained entries: %d %v", remaining, err)
	}

}
