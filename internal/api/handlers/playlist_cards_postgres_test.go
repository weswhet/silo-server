package handlers

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/models"
)

type playlistQueryCounter struct{ count atomic.Int64 }

func (c *playlistQueryCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.count.Add(1)
	return ctx
}
func (*playlistQueryCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestPlaylistCardsBoundedQueriesDB(t *testing.T) {
	dsn := os.Getenv("SILO_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SILO_TEST_DATABASE_URL is not set")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	counter := &playlistQueryCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	prefix := fmt.Sprintf("playlist-cards-%d-", time.Now().UnixNano())
	ids, files, allowed, disabled := seedPlaylistCardsDB(t, pool, prefix)
	handler := NewCatalogResourceHandler(&ItemsHandler{itemRepo: catalog.NewItemRepository(pool), fileRepo: files})
	counter.count.Store(0)
	cards, err := handler.PlaylistCards(t.Context(), ItemViewer{Access: catalog.AccessFilter{AllowedLibraryIDs: []int{allowed}, DisabledLibraryIDs: []int{disabled}}}, ids)
	if err != nil {
		t.Fatal(err)
	}
	if len(cards) != 500 {
		t.Fatalf("cards=%d; restricted parent or dual-library movie leaked", len(cards))
	}
	if counter.count.Load() != 1 || files.movieCalls != 1 || files.episodeCalls != 1 {
		t.Fatalf("500 cards used %d SQL queries, %d movie batches, %d episode batches", counter.count.Load(), files.movieCalls, files.episodeCalls)
	}
	if _, ok := cards[prefix+"episode"]; !ok {
		t.Fatal("accessible episode missing")
	}
	if _, ok := cards[prefix+"hidden-episode"]; ok {
		t.Fatal("episode of disabled parent leaked")
	}
	if _, ok := cards[prefix+"hidden-movie"]; ok {
		t.Fatal("dual-library movie leaked")
	}
}

func seedPlaylistCardsDB(t *testing.T, pool *pgxpool.Pool, prefix string) ([]string, *playlistFiles, int, int) {
	t.Helper()
	ctx := t.Context()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	var allowed, disabled int
	if err := pool.QueryRow(ctx, "INSERT INTO media_folders(type,name,enabled) VALUES('movies',$1,true) RETURNING id", prefix+"allowed").Scan(&allowed); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "INSERT INTO media_folders(type,name,enabled) VALUES('movies',$1,true) RETURNING id", prefix+"disabled").Scan(&disabled); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM episodes WHERE content_id LIKE $1", prefix+"%")
		_, _ = pool.Exec(context.Background(), "DELETE FROM media_items WHERE content_id LIKE $1", prefix+"%")
		_, _ = pool.Exec(context.Background(), "DELETE FROM media_folders WHERE id=ANY($1)", []int{allowed, disabled})
	})
	exec("INSERT INTO media_items(content_id,type,title) SELECT $1||i,'movie','Movie' FROM generate_series(1,499) i", prefix)
	for _, suffix := range []string{"series", "hidden-series"} {
		exec("INSERT INTO media_items(content_id,type,title) VALUES($1,'series','Series')", prefix+suffix)
	}
	exec("INSERT INTO media_items(content_id,type,title) VALUES($1,'movie','Hidden')", prefix+"hidden-movie")
	exec("INSERT INTO media_item_libraries(content_id,media_folder_id) SELECT content_id,$2 FROM media_items WHERE content_id LIKE $1", prefix+"%", allowed)
	exec("INSERT INTO media_item_libraries(content_id,media_folder_id) VALUES($1,$3),($2,$3)", prefix+"hidden-series", prefix+"hidden-movie", disabled)
	for _, suffix := range []string{"", "hidden-"} {
		exec("INSERT INTO episodes(content_id,series_id,season_number,episode_number,title) VALUES($1,$2,1,1,'Episode')", prefix+suffix+"episode", prefix+suffix+"series")
		exec("INSERT INTO episode_libraries(episode_id,media_folder_id) VALUES($1,$2)", prefix+suffix+"episode", allowed)
	}
	files := &playlistFiles{movies: map[string][]*models.MediaFile{}, episodes: map[string][]*models.MediaFile{}}
	ids := make([]string, 0, 502)
	for i := 1; i <= 499; i++ {
		id := fmt.Sprint(prefix, i)
		ids = append(ids, id)
		files.movies[id] = []*models.MediaFile{{MediaFolderID: allowed}}
	}
	for _, suffix := range []string{"episode", "hidden-episode", "hidden-movie"} {
		id := prefix + suffix
		ids = append(ids, id)
		files.episodes[id] = []*models.MediaFile{{MediaFolderID: allowed}}
	}
	return ids, files, allowed, disabled
}
