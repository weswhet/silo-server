package handlers

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/models"
)

type playlistFiles struct {
	EpisodeFileProvider
	movies, episodes         map[string][]*models.MediaFile
	movieCalls, episodeCalls int
	err                      error
}

func (f *playlistFiles) ListByContentIDs(context.Context, []string) (map[string][]*models.MediaFile, error) {
	f.movieCalls++
	return f.movies, f.err
}
func (f *playlistFiles) ListByEpisodeIDs(context.Context, []string) (map[string][]*models.MediaFile, error) {
	f.episodeCalls++
	return f.episodes, f.err
}

func TestReadablePlaylistItemsBatchAndAccess(t *testing.T) {
	files := &playlistFiles{movies: map[string][]*models.MediaFile{}, episodes: map[string][]*models.MediaFile{}}
	items := make([]*models.MediaItem, 0, 500)
	now := time.Now()
	for i := range 500 {
		id := strconv.Itoa(i)
		item := &models.MediaItem{ContentID: id, Type: "movie"}
		file := &models.MediaFile{MediaFolderID: 1, Resolution: "1080p"}
		switch i % 5 {
		case 1:
			file.MediaFolderID = 2
		case 2:
			file.Resolution = "2160p"
		case 3:
			file.ProbeFailedAt = &now
		case 4:
			file.MissingSince = &now
		}
		if i%2 == 0 {
			item.Type = "episode"
			files.episodes[id] = []*models.MediaFile{file}
		} else {
			files.movies[id] = []*models.MediaFile{file}
		}
		items = append(items, item)
	}
	got, err := readablePlaylistItems(t.Context(), files, items, catalog.AccessFilter{AllowedLibraryIDs: []int{1}, MaxPlaybackQuality: "1080p"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 100 || files.movieCalls != 1 || files.episodeCalls != 1 {
		t.Fatalf("items=%d movie calls=%d episode calls=%d", len(got), files.movieCalls, files.episodeCalls)
	}
	files.err = errors.New("file store unavailable")
	if _, err := readablePlaylistItems(t.Context(), files, items, catalog.AccessFilter{}); !errors.Is(err, files.err) {
		t.Fatalf("file failure was hidden: %v", err)
	}
}
