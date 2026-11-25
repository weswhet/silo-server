package handlers

import (
	"context"
	"errors"

	"github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/models"
)

// PlaylistCards returns only currently accessible, readable movies and episodes.
// Each lookup is batched across the request; it does not run detail enrichment,
// trigger metadata refreshes, or cache authorization across requests.
func (h *CatalogResourceHandler) PlaylistCards(ctx context.Context, v ItemViewer, ids []string) (map[string]CollectionItemView, error) {
	if h == nil || h.items == nil || h.items.itemRepo == nil || h.items.fileRepo == nil {
		return nil, errors.New("playlist catalog is not configured")
	}
	items, err := h.items.itemRepo.GetSearchItemsByIDsWithAccess(ctx, ids, v.Access)
	if err != nil {
		return nil, err
	}
	items, err = readablePlaylistItems(ctx, h.items.fileRepo, items, v.Access)
	if err != nil {
		return nil, err
	}
	items = h.items.localizeItemListModels(ctx, items, v.Access)
	metadata := h.items.listEpisodeBrowseMetadata(ctx, items)
	images := h.items.itemListCardImageURLs(ctx, items, metadata, v.Access.Artwork())
	cards := make(map[string]CollectionItemView, len(items))
	for _, item := range items {
		card := itemListResponseShell(item, nil, nil)
		// Playback uses this occurrence's canonical item, never a series target.
		card.PlayContentID = ""
		if meta, ok := metadata[item.ContentID]; ok {
			applyEpisodeBrowseMetadata(&card, meta)
			card.ParentArtwork = episodeParentArtworkView(meta.ParentArtwork, images[item.ContentID].parents)
		}
		card.PosterURL = images[item.ContentID].posterURL
		card.BackdropURL = images[item.ContentID].backdropURL
		card.LogoURL = images[item.ContentID].logoURL
		cards[item.ContentID] = card
	}
	return cards, nil
}

func readablePlaylistItems(ctx context.Context, files EpisodeFileProvider, items []*models.MediaItem, filter catalog.AccessFilter) ([]*models.MediaItem, error) {
	movies, episodes := []string{}, []string{}
	for _, item := range items {
		switch item.Type {
		case itemTypeMovie:
			movies = append(movies, item.ContentID)
		case itemTypeEpisode:
			episodes = append(episodes, item.ContentID)
		}
	}
	grouped := make(map[string][]*models.MediaFile)
	if len(movies) > 0 {
		movieFiles, err := files.ListByContentIDs(ctx, movies)
		if err != nil {
			return nil, err
		}
		for id, fs := range movieFiles {
			grouped[id] = fs
		}
	}
	if len(episodes) > 0 {
		provider, ok := files.(batchEpisodeFileProvider)
		if !ok {
			return nil, errors.New("playlist episode files are not configured")
		}
		episodeFiles, err := provider.ListByEpisodeIDs(ctx, episodes)
		if err != nil {
			return nil, err
		}
		for id, fs := range episodeFiles {
			grouped[id] = fs
		}
	}
	readable := make([]*models.MediaItem, 0, len(items))
	for _, item := range items {
		for _, file := range catalog.FilterMediaFilesByAccess(grouped[item.ContentID], filter) {
			if file != nil && file.MissingSince == nil && !file.ProbeRejected() {
				readable = append(readable, item)
				break
			}
		}
	}
	return readable, nil
}
