package apiv2

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/danielgtaylor/huma/v2"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/Silo-Server/silo-server/internal/api/handlers"
	"github.com/Silo-Server/silo-server/internal/imagesize"
	"github.com/Silo-Server/silo-server/internal/playlists"
)

type PlaylistService interface {
	List(context.Context, playlists.Owner) ([]playlists.Playlist, error)
	Get(context.Context, playlists.Owner, string) (playlists.Playlist, error)
	Create(context.Context, playlists.Owner, string) (playlists.Playlist, error)
	Apply(context.Context, playlists.Owner, string, int64, playlists.Mutation) (playlists.Playlist, error)
}
type PlaylistSummary struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Revision   int64  `json:"revision"`
	EntryCount int    `json:"entry_count"`
}
type PlaylistEntry struct {
	ID        string       `json:"id"`
	Available bool         `json:"available"`
	ItemID    string       `json:"item_id,omitempty" doc:"Absent when the item is unavailable or restricted"`
	Item      *CatalogItem `json:"item,omitempty" doc:"Absent when the item is unavailable or restricted"`
}
type Playlist struct {
	PlaylistSummary
	Entries []PlaylistEntry `json:"entries"`
}
type PlaylistOutput struct {
	CacheControl string `header:"Cache-Control"`
	ETag         string `header:"ETag"`
	Body         Playlist
}
type PlaylistListOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         struct {
		Items []PlaylistSummary `json:"items"`
	}
}
type PlaylistCapabilities struct {
	Capability
	Available bool `json:"available"`
}

func (c PlaylistCapabilities) capabilityState() string {
	return configuredCapabilityState(c.Available)
}

type PlaylistCapabilitiesOutput struct {
	Status       int
	ETag         string `header:"ETag"`
	CacheControl string `header:"Cache-Control"`
	Body         PlaylistCapabilities
}
type PlaylistReadInput struct {
	ID string `path:"id"`
}
type PlaylistIDInput struct {
	ID          string `path:"id"`
	IfMatch     string `header:"If-Match"`
	IfNoneMatch string `header:"If-None-Match"`
}
type PlaylistCreateInput struct {
	Body struct {
		Name string `json:"name" minLength:"1" maxLength:"200"`
	}
}
type PlaylistRenameInput struct {
	ID          string `path:"id"`
	IfMatch     string `header:"If-Match"`
	IfNoneMatch string `header:"If-None-Match"`
	Body        struct {
		Name string `json:"name" minLength:"1" maxLength:"200"`
	}
}
type PlaylistAddInput struct {
	ID          string `path:"id"`
	IfMatch     string `header:"If-Match"`
	IfNoneMatch string `header:"If-None-Match"`
	Body        struct {
		ItemID string `json:"item_id" minLength:"1"`
	}
}
type PlaylistOrderInput struct {
	ID          string `path:"id"`
	IfMatch     string `header:"If-Match"`
	IfNoneMatch string `header:"If-None-Match"`
	Body        struct {
		EntryIDs []string `json:"entry_ids" maxItems:"500"`
	}
}
type PlaylistRemoveInput struct {
	ID          string `path:"id"`
	IfMatch     string `header:"If-Match"`
	IfNoneMatch string `header:"If-None-Match"`
	EntryID     string `path:"entry_id"`
}
type PlaylistPlaybackInput struct {
	ID      string `path:"id"`
	EntryID string `query:"entry_id" required:"true"`
	After   bool   `query:"after"`
}
type PlaylistPlaybackOutput struct {
	CacheControl string `header:"Cache-Control"`
	Body         struct {
		Entry NullablePlaylistEntry `json:"entry"`
	}
}

func registerPlaylists(reg *Registry) {
	op := func(method, path, id, summary string) Operation {
		o := Operation{Operation: humaOp(method, Prefix+"/playlists"+path, id, "playlists", summary), Class: ClassProfileScoped, ServiceBacked: true}
		if method != http.MethodGet {
			o.DemoRestricted = true
			o.RetrySafety = RetrySafetyNonRetryable
			o.Guarded = path != "" && method != http.MethodPost
			if path != "" {
				o.Errors = append(o.Errors, http.StatusPreconditionFailed, http.StatusPreconditionRequired)
			}
		}
		return o
	}
	caps := op(http.MethodGet, "/capabilities", "getPlaylistCapabilities", "Discover private movie and episode playlists.")
	caps.ServiceBacked = false
	Register(reg, caps, func(context.Context, *CapabilityInput) (*PlaylistCapabilitiesOutput, error) {
		return &PlaylistCapabilitiesOutput{Body: PlaylistCapabilities{Available: reg.deps.Playlists != nil && reg.deps.CatalogItems != nil && reg.deps.CatalogAccess != nil}}, nil
	})
	Register(reg, op(http.MethodGet, "", "listPlaylists", "List the acting profile's private playlists."), reg.listPlaylists)
	Register(reg, op(http.MethodPost, "", "createPlaylist", "Create a private playlist."), reg.createPlaylist)
	Register(reg, op(http.MethodGet, "/{id}", "getPlaylist", "Read a playlist, redacting unavailable entries."), reg.getPlaylist)
	Register(reg, op(http.MethodPatch, "/{id}", "renamePlaylist", "Rename a playlist with its current ETag."), reg.renamePlaylist)
	Register(reg, op(http.MethodPost, "/{id}/entries", "addPlaylistEntry", "Append a movie or episode, allowing duplicates."), reg.addPlaylistEntry)
	Register(reg, op(http.MethodPut, "/{id}/entries/order", "reorderPlaylistEntries", "Atomically replace the complete entry order with its current ETag."), reg.reorderPlaylistEntries)
	remove := op(http.MethodDelete, "/{id}/entries/{entry_id}", "removePlaylistEntry", "Remove one occurrence without deleting media.")
	remove.DefaultStatus = http.StatusNoContent
	Register(reg, remove, reg.removePlaylistEntry)
	del := op(http.MethodDelete, "/{id}", "deletePlaylist", "Delete a playlist without deleting media.")
	del.DefaultStatus = http.StatusNoContent
	Register(reg, del, reg.deletePlaylist)
	Register(reg, op(http.MethodGet, "/{id}/playback", "resolvePlaylistPlayback", "Resolve at or after an entry using current profile access; null ends playback."), reg.resolvePlaylistPlayback)
}
func playlistProblem(err error) error {
	switch {
	case errors.Is(err, playlists.ErrNotFound):
		return NewProblem(TypeNotFound, "Playlist or entry not found.")
	case errors.Is(err, playlists.ErrStale):
		return NewProblem(TypePreconditionFailed, "The playlist changed. Reload before editing.")
	case errors.Is(err, playlists.ErrInvalid):
		return NewProblem(TypeValidationFailed, "The playlist edit is invalid.")
	default:
		return serviceProblem(err)
	}
}
func (reg *Registry) playlistStore() (PlaylistService, error) {
	if reg.deps.Playlists == nil {
		return nil, unavailable("playlists")
	}
	return reg.deps.Playlists, nil
}
func playlistSummary(p playlists.Playlist) PlaylistSummary {
	return PlaylistSummary{ID: p.ID, Name: p.Name, Revision: p.Revision, EntryCount: p.EntryCount}
}
func (reg *Registry) listPlaylists(ctx context.Context, _ *struct{}) (*PlaylistListOutput, error) {
	svc, err := reg.playlistStore()
	if err != nil {
		return nil, err
	}
	ps, err := svc.List(ctx, playlistOwner(ctx))
	if err != nil {
		return nil, playlistProblem(err)
	}
	out := &PlaylistListOutput{CacheControl: "private, no-store"}
	out.Body.Items = []PlaylistSummary{}
	for _, p := range ps {
		out.Body.Items = append(out.Body.Items, playlistSummary(p))
	}
	return out, nil
}
func playlistTag(ctx context.Context, p playlists.Playlist) EntityTag {
	return RenderETag("playlist:"+strconv.Itoa(claimsFrom(ctx).UserID)+":"+profileFrom(ctx), p.ID, p.Revision)
}
func (reg *Registry) playlistEntry(ctx context.Context, e playlists.Entry) (PlaylistEntry, error) {
	out := PlaylistEntry{ID: e.ID}
	if reg.deps.CatalogItems == nil || reg.deps.CatalogAccess == nil {
		return out, unavailable("catalog")
	}
	viewer, p := reg.itemViewer(ctx, imagesize.Request{}, "", "")
	if p != nil {
		return out, p
	}
	detail, err := reg.deps.CatalogItems.ItemDetail(ctx, viewer, e.ItemID)
	if err != nil {
		var apiErr *handlers.APIError
		if errors.As(err, &apiErr) && (apiErr.Status == http.StatusNotFound || apiErr.Status == http.StatusForbidden) {
			return out, nil
		}
		return out, serviceProblem(err)
	}
	if detail == nil || (detail.Type != "movie" && detail.Type != "episode") || len(detail.Versions) == 0 {
		return out, nil
	}
	readable := false
	for _, version := range detail.Versions {
		if !version.Unreadable {
			readable = true
			break
		}
	}
	if !readable {
		return out, nil
	}
	card := catalogItemDetailOf(detail, reg.ratingSelection(ctx)).CatalogItem
	out.Available = true
	out.ItemID = e.ItemID
	out.Item = &card
	return out, nil
}
func (reg *Registry) playlistOutput(ctx context.Context, p playlists.Playlist) (*PlaylistOutput, error) {
	out := &PlaylistOutput{CacheControl: "private, no-store", ETag: playlistTag(ctx, p).String(), Body: Playlist{PlaylistSummary: playlistSummary(p), Entries: []PlaylistEntry{}}}
	cache := make(map[string]PlaylistEntry)
	for _, e := range p.Entries {
		entry, ok := cache[e.ItemID]
		if !ok {
			var err error
			entry, err = reg.playlistEntry(ctx, e)
			if err != nil {
				return nil, err
			}
			cache[e.ItemID] = entry
		}
		entry.ID = e.ID
		out.Body.Entries = append(out.Body.Entries, entry)
	}
	return out, nil
}
func (reg *Registry) getPlaylist(ctx context.Context, in *PlaylistReadInput) (*PlaylistOutput, error) {
	svc, err := reg.playlistStore()
	if err != nil {
		return nil, err
	}
	p, err := svc.Get(ctx, playlistOwner(ctx), in.ID)
	if err != nil {
		return nil, playlistProblem(err)
	}
	return reg.playlistOutput(ctx, p)
}
func (reg *Registry) createPlaylist(ctx context.Context, in *PlaylistCreateInput) (*PlaylistOutput, error) {
	svc, err := reg.playlistStore()
	if err != nil {
		return nil, err
	}
	p, err := svc.Create(ctx, playlistOwner(ctx), in.Body.Name)
	if err != nil {
		return nil, playlistProblem(err)
	}
	return reg.playlistOutput(ctx, p)
}
func (reg *Registry) editPlaylist(ctx context.Context, in PlaylistIDInput, m playlists.Mutation) (*PlaylistOutput, error) {
	svc, err := reg.playlistStore()
	if err != nil {
		return nil, err
	}
	p, err := svc.Get(ctx, playlistOwner(ctx), in.ID)
	if err != nil {
		return nil, playlistProblem(err)
	}
	// Wildcards would bypass the stale-editor protection promised by this API.
	if strings.TrimSpace(in.IfMatch) == "*" {
		return nil, NewProblem(TypePreconditionFailed, "Use the playlist's current ETag.")
	}
	if problem := EvaluateGuardedPreconditions(in.IfMatch, in.IfNoneMatch, playlistTag(ctx, p)); problem != nil {
		return nil, problem
	}
	if m.AddItem != "" {
		e, err := reg.playlistEntry(ctx, playlists.Entry{ItemID: m.AddItem})
		if err != nil {
			return nil, err
		}
		if !e.Available {
			return nil, NewProblem(TypeNotFound, "Item not found.")
		}
	}
	p, err = svc.Apply(ctx, playlistOwner(ctx), in.ID, p.Revision, m)
	if err != nil {
		return nil, playlistProblem(err)
	}
	if m.Delete || m.RemoveEntry != "" {
		return nil, nil
	}
	return reg.playlistOutput(ctx, p)
}
func (reg *Registry) renamePlaylist(ctx context.Context, in *PlaylistRenameInput) (*PlaylistOutput, error) {
	return reg.editPlaylist(ctx, PlaylistIDInput{ID: in.ID, IfMatch: in.IfMatch, IfNoneMatch: in.IfNoneMatch}, playlists.Mutation{Name: &in.Body.Name})
}
func (reg *Registry) addPlaylistEntry(ctx context.Context, in *PlaylistAddInput) (*PlaylistOutput, error) {
	return reg.editPlaylist(ctx, PlaylistIDInput{ID: in.ID, IfMatch: in.IfMatch, IfNoneMatch: in.IfNoneMatch}, playlists.Mutation{AddItem: in.Body.ItemID})
}
func (reg *Registry) reorderPlaylistEntries(ctx context.Context, in *PlaylistOrderInput) (*PlaylistOutput, error) {
	order := append([]string{}, in.Body.EntryIDs...)
	return reg.editPlaylist(ctx, PlaylistIDInput{ID: in.ID, IfMatch: in.IfMatch, IfNoneMatch: in.IfNoneMatch}, playlists.Mutation{Order: order})
}
func (reg *Registry) removePlaylistEntry(ctx context.Context, in *PlaylistRemoveInput) (*struct{}, error) {
	_, err := reg.editPlaylist(ctx, PlaylistIDInput{ID: in.ID, IfMatch: in.IfMatch, IfNoneMatch: in.IfNoneMatch}, playlists.Mutation{RemoveEntry: in.EntryID})
	return nil, err
}
func (reg *Registry) deletePlaylist(ctx context.Context, in *PlaylistIDInput) (*struct{}, error) {
	_, err := reg.editPlaylist(ctx, *in, playlists.Mutation{Delete: true})
	return nil, err
}
func (reg *Registry) resolvePlaylistPlayback(ctx context.Context, in *PlaylistPlaybackInput) (*PlaylistPlaybackOutput, error) {
	svc, err := reg.playlistStore()
	if err != nil {
		return nil, err
	}
	p, err := svc.Get(ctx, playlistOwner(ctx), in.ID)
	if err != nil {
		return nil, playlistProblem(err)
	}
	start := -1
	for i, e := range p.Entries {
		if e.ID == in.EntryID {
			start = i
			break
		}
	}
	if start < 0 {
		return nil, NewProblem(TypeNotFound, "Playlist entry not found.")
	}
	if in.After {
		start++
	}
	out := &PlaylistPlaybackOutput{CacheControl: "private, no-store"}
	for _, e := range p.Entries[start:] {
		entry, err := reg.playlistEntry(ctx, e)
		if err != nil {
			return nil, err
		}
		if entry.Available {
			out.Body.Entry.Value = &entry
			break
		}
	}
	return out, nil
}

func playlistOwner(ctx context.Context) playlists.Owner {
	return playlists.Owner{UserID: claimsFrom(ctx).UserID, ProfileID: profileFrom(ctx)}
}

// NullablePlaylistEntry inlines the object schema so explicit null means end of list.
type NullablePlaylistEntry struct{ Value *PlaylistEntry }

func (n NullablePlaylistEntry) MarshalJSON() ([]byte, error)  { return json.Marshal(n.Value) }
func (n *NullablePlaylistEntry) UnmarshalJSON(b []byte) error { return json.Unmarshal(b, &n.Value) }
func (NullablePlaylistEntry) Schema(r huma.Registry) *huma.Schema {
	s := r.Schema(reflect.TypeFor[PlaylistEntry](), false, "")
	out := *s
	out.Nullable = true
	return &out
}
