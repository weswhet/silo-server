# Private playlists API

Playlists are a fork-only native `/api/v2` feature for movies and individual
TV episodes. They belong to the selected household profile, not the login
account. They are separate from collections and the Audiobookshelf beta API.
Jellyfin playlist endpoints, sharing, imports, and external URLs are not supported.

All operations require authentication and an active profile. Discover support
with `GET /api/v2/playlists/capabilities`; older servers can answer 404. Clients
must hide playlist navigation when the capability is unavailable.

## Read and edit

- `GET /playlists` returns `items` with `id`, `name`, `revision`, and `entry_count`.
- `POST /playlists` accepts `{ "name": "Movie night" }` and returns a playlist.
- `GET /playlists/{id}` returns the summary fields plus ordered `entries` and an
  `ETag` for editing that playlist revision.
- `PATCH /playlists/{id}` accepts `{ "name": "New name" }`.
- `POST /playlists/{id}/entries` accepts `{ "item_id": "..." }` and appends an entry.
- `PUT /playlists/{id}/entries/order` accepts `{ "entry_ids": ["..."] }`. The array
  must contain every current entry ID exactly once.
- `DELETE /playlists/{id}/entries/{entry_id}` removes that occurrence.
- `DELETE /playlists/{id}` deletes the playlist and returns 204.

Paths above are relative to `/api/v2`. Every mutation of an existing playlist
requires the exact current `If-Match` validator. Missing preconditions return
428; stale preconditions return 412. Wildcard preconditions are rejected so an
editor cannot accidentally overwrite an intervening edit. Both DELETE operations return 204; fetch the detail again after removing an
entry. Other mutations return the updated detail and validator. Reload after a
conflict and let the user reapply the edit; do not retry it blindly.

Names contain 1–200 characters after trimming. A playlist has at most 500
entries. Each occurrence has its own stable `id`, so duplicate titles remain
independently reorderable and removable. Deleting playlists or entries never
changes media files or catalog items.

## Playback and access

An available entry contains `id`, `available: true`, `item_id`, and `item` (the
standard `CatalogItem` card, whose identifier is `content_id`). An unavailable
or restricted entry contains only its entry `id` and `available: false`. Its
catalog ID, title, and artwork are not disclosed. Access is checked on each
read; the server does not retain a title snapshot in the playlist tables.

Before starting an entry, call
`GET /playlists/{id}/playback?entry_id=<entry>&after=false`. Before advancing,
call the same endpoint with `after=true`. It returns `{ "entry": ... }` for the
first currently accessible, readable movie or episode at that position (or
strictly after it). Unavailable entries are skipped. `{ "entry": null }` ends
the playlist; there is no wraparound or next-episode fallback. A removed cursor
entry returns 404; stop rather than guessing a new position.

Clients pass the returned `item_id` through normal playback creation, which
independently enforces playback authorization. Playlist context is scoped to
the current profile and must be cleared on profile changes. Outside playlist
context, ordinary next-episode behavior is unchanged.

## Persistence and concurrency

`profile_playlists` owns the revision and account/profile ownership;
`profile_playlist_entries` owns stable occurrence IDs and positions. All edits
lock the parent row, compare the expected revision, update the entries, and
advance the revision in one transaction. Reorders use a single set-based
update with a deferred unique position constraint. This works across server
nodes without process-local locks. Account deletion cascades to its playlists; profile deletion purges them through
the profile service because profiles can use per-account SQLite stores;
catalog removal leaves an unavailable entry that the owner can remove.

Profile cleanup follows the existing post-delete purge boundary. Failures are
logged and can leave unreachable playlist rows. Normal profile creation assigns
a new UUID in `ProfileHandler.CreateProfile`; backup restore also creates a new
UUID through `pgstore.NewProfileID` when it needs a new profile. Neither API lets
a caller choose a deleted profile's ID, so recreating a profile with the same
name does not inherit its playlists. Account deletion still removes these rows
through the account foreign key.
