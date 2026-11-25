-- +goose Up
CREATE TABLE profile_playlists (
    id text PRIMARY KEY,
    user_id integer NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    -- Profiles may live in per-account SQLite stores; cleanup uses ProfileHandler.
    profile_id text NOT NULL,
    name text NOT NULL CHECK (length(btrim(name)) BETWEEN 1 AND 200),
    revision bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX profile_playlists_owner ON profile_playlists(user_id, profile_id, created_at, id);
CREATE TABLE profile_playlist_entries (
    id text PRIMARY KEY,
    playlist_id text NOT NULL REFERENCES profile_playlists(id) ON DELETE CASCADE,
    -- Keep the entry when a catalog item disappears, without preserving its metadata.
    item_id text NOT NULL,
    position integer NOT NULL CHECK (position >= 0),
    UNIQUE (playlist_id, position) DEFERRABLE INITIALLY DEFERRED
);
-- +goose Down
DROP TABLE profile_playlist_entries;
DROP TABLE profile_playlists;
