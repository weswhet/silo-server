// Package playlists stores private, profile-owned ordered movie and episode lists.
package playlists

import (
	"context"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("playlist not found")
	ErrStale    = errors.New("playlist changed")
	ErrInvalid  = errors.New("invalid playlist edit")
)

const MaxEntries = 500

type Owner struct {
	UserID    int
	ProfileID string
}

type Entry struct{ ID, ItemID string }
type Playlist struct {
	ID, Name   string
	Revision   int64
	EntryCount int
	Entries    []Entry
}
type Mutation struct {
	Name        *string
	AddItem     string
	RemoveEntry string
	Order       []string
	Delete      bool
}
type Store struct{ Pool *pgxpool.Pool }

func validName(name string) bool {
	return len([]rune(strings.TrimSpace(name))) > 0 && len([]rune(name)) <= 200
}

func (s *Store) List(ctx context.Context, owner Owner) ([]Playlist, error) {
	rows, err := s.Pool.Query(ctx, `SELECT p.id,p.name,p.revision,(SELECT count(*) FROM profile_playlist_entries e WHERE e.playlist_id=p.id) FROM profile_playlists p WHERE p.user_id=$1 AND p.profile_id=$2 ORDER BY p.created_at,p.id`, owner.UserID, owner.ProfileID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []Playlist{}
	for rows.Next() {
		var p Playlist
		if err := rows.Scan(&p.ID, &p.Name, &p.Revision, &p.EntryCount); err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return result, nil
}
func read(ctx context.Context, tx pgx.Tx, owner Owner, id string, lock bool) (Playlist, error) {
	p := Playlist{Entries: []Entry{}}
	q := `SELECT id,name,revision FROM profile_playlists WHERE user_id=$1 AND profile_id=$2 AND id=$3`
	if lock {
		q += " FOR UPDATE"
	}
	err := tx.QueryRow(ctx, q, owner.UserID, owner.ProfileID, id).Scan(&p.ID, &p.Name, &p.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	if err != nil {
		return p, err
	}
	rows, err := tx.Query(ctx, `SELECT id,item_id FROM profile_playlist_entries WHERE playlist_id=$1 ORDER BY position`, id)
	if err != nil {
		return p, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.ItemID); err != nil {
			return p, err
		}
		p.Entries = append(p.Entries, e)
	}
	p.EntryCount = len(p.Entries)
	return p, rows.Err()
}
func (s *Store) Get(ctx context.Context, owner Owner, id string) (Playlist, error) {
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Playlist{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	p, err := read(ctx, tx, owner, id, false)
	if err != nil {
		return p, err
	}
	return p, tx.Commit(ctx)
}
func (s *Store) Create(ctx context.Context, owner Owner, name string) (Playlist, error) {
	name = strings.TrimSpace(name)
	if !validName(name) {
		return Playlist{}, ErrInvalid
	}
	p := Playlist{ID: uuid.NewString(), Name: name, Revision: 1, Entries: []Entry{}}
	_, err := s.Pool.Exec(ctx, `INSERT INTO profile_playlists(id,user_id,profile_id,name) VALUES($1,$2,$3,$4)`, p.ID, owner.UserID, owner.ProfileID, name)
	return p, err
}

// Apply serializes all edits on the parent row. Checking the revision while holding
// that lock makes append, delete, rename and reorder safe across server nodes.
func (s *Store) Apply(ctx context.Context, owner Owner, id string, revision int64, m Mutation) (Playlist, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return Playlist{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	p, err := read(ctx, tx, owner, id, true)
	if err != nil {
		return p, err
	}
	if p.Revision != revision {
		return p, ErrStale
	}
	if m.Delete {
		_, err = tx.Exec(ctx, `DELETE FROM profile_playlists WHERE id=$1`, id)
		if err != nil {
			return p, err
		}
		return p, tx.Commit(ctx)
	}
	if err = apply(&p, m); err != nil {
		return p, err
	}
	_, err = tx.Exec(ctx, `UPDATE profile_playlists SET name=$2,revision=revision+1 WHERE id=$1`, id, p.Name)
	if err != nil {
		return p, err
	}
	if m.AddItem != "" {
		e := p.Entries[len(p.Entries)-1]
		_, err = tx.Exec(ctx, `INSERT INTO profile_playlist_entries(id,playlist_id,item_id,position) VALUES($1,$2,$3,$4)`, e.ID, id, e.ItemID, len(p.Entries)-1)
		if err != nil {
			return p, err
		}
	}
	if m.RemoveEntry != "" {
		_, err = tx.Exec(ctx, `DELETE FROM profile_playlist_entries WHERE playlist_id=$1 AND id=$2`, id, m.RemoveEntry)
		if err != nil {
			return p, err
		}
	}
	if m.Order != nil || m.RemoveEntry != "" {
		ids := make([]string, len(p.Entries))
		for i, e := range p.Entries {
			ids[i] = e.ID
		}
		_, err = tx.Exec(ctx, `UPDATE profile_playlist_entries e SET position=o.position-1 FROM unnest($2::text[]) WITH ORDINALITY AS o(id,position) WHERE e.playlist_id=$1 AND e.id=o.id`, id, ids)
		if err != nil {
			return p, err
		}
	}

	p.Revision++
	p.EntryCount = len(p.Entries)
	return p, tx.Commit(ctx)
}
func apply(p *Playlist, m Mutation) error {
	if m.Name != nil {
		name := strings.TrimSpace(*m.Name)
		if !validName(name) {
			return ErrInvalid
		}
		p.Name = name
	}
	if m.AddItem != "" {
		if len(p.Entries) >= MaxEntries {
			return ErrInvalid
		}
		p.Entries = append(p.Entries, Entry{ID: uuid.NewString(), ItemID: m.AddItem})
	}
	if m.RemoveEntry != "" {
		found := false
		for i, e := range p.Entries {
			if e.ID == m.RemoveEntry {
				p.Entries = append(p.Entries[:i], p.Entries[i+1:]...)
				found = true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
	}
	if m.Order != nil {
		if len(m.Order) != len(p.Entries) {
			return ErrInvalid
		}
		byID := make(map[string]Entry, len(p.Entries))
		for _, e := range p.Entries {
			byID[e.ID] = e
		}
		ordered := make([]Entry, 0, len(m.Order))
		for _, id := range m.Order {
			e, ok := byID[id]
			if !ok {
				return ErrInvalid
			}
			ordered = append(ordered, e)
			delete(byID, id)
		}
		p.Entries = ordered
	}
	return nil
}

func (s *Store) PurgeProfile(ctx context.Context, userID int, profileID string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM profile_playlists WHERE user_id=$1 AND profile_id=$2`, userID, profileID)
	return err
}
