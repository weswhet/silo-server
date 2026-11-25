package playlists

import (
	"errors"
	"testing"
)

func TestDuplicateEntriesAndExactReorder(t *testing.T) {
	p := Playlist{}
	for range 2 {
		if err := apply(&p, Mutation{AddItem: "movie:one"}); err != nil {
			t.Fatal(err)
		}
	}
	if p.Entries[0].ID == p.Entries[1].ID {
		t.Fatal("duplicate titles share an entry ID")
	}
	a, b := p.Entries[0].ID, p.Entries[1].ID
	for _, order := range [][]string{{a}, {a, a}, {a, "other"}, {a, b, "other"}} {
		if err := apply(&p, Mutation{Order: order}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted incomplete or foreign order %v", order)
		}
	}
	if err := apply(&p, Mutation{Order: []string{b, a}}); err != nil {
		t.Fatal(err)
	}
	if p.Entries[0].ID != b {
		t.Fatal("order unchanged")
	}
	if err := apply(&p, Mutation{RemoveEntry: b}); err != nil {
		t.Fatal(err)
	}
	if len(p.Entries) != 1 || p.Entries[0].ID != a {
		t.Fatal("removal deleted the other occurrence")
	}
}
