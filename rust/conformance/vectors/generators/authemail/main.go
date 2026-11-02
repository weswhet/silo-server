// Command authemail records which identifiers the real auth.LookupLogin tries against the email
// column, using a directory whose username lookup always misses. looksLikeEmail is private, so this is
// the only way to reach it without copying it.
//
// Commands assume the repository root is the cwd:
//
//	GOTOOLCHAIN=go1.26.10 go run ./rust/conformance/vectors/generators/authemail
package main

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"os"

	"github.com/Silo-Server/silo-server/internal/auth"
	"github.com/Silo-Server/silo-server/internal/models"
)

type directory struct{ emailCalled bool }

func (d *directory) GetByUsername(context.Context, string) (*models.User, error) {
	return nil, auth.ErrNotFound
}

func (d *directory) GetByEmail(context.Context, string) (*models.User, error) {
	d.emailCalled = true
	return nil, auth.ErrNotFound
}

type record struct {
	Identifier string `json:"identifier"`
	Email      bool   `json:"email"`
}

func main() {
	identifiers := []string{
		"", "@", "a@", "@b", "a@b", "admin@localhost", "root@host", "person@example.com", " person@example.com ", "\tperson@example.com\n",
		" a@b ", "not-an-email", "a,b@example.com", "a..b@example.com", ".a@b", "a.@b", "a@.b", "a@b.", "a@b..c", "a@b.c;", "a;b@c", "a:b@c",
		"group: a@b;", "Name <a@b>", "<a@b>", "a@b (comment)", "(c) a@b", "\"a\"@b", "\"a b\"@c", "\"\"@b", "a@b@c", "a b@c", "a@b c", "a@ b", "a @b",
		"a@[1.2.3.4]", "a@[::1]", "a@[1.2.3]", "a@[]", "a@[1.2.3.4", "a@1.2.3.4]", "a@[1.2.3.4]x", "a@[fe80::1%eth0]", "é@b", "a@é", "a@b c", "a\u0085b@c",
		"a\x7fb@c", "a\x01b@c", "a+b@c", "a!#$%&'*/=?^_`{|}~-@c", "a(b@c", "a)b@c", "a<b@c", "a>b@c", "a[b@c", "a]b@c", "a\\b@c", "a\"b@c", "a@b(c", "a@b,c",
		"person@example.com, other@example.com", "　1@2", "a@b\r\n", "=?utf-8?q?a?=@b",
	}
	r := rand.New(rand.NewSource(20261101))
	alphabet := []string{"a", "b", ".", "@", " ", ",", ";", ":", "<", ">", "(", ")", "[", "]", "\"", "\\", "é", "1", "-", "_", "\t", "%"}
	for i := 0; i < 8000; i++ {
		s := ""
		for n := r.Intn(9); n >= 0; n-- {
			s += alphabet[r.Intn(len(alphabet))]
		}
		identifiers = append(identifiers, s)
	}
	var records []record
	for _, identifier := range identifiers {
		d := &directory{}
		if _, err := auth.LookupLogin(context.Background(), d, identifier); !auth.IsNotFound(err) {
			log.Fatalf("%q: %v", identifier, err)
		}
		records = append(records, record{Identifier: identifier, Email: d.emailCalled})
	}
	data, err := json.Marshal(records)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile("rust/conformance/vectors/auth/looks_like_email.json", append(data, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %d cases", len(records))
}
