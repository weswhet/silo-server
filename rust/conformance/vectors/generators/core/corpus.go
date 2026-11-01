//go:build core_vectors

package main

import (
	"fmt"
	"math/rand/v2"
	"strings"
)

var textPool = []string{
	"", " ", "a", "A", "movie", "The Matrix", "Ünïcödé", "日本語のタイトル", "emoji😀", "<b>&\"'</b>", "path/to/file.mkv",
	" line ", "tab\there", "new\nline", "K", "K", "ß", "İ", "ı", "ς", "Σ", "́", "é", "ﬁ", "\x7f", "\x01",
	"a b", "a+b", "a%20b", "a&b=c", "#frag", "?q", "/leading", "trailing/", "..", ".", "..hidden", "0", "00", "-1", "1e3",
	"user@example.com", "x-y_z.w~", "$&+,;=:@", "!'()*", "[]{}|\\^`", " nbsp ", "　wide　", "\u0085nel",
}

func pick[T any](r *rand.Rand, list []T) T { return list[r.IntN(len(list))] }

func text(r *rand.Rand) string {
	switch r.IntN(4) {
	case 0:
		return pick(r, textPool)
	case 1:
		return pick(r, textPool) + pick(r, textPool)
	case 2:
		n := r.IntN(24)
		var b strings.Builder
		for range n {
			b.WriteRune(rune(0x20 + r.IntN(0x5f)))
		}
		return b.String()
	default:
		n := r.IntN(12)
		var b strings.Builder
		for range n {
			b.WriteRune(randomRune(r))
		}
		return b.String()
	}
}

func randomRune(r *rand.Rand) rune {
	for {
		c := rune(r.IntN(0x110000))
		if r.IntN(3) > 0 {
			c = rune(r.IntN(0x3000))
		}
		if c >= 0xd800 && c < 0xe000 {
			continue
		}
		return c
	}
}

// rawBytes is a string that is usually not valid UTF-8.
func rawBytes(r *rand.Rand) string {
	n := r.IntN(32)
	b := make([]byte, n)
	for i := range b {
		switch r.IntN(4) {
		case 0:
			b[i] = byte(r.IntN(256))
		case 1:
			b[i] = byte(0x80 + r.IntN(0x80))
		default:
			b[i] = byte(0x20 + r.IntN(0x5f))
		}
	}
	return string(b)
}

func randHex(r *rand.Rand, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	return fmt.Sprintf("%x", b)
}

func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.IntN(256))
	}
	return b
}

func masterKey(r *rand.Rand) string {
	n := 32 + r.IntN(32)
	const chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
	b := make([]byte, n)
	for i := range b {
		b[i] = chars[r.IntN(len(chars))]
	}
	return string(b)
}

func smallInt(r *rand.Rand) int {
	switch r.IntN(5) {
	case 0:
		return 0
	case 1:
		return r.IntN(10)
	case 2:
		return r.IntN(100000)
	case 3:
		return -r.IntN(100)
	default:
		return r.IntN(1 << 40)
	}
}

func posInt(r *rand.Rand) int { return 1 + r.IntN(1<<40) }

func optStr(r *rand.Rand) *string {
	if r.IntN(2) == 0 {
		return nil
	}
	s := text(r)
	return &s
}

func optInt(r *rand.Rand) *int {
	if r.IntN(2) == 0 {
		return nil
	}
	v := smallInt(r)
	return &v
}

func optInt64(r *rand.Rand) *int64 {
	if r.IntN(2) == 0 {
		return nil
	}
	v := int64(smallInt(r))
	return &v
}

func randFloat(r *rand.Rand) float64 {
	switch r.IntN(6) {
	case 0:
		return 0
	case 1:
		return float64(r.IntN(100000))
	case 2:
		return float64(r.IntN(100000)) / 8
	case 3:
		return r.Float64() * 1e7
	case 4:
		return r.Float64() * 1e-7
	default:
		return float64(r.Int64N(1 << 62))
	}
}

func contentIDInput(r *rand.Rand) string {
	providers := []string{"tmdb", "imdb", "tvdb", "TMDB", "plex", ""}
	p := pick(r, providers)
	id := fmt.Sprintf("%d", r.Int64N(1<<40))
	if p == "imdb" && r.IntN(4) > 0 {
		id = "tt" + id
	}
	if r.IntN(10) == 0 {
		id = "18446744073709551616" + id
	}
	num := func() string { return fmt.Sprintf("%d", r.IntN(40)) }
	switch r.IntN(12) {
	case 0, 1:
		return "movie-" + p + "-" + id
	case 2, 3:
		return "series-" + p + "-" + id
	case 4, 5:
		return "season-" + p + "-" + id + "-" + num()
	case 6, 7:
		return "episode-" + p + "-" + id + "-" + num() + "-" + num()
	case 8:
		return "local-" + randHex(r, 14)
	case 9:
		return fmt.Sprintf("%d", r.Int64N(1<<62))
	case 10:
		return pick(r, []string{" movie-tmdb-1 ", "series-", "episode-tvdb-296762", "season-tvdb-1", "local-zz", "local-" + randHex(r, 13), "movie-tmdb-1-2", "episode-tvdb-1-a-2", "MOVIE-tmdb-1", "movie-imdb-TT0944947", "movie-imdb-tt0944947", "movie-tvdb-007", " movie-tmdb-9　"})
	default:
		return text(r)
	}
}
