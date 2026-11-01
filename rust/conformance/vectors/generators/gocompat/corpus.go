//go:build gocompat_vectors

package main

import (
	"math/rand/v2"
	"strings"
	"unicode"
)

// adversarialRunes covers the places Go's simple case maps and Rust's full ones disagree, runes
// with long fold orbits, whitespace, separators, and code points assigned after Unicode 15.
var adversarialRunes = []rune{
	'a', 'A', 'k', 'K', 's', 'S', 'i', 'I', 'z', 'Z', '0', '9', ' ', '\t', '\n', '\r', '\v', '\f',
	0x00, 0x08, 0x1F, 0x7F, 0x85, 0xA0, 0xAD, 0xB5, 0xDF, 0xC9, 0xE9, 0xFF,
	0x130, 0x131, 0x149, 0x178, 0x17F, 0x1C4, 0x1C5, 0x1C6, 0x1F0, 0x390, 0x3A3, 0x3C2, 0x3C3,
	0x345, 0x399, 0x3B9, 0x1FBE, 0x3B8, 0x398, 0x3D1, 0x3F4, 0x3B2, 0x3D0, 0x3B5, 0x3F5, 0x3BA, 0x3F0,
	0x3C0, 0x3D6, 0x3C1, 0x3F1, 0x3C6, 0x3D5, 0x3C9, 0x2126, 0x212A, 0x212B, 0xE5, 0xC5, 0x1E9E,
	0x531, 0x561, 0x587, 0x10A0, 0x2D00, 0x10D0, 0x1C90, 0x13A0, 0xAB70, 0x13F8, 0x1E00, 0x1E01,
	0x2160, 0x2170, 0x24B6, 0x24D0, 0xFB00, 0xFB01, 0xFF21, 0xFF41, 0xFF10, 0xFF11, 0x660, 0x663,
	0x10400, 0x10428, 0x104B0, 0x10570, 0x10C80, 0x118A0, 0x16E40, 0x1E900, 0x1E922, 0x1E943,
	0x10D50, 0x10D70, 0x1C89, 0x1C8A, 0xA7CB, 0xA7DA, 0xA7DC, 0xA7CC,
	0x1680, 0x180E, 0x2000, 0x2009, 0x200A, 0x200B, 0x2028, 0x2029, 0x202F, 0x205F, 0x2060, 0x3000, 0xFEFF,
	0x301, 0x307, 0x308, 0xFFFD, 0xFFFE, 0xFFFF, 0x10FFFF, 0x1F3AC, 0x65E5, 0x672C,
	0xE000, 0xD7FF, '<', '>', '&', '"', '\\', '/', '.', '-', '_', '%', '+', '$',
}

var mediaStrings = []string{
	"Show.Name.S01E02.1080p.WEB-DL.x264-GROUP.mkv",
	"The Movie (2019) [1080p].mkv",
	"Movie.2019.2160p.BluRay.HEVC.TrueHD.7.1.mkv",
	"[Group] Anime - 12 [720p].mkv",
	"Series 1x02 Title.avi",
	"Season 03/Episode 12.mp4",
	"/media/tv/Show/Season 1/ep.mkv",
	"İstanbul ΣΑΣ Straße",
	"Pokémon: The Movie",
	"ΣΊΣΥΦΟΣ",
	"ǅungla",
	"日本語のタイトル",
}

func randomAdversarial(r *rand.Rand, maxLen int) string {
	var b strings.Builder
	n := r.IntN(maxLen + 1)
	for range n {
		b.WriteRune(adversarialRunes[r.IntN(len(adversarialRunes))])
	}
	return b.String()
}

// foldRunes returns a sample of every rune with a nontrivial fold orbit.
func foldRunes(step int) []rune {
	var out []rune
	n := 0
	for c := rune(0); c <= unicode.MaxRune; c++ {
		if unicode.SimpleFold(c) != c {
			if n%step == 0 {
				out = append(out, c)
			}
			n++
		}
	}
	return out
}

// invalidUTF8 holds byte strings that do not decode: lone continuations, truncated sequences,
// overlongs, surrogates, and values above U+10FFFF.
var invalidUTF8 = []string{
	"\xff", "\xfe", "\x80", "\xbf", "\xc0\x80", "\xc1\xbf", "\xc2", "\xe0\x80\x80", "\xe2\x82",
	"\xed\xa0\x80", "\xed\xbf\xbf", "\xf0\x80\x80\x80", "\xf0\x9f", "\xf0\x9f\x8e", "\xf4\x90\x80\x80",
	"\xf8\x88\x80\x80\x80", "a\xffb", "\xffA", "A\xff", "\xc3\xa9\xff", "\xff\xc3\xa9", "\xef\xbf\xbd\xff",
}
