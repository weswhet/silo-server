//go:build gocompat_vectors

package main

import (
	"strings"
	"unicode"
)

type mapCase struct {
	In  S `json:"in"`
	Out S `json:"out"`
}

type foldCase struct {
	A  S    `json:"a"`
	B  S    `json:"b"`
	Eq bool `json:"eq"`
}

type fieldsCase struct {
	In  S   `json:"in"`
	Out []S `json:"out"`
}

type stringsVector struct {
	Meta
	ToLower   []mapCase    `json:"to_lower"`
	ToUpper   []mapCase    `json:"to_upper"`
	EqualFold []foldCase   `json:"equal_fold"`
	TrimSpace []mapCase    `json:"trim_space"`
	Fields    []fieldsCase `json:"fields"`
}

func genStrings() stringsVector {
	r := newRand(1)
	var valid []string
	valid = append(valid, "", "abc", "ABC", "aBc1!", "İ", "i̇", "ı", "I", "ß", "SS", "ẞ", "ſ", "K", "k", "Σ", "σ", "ς", "ΣΑΣ", "σας", "ΑΣ ΣΑ",
		"ǅ", "ǆ", "Ǆ", "ﬁ", "FI", "ŉ", "ΐ", "ᾳ", "Ꭰ", "ꭰ", "ა", "Ა", "և", "𐐀", "𐐨", "𞤀", "𞤢", "\u10D50", "Ⓐ", "ⓐ", "Ⅷ", "ⅷ", "Ａ", "ａ")
	valid = append(valid, mediaStrings...)
	for _, c := range adversarialRunes {
		valid = append(valid, string(c), "a"+string(c)+"b", " "+string(c)+" ", string(c)+string(c))
	}
	for _, c := range foldRunes(9) {
		valid = append(valid, string(c), "X"+string(c))
	}
	for range 500 {
		valid = append(valid, randomAdversarial(r, 8))
	}

	v := stringsVector{Meta: newMeta()}
	for _, s := range valid {
		v.ToLower = append(v.ToLower, mapCase{S(s), S(strings.ToLower(s))})
		v.ToUpper = append(v.ToUpper, mapCase{S(s), S(strings.ToUpper(s))})
		v.TrimSpace = append(v.TrimSpace, mapCase{S(s), S(strings.TrimSpace(s))})
		v.Fields = append(v.Fields, fieldsCase{S(s), strs(strings.Fields(s))})
	}
	for _, s := range invalidUTF8 {
		v.ToLower = append(v.ToLower, mapCase{S(s), S(strings.ToLower(s))})
		v.ToUpper = append(v.ToUpper, mapCase{S(s), S(strings.ToUpper(s))})
	}

	addFold := func(a, b string) {
		v.EqualFold = append(v.EqualFold, foldCase{S(a), S(b), strings.EqualFold(a, b)})
	}
	for _, s := range valid {
		addFold(s, strings.ToUpper(s))
		addFold(s, strings.ToLower(s))
		addFold(strings.ToUpper(s), strings.ToLower(s))
		addFold(s, s+"x")
		addFold(s, randomAdversarial(r, 3))
	}
	for _, c := range foldRunes(4) {
		for f := unicode.SimpleFold(c); f != c; f = unicode.SimpleFold(f) {
			addFold(string(c), string(f))
			addFold("pre"+string(c)+"post", "PRE"+string(f)+"POST")
		}
		addFold(string(c), string(c+1))
	}
	for _, p := range [][2]string{
		{"ß", "SS"}, {"ß", "ẞ"}, {"ſ", "s"}, {"ſ", "S"}, {"K", "k"}, {"K", "K"}, {"İ", "i"}, {"İ", "I"}, {"ı", "I"}, {"ı", "i"},
		{"ς", "σ"}, {"ς", "Σ"}, {"ǅ", "ǆ"}, {"ǅ", "Ǆ"}, {"Å", "å"}, {"Å", "Å"}, {"µ", "μ"}, {"µ", "Μ"}, {"", ""}, {"a", ""}, {"", "a"},
	} {
		addFold(p[0], p[1])
		addFold(p[1], p[0])
	}
	for _, a := range invalidUTF8 {
		addFold(a, a)
		addFold(a, "\xff")
		addFold(a, "\ufffd")
		addFold("\xfe", a)
	}
	return v
}
