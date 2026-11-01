//go:build gocompat_vectors

package main

import (
	"path"
	"path/filepath"
	"strings"
)

type pathCase struct {
	In    S    `json:"in"`
	Clean S    `json:"clean"`
	Base  S    `json:"base"`
	Dir   S    `json:"dir"`
	Ext   S    `json:"ext"`
	IsAbs bool `json:"is_abs"`
	Split [2]S `json:"split"`
	// The filepath results, kept separate in case the two packages ever differ.
	FClean S    `json:"f_clean"`
	FBase  S    `json:"f_base"`
	FDir   S    `json:"f_dir"`
	FExt   S    `json:"f_ext"`
	FIsAbs bool `json:"f_is_abs"`
	FSplit [2]S `json:"f_split"`
}

type joinCase struct {
	In    []S `json:"in"`
	Path  S   `json:"path"`
	FPath S   `json:"f_path"`
}

type relCase struct {
	Base S  `json:"base"`
	Targ S  `json:"targ"`
	Out  *S `json:"out"`
	Err  *S `json:"err"`
}

type matchCase struct {
	Pattern S    `json:"pattern"`
	Name    S    `json:"name"`
	Path    bool `json:"path"`
	PathErr bool `json:"path_err"`
	File    bool `json:"file"`
	FileErr bool `json:"file_err"`
}

type pathVector struct {
	Meta
	Paths []pathCase  `json:"paths"`
	Joins []joinCase  `json:"joins"`
	Rels  []relCase   `json:"rels"`
	Match []matchCase `json:"match"`
}

var pathTokens = []string{
	"", ".", "..", "...", "a", "b", "é", "日本", ".hidden", "file.tar.gz", "a b", "\\", "..a", "a..", "a.", ".a.", "İ", "🎬", "c:", "~", "-", "a\tb",
}

func genPath() pathVector {
	r := newRand(2)
	v := pathVector{Meta: newMeta()}
	seen := map[string]bool{}
	var inputs []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			inputs = append(inputs, s)
		}
	}
	for _, s := range []string{
		"", ".", "..", "/", "//", "///", "/.", "/..", "/../", "/../..", "./", "../", "a/", "a//b", "a/./b", "a/../b", "a/b/..", "a/b/../..", "a/b/../../..",
		"../a", "../../a", "/a/../../b", "/a/b/c/../../..", "abc", "abc/def", "a/b/c", "/abc/", "abc/", "./abc", "../abc", "abc/./def/.", "abc//def//ghi",
		"abc/../..", "/../abc", "abc/def/../../..", "/abc/def/../../..", "a.txt", "a/b.txt", ".bashrc", "a/.bashrc", "a.b/c", "a.b/", "a.", "..txt",
		"/media/tv/Show/Season 1/ep.mkv", "/media//tv/./Show/../Show/ep.mkv", "C:\\Media\\x.mkv", "foo\\bar/baz", "é/ü/../ñ.mkv",
	} {
		add(s)
	}
	for range 700 {
		n := r.IntN(6)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = pathTokens[r.IntN(len(pathTokens))]
		}
		s := strings.Join(parts, "/")
		switch r.IntN(4) {
		case 0:
			s = "/" + s
		case 1:
			s += "/"
		}
		add(s)
	}
	for _, s := range inputs {
		d, f := path.Split(s)
		fd, ff := filepath.Split(s)
		v.Paths = append(v.Paths, pathCase{
			In: S(s), Clean: S(path.Clean(s)), Base: S(path.Base(s)), Dir: S(path.Dir(s)), Ext: S(path.Ext(s)), IsAbs: path.IsAbs(s), Split: [2]S{S(d), S(f)},
			FClean: S(filepath.Clean(s)), FBase: S(filepath.Base(s)), FDir: S(filepath.Dir(s)), FExt: S(filepath.Ext(s)), FIsAbs: filepath.IsAbs(s), FSplit: [2]S{S(fd), S(ff)},
		})
	}
	for _, parts := range [][]string{
		{}, {""}, {"", ""}, {"a"}, {"a", ""}, {"", "a"}, {"a", "b"}, {"a", "/b"}, {"/a", "/b"}, {"a/", "b"}, {"", "", "a"}, {"a", "", "b"}, {"/", "a"}, {"..", "a"}, {"a", ".."}, {"", "/"}, {"/", ""},
	} {
		v.Joins = append(v.Joins, joinCase{strs(parts), S(path.Join(parts...)), S(filepath.Join(parts...))})
	}
	for range 400 {
		n := r.IntN(5)
		parts := make([]string, n)
		for i := range parts {
			parts[i] = inputs[r.IntN(len(inputs))]
			if r.IntN(3) == 0 {
				parts[i] = pathTokens[r.IntN(len(pathTokens))]
			}
		}
		v.Joins = append(v.Joins, joinCase{strs(parts), S(path.Join(parts...)), S(filepath.Join(parts...))})
	}

	addRel := func(base, targ string) {
		c := relCase{Base: S(base), Targ: S(targ)}
		out, err := filepath.Rel(base, targ)
		if err != nil {
			e := S(err.Error())
			c.Err = &e
		} else {
			o := S(out)
			c.Out = &o
		}
		v.Rels = append(v.Rels, c)
	}
	for _, p := range [][2]string{
		{"a/b", "a/b"}, {"a/b/.", "a/b"}, {"a/b", "a/b/."}, {"./a/b", "a/b"}, {"a/b", "./a/b"}, {"ab/cd", "ab/cde"}, {"ab/cd", "ab/c"}, {"a/b", "a/b/c/d"}, {"a/b", "a/b/../c"},
		{"a/b/../c", "a/b"}, {"a/b/c", "a/c/d"}, {"a/b", "c/d"}, {"a/b/c/d", "a/b"}, {"a/b/c/d", "a/b/"}, {"a/b/c/d/", "a/b"}, {"a/b/c/d/", "a/b/"}, {"../../a/b", "../../a/b/c/d"},
		{"/a/b", "/a/b"}, {"/a/b/.", "/a/b"}, {"/a/b", "/a/b/."}, {"/ab/cd", "/ab/cde"}, {"/ab/cd", "/ab/c"}, {"/a/b", "/a/b/c/d"}, {"/a/b", "/a/b/../c"}, {"/a/b/../c", "/a/b"},
		{"/a/b/c", "/a/c/d"}, {"/a/b", "/c/d"}, {"/a/b/c/d", "/a/b"}, {"/a/b/c/d", "/a/b/"}, {"/a/b/c/d/", "/a/b"}, {"/a/b/c/d/", "/a/b/"}, {"/../../a/b", "/../../a/b/c/d"}, {".", "a/b"}, {".", ".."},
		{"..", "."}, {"..", "a"}, {"../..", ".."}, {"a", "/a"}, {"/a", "a"}, {"", ""}, {"", "."}, {".", ""}, {"/", "/"}, {"/", "a"}, {"a", "/"},
	} {
		addRel(p[0], p[1])
	}
	for range 400 {
		addRel(inputs[r.IntN(len(inputs))], inputs[r.IntN(len(inputs))])
	}

	addMatch := func(pattern, name string) {
		p, perr := path.Match(pattern, name)
		f, ferr := filepath.Match(pattern, name)
		v.Match = append(v.Match, matchCase{S(pattern), S(name), p, perr != nil, f, ferr != nil})
	}
	for _, p := range [][2]string{
		{"abc", "abc"}, {"*", "abc"}, {"*c", "abc"}, {"a*", "a"}, {"a*", "abc"}, {"a*", "ab/c"}, {"a*/b", "abc/b"}, {"a*/b", "a/c/b"}, {"a*b*c*d*e*/f", "axbxcxdxe/f"}, {"a*b*c*d*e*/f", "axbxcxdxexxx/f"},
		{"a*b*c*d*e*/f", "axbxcxdxe/xxx/f"}, {"a*b*c*d*e*/f", "axbxcxdxexxx/fff"}, {"a*b?c*x", "abxbbxdbxebxczzx"}, {"a*b?c*x", "abxbbxdbxebxczzy"}, {"ab[c]", "abc"}, {"ab[b-d]", "abc"}, {"ab[e-g]", "abc"},
		{"ab[^c]", "abc"}, {"ab[^b-d]", "abc"}, {"ab[^e-g]", "abc"}, {"a\\*b", "a*b"}, {"a\\*b", "ab"}, {"a?b", "a☺b"}, {"a[^a]b", "a☺b"}, {"a???b", "a☺b"}, {"a[^a][^a][^a]b", "a☺b"}, {"[a-ζ]*", "α"}, {"*[a-ζ]", "A"},
		{"a?b", "a/b"}, {"a*b", "a/b"}, {"[\\]a]", "]"}, {"[\\-]", "-"}, {"[x\\-]", "x"}, {"[x\\-]", "-"}, {"[x\\-]", "z"}, {"[\\-x]", "x"}, {"[\\-x]", "-"}, {"[\\-x]", "a"}, {"[]a]", "]"}, {"[-]", "-"}, {"[x-]", "x"},
		{"[x-]", "-"}, {"[x-]", "z"}, {"[-x]", "x"}, {"[-x]", "-"}, {"[-x]", "a"}, {"\\", "a"}, {"[a-b-c]", "a"}, {"[", "a"}, {"[^", "a"}, {"[^bc", "a"}, {"a[", "a"}, {"a[", "ab"}, {"a[", "x"}, {"a/b[", "x"}, {"*x", "xxx"},
		{"*.mkv", "movie.mkv"}, {"*.MKV", "movie.mkv"}, {"@eaDir", "@eaDir"}, {".DS_Store", ".DS_Store"}, {"sample*", "sample-video.mkv"}, {"*sample*", "the.sample.mkv"}, {"[Ss]ample", "Sample"}, {"*/extras/*", "x/extras/y"},
		{"a*[", "ab"}, {"*[", "x"}, {"*\\", "x"}, {"[a", "b"}, {"x*[", "y"},
	} {
		addMatch(p[0], p[1])
	}
	patTokens := []string{"*", "?", "[a-c]", "[^a]", "[]a]", "[", "]", "\\", "\\*", "[a-", "[-]", "a", "b", "é", "日", "/", "[é-ü]", "[^é]", "**", "\\[", "[\\]]", "[a-c", "a-b", "^", "-", "[^", "[]", "x"}
	nameTokens := []string{"a", "b", "c", "x", "é", "ü", "日", "/", "*", "[", "]", "-", "\\", "^", "🎬", "İ"}
	for range 2000 {
		var pb, nb strings.Builder
		for range r.IntN(5) {
			pb.WriteString(patTokens[r.IntN(len(patTokens))])
		}
		for range r.IntN(5) {
			nb.WriteString(nameTokens[r.IntN(len(nameTokens))])
		}
		addMatch(pb.String(), nb.String())
	}
	return v
}
