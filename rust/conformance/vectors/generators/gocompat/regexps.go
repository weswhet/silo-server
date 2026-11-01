//go:build gocompat_vectors

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"math/rand/v2"
	"os"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

type regexCase struct {
	Common *int    `json:"i,omitempty"`
	In     *S      `json:"in,omitempty"`
	M      []int   `json:"m,omitempty"`
	All    [][]int `json:"all,omitempty"`
	Rep    *S      `json:"rep,omitempty"`
	Lit    *S      `json:"lit,omitempty"`
	Split  []S     `json:"split,omitempty"`
	Split2 []S     `json:"split2,omitempty"`
	Func   *S      `json:"func,omitempty"`
}

type regexPattern struct {
	P      S        `json:"p"`
	Source string   `json:"source"`
	Err    *S       `json:"err,omitempty"`
	Names  []string `json:"names,omitempty"`
	// Common says the shared inputs were run too, so absent ones are known not to match.
	Common bool        `json:"common,omitempty"`
	Cases  []regexCase `json:"cases,omitempty"`
}

type quoteCase = mapCase

type regexpVector struct {
	Meta
	CommonInputs []S            `json:"common_inputs"`
	Template     string         `json:"template"`
	QuoteMeta    []quoteCase    `json:"quote_meta"`
	Patterns     []regexPattern `json:"patterns,omitempty"`
}

// commonInputs are run against every pattern. A pattern's case list holds only those that match,
// so an absent input means Go found no match.
var commonInputs = []string{
	"", "a", "A", "b", "abc", "ABC", "aaa", "aab", "foo bar", "foo.bar", "\n", "a\nb", "a\n", "\nb", "\n\n", "\t \r\n", "\v", "\f", "\u00a0", "\u0085", "\u2028", "é", "É", "éxé", "xéx", "x", "_", "0", "9", "K", "k", "\u212a", "ſ", "s", "S", "ß", "ẞ", "ı", "İ", "i", "I", "σ", "ς", "Σ",
	"٣", "１２３", "١٢", "０", "Ⅷ", "日本語", "🎬", "a🎬b", "\ufffd", "\U0010ffff",
	"Show.Name.S01E02.1080p.WEB-DL.x264-GROUP.mkv", "The Movie (2019) [1080p].mkv", "Movie.2019.2160p.BluRay.HEVC.TrueHD.7.1.mkv", "[Group] Anime - 12 [720p].mkv", "Series 1x02 Title.avi", "season 3", "Season 03/Episode 12.mp4", "E05", "S01", "s1e1", "2019", "(2019)", "1999-12-31", "12:34:56", "1.2.3", "v1.2.3-beta+build",
	"/media/tv/Show/Season 1/ep.mkv", "C:\\Media\\x.mkv", "http://example.com/a?b=c", "https://example.com:8443/x", "user@example.com", "550e8400-e29b-41d4-a716-446655440000", "deadbeef", "0x1F", "127.0.0.1", "[::1]:8080", "<b>bold</b>", "a_b-c d", "  spaced  ", "UPPER lower", "Ünïcödé", "Ｓ０１Ｅ０２", "ｓ01e02", "ﬁle", "ǅ", "Ǆ", "ǆ", "Pokémon", "Ω", "ω", "\u2126", "Å", "å", "\u212b", "$1", "a.b*c", "{}", "[]", "()",
}

// writeRegexpVector writes one pattern per line, because this file is too big to pretty-print.
func writeRegexpVector(v regexpVector) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	patterns := v.Patterns
	v.Patterns = nil
	if err := enc.Encode(v); err != nil {
		panic(err)
	}
	head := bytes.TrimRight(b.Bytes(), "}\n")
	var out bytes.Buffer
	out.Write(head)
	out.WriteString(",\"patterns\":[\n")
	for i, p := range patterns {
		b.Reset()
		if err := enc.Encode(p); err != nil {
			panic(err)
		}
		out.Write(bytes.TrimRight(b.Bytes(), "\n"))
		if i+1 < len(patterns) {
			out.WriteByte(',')
		}
		out.WriteByte('\n')
	}
	out.WriteString("]}\n")
	if err := os.WriteFile(filepath.Join(outDir, "regexp.json"), out.Bytes(), 0o644); err != nil {
		panic(err)
	}
}

const replaceTemplate = "<$1|${name}|$$|$1x|${0}>"

func runCases(re *regexp.Regexp, extra []string, common bool) []regexCase {
	var cases []regexCase
	lit := "lit$1"
	record := func(common *int, in string) {
		m := re.FindStringSubmatchIndex(in)
		all := re.FindAllStringSubmatchIndex(in, -1)
		if m == nil && all == nil && common != nil {
			return
		}
		c := regexCase{Common: common, M: m}
		// All is omitted when it is exactly the single match.
		if len(all) != 1 {
			c.All = all
		}
		if common == nil {
			s := S(in)
			c.In = &s
		}
		if all != nil {
			rep := S(re.ReplaceAllString(in, replaceTemplate))
			c.Rep = &rep
			l := S(re.ReplaceAllLiteralString(in, lit))
			c.Lit = &l
			c.Split = strs(re.Split(in, -1))
			c.Split2 = strs(re.Split(in, 2))
			fn := S(re.ReplaceAllStringFunc(in, func(m string) string { return "[" + strings.ToUpper(m) + "]" }))
			c.Func = &fn
		}
		cases = append(cases, c)
	}
	if common {
		for i, in := range commonInputs {
			record(&i, in)
		}
	}
	seen := map[string]bool{}
	for _, in := range extra {
		if !utf8.ValidString(in) || seen[in] || (common && slices.Contains(commonInputs, in)) {
			continue
		}
		seen[in] = true
		record(nil, in)
	}
	return cases
}

func patternEntry(p, source string, extra []string) regexPattern {
	common := source == "tree" || source == "re2-search"
	e := regexPattern{P: S(p), Source: source, Common: common}
	re, err := regexp.Compile(p)
	if err != nil {
		msg := S(err.Error())
		e.Err = &msg
		return e
	}
	e.Names = re.SubexpNames()
	e.Cases = runCases(re, extra, common)
	return e
}

// sample builds a string the parsed pattern should match, preferring non-ASCII class members some
// of the time, so anchored patterns get exercised past their first byte.
func sample(r *rand.Rand, re *syntax.Regexp, b *strings.Builder, budget *int) {
	if *budget <= 0 {
		return
	}
	*budget--
	switch re.Op {
	case syntax.OpLiteral:
		for _, c := range re.Rune {
			if re.Flags&syntax.FoldCase != 0 && r.IntN(2) == 0 {
				c = unicode.SimpleFold(c)
			}
			b.WriteRune(c)
		}
	case syntax.OpCharClass:
		if len(re.Rune) == 0 {
			return
		}
		i := r.IntN(len(re.Rune) / 2)
		if r.IntN(3) == 0 {
			i = len(re.Rune)/2 - 1
		}
		lo, hi := re.Rune[2*i], re.Rune[2*i+1]
		c := lo + rune(r.Int64N(int64(hi-lo)+1))
		if c >= 0xD800 && c <= 0xDFFF {
			c = 'x'
		}
		b.WriteRune(c)
	case syntax.OpAnyCharNotNL, syntax.OpAnyChar:
		b.WriteRune([]rune{'x', 'é', '日', ' ', '🎬', '.', '-'}[r.IntN(7)])
	case syntax.OpCapture:
		sample(r, re.Sub[0], b, budget)
	case syntax.OpStar, syntax.OpQuest, syntax.OpPlus, syntax.OpRepeat:
		lo, hi := 0, 2
		switch re.Op {
		case syntax.OpPlus:
			lo = 1
		case syntax.OpQuest:
			hi = 1
		case syntax.OpRepeat:
			lo = re.Min
			hi = re.Max
			if hi < 0 {
				hi = lo + 2
			}
		}
		if hi > lo+3 {
			hi = lo + 3
		}
		for range lo + r.IntN(hi-lo+1) {
			sample(r, re.Sub[0], b, budget)
		}
	case syntax.OpConcat:
		for _, sub := range re.Sub {
			sample(r, sub, b, budget)
		}
	case syntax.OpAlternate:
		sample(r, re.Sub[r.IntN(len(re.Sub))], b, budget)
	}
}

func samplesFor(r *rand.Rand, pattern string, n int) []string {
	parsed, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	var out []string
	for range n {
		var b strings.Builder
		budget := 400
		sample(r, parsed, &b, &budget)
		s := b.String()
		out = append(out, s, "pre "+s+" post", "é"+s+"é")
		if s != "" {
			out = append(out, mutate(r, s))
		}
	}
	return out
}

// treePatterns extracts every literal pattern compiled in the server's non-test Go source.
func treePatterns() []string {
	seen := map[string]bool{}
	var out []string
	for _, root := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return nil
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "regexp" {
					return true
				}
				switch sel.Sel.Name {
				case "MustCompile", "Compile", "MatchString":
				default:
					return true
				}
				if p, ok := literalString(call.Args[0]); ok && !seen[p] {
					seen[p] = true
					out = append(out, p)
				}
				return true
			})
			return nil
		})
		if err != nil {
			panic(err)
		}
	}
	slices.Sort(out)
	return out
}

func literalString(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		a, ok1 := literalString(v.X)
		b, ok2 := literalString(v.Y)
		return a + b, ok1 && ok2
	case *ast.ParenExpr:
		return literalString(v.X)
	}
	return "", false
}

// re2SearchPatterns reads RE2's search test file from GOROOT: blocks of strings and regexps.
func re2SearchPatterns() map[string][]string {
	f, err := os.Open(filepath.Join(runtime.GOROOT(), "src/regexp/testdata/re2-search.txt"))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	out := map[string][]string{}
	var strs []string
	mode := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "strings":
			mode = "strings"
			strs = nil
		case line == "regexps":
			mode = "regexps"
		case strings.HasPrefix(line, `"`):
			s, err := strconv.Unquote(line)
			if err != nil {
				continue
			}
			if mode == "strings" {
				strs = append(strs, s)
			} else if mode == "regexps" {
				out[s] = append(out[s], strs...)
			}
		}
	}
	return out
}

// datPatterns reads the AT&T POSIX test files from GOROOT for their patterns and inputs.
func datPatterns(name string) map[string][]string {
	f, err := os.Open(filepath.Join(runtime.GOROOT(), "src/regexp/testdata", name))
	if err != nil {
		panic(err)
	}
	defer f.Close()
	out := map[string][]string{}
	sc := bufio.NewScanner(f)
	unescape := func(s string) string {
		u, err := strconv.Unquote(`"` + strings.ReplaceAll(s, `"`, `\"`) + `"`)
		if err != nil {
			return s
		}
		return u
	}
	last := ""
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		fields := slices.DeleteFunc(strings.Split(line, "\t"), func(s string) bool { return s == "" })
		if len(fields) < 3 {
			continue
		}
		p, in := fields[1], fields[2]
		if p == "SAME" {
			p = last
		}
		last = p
		if in == "NULL" {
			in = ""
		}
		p = unescape(p)
		out[p] = append(out[p], unescape(in))
	}
	return out
}

// adversarialPatterns target every place Go's syntax and Rust's differ, so a naive pass-through
// translation would fail here.
var adversarialPatterns = []string{
	`\d`, `\D`, `\w`, `\W`, `\s`, `\S`, `\b`, `\B`, `\bx\b`, `\Bx\B`, `\b\w+\b`, `[\d]`, `[\D]`, `[\w]`, `[\W]`, `[\s]`, `[\S]`, `[^\d]`, `[^\D]`, `[^\w]`, `[^\W]`, `[^\s]`, `[^\S]`, `[\d\s]`, `[\D\S]`, `[\w-]`, `[a\d]`, `[\db]`,
	`(?i)\d`, `(?i)\w`, `(?i)\W`, `(?i)\s`, `(?i)\S`, `(?i)[\w]`, `(?i)[\W]`, `(?i)[^\w]`, `(?i)[^\W]`, `(?i)k`, `(?i)K`, `(?i)\x{212a}`, `(?i)s`, `(?i)ſ`, `(?i)ß`, `(?i)ẞ`, `(?i)σ`, `(?i)ς`, `(?i)Σ`, `(?i)ı`, `(?i)i`, `(?i)İ`, `(?i)ǅ`, `(?i)å`, `(?i)Å`, `(?i)ω`, `(?i)Ω`, `(?i)\x{2126}`, `(?i)[k]`, `(?i)[^k]`, `(?i)[a-z]`, `(?i)[^a-z]`, `(?i)[A-Z]`, `(?i)[j-l]`, `(?i)[r-t]`, `(?i)[σ]`, `(?i)[^σ]`, `(?i)straße`, `(?i)STRASSE`,
	`[[:alpha:]]`, `[[:^alpha:]]`, `[[:digit:]]`, `[[:space:]]`, `[[:^space:]]`, `[[:word:]]`, `[[:^word:]]`, `[[:upper:]]`, `[[:lower:]]`, `(?i)[[:upper:]]`, `(?i)[[:lower:]]`, `(?i)[[:^upper:]]`, `[[:punct:]]`, `[[:cntrl:]]`, `[[:graph:]]`, `[[:print:]]`, `[[:xdigit:]]`, `[[:blank:]]`, `[[:ascii:]]`, `[[:alnum:]]`, `[[:alpha:]_]`, `[^[:alpha:]]`, `[[:foo:]]`, `[[:alpha]`, `[[:`, `[:alpha:]`,
	`\pL`, `\PL`, `\p{L}`, `\P{L}`, `\p{^L}`, `\P{^L}`, `\pN`, `\p{N}`, `\pM`, `\pP`, `\pS`, `\pZ`, `\pC`, `\p{Lu}`, `\p{Ll}`, `\p{Lt}`, `\p{Nd}`, `\p{Greek}`, `\P{Greek}`, `\p{Latin}`, `\p{Han}`, `\p{Cyrillic}`, `\p{Arabic}`, `\p{Common}`, `\p{Inherited}`, `\p{Any}`, `\P{Any}`, `\p{ascii}`, `\p{ASCII}`, `\p{Assigned}`, `\P{Assigned}`, `\p{LC}`, `\p{lc}`, `\p{Cn}`, `\p{letter}`, `\p{Letter}`, `\p{uppercase_letter}`, `\p{Decimal_Number}`, `\p{greek}`, `\p{GREEK}`, `\p{Foo}`, `\pX`, `\p`, `\p{`, `\p{}`, `\p{^}`, `\pé`, `\p{é}`,
	`(?i)\pL`, `(?i)\p{Lu}`, `(?i)\P{Lu}`, `(?i)\p{Ll}`, `(?i)\p{Greek}`, `(?i)\p{Latin}`, `(?i)\P{Latin}`, `(?i)\p{ascii}`, `(?i)\P{ascii}`, `(?i)\p{Any}`, `(?i)\p{Assigned}`, `(?i)[\p{Lu}]`, `(?i)[^\p{Lu}]`, `[\pL\pN]`, `[^\pL\pN]`, `[^\p{L}\p{N}]+`, `[\p{Greek}a]`, `[\P{Greek}]`, `[^\P{Greek}]`,
	`[a&&b]`, `[a--b]`, `[a~~b]`, `[a||b]`, `[[a]`, `[[a]b]`, `[a[b]`, `[]a]`, `[^]a]`, `[]]`, `[^]]`, `[]`, `[^]`, `[a-]`, `[-a]`, `[a-b-c]`, `[--a]`, `[+--]`, `[a\-z]`, `[\]]`, `[\[]`, `[\\]`, `[\^a]`, `[^^]`, `[z-a]`, `[é-ü]`, `[ü-é]`, `[\x{10000}-\x{10ffff}]`, `[\x00-\x{10ffff}]`, `[^\x00-\x{10ffff}]`, `[\x{d7ff}-\x{e000}]`, `[\x{d800}-\x{dfff}]`, `\x{d800}`, `[#]`, `[ ]`, `[&]`, `[~]`, `[a&]`, `[&&]`, `[~~]`, `[--]`, `[---]`, `[\b]`, `[\B]`, `[\A]`, `[\z]`, `[\Q]`, `[\C]`, `[\a\f\n\r\t\v]`, `[\1]`, `[\01]`, `[\123]`, `[\x41]`, `[\x{41}]`, `[\e]`, `[\_]`,
	`\<`, `\>`, `\<x\>`, `\-`, `\ `, `\/`, `\_`, `\:`, `\#`, `\&`, `\~`, `\@`, `\%`, `\!`, `\"`, "\\`", `\'`, `\,`, `\;`, `\=`, `\\`, `\.`, `\*`, `\+`, `\?`, `\(`, `\)`, `\[`, `\]`, `\{`, `\}`, `\|`, `\^`, `\$`, `\é`, `\日`, `\🎬`,
	`\a`, `\f`, `\t`, `\n`, `\r`, `\v`, `\e`, `\c`, `\g`, `\h`, `\i`, `\j`, `\k`, `\l`, `\m`, `\o`, `\q`, `\u`, `\y`, `\E`, `\F`, `\G`, `\H`, `\I`, `\J`, `\K`, `\L`, `\M`, `\N`, `\O`, `\R`, `\T`, `\U`, `\V`, `\X`, `\Y`, `\Z`, `\u0041`, `\u{41}`, `\U00000041`, `\C`, `\1`, `\9`, `\8`, `\0`, `\00`, `\000`, `\0000`, `\01`, `\12`, `\123`, `\1234`, `\377`, `\400`, `\777`, `\18`, `\x`, `\x4`, `\x41`, `\x4g`, `\xg4`, `\x{`, `\x{}`, `\x{41`, `\x{41}`, `\x{0041}`, `\x{g}`, `\x{110000}`, `\x{10ffff}`, `\x{ffffffff}`, `\`, `a\`, `[\`,
	`\Qa.b\E`, `\Q.*\E+`, `\Qab`, `\Q`, `\E`, `\Q\E`, `\Q\E*`, `a\Q\E*`, `\Q\\E`, `\Q\E\E`, `(?i)\Qab\E`, `\Qé\E`, `[\Qa\E]`,
	`(?i)a`, `(?-i)a`, `(?i-i)a`, `(?i:a)b`, `a(?i)b`, `a(?i:b)c`, `(?i)a(?-i)b`, `(?i)a|b`, `(a(?i)b)c`, `(?i)(a)(?-i)b`, `(?s).`, `(?-s).`, `(?s:.)x`, `(?m)^a`, `(?m)a$`, `(?m)^`, `(?m)$`, `(?m)^$`, `(?m:^a)b`, `^a`, `a$`, `^`, `$`, `^$`, `\Aa`, `a\z`, `\A`, `\z`, `(?m)\Aa`, `(?m)a\z`, `(?U)a+`, `(?U)a+?`, `(?U)a*`, `(?U)a??`, `(?U:a+)a`, `(?Ui)A+`, `(?ims)a`, `(?i-s)a`, `(?-ims)a`, `(?imsU-imsU)a`,
	`(?x)a b`, `(?x) a`, `(?u)a`, `(?R)a`, `(?-x)a`, `(?-u)a`, `(?i`, `(?`, `(?-`, `(?-)`, `(?i-)`, `(?--i)`, `(?i--)`, `(?:`, `(?)`, `(?a)`, `(?=a)`, `(?!a)`, `(?<=a)`, `(?<!a)`, `(?>a)`, `(?#c)`, `(?|a)`, `(?P=n)`, `(?P>n)`, `(?'n'a)`, `(?P<n>a)`, `(?<n>a)`, `(?P<n>a)(?P<n>b)`, `(?P<>a)`, `(?<>a)`, `(?P<n`, `(?<n`, `(?P<`, `(?<`, `(?P`, `(?P<1>a)`, `(?P<1a>a)`, `(?<1>a)`, `(?P<a1>a)`, `(?P<_>a)`, `(?P<a.b>a)`, `(?P<a[0]>a)`, `(?P<é>a)`, `(?P<n>a)|(?P<m>b)`, `(a)(?P<n>b)(c)`,
	`a*`, `a+`, `a?`, `a*?`, `a+?`, `a??`, `a**`, `a*+`, `a*?*`, `a+*`, `a++`, `a?+`, `a{2}*`, `a{2}+`, `a{2}{2}`, `a*{2}`, `a{2}?`, `a{2}??`, `a{2,3}`, `a{2,3}?`, `a{2,}`, `a{2,}?`, `a{0}`, `a{0,0}`, `a{0,}`, `a{1}`, `a{1,1}`, `(a{0})`, `(a){0}`, `(a|b){0}c`, `(a){0}(b)`, `(b)(a){0}(c)?`, `((a){0}b)`, `(?:(a)|(b)){0}(c)`, `(?:(a){0})*b`, `(a){0,0}`, `(?P<x>a){0}(?P<y>b)`, `(a){0}?`, `(?U)(a){0}`, `(?P<n>a)(?P<n>b)`, `(?P<n>a)|(?P<n>b)`, `*`, `+`, `?`, `{2}`, `{`, `}`, `{}`, `{,}`, `{,2}`, `a{`, `a{}`, `a{,}`, `a{,2}`, `a{2`, `a{2,`, `a{2,3`, `a{x}`, `a{2,x}`, `a{ 2}`, `a{2 }`, `a{02}`, `a{2,03}`, `a{00}`, `a{3,2}`, `a{1000}`, `a{1001}`, `a{0,1000}`, `a{0,1001}`, `a{1000,}`, `a{1001,}`, `a{100000000}`, `a{1000000000}`, `a{99999999999}`, `a{2,99999999999}`, `(a{1000})`, `(a{1000}){2}`, `(a{500}){2}`, `(a{501}){2}`, `(?:a{100}){10}`, `(?:a{100}){11}`, `((a{10}){10}){10}`, `((a{10}){10}){11}`, `(a{1000})*`, `(a*){1000}`, `(a{1000}|b){1000}`, `(?:a{2,}){1000}`, `(?:a{0}){1000}`, `(?:a{0,1}){1000}`, `(?:a?){1000}`, `\pL{1000}`, `.{1000}`,
	`a|*`, `(*)`, `(|*)`, `(+)`, `(?)`, `(?:*)`, `(?i)*`, `a(?i)*`, `a(?i)+?`, `a*(?i)*`, `^*`, `$*`, `\b*`, `\B+`, `^+`, `$?`, `(^)*`, `(?:^)*`, `\A*`, `\z{2}`, `(?m)^*`, `(?m)$+`, `\b{2}`, `\b{start}`, `\b{end}`, `\b{start-half}`, `\y`, `.{2}`, `(?s).{2}`,
	`(`, `)`, `()`, `(()`, `())`, `(a`, `a)`, `(a))`, `((a)`, `(|)`, `(||)`, `|`, `||`, `a|`, `|a`, `a||b`, `(a|)`, `(|a)`, `(|a)*`, `(|a)+`, `(a|)*`, `(a|)+`, `(?:|a)*`, `(?:a|)*`, `(a*)*`, `(a*)+`, `(a+)*`, `(a*?)*`, `(a*)*?`, `(a|b)*`, `(a*|b)*`, `(a|b*)*`, `(a*|b*)*`, `()*`, `()+`, `()?`, `(){2}`, `(?:)*`, `(?:)+`, `(?:)`, `(a?)*`, `(a?)+`, `(a??)*`, `(a?)*?`, `((a)|(b))+`, `((a)|b)+`, `(a)|(b)`, `(a)|b`, `a|(b)`, `(a)?`, `(a)?b`, `(a)*b`, `(a)??b`, `(?:(a)|b)*`, `(?:(a)|(b)|(c))+`, `(a|ab)(c|bcd)(d*)`, `(a+)(b+)?`, `(a*)(b*)`, `(.*)(.*)`, `(.*?)(.*)`, `(.+)(.+)`, `^(.*)$`, `(?s)^(.*)$`, `(?m)^(.*)$`, `.*`, `.+`, `.*?`, `.+?`, `(?s).*`,
	"é", "日本語", "🎬", "é+", "(?i)É", "[é]", "[^é]", "é|ü", "\t", "\n", " ", "#", "# comment", "a b", "a#b", "a\nb", "\u2028", "\ufffd", "\U0010ffff", "\u00a0", "&", "~", "-", "<", ">", "=", "!", "@", "%", "/", ",", ";", ":", "\"", "'", "_", "`",
	`(?i)(?:^|[^\p{L}\p{N}])s(?:eason)?[ ._-]*(\d{1,4})`, `^(?P<year>\d{4})-(?P<mon>\d{2})$`, `(?P<a>x)|(?P<b>y)`, `(?P<word>\w+)\s+(?P<num>\d+)`,
}

func genRegexp() regexpVector {
	r := newRand(7)
	v := regexpVector{Meta: newMeta(), CommonInputs: strs(commonInputs), Template: replaceTemplate}
	added := map[string]bool{}
	add := func(p, source string, extra []string) {
		if added[p] {
			return
		}
		added[p] = true
		v.Patterns = append(v.Patterns, patternEntry(p, source, extra))
	}
	for _, p := range treePatterns() {
		add(p, "tree", samplesFor(r, p, 4))
	}
	adversarialInputs := []string{"a b", "ab", "aa", "aaaa", "aaaaaa", "abab", "b", "bb", "c", "abc abc", "a&b", "a--b", "[a]", "[", "]", "-", "^", "&", "~", "<x>", "x y", "<", ">", "#", "1", "12", "123", "A1", "aA", "Aa", "\n", "a\n", "\nb", "a\nb\n", "a\r\nb", "x\ny", "é ü", "éa", "aé", "日a本", "K", "ſ", "σς", "ΣΑΣ", "İ", "ß", "SS", "ss", "straße", "STRASSE", "Ａ", "ａ", "a.b", "a*", "ab+", "\\", "\\Q", "{}", "{2}", "a{2}", "a{,2}", "a{", "{", "}", "a}", "(a)", "$1", "\x7f", "\u0085", "\u00a0", "\u2028", "\u3000", "١", "𐐀", "𐐨", "\U0001E900", "\U0001E922", "\u10D50", "\U00010D70", "\u1C89", "\uA7CB"}
	for _, p := range adversarialPatterns {
		add(p, "adversarial", append(samplesFor(r, p, 2), adversarialInputs...))
	}
	for _, name := range []string{"basic.dat", "nullsubexpr.dat", "repetition.dat"} {
		patterns := datPatterns(name)
		for _, p := range sortedKeys(patterns) {
			add(p, name, patterns[p])
		}
	}
	re2 := re2SearchPatterns()
	for _, p := range sortedKeys(re2) {
		add(p, "re2-search", re2[p])
	}
	// Go's height limit, around its boundary.
	for _, depth := range []int{10, 100, 250, 500, 998, 999, 1000, 1001, 1100} {
		add(strings.Repeat("(", depth)+"a"+strings.Repeat(")", depth), "limits", []string{"a", "b"})
		add(strings.Repeat("(?:", depth)+"a"+strings.Repeat(")", depth), "limits", []string{"a", "b"})
		add(strings.Repeat("(?:a|", depth)+"a"+strings.Repeat(")", depth), "limits", []string{"a", "b"})
		add(strings.Repeat("(a*", depth)+"a"+strings.Repeat(")", depth), "limits", []string{"a", "b"})
	}
	for _, s := range []string{"", "abc", `\.+*?()|[]{}^$`, "a.b", "(x)", "é.日", "a b", "-", "/", "#", "[]", "\\", "$1", "{2}", "^a$", "<&>"} {
		v.QuoteMeta = append(v.QuoteMeta, mapCase{S(s), S(regexp.QuoteMeta(s))})
	}
	for range 300 {
		s := randomAdversarial(r, 6)
		v.QuoteMeta = append(v.QuoteMeta, mapCase{S(s), S(regexp.QuoteMeta(s))})
	}
	return v
}
