//go:build goose_vectors

// Command goose writes parser vectors from goose's real internal/sqlparser. That package is internal
// to goose, so run.sh compiles its parser.go into this program through a -overlay file:
//
//	rust/conformance/vectors/generators/goose/run.sh
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/Silo-Server/silo-server/migrations"
)

const outDir = "rust/conformance/vectors/goose"

type digest struct {
	File  string `json:"file"`
	UseTx bool   `json:"use_tx"`
	Up    string `json:"up_sha256"`
	UpN   int    `json:"up_count"`
	Down  string `json:"down_sha256"`
	DownN int    `json:"down_count"`
}

type literal struct {
	Name  string   `json:"name"`
	Input string   `json:"input"`
	Up    []string `json:"up"`
	UpErr string   `json:"up_err"`
	Down  []string `json:"down"`
	DnErr string   `json:"down_err"`
	UseTx bool     `json:"use_tx"`
}

func hash(stmts []string) string {
	h := sha256.New()
	for _, s := range stmts {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func parse(contents string, up bool) ([]string, bool, string) {
	direction := DirectionDown
	if up {
		direction = DirectionUp
	}
	stmts, useTx, err := ParseSQLMigration(strings.NewReader(contents), direction, false)
	if err != nil {
		return nil, false, err.Error()
	}
	if stmts == nil {
		stmts = []string{}
	}
	return stmts, useTx, ""
}

func lit(name, input string) literal {
	up, useTx, upErr := parse(input, true)
	down, _, downErr := parse(input, false)
	return literal{name, input, up, upErr, down, downErr, useTx}
}

func main() {
	entries, err := migrations.FS.ReadDir("sql")
	if err != nil {
		panic(err)
	}
	digests := make([]digest, 0, len(entries))
	for _, entry := range entries {
		body, err := migrations.FS.ReadFile("sql/" + entry.Name())
		if err != nil {
			panic(err)
		}
		up, useTx, upErr := parse(string(body), true)
		down, _, downErr := parse(string(body), false)
		if upErr != "" || downErr != "" {
			panic(entry.Name() + ": " + upErr + downErr)
		}
		digests = append(digests, digest{entry.Name(), useTx, hash(up), len(up), hash(down), len(down)})
	}

	literals := []literal{
		lit("empty", ""),
		lit("blank only", "\n\n  \n"),
		lit("no up", "SELECT 1;\n"),
		lit("comment only", "-- nothing\n"),
		lit("up only", "-- +goose Up\nSELECT 1;\n"),
		lit("up and down", "-- +goose Up\nSELECT 1;\n-- +goose Down\nSELECT 2;\n"),
		lit("two ups", "-- +goose Up\n-- +goose Up\n"),
		lit("down first", "-- +goose Down\nSELECT 1;\n"),
		lit("unfinished up", "-- +goose Up\nSELECT 1\n-- +goose Down\nSELECT 2;\n"),
		lit("unfinished at eof", "-- +goose Up\nSELECT 1\n"),
		lit("trailing comment after semicolon", "-- +goose Up\nSELECT 1; -- done\nSELECT 2 -- not; done\n;\n"),
		lit("semicolon in comment only", "-- +goose Up\nSELECT 1 -- a;\n, 2;\n"),
		lit("comment glued to semicolon", "-- +goose Up\nSELECT 1;--done\nSELECT 2;\n"),
		lit("leading comments dropped", "-- +goose Up\n-- one\n\n-- two\nSELECT 1;\n"),
		lit("inner comments kept", "-- +goose Up\nSELECT\n-- inner\n1;\n"),
		lit("statement block", "-- +goose Up\n-- +goose StatementBegin\nCREATE FUNCTION f() AS $$\nBEGIN\n  x;\nEND;\n$$;\n-- +goose StatementEnd\n-- +goose Down\nDROP FUNCTION f;\n"),
		lit("block without end", "-- +goose Up\n-- +goose StatementBegin\nSELECT 1;\n"),
		lit("end without begin", "-- +goose Up\n-- +goose StatementEnd\n"),
		lit("begin before up", "-- +goose StatementBegin\nSELECT 1;\n-- +goose StatementEnd\n"),
		lit("no transaction", "-- +goose NO TRANSACTION\n-- +goose Up\nCREATE INDEX CONCURRENTLY a ON b (c);\nCREATE INDEX CONCURRENTLY d ON e (f);\n"),
		lit("no transaction after up", "-- +goose Up\n-- +goose NO TRANSACTION\nSELECT 1;\n"),
		lit("annotation case", "-- +GOOSE UP\nSELECT 1;\n"),
		lit("annotation mixed case", "-- +goose uP\n-- +goose statementbegin\nSELECT 1;\n-- +goose STATEMENTEND\n"),
		lit("unknown annotation", "-- +goose Sideways\n"),
		lit("empty annotation", "-- +goose\n"),
		lit("two gooses", "-- +goose Up +goose\n"),
		lit("indented annotation", "  -- +goose Up\n"),
		lit("no space annotation", "--+goose Up\nSELECT 1;\n"),
		lit("dashes in annotation", "-- +goose -- Up\nSELECT 1;\n"),
		lit("not an annotation", "-- +goose Up\nSELECT '+goose';\n"),
		lit("crlf", "-- +goose Up\r\nSELECT 1;\r\n-- +goose Down\r\nSELECT 2;\r\n"),
		lit("no final newline", "-- +goose Up\nSELECT 1;"),
		lit("unicode space before semicolon", "-- +goose Up\nSELECT 1 ;\n"),
		lit("semicolon then unicode space", "-- +goose Up\nSELECT 1;　\n"),
		lit("blank line inside statement", "-- +goose Up\nSELECT\n\n1;\n"),
		lit("whitespace line in up", "-- +goose Up\n   \nSELECT 1;\n"),
		lit("block then simple", "-- +goose Up\n-- +goose StatementBegin\nA;\nB;\n-- +goose StatementEnd\nC;\n-- +goose Down\nD;\n"),
		lit("comment in block", "-- +goose Up\n-- +goose StatementBegin\n-- leading\nA;\n-- trailing\n-- +goose StatementEnd\n"),
		lit("empty block", "-- +goose Up\n-- +goose StatementBegin\n-- +goose StatementEnd\n"),
		lit("down then up", "-- +goose Up\nA;\n-- +goose Down\nB;\n-- +goose Up\nC;\n"),
		lit("second down", "-- +goose Up\nA;\n-- +goose Down\nB;\n-- +goose Down\nC;\n"),
	}

	// goose's own corpus, in its module.
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/pressly/goose/v3").Output()
	if err != nil {
		panic(err)
	}
	testdata := filepath.Join(strings.TrimSpace(string(out)), "internal/sqlparser/testdata")
	var corpus []string
	err = filepath.WalkDir(testdata, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".sql") {
			corpus = append(corpus, path)
		}
		return nil
	})
	if err != nil {
		panic(err)
	}
	sort.Strings(corpus)
	for _, path := range corpus {
		body, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}
		rel, _ := filepath.Rel(testdata, path)
		literals = append(literals, lit("goose testdata "+filepath.ToSlash(rel), string(body)))
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		panic(err)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(map[string]any{"files": digests, "literals": literals}); err != nil {
		panic(err)
	}
	if err := os.WriteFile(filepath.Join(outDir, "statements.json"), b.Bytes(), 0o644); err != nil {
		panic(err)
	}
	fmt.Printf("%d files, %d literals\n", len(digests), len(literals))
}
