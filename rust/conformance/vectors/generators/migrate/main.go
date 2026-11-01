//go:build migrate_harness

// Command migrate drives the real Go migration provider for the Rust migrator's exit gate, and
// writes vectors for the two private conversions in internal/database. The provider constructor is
// private, so build.sh adds a small export through a -overlay file.
//
//	migrate up                 database.RunMigrations
//	migrate up-to VERSION      provider.UpTo
//	migrate apply VERSION      provider.ApplyVersion, up
//	migrate down-to VERSION    database.MigrateDownTo
//	migrate status             database.PrintMigrationStatus
//	migrate vectors DIR        writes the conversion vectors
//
// DATABASE_URL names the database. Both the Go harness and the Rust one run from the same directory
// because the jsonschema error text stored in rejects embeds the working directory.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/Silo-Server/silo-server/internal/config"
	"github.com/Silo-Server/silo-server/internal/database"
	"github.com/Silo-Server/silo-server/migrations"
)

func die(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func main() {
	if len(os.Args) < 2 {
		die(fmt.Errorf("usage: migrate up|up-to|apply|down-to|vectors"))
	}
	if os.Args[1] == "vectors" {
		writeVectors(os.Args[2])
		return
	}
	ctx := context.Background()
	pool, err := database.NewPool(ctx, config.DatabaseConfig{URL: os.Getenv("DATABASE_URL"), MaxConnections: 20})
	if err != nil {
		die(err)
	}
	defer pool.Close()

	version := func() int64 {
		v, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			die(err)
		}
		return v
	}
	switch os.Args[1] {
	case "up":
		err = database.RunMigrations(ctx, pool, migrations.FS, "sql")
	case "up-to":
		provider, perr := database.ConformanceProvider(pool)
		if perr != nil {
			die(perr)
		}
		defer provider.Close()
		_, err = provider.UpTo(ctx, version())
	case "apply":
		provider, perr := database.ConformanceProvider(pool)
		if perr != nil {
			die(perr)
		}
		defer provider.Close()
		_, err = provider.ApplyVersion(ctx, version(), true)
	case "down-to":
		err = database.MigrateDownTo(ctx, pool, migrations.FS, "sql", version())
	case "status":
		err = database.PrintMigrationStatus(ctx, pool, migrations.FS, "sql", os.Stdout)
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		die(err)
	}
}

type repairCase struct {
	Video    string `json:"video"`
	Stored   string `json:"stored"`
	OK       bool   `json:"ok"`
	Err      string `json:"err"`
	Repaired string `json:"repaired"`
}

func writeVectors(dir string) {
	videos := []string{"/m/Movie.mkv", "/m/Movie.2024.mkv"}
	elements := []string{
		`{"path":"/m/Movie.sdh.en.srt","language":"sdh","hearing_impaired":false}`,
		`{"path":"/m/Movie.en.srt","language":"en","hearing_impaired":false}`,
		`{"path":"/m/Movie.en.srt","language":"en"}`,
		`{"path":"/m/Movie.fr.forced.srt","language":"fra","hearing_impaired":false,"forced":true,"codec":"subrip"}`,
		`{"path":"/m/Movie.hi.srt","language":"","hearing_impaired":true}`,
		`{"path":"/m/Other.en.srt","language":"xx","hearing_impaired":true}`,
		`{"path":"","language":"xx"}`,
		`{"language":"xx"}`,
		`{}`,
		`null`,
		`12`,
		`"text"`,
		`[1]`,
		`{"path":12,"language":"en"}`,
		`{"path":"/m/Movie.de.srt","language":12}`,
		`{"path":"/m/Movie.de.srt","hearing_impaired":"no"}`,
		`{"path":"/m/Movie.de.srt","language":null,"hearing_impaired":null}`,
		`{"Path":"/m/Movie.de.srt","LANGUAGE":"en"}`,
		`{"PATH":"/m/Movie.de.srt","path":"/m/Movie.fr.srt","language":"de"}`,
		`{"HEARING_IMPAIRED":true,"path":"/m/Movie.de.srt","language":"de"}`,
		`{"path":"/m/Movie.de.srt","language":"de","hearing_impaired":false,"note":"<&> ","n":1.50}`,
		`{"path":"/m/Movie.日本語.ja.srt","language":"ja"}`,
		`{"path":"/m/movie.PT-br.CC.srt","language":"pt","hearing_impaired":false}`,
	}
	var repairs []repairCase
	add := func(video, stored string) {
		out, ok, err := database.ConformanceRepair(video, []byte(stored))
		c := repairCase{Video: video, Stored: stored, OK: ok, Repaired: string(out)}
		if err != nil {
			c.Err = err.Error()
		}
		repairs = append(repairs, c)
	}
	for _, video := range videos {
		for _, element := range elements {
			add(video, "["+element+"]")
		}
		add(video, "["+elements[0]+","+elements[1]+","+elements[5]+","+elements[3]+"]")
	}
	for _, stored := range []string{`[]`, `{}`, `12`, `null`, `"x"`, `[`} {
		add("/m/Movie.mkv", stored)
	}

	stored := []string{
		"", "en", "eng", "English", "pt-br", "en-US", "zh-Hans", "sr-Latn", "fre", "ger", "spa", "und", "fil",
		"forced", "Монгол", "x-foo", "i-klingon", "ENG", "Portuguese (Brazil)", " en ", "en_US", "sdh", "cc",
	}
	rewrite, unparseable := database.ConformanceRewrites(stored)

	if err := os.MkdirAll(dir, 0o755); err != nil {
		die(err)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(map[string]any{
		"repairs":  repairs,
		"rewrites": map[string]any{"stored": stored, "rewrite": rewrite, "unparseable": unparseable},
	}); err != nil {
		die(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "conversions.json"), b.Bytes(), 0o644); err != nil {
		die(err)
	}
}
