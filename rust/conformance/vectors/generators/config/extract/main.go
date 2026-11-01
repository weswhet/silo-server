//go:build silo_config_vectors

// Command extract copies unexported startup readers out of packages the config generator cannot
// import: package main under cmd/silo, and packages whose closure needs libvips through cgo. It keeps
// their real source, not a hand copy. Run it from the repository root before the generator:
//
//	GOTOOLCHAIN=go1.26.7 go run -tags silo_config_vectors ./rust/conformance/vectors/generators/config/extract
package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type source struct {
	file  string
	decls []string
}

type spec struct {
	pkg     string
	sources []source
	imports []string
	exports map[string]string
}

var specs = []spec{
	{
		pkg: "xcmdsilo",
		sources: []source{
			{"cmd/silo/node_drain.go", []string{"nodeDrainTimeoutEnv", "defaultNodeDrainTimeout", "nodeDrainTimeout"}},
			{"cmd/silo/api_shutdown.go", []string{"apiShutdownDelayEnv", "defaultAPIShutdownDelay", "apiShutdownDelay", "maxDurationSeconds"}},
			{"cmd/silo/main.go", []string{"resolveNodeIdentity"}},
			{"cmd/silo/auth_command.go", []string{"authLocalLoginCommand", "authEnableAction", "authCommandUsage", "authCommand", "parseAuthCommand"}},
			{"cmd/silo/owner_command.go", []string{"ownerSetCommand", "ownerCommandUsage", "parseOwnerCommand"}},
			{"cmd/silo/main.go", []string{"applyBootstrapOverrides", "addRedisBootstrapSettings"}},
		},
		imports: []string{"errors", "flag", "io", "log/slog", "math", "os", "strconv", "strings", "time", "github.com/Silo-Server/silo-server/internal/config"},
		exports: map[string]string{
			"ApplyBootstrapOverrides":   "applyBootstrapOverrides",
			"AddRedisBootstrapSettings": "addRedisBootstrapSettings",
			"NodeDrainTimeout":          "nodeDrainTimeout",
			"APIShutdownDelay":          "apiShutdownDelay",
			"ResolveNodeIdentity":       "resolveNodeIdentity",
			"ParseOwnerCommand":         "parseOwnerCommand",
		},
	},
	{
		pkg: "xcatalog",
		sources: []source{{"internal/catalog/search_env.go", []string{
			"EnvSearchProvider", "EnvMeilisearchURL", "EnvMeilisearchAPIKey",
			"searchSettingEnvVars", "SearchSettingsFromEnv",
		}}, {"internal/catalog/search_provider.go", []string{
			"SearchSettingProvider", "SearchSettingMeilisearchURL", "SearchSettingMeilisearchAPIKey",
		}}},
		imports: []string{"fmt", "strings", "github.com/Silo-Server/silo-server/internal/config"},
	},
	{
		pkg:     "xmetadata",
		sources: []source{{"internal/metadata/match_confidence.go", []string{"minTitleScore", "matchThreshold"}}},
		imports: []string{"math", "os", "strconv", "strings"},
		exports: map[string]string{"MatchThreshold": "matchThreshold"},
	},
	{
		pkg: "xebooks",
		sources: []source{
			{"internal/ebooks/enrichment.go", []string{"defaultEnrichWorkers", "maxEnrichWorkers", "ebookEnrichWorkers"}},
			{"internal/ebooks/enrichment_queue.go", []string{"defaultRateLimitCooldown", "rateLimitCooldownEnv", "rateLimitCooldownFloor"}},
		},
		imports: []string{"os", "strconv", "time"},
		exports: map[string]string{"EnrichWorkers": "ebookEnrichWorkers", "RateLimitCooldownFloor": "rateLimitCooldownFloor"},
	},
	{
		pkg:     "xaudiobooks",
		sources: []source{{"internal/audiobooks/enrichment.go", []string{"defaultEnrichBatchSize", "defaultEnrichWorkers", "audiobookEnrichBatchSize", "audiobookEnrichWorkers"}}},
		imports: []string{"os", "strconv"},
		exports: map[string]string{"EnrichBatchSize": "audiobookEnrichBatchSize", "EnrichWorkers": "audiobookEnrichWorkers"},
	},
	{
		pkg:     "xmanga",
		sources: []source{{"internal/manga/enrichment.go", []string{"defaultEnrichBatchSize", "defaultEnrichWorkers", "mangaEnrichWorkers", "mangaEnrichBatchSize"}}},
		imports: []string{"os", "strconv"},
		exports: map[string]string{"EnrichBatchSize": "mangaEnrichBatchSize", "EnrichWorkers": "mangaEnrichWorkers"},
	},
	{
		pkg: "xscanner",
		sources: []source{
			{"internal/scanner/ebook_scan.go", []string{"ebookScanWorkers"}},
			{"internal/scanner/audiobook_scan.go", []string{"audiobookScanWorkers"}},
		},
		imports: []string{"os", "strconv"},
		exports: map[string]string{"EbookScanWorkers": "ebookScanWorkers", "AudiobookScanWorkers": "audiobookScanWorkers"},
	},
	{
		pkg: "xtasks",
		sources: []source{{"internal/taskmanager/tasks/sync_ebook_metadata.go", []string{
			"ebookBackfillMaxClaimsEnv", "ebookBackfillBatchDelayEnv", "parseEbookBackfillMaxClaims", "parseEbookBackfillBatchDelay",
		}}},
		imports: []string{"fmt", "strconv", "strings", "time"},
		exports: map[string]string{"MaxClaims": "parseEbookBackfillMaxClaims", "BatchDelay": "parseEbookBackfillBatchDelay"},
	},
	{
		pkg:     "xhttpstream",
		sources: []source{{"internal/httpstream/rolling_deadline.go", []string{"DefaultStallWindow", "stallWindowEnv", "StallWindow"}}},
		imports: []string{"os", "strconv", "time"},
	},
}

func main() {
	for _, s := range specs {
		if err := emit(s); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
}

func emit(s spec) error {
	var body bytes.Buffer
	for _, src := range s.sources {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, src.file, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		found := map[string]bool{}
		for _, d := range file.Decls {
			switch decl := d.(type) {
			case *ast.FuncDecl:
				if decl.Recv == nil && slices.Contains(src.decls, decl.Name.Name) {
					found[decl.Name.Name] = true
					decl.Doc = nil
					if err := printer.Fprint(&body, fset, decl); err != nil {
						return err
					}
					body.WriteString("\n\n")
				}
			case *ast.GenDecl:
				for _, sp := range decl.Specs {
					switch ts := sp.(type) {
					case *ast.ValueSpec:
						if len(ts.Names) == 1 && slices.Contains(src.decls, ts.Names[0].Name) {
							found[ts.Names[0].Name] = true
							ts.Doc, ts.Comment = nil, nil
							body.WriteString(decl.Tok.String() + " ")
							if err := printer.Fprint(&body, fset, ts); err != nil {
								return err
							}
							body.WriteString("\n\n")
						}
					case *ast.TypeSpec:
						if slices.Contains(src.decls, ts.Name.Name) {
							found[ts.Name.Name] = true
							body.WriteString("type ")
							if err := printer.Fprint(&body, fset, ts); err != nil {
								return err
							}
							body.WriteString("\n\n")
						}
					}
				}
			}
		}
		for _, name := range src.decls {
			if !found[name] {
				return fmt.Errorf("%s: %s not found", src.file, name)
			}
		}
	}
	names := make([]string, 0, len(s.exports))
	for name := range s.exports {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&body, "var %s = %s\n", name, s.exports[name])
	}
	if s.pkg == "xcmdsilo" {
		// The struct is unexported, so hand back its fields.
		body.WriteString(`
func ParseAuthCommand(args []string) (envFile, user string, temporary bool, err error) {
	cmd, err := parseAuthCommand(args)
	return cmd.envFile, cmd.user, cmd.temporaryPassword, err
}
`)
	}
	var out bytes.Buffer
	out.WriteString("//go:build silo_config_vectors\n\n")
	out.WriteString("// Code generated by generators/config/extract from the Go sources it names. DO NOT EDIT.\n\n")
	fmt.Fprintf(&out, "package %s\n\nimport (\n", s.pkg)
	used := body.String()
	for _, imp := range s.imports {
		base := imp[strings.LastIndex(imp, "/")+1:]
		if base == "slog" {
			base = "slog"
		}
		if strings.Contains(used, base+".") {
			fmt.Fprintf(&out, "\t%q\n", imp)
		}
	}
	out.WriteString(")\n\n")
	out.Write(body.Bytes())
	formatted, err := format.Source(out.Bytes())
	if err != nil {
		return fmt.Errorf("%s: %w\n%s", s.pkg, err, out.String())
	}
	dir := filepath.Join("rust/conformance/vectors/generators/config/extracted", s.pkg)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "extracted.go"), formatted, 0o644)
}
