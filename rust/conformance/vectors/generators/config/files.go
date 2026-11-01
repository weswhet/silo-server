//go:build silo_config_vectors

package main

import (
	"encoding/hex"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/joho/godotenv"

	"github.com/Silo-Server/silo-server/internal/config"
	xcmdsilo "github.com/Silo-Server/silo-server/rust/conformance/vectors/generators/config/extracted/xcmdsilo"
)

type yamlVector struct {
	Doc   string            `json:"doc"`
	Map   map[string]string `json:"map,omitempty"`
	Error string            `json:"error,omitempty"`
}

func writeYAMLVectors() {
	docs := []string{
		"", "---\n", "# just a comment\n", "null\n", "~\n", "42\n", "text\n", "- a\n- b\n", "{}\n", "server: {}\n", "server: null\n", "server: 5\n", "server: [a]\n",
		"server:\n  listen: ':9'\n  mode: api\n  log_level: debug\n  log_format: json\n  log_quiet: 'a,b'\n  public_url: http://x\n  lan_discovery: false\n",
		"server:\n  listen: 9090\n  mode: true\n  log_level: 1.5\n  log_quiet: 2001-01-01\n",
		"server:\n  listen: null\n  mode: ~\n  log_level: ''\n  log_format: \"\"\n",
		"server:\n  listen: [a]\n", "server:\n  listen: {a: b}\n",
		"database:\n  url: postgres://x\n  max_connections: 7\n", "database:\n  max_connections: 0\n", "database:\n  max_connections: abc\n", "database:\n  max_connections: 1.9\n", "database:\n  max_connections: '5'\n", "database:\n  max_connections: 0x10\n", "database:\n  max_connections: 0o10\n", "database:\n  max_connections: 010\n", "database:\n  max_connections: 0b11\n", "database:\n  max_connections: 1_000\n", "database:\n  max_connections: true\n", "database:\n  max_connections: null\n", "database:\n  max_connections: 18446744073709551615\n", "database:\n  max_connections: 1e3\n", "database:\n  max_connections: .inf\n", "database:\n  max_connections: .nan\n", "database:\n  max_connections: -.inf\n", "database:\n  max_connections: 2001-01-01\n", "database:\n  max_connections: !!str 5\n", "database:\n  max_connections: !!int abc\n", "database:\n  max_connections: !!float 3\n",
		"s3:\n  public_endpoint: https://p\n  public_read_endpoint: https://r\n  public_region: r\n  public_path_style: false\n  public_bucket: b\n  public_key_prefix: k\n  public_access_key: a\n  public_secret_key: s\n  public_url_auth: public\n  public_token_secret: t\n  public_token_param: q\n  public_token_ttl: 60\n  metadata_presign_expiry: 1h\n",
		"s3:\n  private_endpoint: https://p\n  private_region: r\n  private_path_style: false\n  private_bucket: b\n  private_key_prefix: k\n  private_access_key: a\n  private_secret_key: s\n  user_db_endpoint: e\n  user_db_region: r\n  user_db_path_style: false\n  user_db_bucket: b\n  user_db_key_prefix: k\n  user_db_access_key: a\n  user_db_secret_key: s\n",
		"s3:\n  operational_endpoint: https://o\n  operational_public_endpoint: https://op\n  operational_region: r\n  operational_path_style: false\n  operational_bucket: b\n  operational_key_prefix: k\n  operational_access_key: a\n  operational_secret_key: s\n  operational_url_auth: u\n  operational_token_secret: t\n  operational_token_param: p\n  operational_token_ttl: 9\n",
		"s3:\n  operational_path_style: false\n", "s3:\n  metadata_presign_expiry: ''\n  operational_path_style: false\n", "s3:\n  metadata_presign_expiry: ''\n  operational_bucket: b\n  operational_path_style: false\n  private_bucket: p\n",
		"s3:\n  public_token_ttl: -1\n  operational_token_ttl: -1\n", "s3:\n  public_path_style: maybe\n",
		"user_db:\n  backend: sqlite\n  pool_max_open: 0\n  idle_timeout: 1h\n  litestream_sync: 2s\n  stale_grace_seconds: 0\n", "user_db:\n  backend: ''\n  idle_timeout: ''\n",
		"scanner:\n  workers: 0\n  max_concurrent_libraries: 0\n  max_concurrent_scoped: 0\n  file_removal_grace: 1h\n  empty_trash_after_scan: yes\n  realtime_monitoring: no\n",
		"scanner:\n  empty_trash_after_scan: Yes\n", "scanner:\n  empty_trash_after_scan: y\n  realtime_monitoring: n\n", "scanner:\n  empty_trash_after_scan: on\n  realtime_monitoring: off\n", "scanner:\n  empty_trash_after_scan: TRUE\n  realtime_monitoring: False\n", "scanner:\n  empty_trash_after_scan: 1\n", "scanner:\n  empty_trash_after_scan: 'true'\n", "scanner:\n  empty_trash_after_scan: maybe\n", "scanner:\n  realtime_monitoring: null\n", "scanner:\n  realtime_monitoring: [a]\n",
		"artwork:\n  storage_backend: s3\n  local_path: /a\n", "artwork:\n  storage_backend: ''\n  local_path: ''\n",
		"matcher:\n  workers: 0\n  batch_size: 0\n  enable_tv_series_root_queue: false\n", "matcher:\n  enable_tv_series_root_queue: false\n  enable_tv_series_group_queue: true\n", "matcher:\n  workers: 2\n  batch_size: 3\n",
		"playback:\n  ffmpeg_path: /f\n  transcode_dir: /t\n  segment_retention_seconds: 0\n  hw_accel: qsv\n  hw_device: /d\n  chapter_thumbnail_workers: 0\n  chapter_thumbnail_execution: x\n  chapter_thumbnail_node_capacity: 0\n  transcode_enabled: false\n  routing: x\n",
		"redis:\n  url: redis://h:1\n", "redis:\n  url: ''\n", "rate_limiting:\n  enabled: false\n  backend: redis\n", "rate_limiting:\n  backend: ''\n",
		"auth:\n  jwt_secret: s\n  access_token_expiry: 1h\n  refresh_token_expiry: 2h\n", "auth:\n  access_token_expiry: ''\n  refresh_token_expiry: ''\n",
		"jellyfin_compat:\n  enabled: true\n", "jellyfin_compat:\n  enabled: false\n", "jellyfin_compat:\n  listen: ''\n", "jellyfin_compat:\n  listen: ':1'\n  public_url: u\n  emulated_server_version: v\n  server_id: i\n  server_name: n\n  web_enabled: false\n  web_version: w\n  web_dir: d\n  web_install_dir: id\n  session_ttl: 1h\n  playback_session_ttl: 2h\n", "jellyfin_compat:\n  enabled: null\n",
		"unknown_section:\n  a: 1\nserver:\n  unknown_key: x\n",
		"server:\n  listen: ':1'\n  listen: ':2'\n", "server:\n  mode: api\nserver:\n  mode: proxy\n",
		"base: &b\n  listen: ':7'\n  mode: api\nserver: *b\n", "base: &b\n  listen: ':7'\nserver:\n  <<: *b\n  mode: proxy\n", "base: &b\n  listen: ':7'\nserver:\n  listen: ':8'\n  <<: *b\n", "a: &a\n  listen: ':1'\nb: &b\n  mode: x\nserver:\n  <<: [*a, *b]\n", "server:\n  <<: 5\n", "server:\n  <<: [5]\n", "x: &x 5\nserver:\n  <<: *x\n", "x: &x ':3'\nserver:\n  listen: *x\n",
		"? server\n: mode: api\n", "1: x\ntrue: y\nnull: z\n", "'server': {'mode': 'api'}\n", "{server: {mode: api, listen: ':5'}}\n", "server: {mode: api\n", "server:\n\tmode: api\n", "a: b: c\n", "server: *unknown\n", "- [\n", "---\nserver:\n  mode: first\n---\nserver:\n  mode: second\n", "---\nserver:\n  mode: first\n...\n---\n{bad\n",
		"server:\n  mode: !!binary YXBp\n", "server:\n  mode: !!binary '!!'\n", "server:\n  mode: !custom api\n", "server:\n  mode: !!str 5\n", "server:\n  mode: |\n    multi\n    line\n", "server:\n  mode: >\n    folded\n    line\n", "server:\n  listen: 0x10\n  mode: 010\n  log_level: 1_000\n  log_format: 1e3\n  log_quiet: .5\n  public_url: ~x\n",
		"database:\n  max_connections: 12345678901\n  url: 'a very long string value here'\n", "database:\n  max_connections: 'a very long string value here'\n", "database: 'a very long string value here'\n",
	}
	dir, err := os.MkdirTemp("", "silo-yaml-vectors")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "silo.yaml")
	out := make([]yamlVector, 0, len(docs))
	for _, d := range docs {
		if err := os.WriteFile(path, []byte(d), 0o644); err != nil {
			panic(err)
		}
		m, yerr := config.YAMLToSettingsMap(path)
		vec := yamlVector{Doc: d, Map: m}
		if yerr != nil {
			vec.Error = yerr.Error()
		}
		out = append(out, vec)
	}
	write("yaml_import.json", out)
}

type dotenvVector struct {
	In    string            `json:"in"`
	InHex string            `json:"in_hex"`
	Out   map[string]string `json:"out,omitempty"`
	Error string            `json:"error,omitempty"`
}

func writeDotenvVectors() {
	in := []string{
		"", "\n", "   \n\t\n", "# c\n", "A=1", "A=1\n", "A=1\r\nB=2\r\n", "A = 1\n", " A=1\n", "export A=1\n", "exportA=1\n", "export  A=1\n", "export\tA=1\n", "A:1\n", "A: 1\n", "A=\n", "A=\nB=2\n", "A=  \nB=2\n", "A= # c\nB=2\n",
		"A=1 # c\n", "A=1# c\n", "A=1 #\n", "A=#x\n", "A='1 # c'\n", "A=\"1 # c\"\n", "A='a'b\n", "A='it''s'\n", "A=\"x\\\"y\"\n", "A='x\\'y'\n", "A=\"a\\nb\\rc\\td\"\n", "A='a\\nb'\n", "A=a\\nb\n", "A=\"\\$B\"\n",
		"B=2\nA=$B\n", "B=2\nA=${B}\n", "B=2\nA=$(B)\n", "B=2\nA=\"$B\"\n", "B=2\nA='$B'\n", "A=$UNSET\n", "A=x${UNSET}y\n", "b=2\nA=$b\n", "A=$\n", "A=\\$B\n", "B=2\nA=\\$B\n", "B=2\nA=\"\\${B}\"\n", "A=$$\n", "B=2\nA=$B$B\n", "A=${}\n", "B=2\nA=${B\n",
		"A=\"multi\nline\"\n", "A='multi\nline'\n", "A=\"unterminated\n", "A='unterminated\n", "A=\"\n", "A=''\n", "A=\"\"\n", "A=''x\n", "A=\"\"\"\n",
		"FOO\n", "FOO", "FOO BAR=1\n", "FOO-BAR=1\n", "FOO.BAR=1\n", "FOO_BAR=1\n", "_A=1\n", "1A=1\n", "=1\n", ":1\n", "A==1\n", "A=1=2\n", "A:B:C\n", "é=1\n", "A=é\n", "A=日本語\n", "日本=1\n", "A=\xff\n", "A='\xff'\n", "\xffA=1\n", "A=1\x85\n", "A=1\xa0\n", "A\xa0=1\n",
		"A=1\nA=2\n", "# only\n# comments", "A=1 \n", "\tA=1\t\n", "A=\t1\n", "A=\"1\" trailing\nB=2\n", "A='1' # c\nB=2\n", "export\n", "export=1\n", "export A\n", "A=1\rB=2\n", "A=x\x00y\n",
	}
	out := make([]dotenvVector, 0, len(in))
	for _, v := range in {
		m, err := godotenv.UnmarshalBytes([]byte(v))
		vec := dotenvVector{In: v, InHex: hex.EncodeToString([]byte(v)), Out: m}
		if err != nil {
			vec.Out = nil
			vec.Error = err.Error()
		}
		out = append(out, vec)
	}
	write("dotenv.json", out)
}

type flagVector struct {
	Args  []string `json:"args"`
	Ok    string   `json:"ok,omitempty"`
	Error string   `json:"error,omitempty"`
}

func serverFlags(args []string) flagVector {
	flags := flag.NewFlagSet("silo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	envFile := flags.String("env", ".env", "")
	migrateOnly := flags.Bool("migrate-only", false, "")
	migrateStatus := flags.Bool("migrate-status", false, "")
	migrateDownTo := flags.Int64("migrate-down-to", -1, "")
	vec := flagVector{Args: args}
	if err := flags.Parse(args); err != nil {
		vec.Error = err.Error()
		return vec
	}
	rest := flags.Args()
	if rest == nil {
		rest = []string{}
	}
	vec.Ok = goJSON(map[string]any{"env": *envFile, "migrate_only": *migrateOnly, "migrate_status": *migrateStatus, "migrate_down_to": *migrateDownTo, "args": rest})
	return vec
}

// compatWebFlags is runCompatWebCommand up to its dispatch, with the real flag package.
func compatWebFlags(args []string) flagVector {
	vec := flagVector{Args: args}
	if len(args) == 0 {
		vec.Error = "usage: silo compat-web {status|install|update|remove}"
		return vec
	}
	command := args[0]
	flags := flag.NewFlagSet("compat-web "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("dir", config.DefaultJellyfinWebInstallDir, "")
	version := flags.String("version", config.DefaultJellyfinWebVersion, "")
	source := flags.String("source", jellycompatDefaultWebSourceURL, "")
	if err := flags.Parse(args[1:]); err != nil {
		vec.Error = err.Error()
		return vec
	}
	switch command {
	case "status", "install", "update", "remove":
		vec.Ok = goJSON(map[string]string{"command": command, "dir": *root, "version": *version, "source": *source})
	default:
		vec.Error = "unknown compat-web command " + strconv.Quote(command)
	}
	return vec
}

// jellycompat.DefaultWebSourceURL. That package needs libvips through cgo, so it cannot be imported.
const jellycompatDefaultWebSourceURL = "https://github.com/jellyfin/jellyfin-web.git"

func writeFlagVectors() {
	server := [][]string{
		{}, {"-env", "x.env"}, {"--env", "x.env"}, {"-env=x.env"}, {"--env=x.env"}, {"-env"}, {"-env="}, {"-migrate-only"}, {"--migrate-only"}, {"-migrate-only=true"}, {"-migrate-only=false"}, {"-migrate-only=0"}, {"-migrate-only=T"}, {"-migrate-only=maybe"}, {"-migrate-only", "false"},
		{"-migrate-status"}, {"-migrate-down-to", "5"}, {"-migrate-down-to=5"}, {"-migrate-down-to", "x"}, {"-migrate-down-to", "0x10"}, {"-migrate-down-to", "010"}, {"-migrate-down-to", "1_000"}, {"-migrate-down-to", "-3"}, {"-migrate-down-to=99999999999999999999"}, {"-migrate-down-to"},
		{"positional"}, {"positional", "-env", "x"}, {"-env", "x", "positional", "more"}, {"--", "-env", "x"}, {"-"}, {"---env"}, {"-=x"}, {"--=x"}, {"-nope"}, {"-nope=1"}, {"-h"}, {"-help"}, {"--help"}, {"-h=1"}, {"-env", "a", "-env", "b"}, {"-migrate-only", "-migrate-status", "-env", "y"},
	}
	sv := make([]flagVector, 0, len(server))
	for _, a := range server {
		sv = append(sv, serverFlags(a))
	}
	auth := [][]string{{}, {"local-login"}, {"local-login", "enable"}, {"local-login", "disable"}, {"other", "enable"}, {"local-login", "enable", "-user", " bob "}, {"local-login", "enable", "-user", "bob", "-temporary-password"}, {"local-login", "enable", "-temporary-password"}, {"local-login", "enable", "-user", " ", "-temporary-password"}, {"local-login", "enable", "-env", "x"}, {"local-login", "enable", "extra"}, {"local-login", "enable", "-nope"}, {"local-login", "enable", "-temporary-password=false", "-user=a"}, {"local-login", "enable", "-h"}}
	av := make([]flagVector, 0, len(auth))
	for _, a := range auth {
		env, user, temp, err := xcmdsilo.ParseAuthCommand(a)
		vec := flagVector{Args: a}
		if err != nil {
			vec.Error = err.Error()
		} else {
			vec.Ok = goJSON(map[string]any{"env_file": env, "user": user, "temporary_password": temp})
		}
		av = append(av, vec)
	}
	owner := [][]string{{}, {"get"}, {"set"}, {"set", "bob"}, {"set", "-env", "x", "bob"}, {"set", "bob", "-env", "x"}, {"set", ""}, {"set", "a", "b"}, {"set", "-nope", "a"}, {"set", "-env=x", "a"}, {"set", "--", "-weird"}}
	ov := make([]flagVector, 0, len(owner))
	for _, a := range owner {
		env, name, err := xcmdsilo.ParseOwnerCommand(a)
		vec := flagVector{Args: a}
		if err != nil {
			vec.Error = err.Error()
		} else {
			vec.Ok = goJSON([]string{env, name})
		}
		ov = append(ov, vec)
	}
	web := [][]string{{}, {"status"}, {"install"}, {"update"}, {"remove"}, {"bogus"}, {"status", "-dir", "/d", "-version", "9", "-source", "http://s"}, {"status", "--dir=/d"}, {"status", "-nope"}, {"bogus", "-nope"}, {"status", "extra"}, {"status", "-dir"}, {"status", "-h"}}
	wv := make([]flagVector, 0, len(web))
	for _, a := range web {
		wv = append(wv, compatWebFlags(a))
	}
	write("flags.json", map[string]any{"server": sv, "auth": av, "owner": ov, "compat_web": wv})
}
