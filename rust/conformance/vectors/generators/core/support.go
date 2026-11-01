//go:build core_vectors

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"hash/fnv"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/Silo-Server/silo-server/internal/playback"
)

func registerAll() {
	registerIDs()
	registerSecret()
	registerTokens()
	registerHashes()
	registerMore()
}

func encodeRaw(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func hmacOf(secret []byte, text string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(text))
	return h.Sum(nil)
}

func fnvNew32a() hash.Hash32 { return fnv.New32a() }

func reflectValue(p any) reflect.Value { return reflect.ValueOf(p).Elem() }

func marshalGo(v any) ([]byte, error) { return json.Marshal(v) }

type directPlayOut struct {
	Dev       uint64 `json:"dev"`
	Ino       uint64 `json:"ino"`
	CtimeSec  int64  `json:"ctime_sec"`
	CtimeNsec int64  `json:"ctime_nsec"`
	MtimeNano int64  `json:"mtime_nano"`
	Size      int64  `json:"size"`
	OS        string `json:"os"`
	ETag      string `json:"etag"`
	// Path is set only on Rust's output, naming the file it stat'ed.
	Path string `json:"path,omitempty"`
}

// directPlayCase writes a real file and reads its validator back. The file fields travel with it, because
// they differ on every run.
func directPlayCase(seed int) directPlayOut {
	dir, err := os.MkdirTemp("", "directplay")
	if err != nil {
		panic(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	path := filepath.Join(dir, "f")
	if err := os.WriteFile(path, make([]byte, seed%4096), 0o600); err != nil {
		panic(err)
	}
	f, err := os.Open(path)
	if err != nil {
		panic(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		panic(err)
	}
	out := statFields(info)
	out.ETag = playback.DirectPlayEntityTag(f, info)
	return out
}

// writeDirectPlay writes the directplay vector for this platform, to pin the Linux revision string from
// a Linux build run in a container.
func writeDirectPlay(path string) error {
	var b strings.Builder
	b.WriteString("{\n\"family\": \"playback_directplay_etag_linux\",\n\"source\": \"internal/playback DirectPlayEntityTag, Linux build\",\n\"cases\": [\n")
	for i := range 500 {
		raw, err := marshal(directPlayCase(i * 37))
		if err != nil {
			return err
		}
		sep := ","
		if i == 499 {
			sep = ""
		}
		fmt.Fprintf(&b, "{\"in\":%d,\"out\":%s}%s\n", i*37, raw, sep)
	}
	b.WriteString("]\n}\n")
	return os.WriteFile(path, []byte(b.String()), 0o644)
}
