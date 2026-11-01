//go:build core_vectors

package main

import (
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sony/sonyflake/v2"

	"github.com/Silo-Server/silo-server/internal/apiv2"
	"github.com/Silo-Server/silo-server/internal/artworkkey"
	"github.com/Silo-Server/silo-server/internal/artworkurl"
	"github.com/Silo-Server/silo-server/internal/contentid"
	"github.com/Silo-Server/silo-server/internal/fspath"
	"github.com/Silo-Server/silo-server/internal/idgen"
	"github.com/Silo-Server/silo-server/internal/jellycompat"
	"github.com/Silo-Server/silo-server/internal/lantls"
	"github.com/Silo-Server/silo-server/internal/nodeauth"

	"context"

	"github.com/Silo-Server/silo-server/internal/access"
)

func registerIDs() {
	type providerIn struct {
		Tmdb, Imdb, Tvdb S
		Season, Episode  int
	}
	type providerOut struct {
		Movie, Series, Season, Episode *string
		SeriesAnchor                   []string
	}
	optional := func(v string, ok bool) *string {
		if !ok {
			return nil
		}
		return &v
	}
	det("contentid_provider", "internal/contentid", 600, func(r *rand.Rand, _ int) providerIn {
		id := func(digits bool) S {
			switch r.IntN(7) {
			case 0:
				return ""
			case 1:
				return S(text(r))
			case 2:
				return S(" \t" + fmt.Sprint(r.IntN(99999)) + " ")
			case 3:
				return "0000123"
			}
			if digits {
				return S(fmt.Sprint(r.Int64N(1 << 50)))
			}
			return S(pick(r, []string{"tt", "TT", "Tt", ""}) + fmt.Sprint(r.Int64N(1<<40)))
		}
		return providerIn{Tmdb: id(true), Imdb: id(false), Tvdb: id(true), Season: smallInt(r), Episode: smallInt(r)}
	}, func(in providerIn) providerOut {
		ids := contentid.ProviderIDs{Tmdb: string(in.Tmdb), Imdb: string(in.Imdb), Tvdb: string(in.Tvdb)}
		movie, movieOK := contentid.ForMovie(ids)
		series, seriesOK := contentid.ForSeries(ids)
		season, seasonOK := contentid.ForSeason(series, in.Season)
		episode, episodeOK := contentid.ForEpisode(series, in.Season, in.Episode)
		return providerOut{optional(movie, movieOK), optional(series, seriesOK), optional(season, seasonOK), optional(episode, episodeOK), contentid.AnchorPrecedence(string(in.Tmdb))}
	})

	det("contentid_local", "internal/contentid ForLocal", 800, func(r *rand.Rand, i int) string {
		switch {
		case i%5 == 0:
			return " /media/" + text(r) + "\n"
		case i%5 == 1:
			return "/media/" + fspath.Encode(rawBytes(r))
		case i%5 == 2:
			// Long runs of non-starters exercise Go's stream-safe limit.
			var b strings.Builder
			b.WriteString("e")
			for range r.IntN(70) {
				b.WriteRune(rune(0x300 + r.IntN(0x70)))
			}
			return b.String()
		case i%5 == 3:
			var b strings.Builder
			for range r.IntN(16) {
				b.WriteRune(pick(r, []rune{'e', 'a', 'o', 0x301, 0x308, 0x323, 0x1100, 0x1161, 0x11a8, 0xac00, 0x212b, 0x2126, 0xf900, 0x1d15e, 0x0344, 0x0f73, 0x1e0a, 0x0307, 0x0958, 0x3099, 0x304b, 0x5c8, 0x1ad0, 0x105d2, 0x105c9, 0x1611e, 0x16121, 0x113c2, 0x113b8, 0x113c5, 0x10d69}))
			}
			return b.String()
		default:
			return text(r) + text(r)
		}
	}, contentid.ForLocal)

	type transformOut struct {
		Series         *string  `json:"series"`
		Anchored       bool     `json:"anchored"`
		Anchor         []string `json:"anchor"`
		Local          bool     `json:"local"`
		Packed         *string  `json:"packed"`
		Unpacked       *string  `json:"unpacked"`
		UnpackedPadded *string  `json:"unpacked_padded"`
	}
	det("contentid_codec", "internal/contentid", 800, func(r *rand.Rand, _ int) S {
		return S(contentIDInput(r))
	}, func(in S) transformOut {
		id := string(in)
		series, ok := contentid.SeriesIDFromContentID(id)
		p, v, anchored := contentid.ProviderAnchor(id)
		out := transformOut{Series: optional(series, ok), Anchored: contentid.IsProviderAnchored(id), Local: contentid.IsLocal(id)}
		if anchored {
			out.Anchor = []string{p, v}
		}
		if packed, ok := contentid.Pack(id); ok {
			h := hex.EncodeToString(packed)
			out.Packed = &h
			u, uOK := contentid.Unpack(packed)
			out.Unpacked = optional(u, uOK)
			padded := append(append([]byte{}, packed...), 0, 0, 0)
			u, uOK = contentid.Unpack(padded)
			out.UnpackedPadded = optional(u, uOK)
		}
		return out
	})

	det("contentid_unpack", "internal/contentid Unpack", 600, func(r *rand.Rand, _ int) H {
		b := randBytes(r, r.IntN(20))
		if r.IntN(3) > 0 && len(b) > 2 {
			b[0] = byte(0xC0 + r.IntN(6))
			b[1] = byte(r.IntN(5))
		}
		return H(b)
	}, func(in H) *string {
		return optional(contentid.Unpack(in))
	})

	type fspathOut struct {
		Encoded   S    `json:"encoded"`
		Decoded   S    `json:"decoded"`
		Display   S    `json:"display"`
		IsEncoded bool `json:"is_encoded"`
		// RawDecode and RawDisplay run on the input as given, which need not be encoded.
		RawDecode  S    `json:"raw_decode"`
		RawDisplay S    `json:"raw_display"`
		RawIs      bool `json:"raw_is_encoded"`
	}
	det("fspath", "internal/fspath", 1000, func(r *rand.Rand, i int) S {
		switch {
		case i < 256:
			return S([]byte{byte(i)})
		case i%4 == 0:
			return S("/media/" + rawBytes(r) + "/x.mkv")
		case i%4 == 1:
			return S(string(rune(0x10FE80+r.IntN(0x80))) + text(r))
		case i%4 == 2:
			b := []byte(string(rune(0x10F000 + r.IntN(0xFFF))))
			return S(append(b[:r.IntN(len(b))+1:len(b)], rawBytes(r)...))
		default:
			return S(text(r))
		}
	}, func(in S) fspathOut {
		enc := fspath.Encode(string(in))
		return fspathOut{S(enc), S(fspath.Decode(enc)), S(fspath.Display(enc)), fspath.IsEncoded(enc), S(fspath.Decode(string(in))), S(fspath.Display(string(in))), fspath.IsEncoded(string(in))}
	})

	type sonyIn struct {
		UnixNanos int64 `json:"unix_nanos"`
		Sequence  int   `json:"sequence"`
		Machine   int   `json:"machine"`
	}
	type sonyOut struct {
		ID       *int64           `json:"id"`
		Error    string           `json:"error"`
		Parts    map[string]int64 `json:"parts"`
		ToUnixNS *int64           `json:"to_unix_nanos"`
	}
	epoch := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	sf, err := sonyflake.New(sonyflake.Settings{StartTime: epoch, MachineID: func() (int, error) { return 0, nil }})
	if err != nil {
		panic(err)
	}
	det("sonyflake_compose", "github.com/sony/sonyflake/v2 under internal/idgen settings", 800, func(r *rand.Rand, _ int) sonyIn {
		nanos := epoch.UnixNano() + r.Int64N(int64(170*365*24*time.Hour))
		seq, machine := r.IntN(256), r.IntN(65536)
		if r.IntN(10) == 0 {
			nanos = epoch.UnixNano() - r.Int64N(int64(time.Hour))
		}
		if r.IntN(10) == 0 {
			seq = 256 + r.IntN(4)
		}
		if r.IntN(10) == 0 {
			machine = 65536 + r.IntN(4)
		}
		return sonyIn{nanos, seq, machine}
	}, func(in sonyIn) sonyOut {
		id, err := sf.Compose(time.Unix(0, in.UnixNanos), in.Sequence, in.Machine)
		if err != nil {
			return sonyOut{Error: err.Error()}
		}
		parts := sf.Decompose(id)
		ns := sf.ToTime(id).UnixNano()
		return sonyOut{ID: &id, Parts: parts, ToUnixNS: &ns}
	})

	type mintedOut struct {
		IDs []string `json:"ids"`
	}
	nondet("sonyflake_mint", "internal/idgen mintID", 20, func(r *rand.Rand, i int) int {
		return r.IntN(65536)
	}, func(machine int) (mintedOut, error) {
		next, err := idgen.VectorNextID(machine)
		if err != nil {
			return mintedOut{}, err
		}
		var out mintedOut
		// Enough to overflow the 8-bit sequence inside one time unit.
		for range 600 {
			id, err := next()
			if err != nil {
				return mintedOut{}, err
			}
			out.IDs = append(out.IDs, id)
		}
		return out, nil
	}, func(machine int, out mintedOut) error {
		var last int64
		for _, text := range out.IDs {
			var id int64
			if _, err := fmt.Sscan(text, &id); err != nil {
				return err
			}
			if id <= last {
				return fmt.Errorf("IDs do not increase: %d after %d", id, last)
			}
			last = id
			parts := sf.Decompose(id)
			if parts["machine"] != int64(machine) {
				return fmt.Errorf("id %d has machine %d, want %d", id, parts["machine"], machine)
			}
			at := sf.ToTime(id)
			if d := time.Since(at); d < -time.Hour || d > 365*24*time.Hour*100 {
				return fmt.Errorf("id %d has time %v", id, at)
			}
		}
		return nil
	})

	det("lantls_pin", "internal/lantls", 500, func(r *rand.Rand, _ int) string {
		return masterKey(r)
	}, func(key string) string {
		id, err := lantls.New([]byte(key))
		if err != nil {
			panic(err)
		}
		return id.Pin()
	})

	type nodeSignIn struct {
		Secret  string `json:"secret"`
		Method  string `json:"method"`
		URL     string `json:"url"`
		NodeURL string `json:"node_url"`
		Body    *S     `json:"body"`
		Now     int64  `json:"now"`
	}
	nodeURLs := []string{"http://node:8080", "http://node:8080/", "https://proxy.example/prefix", "https://proxy.example/pre%20fix/", "https://proxy.example/a/b", "http://[::1]:9000/w", "http://u:p@node/x", "://bad", "node:8080/x", "http://no de/x", "http://node:port/x", "", "/rel/path", "http://node/%zz"}
	targetPaths := []string{"/internal/segments/seg_00001.m4s", "/prefix/internal/x", "/pre%20fix/a/b", "/a/b/c", "/w/health", "/x/y", "/", "", "/a%2Fb/c", "/ünï/✓", "/a b/c", "/prefix", "/prefix/"}
	det("nodeauth_sign", "internal/nodeauth", 800, func(r *rand.Rand, _ int) nodeSignIn {
		path := pick(r, targetPaths)
		query := pick(r, []string{"", "?a=1", "?a=1&b=two%20words", "?z=%7E&y"})
		base := pick(r, []string{"http://host:1234", "http://host"})
		var body *S
		if r.IntN(2) == 0 {
			b := S(rawBytes(r))
			body = &b
		}
		return nodeSignIn{masterKey(r), pick(r, []string{"GET", "POST", "DELETE", "PUT"}), base + path + query, pick(r, nodeURLs), body, 1_800_000_000 + r.Int64N(1000)}
	}, func(in nodeSignIn) string {
		req := nodeRequest(in.Method, in.URL, in.Body)
		if err := nodeauth.VectorSign(req, in.NodeURL, in.Secret, time.Unix(in.Now, 0)); err != nil {
			panic(err)
		}
		return req.Header.Get("Authorization")
	})

	type nodeVerifyIn struct {
		Secret        string `json:"secret"`
		Method        string `json:"method"`
		Target        string `json:"target"`
		Authorization S      `json:"authorization"`
		Body          *S     `json:"body"`
		NowNanos      int64  `json:"now_nanos"`
	}
	det("nodeauth_verify", "internal/nodeauth verify", 800, func(r *rand.Rand, i int) nodeVerifyIn {
		secret := masterKey(r)
		now := int64(1_800_000_000)
		method := pick(r, []string{"GET", "POST"})
		target := "http://h" + pick(r, targetPaths[:6]) + pick(r, []string{"", "?a=1", "?b=%7E"})
		var body *S
		if r.IntN(2) == 0 {
			b := S(rawBytes(r))
			body = &b
		}
		req := nodeRequest(method, target, body)
		_ = nodeauth.VectorSign(req, "", secret, time.Unix(now, 0))
		auth := req.Header.Get("Authorization")
		nowNanos := now*1e9 + r.Int64N(1e9)
		switch i % 12 {
		case 0:
			auth = "Bearer " + secret
		case 1:
			auth = "bearer " + secret + "x"
		case 2:
			auth = strings.ToLower(nodeauth.Scheme) + auth[len(nodeauth.Scheme):]
		case 3:
			auth = strings.Replace(auth, "t=", "t=+", 1)
		case 4:
			auth = auth[:len(auth)-1]
		case 5:
			nowNanos = (now + 30) * 1e9
		case 6:
			nowNanos = (now+30)*1e9 + 1
		case 7:
			nowNanos = (now - 30) * 1e9
		case 8:
			nowNanos = (now-30)*1e9 - 1
		case 9:
			if body != nil {
				b := *body + "tampered"
				body = &b
			}
		case 10:
			auth = pick(r, []string{"", "Silo-Node-HMAC-SHA256", nodeauth.Scheme + " t=1", nodeauth.Scheme + " nokv", nodeauth.Scheme + " t=x,b=y,sig=z", "Basic abc", " " + auth})
		case 11:
			parts := strings.SplitN(auth, " ", 2)
			fields := strings.Split(parts[1], ",")
			auth = parts[0] + " " + fields[2] + " , " + fields[0] + "," + fields[1] + ",extra=1"
		}
		return nodeVerifyIn{secret, method, target, S(auth), body, nowNanos}
	}, func(in nodeVerifyIn) string {
		req := nodeRequest(in.Method, in.Target, in.Body)
		req.Header.Set("Authorization", string(in.Authorization))
		// nodeauth reads the same fields a server gets from net/http.
		if err := nodeauth.VectorVerify(req, in.Secret, time.Unix(0, in.NowNanos)); err != nil {
			return err.Error()
		}
		return "ok"
	})

	type etagIn struct {
		Scope   S     `json:"scope"`
		ID      S     `json:"id"`
		Version int64 `json:"version"`
	}
	det("apiv2_etag", "internal/apiv2 RenderETag", 800, func(r *rand.Rand, i int) etagIn {
		v := r.Int64()
		switch i % 4 {
		case 0:
			v = int64(r.IntN(1000))
		case 1:
			v = -v
		}
		scope, id := text(r), text(r)
		if i%7 == 0 {
			scope, id = rawBytes(r), rawBytes(r)
		}
		return etagIn{S(scope), S(id), v}
	}, func(in etagIn) string {
		return apiv2.RenderETag(string(in.Scope), string(in.ID), in.Version).String()
	})

	type etagListOut struct {
		Star  bool     `json:"star"`
		Error bool     `json:"error"`
		Tags  []string `json:"tags"`
	}
	det("apiv2_etag_list", "internal/apiv2 ParseETagList", 700, func(r *rand.Rand, i int) S {
		tag := func() string {
			return pick(r, []string{`"a"`, `W/"b"`, `""`, `"a,b"`, `w/"c"`, `"unterminated`, `W/`, `"bad space"`, `"` + "\xff" + `"`, `"` + "\x7f" + `"`, `abc`, `*`})
		}
		sep := func() string { return pick(r, []string{",", ", ", " ,", ",,", " , , ", "\t,", " ", ""}) }
		switch i % 6 {
		case 0:
			return S(pick(r, []string{"*", " * ", "\t*", "*,", "*, *", ""}))
		default:
			var b strings.Builder
			for range r.IntN(4) + 1 {
				b.WriteString(tag())
				b.WriteString(sep())
			}
			return S(b.String())
		}
	}, func(in S) etagListOut {
		tags, star, err := apiv2.ParseETagList(string(in))
		out := etagListOut{Star: star, Error: err != nil, Tags: []string{}}
		for _, t := range tags {
			out.Tags = append(out.Tags, t.String())
		}
		return out
	})

	type cursorPosition struct {
		Key  string  `json:"key"`
		Sort float64 `json:"sort,omitempty"`
		ID   int64   `json:"id"`
		HTML string  `json:"html"`
	}
	det("apiv2_cursor", "internal/apiv2 Cursors", 800, func(r *rand.Rand, _ int) struct {
		Secret string         `json:"secret"`
		Scope  [5]string      `json:"scope"`
		Pos    cursorPosition `json:"pos"`
	} {
		return struct {
			Secret string         `json:"secret"`
			Scope  [5]string      `json:"scope"`
			Pos    cursorPosition `json:"pos"`
		}{masterKey(r), [5]string{text(r), text(r), text(r), text(r), text(r)}, cursorPosition{text(r), randFloat(r), r.Int64(), "<a&b>" + text(r)}}
	}, func(in struct {
		Secret string         `json:"secret"`
		Scope  [5]string      `json:"scope"`
		Pos    cursorPosition `json:"pos"`
	}) string {
		c, err := apiv2.NewCursors([]byte(in.Secret)).Encode(apiv2.CursorScope{OperationID: in.Scope[0], Security: in.Scope[1], Filter: in.Scope[2], Sort: in.Scope[3], Tiebreaker: in.Scope[4]}, in.Pos)
		if err != nil {
			panic(err)
		}
		return c
	})

	type cursorDecodeIn struct {
		Secret string    `json:"secret"`
		Scope  [5]string `json:"scope"`
		Cursor S         `json:"cursor"`
	}
	type cursorDecodeOut struct {
		Valid bool    `json:"valid"`
		Key   string  `json:"key"`
		ID    int64   `json:"id"`
		Sort  float64 `json:"sort"`
	}
	det("apiv2_cursor_decode", "internal/apiv2 Cursors.Decode", 700, func(r *rand.Rand, i int) cursorDecodeIn {
		secret := masterKey(r)
		scope := [5]string{"op", "sec", text(r), "sort", "item_id"}
		cs := apiv2.CursorScope{OperationID: scope[0], Security: scope[1], Filter: scope[2], Sort: scope[3], Tiebreaker: scope[4]}
		c, _ := apiv2.NewCursors([]byte(secret)).Encode(cs, cursorPosition{Key: text(r), Sort: 2.5, ID: 7})
		switch i % 6 {
		case 1:
			scope[0] = "other-op"
		case 2:
			c = c[:len(c)-2] + "AA"
		case 3:
			c = forgeCursor(secret, cs, pick(r, []string{
				`{"v":2,"p":{}}`, `{"V":1,"P":{"KEY":"folded","Id":5}}`, `{"v":1}`, `{"v":1,"p":null}`, `{"v":null,"p":{}}`, `{"p":{"key":"x"},"v":1,"v":2}`, `[]`, `null`, `not json`, `{"v":"1","p":{}}`, `{"v":1,"p":{"id":"x"}}`, `{"v":1.0,"p":{}}`, ` { "v" : 1 , "p" : { "key" : "ws" } } `,
			}))
		case 4:
			c = pick(r, []string{"", ".", "a", "a.b", "!!!.@@@"})
		}
		return cursorDecodeIn{secret, scope, S(c)}
	}, func(in cursorDecodeIn) cursorDecodeOut {
		cs := apiv2.CursorScope{OperationID: in.Scope[0], Security: in.Scope[1], Filter: in.Scope[2], Sort: in.Scope[3], Tiebreaker: in.Scope[4]}
		var pos cursorPosition
		if p := apiv2.NewCursors([]byte(in.Secret)).Decode(cs, string(in.Cursor), &pos); p != nil {
			return cursorDecodeOut{}
		}
		return cursorDecodeOut{true, pos.Key, pos.ID, pos.Sort}
	})

	type viewerIn struct {
		None                bool   `json:"none"`
		PolicyRevision      int64  `json:"policy_revision"`
		LibrariesRestricted bool   `json:"libraries_restricted"`
		Allowed             *[]int `json:"allowed"`
		Disabled            *[]int `json:"disabled"`
		MaxContentRating    string `json:"max_content_rating"`
		AllowUnrated        bool   `json:"allow_unrated"`
		MaxAdvisoryAge      int    `json:"max_advisory_age"`
		RequireAdvisoryAge  bool   `json:"require_advisory_age"`
	}
	det("apiv2_viewer_scope_digest", "internal/apiv2 viewerScopeDigest", 600, func(r *rand.Rand, i int) viewerIn {
		ids := func() *[]int {
			switch r.IntN(3) {
			case 0:
				return nil
			case 1:
				return &[]int{}
			}
			list := make([]int, r.IntN(5)+1)
			for j := range list {
				list[j] = r.IntN(1000)
			}
			return &list
		}
		return viewerIn{i%25 == 0, r.Int64N(1 << 40), r.IntN(2) == 0, ids(), ids(), pick(r, []string{"", "PG-13", "TV-MA", text(r)}), r.IntN(2) == 0, pick(r, []int{0, 0, 7, 13, 18, -1}), r.IntN(2) == 0}
	}, func(in viewerIn) string {
		if in.None {
			return apiv2.VectorViewerScopeDigest(context.Background())
		}
		scope := access.Scope{PolicyRevision: in.PolicyRevision, LibrariesRestricted: in.LibrariesRestricted}
		scope.MaxContentRating = in.MaxContentRating
		scope.AllowUnratedContent = in.AllowUnrated
		scope.MaxAdvisoryAge = in.MaxAdvisoryAge
		scope.RequireAdvisoryAge = in.RequireAdvisoryAge
		if in.Allowed != nil {
			scope.AllowedLibraryIDs = *in.Allowed
		}
		if in.Disabled != nil {
			scope.DisabledLibraryIDs = *in.Disabled
		}
		return apiv2.VectorViewerScopeDigest(access.SetScope(context.Background(), scope))
	})

	type artworkIn struct {
		Secret  string `json:"secret"`
		Job     bool   `json:"job"`
		TTL     int64  `json:"ttl_nanos"`
		SignTTL int64  `json:"sign_ttl_nanos"`
		Key     S      `json:"key"`
		Now     int64  `json:"now_nanos"`
	}
	type artworkOut struct {
		URL      S     `json:"url"`
		Expires  int64 `json:"expires_nanos"`
		Verified bool  `json:"verified"`
	}
	det("artworkurl", "internal/artworkurl", 800, func(r *rand.Rand, _ int) artworkIn {
		keys := []string{"tmdb/movie/1/poster/original.abc.webp", "tmdb/movie/1/poster/w500.webp", "/leading/slash.webp", "uploads/a b#c?d%25.webp", "x", "ünï/✓.r1.webp", "a/b.c.d.webp", "job-" + randHex(r, 4), "a'b(c)!*.webp"}
		ttls := []int64{0, int64(time.Second), int64(7 * time.Minute), int64(15 * time.Minute), int64(time.Hour), int64(4 * time.Hour), int64(48 * time.Hour), -1}
		return artworkIn{masterKey(r), r.IntN(3) == 0, pick(r, ttls), pick(r, ttls), S(pick(r, keys)), 1_800_000_000_000_000_000 + r.Int64N(int64(30*24*time.Hour))}
	}, func(in artworkIn) artworkOut {
		var s *artworkurl.Signer
		if in.Job {
			s = artworkurl.NewJobArtifactSigner(in.Secret, time.Duration(in.TTL))
		} else {
			s = artworkurl.NewSigner(in.Secret, time.Duration(in.TTL))
		}
		now := time.Unix(0, in.Now)
		url, exp := s.SignFor(string(in.Key), now, time.Duration(in.SignTTL))
		sig := url[strings.LastIndex(url, "sig=")+4:]
		return artworkOut{S(url), exp.UnixNano(), s.Verify(string(in.Key), exp.Unix(), sig, now) == nil}
	})

	type keyIn struct {
		A, B, C, D S
		Path       S
	}
	type keyOut struct {
		Build, Original, Variant, Directory, Revision, OriginalOf, ImageTypeOf string
		Local                                                                  bool
		Widths                                                                 []int
		Names, Keys                                                            []string
		Ladder                                                                 int
	}
	det("artworkkey", "internal/artworkkey", 700, func(r *rand.Rand, _ int) keyIn {
		paths := []string{"tmdb/movie/1/poster/original.abc.webp", "tmdb/movie/1/poster/original.webp", "tmdb/movie/1/backdrop/w500.r1.webp", "local/x/still/original.r.jpg", "nfo/y/logo/original.webp", "https://x/y/z.webp", "a", "", " /a/b/c.d.e ", "/a/b", "a/b/", "original.abc", "x/thumb/disc", "x/clearart/original.a.b.webp"}
		bases := []string{"tmdb/movie/1/poster", "a/", " b ", "", "c//", text(r)}
		variants := []string{"original", "w500", " w300 ", "", text(r)}
		revs := []string{"", "abc", " r1 ", text(r)}
		exts := []string{"", ".webp", "jpg", "..x"}
		return keyIn{S(pick(r, bases)), S(pick(r, variants)), S(pick(r, revs)), S(pick(r, exts)), S(pick(r, paths))}
	}, func(in keyIn) keyOut {
		p := string(in.Path)
		types := []string{"poster", "BACKDROP", " still ", "logo", "profile", "banner", "thumb", "clearart", "disc", "unknown", ""}
		imageType := types[(len(p)+len(in.A))%len(types)]
		return keyOut{
			artworkkey.Build(string(in.A), string(in.B), string(in.C), string(in.D)),
			artworkkey.Original(string(in.A), string(in.C), string(in.D)),
			artworkkey.Variant(p, string(in.B)),
			artworkkey.Directory(p), artworkkey.Revision(p), artworkkey.OriginalOf(p), artworkkey.ImageTypeOf(p, "fallback"),
			artworkkey.IsLocal(p), artworkkey.VariantWidths(imageType), artworkkey.VariantNames(imageType), artworkkey.ObjectKeys(p, imageType), artworkkey.LadderVersion,
		}
	})

	type jellyIn struct {
		Kind    int    `json:"kind"`
		Value   S      `json:"value"`
		User    int    `json:"user"`
		Profile S      `json:"profile"`
		Number  uint64 `json:"number"`
	}
	type jellyOut struct {
		Encoded  string  `json:"encoded"`
		Decode   *string `json:"decode"`
		Pseudo   string  `json:"pseudo"`
		Numeric  string  `json:"numeric"`
		Packed   *string `json:"packed"`
		Unpacked *string `json:"unpacked"`
		DecodeID *string `json:"decode_id"`
	}
	det("jellycompat_ids", "internal/jellycompat idcodec", 800, func(r *rand.Rand, i int) jellyIn {
		value := pick(r, []string{contentIDInput(r), text(r), fmt.Sprint(r.Int64N(1 << 50)), "18446744073709551615", "18446744073709551616", "+5", "-5", "1_000", ""})
		return jellyIn{1 + r.IntN(11), S(value), posInt(r), S(text(r)), r.Uint64()}
	}, func(in jellyIn) jellyOut {
		codec := jellycompat.NewResourceIDCodec()
		kind := jellycompat.EncodedIDType(in.Kind)
		encoded := codec.EncodeStringID(kind, string(in.Value))
		var decode *string
		if v, err := codec.DecodeStringID(kind, encoded); err == nil {
			decode = &v
		}
		numeric := jellycompat.EncodeNumericID(kind, in.Number).String()
		out := jellyOut{Encoded: encoded, Decode: decode, Pseudo: jellycompat.PseudoUserID(in.User, string(in.Profile)).String(), Numeric: numeric}
		if v, ok := jellycompat.VectorPackUUID(kind, string(in.Value)); ok {
			out.Packed = &v
		}
		if v, ok := jellycompat.VectorUnpackUUID(kind, encoded); ok {
			out.Unpacked = &v
		}
		if d, err := jellycompat.DecodeID(encoded); err == nil {
			v := fmt.Sprintf("%d:%d", d.Type, d.Value)
			out.DecodeID = &v
		}
		return out
	})

	type uuidIn struct {
		Raw S `json:"raw"`
	}
	det("uuid_parse", "github.com/google/uuid Parse through jellycompat.DecodeID", 500, func(r *rand.Rand, i int) uuidIn {
		id := jellycompat.EncodeNumericID(jellycompat.EncodedIDType(1+r.IntN(11)), r.Uint64()).String()
		switch i % 6 {
		case 0:
			return uuidIn{S(strings.ToUpper(id))}
		case 1:
			return uuidIn{S(strings.ReplaceAll(id, "-", ""))}
		case 2:
			return uuidIn{S("urn:uuid:" + id)}
		case 3:
			return uuidIn{S("{" + id + "}")}
		case 4:
			return uuidIn{S(pick(r, []string{"URN:UUID:" + id, "[" + id + "]", id + "x", id[:35], "x" + id[1:], strings.Replace(id, "-", "_", 1), "", randHex(r, 16), "g" + randHex(r, 16)[1:]}))}
		default:
			return uuidIn{S(id)}
		}
	}, func(in uuidIn) *string {
		d, err := jellycompat.DecodeID(string(in.Raw))
		if err != nil {
			return nil
		}
		v := fmt.Sprintf("%d:%d", d.Type, d.Value)
		return &v
	})

	// Exercises the file-based Go function on real files, built from a byte stream Rust can reproduce.
	type oshashIn struct {
		Seed uint64 `json:"seed"`
		Size int64  `json:"size"`
	}
	dir, err := os.MkdirTemp("", "oshash")
	if err != nil {
		panic(err)
	}
	det("oshash", "internal/scanner ComputeOSHash", 500, func(r *rand.Rand, _ int) oshashIn {
		return oshashIn{r.Uint64() | 1, 131072 + r.Int64N(200000)}
	}, func(in oshashIn) string {
		return computeOSHash(filepath.Join(dir, "f"), in.Seed, in.Size)
	})
}

func nodeRequest(method, target string, body *S) *http.Request {
	var reader *strings.Reader
	if body != nil {
		reader = strings.NewReader(string(*body))
	}
	var (
		req *http.Request
		err error
	)
	if reader != nil {
		req, err = http.NewRequest(method, target, reader)
	} else {
		req, err = http.NewRequest(method, target, nil)
	}
	if err != nil {
		panic(err)
	}
	return req
}
