//go:build core_vectors

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/rand/v2"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"context"

	"github.com/google/uuid"
	"golang.org/x/text/unicode/norm"

	"github.com/Silo-Server/silo-server/internal/adminjob"
	"github.com/Silo-Server/silo-server/internal/api/handlers"
	"github.com/Silo-Server/silo-server/internal/audiobooks"
	"github.com/Silo-Server/silo-server/internal/auth"
	"github.com/Silo-Server/silo-server/internal/autoscan"
	"github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/clientip"
	"github.com/Silo-Server/silo-server/internal/config"
	"github.com/Silo-Server/silo-server/internal/downloadprepare"
	"github.com/Silo-Server/silo-server/internal/downloads"
	"github.com/Silo-Server/silo-server/internal/ebookconvert"
	"github.com/Silo-Server/silo-server/internal/imagecache"
	"github.com/Silo-Server/silo-server/internal/imageutil"
	"github.com/Silo-Server/silo-server/internal/jellycompat"
	"github.com/Silo-Server/silo-server/internal/literaryworks"
	"github.com/Silo-Server/silo-server/internal/mediaartifact"
	"github.com/Silo-Server/silo-server/internal/metadata"
	"github.com/Silo-Server/silo-server/internal/metadata/translation"
	"github.com/Silo-Server/silo-server/internal/models"
	"github.com/Silo-Server/silo-server/internal/noderecipe"
	"github.com/Silo-Server/silo-server/internal/nodesessions"
	"github.com/Silo-Server/silo-server/internal/notifications"
	"github.com/Silo-Server/silo-server/internal/playback"
	"github.com/Silo-Server/silo-server/internal/playback/connectionstore"
	"github.com/Silo-Server/silo-server/internal/recommendations"
	"github.com/Silo-Server/silo-server/internal/s3client"
	"github.com/Silo-Server/silo-server/internal/scanner"
	"github.com/Silo-Server/silo-server/internal/sections/recipes"
	"github.com/Silo-Server/silo-server/internal/server"
	"github.com/Silo-Server/silo-server/internal/settingscontract"
	"github.com/Silo-Server/silo-server/internal/tonemap"
)

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func xorshiftBlock(seed uint64, size int64) []byte {
	b := make([]byte, size)
	s := seed
	for i := int64(0); i < size; i += 8 {
		s ^= s << 13
		s ^= s >> 7
		s ^= s << 17
		var w [8]byte
		binary.LittleEndian.PutUint64(w[:], s)
		copy(b[i:], w[:])
	}
	return b
}

func computeOSHash(path string, seed uint64, size int64) string {
	if err := os.WriteFile(path, xorshiftBlock(seed, size), fs.FileMode(0o600)); err != nil {
		panic(err)
	}
	h, err := scanner.ComputeOSHash(path)
	if err != nil {
		panic(err)
	}
	return h
}

func registerHashes() {
	// A table of one-string functions: name, the real Go function, and a mapping Rust repeats.
	oneArg := map[string]func(string) string{
		"hash_link_token":             auth.HashLinkToken,
		"hash_device_login_secret":    auth.VectorHashDeviceLoginSecret,
		"normalize_user_code":         auth.VectorNormalizeUserCode,
		"format_user_code":            auth.VectorFormatUserCode,
		"quick_connect_code":          auth.QuickConnectCode,
		"quick_connect_session_token": jellycompat.VectorQuickConnectSessionToken,
		"sign_in_attempt_key":         auth.VectorSignInAttemptKey,
		"binder_hash":                 auth.VectorBinderHash,
		"binder_cookie_name":          auth.OAuthBinderCookieName,
		"pkce_challenge":              auth.PKCEChallengeS256,
		"completion_code_hash":        auth.VectorCompletionCodeHash,
		"apns_token_hash":             notifications.VectorAPNsTokenHash,
		"fcm_token_hash":              notifications.VectorFCMTokenHash,
		"hash_email_token":            notifications.VectorHashEmailToken,
		"hash_webhook_token":          autoscan.VectorHashWebhookToken,
		"abs_token_hash":              audiobooks.VectorTokenHash,
		"expired_stop_id":             handlers.VectorExpiredStopID,
		"abort_stop_id":               handlers.VectorAbortStopID,
		"admin_stop_id":               handlers.VectorAdminStopID,
		"node_hash":                   nodesessions.VectorNodeHash,
		"node_recipe_digest":          func(s string) string { return noderecipe.VectorDigest([]byte(s)) },
		"smart_definition_key":        catalog.VectorSmartDefinitionKey,
		"frontend_content_etag":       func(s string) string { return server.VectorContentETag([]byte(s)) },
		"tag_value":                   jellycompat.VectorTagValue,
		"canonical_image_tag":         jellycompat.VectorCanonicalTag,
		"plain_sha256_hex": func(s string) string {
			sum := sha256.Sum256([]byte(s))
			return hex.EncodeToString(sum[:])
		},
	}
	names := sortedKeys(oneArg)
	type oneIn struct {
		Fn string `json:"fn"`
		V  S      `json:"v"`
	}
	byteSafe := map[string]bool{"hash_link_token": true, "hash_device_login_secret": true, "binder_hash": true, "binder_cookie_name": true, "pkce_challenge": true, "completion_code_hash": true, "hash_email_token": true, "hash_webhook_token": true, "abs_token_hash": true, "node_recipe_digest": true, "smart_definition_key": true, "frontend_content_etag": true, "plain_sha256_hex": true}
	det("credential_hashes", "internal/auth, notifications, autoscan, audiobooks, playback, catalog", 500*len(names), func(r *rand.Rand, i int) oneIn {
		name := names[i%len(names)]
		v := text(r)
		switch r.IntN(6) {
		case 0:
			if byteSafe[name] {
				v = rawBytes(r)
			}
		case 1:
			v = strings.ToLower(randHex(r, 8)) + "-" + strconv.Itoa(r.IntN(100))
		}
		return oneIn{name, S(v)}
	}, func(in oneIn) string { return oneArg[in.Fn](string(in.V)) })

	type apiKeyIn struct {
		Random H `json:"random"`
	}
	type apiKeyOut struct {
		Key       string `json:"key"`
		KeyHash   string `json:"key_hash"`
		KeyPrefix string `json:"key_prefix"`
	}
	det("api_key", "internal/auth generateAPIKey and insertAPIKey", 500, func(r *rand.Rand, _ int) apiKeyIn {
		return apiKeyIn{H(randBytes(r, 32))}
	}, func(in apiKeyIn) apiKeyOut {
		key := "sa_" + hex.EncodeToString(in.Random)
		return apiKeyOut{key, auth.HashLinkToken(key), key[:11]}
	})

	det("api_key_valid_text", "internal/auth ValidTextKey", 500, func(r *rand.Rand, i int) S {
		if i%2 == 0 {
			return S("sa_" + rawBytes(r))
		}
		return S(text(r))
	}, func(in S) bool { return auth.ValidTextKey(string(in)) })

	type stateIn struct {
		Secret  H     `json:"secret"`
		Nonce   S     `json:"nonce"`
		Install S     `json:"install"`
		Expires int64 `json:"expires_nanos"`
	}
	type stateOut struct {
		Derived string `json:"derived"`
		Signed  string `json:"signed"`
	}
	det("oauth_state", "internal/auth oauth_state", 600, func(r *rand.Rand, _ int) stateIn {
		return stateIn{H(randBytes(r, 32)), S(text(r)), S(text(r)), 1_800_000_000_000_000_000 + r.Int64N(1e15)}
	}, func(in stateIn) stateOut {
		derived := auth.DeriveOAuthStateSecret(in.Secret)
		signed := auth.SignState(derived, auth.StatePayload{Nonce: string(in.Nonce), InstallID: string(in.Install), ExpiresAt: time.Unix(0, in.Expires).UTC()})
		return stateOut{hex.EncodeToString(derived), signed}
	})

	type stateVerifyIn struct {
		Secret H `json:"secret"`
		Signed S `json:"signed"`
	}
	type stateVerifyOut struct {
		Class   string `json:"class"`
		Nonce   string `json:"nonce"`
		Install string `json:"install"`
		Expires string `json:"expires"`
	}
	det("oauth_state_verify", "internal/auth VerifyState", 500, func(r *rand.Rand, i int) stateVerifyIn {
		secret := randBytes(r, 32)
		expires := time.Date(2100, 1, 1, 0, 0, 0, r.IntN(1e9), time.UTC)
		switch i % 6 {
		case 1:
			expires = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
		case 2:
			expires = expires.In(time.FixedZone("", 5400))
		}
		signed := auth.SignState(secret, auth.StatePayload{Nonce: text(r), InstallID: text(r), ExpiresAt: expires})
		switch i % 6 {
		case 3:
			signed = signed[:len(signed)-1] + "A"
		case 4:
			signed = pick(r, []string{"", "abc", "abc.def", "."})
		case 5:
			body := pick(r, []string{`null`, `[]`, `{"N":"folded","I":"x","E":"2100-01-01T00:00:00Z"}`, `{"e":"not-a-time"}`, `{"e":null,"n":"x"}`, `{"n":1}`, `not json`})
			enc := encodeRaw([]byte(body))
			signed = enc + "." + encodeRaw(hmacOf(secret, enc))
		}
		return stateVerifyIn{H(secret), S(signed)}
	}, func(in stateVerifyIn) stateVerifyOut {
		p, err := auth.VerifyState(in.Secret, string(in.Signed))
		out := stateVerifyOut{Class: "ok", Nonce: p.Nonce, Install: p.InstallID}
		if !p.ExpiresAt.IsZero() {
			out.Expires = p.ExpiresAt.UTC().Format(time.RFC3339Nano)
		}
		switch {
		case err == nil:
		case errors.Is(err, auth.ErrStateExpired):
			out.Class = "expired"
		default:
			return stateVerifyOut{Class: "error"}
		}
		return out
	})

	type planIn struct {
		Attempt     S       `json:"attempt"`
		Requested   int     `json:"requested"`
		Effective   int     `json:"effective"`
		PlanID      S       `json:"plan_id"`
		Delivery    S       `json:"delivery"`
		Protocol    S       `json:"protocol"`
		Container   S       `json:"container"`
		Video       S       `json:"video"`
		Audio       S       `json:"audio"`
		Width       *int    `json:"width"`
		Height      *int    `json:"height"`
		Bitrate     *int    `json:"bitrate"`
		Range       S       `json:"range"`
		Sample      S       `json:"sample"`
		Segment     S       `json:"segment"`
		AudioTrack  *[2]any `json:"audio_track"`
		SubTrack    *[2]any `json:"sub_track"`
		Mode        S       `json:"mode"`
		EmbeddedIdx *int    `json:"embedded_idx"`
		EmbeddedID  S       `json:"embedded_id"`
		HLSGroup    *string `json:"hls_group"`
		HLSFormat   S       `json:"hls_format"`
		Transforms  [][3]S  `json:"transforms"`
		Quirks      [][2]S  `json:"quirks"`
		Corrections []S     `json:"corrections"`
		Output      S       `json:"output"`
		Mutations   []S     `json:"mutations"`
	}
	type planOut struct {
		PlanID     string `json:"plan_id"`
		AttemptKey string `json:"attempt_key"`
	}
	track := func(r *rand.Rand) *[2]any {
		if r.IntN(2) == 0 {
			return nil
		}
		v := [2]any{text(r), nil}
		if r.IntN(2) == 0 {
			v[1] = r.IntN(40)
		}
		return &v
	}
	toTrack := func(v *[2]any) *playback.TrackIdentityV3 {
		if v == nil {
			return nil
		}
		t := &playback.TrackIdentityV3{ID: v[0].(string)}
		if v[1] != nil {
			var idx int
			switch n := v[1].(type) {
			case int:
				idx = n
			case float64:
				idx = int(n)
			}
			t.Index = &idx
		}
		return t
	}
	sl := func(r *rand.Rand, n int) []S {
		out := make([]S, r.IntN(n))
		for i := range out {
			out[i] = S(text(r))
		}
		return out
	}
	det("playback_plan_identity", "internal/playback plan_key_v3", 800, func(r *rand.Rand, _ int) planIn {
		in := planIn{Attempt: S(text(r)), Requested: smallInt(r), Effective: smallInt(r), PlanID: S("plan:" + randHex(r, 16)), Delivery: S(pick(r, []string{"direct_play", "direct_stream", "transcode", text(r)})), Protocol: S(pick(r, []string{"hls", "progressive"})), Container: S(pick(r, []string{"MP4", "mkv", "ß", text(r)})), Video: S(pick(r, []string{"H264", "hevc", "İ"})), Audio: S(pick(r, []string{"AAC", "eac3"})), Width: optInt(r), Height: optInt(r), Bitrate: optInt(r), Range: S(pick(r, []string{"SDR", "hdr10", "ς"})), Sample: S(pick(r, []string{"", " HVC1 ", "dvh1", "  "})), Segment: S(pick(r, []string{"", " MPEGTS ", "fmp4"})), AudioTrack: track(r), SubTrack: track(r), Mode: S(pick(r, []string{"none", "burn_in", "sidecar"})), Output: S(text(r)), Mutations: sl(r, 4), Corrections: sl(r, 3)}
		if r.IntN(2) == 0 {
			idx := r.IntN(10)
			in.EmbeddedIdx = &idx
			in.EmbeddedID = S(text(r))
		}
		if r.IntN(2) == 0 {
			g := text(r)
			in.HLSGroup = &g
			in.HLSFormat = S(pick(r, []string{"vtt", "ttml"}))
		}
		for range r.IntN(4) {
			in.Transforms = append(in.Transforms, [3]S{S(text(r)), S(text(r)), S(text(r))})
		}
		for range r.IntN(3) {
			in.Quirks = append(in.Quirks, [2]S{S(text(r)), S(text(r))})
		}
		return in
	}, func(in planIn) planOut {
		p := playback.PlanV3{PlanID: string(in.PlanID), Delivery: playback.DeliveryV3(in.Delivery)}
		p.Stream.Protocol = playback.StreamProtocolV3(in.Protocol)
		p.Stream.Container = string(in.Container)
		p.EffectiveRecipe.VideoCodec = string(in.Video)
		p.EffectiveRecipe.AudioCodec = string(in.Audio)
		p.EffectiveRecipe.Width = in.Width
		p.EffectiveRecipe.Height = in.Height
		p.EffectiveRecipe.BitrateKbps = in.Bitrate
		p.EffectiveRecipe.DynamicRange = string(in.Range)
		p.EffectiveRecipe.VideoSampleEntry = string(in.Sample)
		p.EffectiveRecipe.SegmentContainer = string(in.Segment)
		p.SelectedTracks.Audio = toTrack(in.AudioTrack)
		p.SelectedTracks.Subtitle = toTrack(in.SubTrack)
		p.Subtitle.Mode = playback.SubtitleModeV3(in.Mode)
		if in.EmbeddedIdx != nil {
			p.Subtitle.Embedded = &playback.EmbeddedSubtitleV3{StreamIndex: *in.EmbeddedIdx, ContainerTrackID: string(in.EmbeddedID)}
		}
		if in.HLSGroup != nil {
			p.Subtitle.HLSRendition = &playback.HLSSubtitleRenditionV3{GroupID: *in.HLSGroup, Format: string(in.HLSFormat)}
		}
		for _, t := range in.Transforms {
			p.Transformations = append(p.Transformations, playback.TransformationV3{Executor: string(t[0]), Name: string(t[1]), RecipeVersion: string(t[2])})
		}
		for _, q := range in.Quirks {
			p.AppliedQuirks = append(p.AppliedQuirks, playback.AppliedQuirkV3{RegistryRevision: string(q[0]), ID: string(q[1])})
		}
		for _, c := range in.Corrections {
			p.RuntimeCorrections = append(p.RuntimeCorrections, string(c))
		}
		var mutations []string
		for _, m := range in.Mutations {
			mutations = append(mutations, string(m))
		}
		return planOut{playback.DeterministicPlanIDV3(string(in.Attempt), in.Requested, in.Effective, p), playback.PlanAttemptKeyV3(p, string(in.Output), mutations)}
	})

	// The revision string is platform-specific. The file fields travel in the vector, because they differ
	// on every run. Rust's output names a real file, so the Go function reads the same inode.
	nondet("playback_directplay_etag", "internal/playback DirectPlayEntityTag on real files", 500, func(r *rand.Rand, _ int) int {
		return r.IntN(1 << 30)
	}, func(seed int) (directPlayOut, error) {
		return directPlayCase(seed), nil
	}, func(_ int, out directPlayOut) error {
		if out.Path == "" {
			return nil
		}
		f, err := os.Open(out.Path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			return err
		}
		if got := playback.DirectPlayEntityTag(f, info); got != out.ETag {
			return fmt.Errorf("etag %s, rust said %s", got, out.ETag)
		}
		return nil
	})

	type connIn struct {
		Secret string `json:"secret"`
		IP     string `json:"ip"`
	}
	det("playback_connection_key", "internal/playback/connectionstore Key", 600, func(r *rand.Rand, i int) connIn {
		var ip net.IP
		if i%2 == 0 {
			ip = net.IPv4(byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256)), byte(r.IntN(256)))
		} else {
			ip = net.IP(randBytes(r, 16))
			ip[0] = 0x20
		}
		text := ip.String()
		if i%10 == 3 {
			text = "::ffff:" + net.IPv4(1, 2, 3, byte(r.IntN(256))).String()
		}
		return connIn{masterKey(r), text}
	}, func(in connIn) string {
		key, _ := connectionstore.Key(clientip.SetContext(context.Background(), in.IP), in.Secret)
		return key
	})

	type revisionFields struct {
		MediaFileID int   `json:"media_file_id"`
		FileSize    int64 `json:"file_size"`
		FileMod     int64 `json:"file_mod"`
		FileHash    S     `json:"file_hash"`
		ProbeMod    int64 `json:"probe_mod"`
		VideoIndex  int   `json:"video_index"`
		Signature   S     `json:"signature"`
	}
	genRevision := func(r *rand.Rand) revisionFields {
		if r.IntN(4) == 0 {
			return revisionFields{}
		}
		return revisionFields{posInt(r), r.Int64N(1 << 40), r.Int64N(1 << 62), S(pick(r, []string{"", randHex(r, 8), "<&>"})), r.Int64N(1 << 62), r.IntN(3), S(text(r))}
	}
	toRevision := func(f revisionFields) tonemap.SourceRevision {
		return tonemap.SourceRevision{MediaFileID: f.MediaFileID, FileSize: f.FileSize, FileModifiedUnixNano: f.FileMod, FileHash: string(f.FileHash), ProbeUpdatedUnixNano: f.ProbeMod, VideoStreamIndex: f.VideoIndex, StreamSignature: string(f.Signature)}
	}
	type revisionOut struct {
		Fingerprint string `json:"fingerprint"`
		Encoded     string `json:"encoded"`
		IsZero      bool   `json:"is_zero"`
	}
	det("tonemap_revision", "internal/tonemap SourceRevision", 500, func(r *rand.Rand, _ int) revisionFields { return genRevision(r) }, func(in revisionFields) revisionOut {
		rev := toRevision(in)
		return revisionOut{rev.Fingerprint(), rev.Encode(), rev.IsZero()}
	})

	type paramsIn struct {
		Format, Container, Video, Audio, Resolution S
		Track, Bitrate                              int
		BurnIn                                      bool
		Policy, Mode, Kind, Recipe                  S
		Preflight                                   bool
		Revision                                    revisionFields
	}
	det("downloads_params_hash", "internal/downloads paramsHashWithToneMapRevision", 600, func(r *rand.Rand, i int) paramsIn {
		in := paramsIn{Format: S(text(r)), Container: S(text(r)), Video: S(text(r)), Audio: S(text(r)), Resolution: S(text(r)), Track: smallInt(r), Bitrate: smallInt(r), BurnIn: r.IntN(2) == 0}
		if i%2 == 0 {
			in.Policy = S(pick(r, []string{"", "none", "off", "auto"}))
			in.Mode = S(pick(r, []string{"", "hable"}))
			in.Kind = S(pick(r, []string{"", "dv"}))
			in.Recipe = S(pick(r, []string{"", "v3"}))
			in.Preflight = r.IntN(3) == 0
			in.Revision = genRevision(r)
		}
		return in
	}, func(in paramsIn) string {
		return downloads.VectorParamsHash(string(in.Format), string(in.Container), string(in.Video), string(in.Audio), string(in.Resolution), in.Track, in.Bitrate, in.BurnIn, string(in.Policy), string(in.Mode), string(in.Kind), string(in.Recipe), in.Preflight, toRevision(in.Revision))
	})

	type etagIn struct {
		ID, Format, Quality, Effective S
		Revision, Bitrate              int
		Size                           int64
		Modified                       *int64
	}
	det("downloads_metadata_etag", "internal/downloads buildIntegrity", 500, func(r *rand.Rand, _ int) etagIn {
		var mod *int64
		if r.IntN(3) > 0 {
			v := 1_700_000_000_000_000_000 + r.Int64N(1e15)
			if r.IntN(2) == 0 {
				v -= v % 1e9
			}
			mod = &v
		}
		return etagIn{S(text(r)), S(text(r)), S(text(r)), S(text(r)), smallInt(r), smallInt(r), r.Int64N(1 << 40), mod}
	}, func(in etagIn) string {
		var mod *time.Time
		if in.Modified != nil {
			t := time.Unix(0, *in.Modified).In(time.FixedZone("", 3600))
			mod = &t
		}
		return downloads.VectorMetadataETag(string(in.ID), in.Revision, string(in.Format), string(in.Quality), string(in.Effective), in.Bitrate, in.Size, mod)
	})

	type prepareOut struct {
		Fingerprint string `json:"fingerprint"`
		JSON        string `json:"json"`
	}
	det("downloads_execution_fingerprint", "internal/downloadprepare Request", 600, func(r *rand.Rand, _ int) downloadprepare.Request {
		var req downloadprepare.Request
		fill(r, reflectValue(&req))
		req.InputPath = "/m/<a&b>/" + text(r)
		if r.IntN(2) == 0 {
			req.ToneMapSourceRevision = toRevision(genRevision(r))
		}
		switch r.IntN(4) {
		case 0:
			req.PreparedTracks = &playback.PreparedTracks{}
		case 1:
			tracks := &playback.PreparedTracks{Audio: []playback.PreparedAudioTrack{}}
			for range r.IntN(3) {
				var a playback.PreparedAudioTrack
				fill(r, reflectValue(&a))
				tracks.Audio = append(tracks.Audio, a)
			}
			for range r.IntN(3) {
				var s playback.PreparedSubtitleTrack
				fill(r, reflectValue(&s))
				tracks.Subtitles = append(tracks.Subtitles, s)
			}
			req.PreparedTracks = tracks
		}
		return req
	}, func(in downloadprepare.Request) prepareOut {
		in2 := in
		in2.ArtifactID, in2.LogSessionID = "", ""
		raw, _ := marshalGo(in2)
		return prepareOut{in.ExecutionFingerprint(), string(raw)}
	})

	type markerIn struct {
		ID, Size, Duration, Season, Episode   int64
		Hash, Content, EpisodeID, Extra, Path S
		Modified                              *int64
		Kind                                  S
		Start, End                            float64
	}
	type markerOut struct {
		File  string `json:"file"`
		Thumb string `json:"thumb"`
	}
	det("marker_identity", "internal/models MarkerFileIdentity", 500, func(r *rand.Rand, _ int) markerIn {
		var mod *int64
		if r.IntN(3) > 0 {
			v := 1_700_000_000_000_000_000 + r.Int64N(1e15)
			mod = &v
		}
		return markerIn{int64(posInt(r)), r.Int64N(1 << 40), int64(r.IntN(10000)), int64(r.IntN(30)), int64(r.IntN(30)), S(text(r)), S(text(r)), S(text(r)), S(text(r)), S(text(r)), mod, S(pick(r, []string{"intro", "credits"})), randFloat(r), randFloat(r)}
	}, func(in markerIn) markerOut {
		f := models.MediaFile{ID: int(in.ID), FileHash: string(in.Hash), FileSize: in.Size, Duration: int(in.Duration), ContentID: string(in.Content), EpisodeID: string(in.EpisodeID), ExtraID: string(in.Extra), SeasonNumber: int(in.Season), EpisodeNumber: int(in.Episode), FilePath: string(in.Path)}
		if in.Modified != nil {
			t := time.Unix(0, *in.Modified).UTC()
			f.FileModifiedAt = &t
		}
		return markerOut{models.MarkerFileIdentity(&f), models.MarkerThumbnailIdentity(&f, models.MarkerSegment{Kind: string(in.Kind), StartSeconds: in.Start, EndSeconds: in.End})}
	})

	type tagIn struct {
		Secret   string `json:"secret"`
		Route    S      `json:"route"`
		Type     S      `json:"type"`
		Size     S      `json:"size"`
		RawPath  S      `json:"raw_path"`
		Thumb    S      `json:"thumb"`
		Updated  *int64 `json:"updated"`
		Fallback S      `json:"fallback"`
		Key      string `json:"key"`
	}
	type tagOut struct {
		Seed    S      `json:"seed"`
		Tag     string `json:"tag"`
		Collage string `json:"collage"`
	}
	det("jellycompat_image_tags", "internal/jellycompat image_tag_signer", 700, func(r *rand.Rand, _ int) tagIn {
		var updated *int64
		if r.IntN(2) == 0 {
			v := 1_700_000_000_000_000_000 + r.Int64N(1e15)
			updated = &v
		}
		return tagIn{pick(r, []string{masterKey(r), masterKey(r), "  "}), S(text(r)), S(pick(r, []string{"Primary", "BACKDROP", " Logo "})), S(pick(r, []string{"small", "medium", ""})), S(pick(r, []string{"", " /a/b.webp ", text(r)})), S(pick(r, []string{"", "abc="})), updated, S(text(r)), randHex(r, 8)}
	}, func(in tagIn) tagOut {
		var updated time.Time
		if in.Updated != nil {
			updated = time.Unix(0, *in.Updated).UTC()
		}
		seed := jellycompat.VectorImageTagSeed(string(in.Route), string(in.Type), string(in.Size), string(in.RawPath), string(in.Thumb), updated)
		out := tagOut{Seed: S(seed), Tag: jellycompat.VectorImageTag(in.Secret, seed, string(in.Fallback))}
		if strings.TrimSpace(in.Secret) != "" {
			out.Collage = jellycompat.VectorCollageTag(in.Secret, string(in.Route), in.Key)
		}
		return out
	})

	type misc struct {
		Fn string `json:"fn"`
		A  S      `json:"a"`
		B  S      `json:"b"`
		C  S      `json:"c"`
		D  S      `json:"d"`
		E  S      `json:"e"`
		F  S      `json:"f"`
		N  int64  `json:"n"`
		M  int64  `json:"m"`
		T  bool   `json:"t"`
		U  bool   `json:"u"`
		L  []S    `json:"l"`
	}
	strs := func(l []S) []string {
		out := make([]string, len(l))
		for i, s := range l {
			out[i] = string(s)
		}
		return out
	}
	miscFns := map[string]func(misc) string{
		"collection_collage_key":     func(m misc) string { return catalog.CollectionCollageKey(strs(m.L)) },
		"media_artifact_config_hash": func(m misc) string { return mediaartifact.ConfigHash(string(m.A), string(m.B)) },
		"translation_idempotency": func(m misc) string {
			return translation.VectorIdempotencyKey(string(m.A), string(m.B), string(m.C), string(m.D), m.T, m.U)
		},
		"translation_legacy": func(m misc) string {
			return translation.VectorLegacyIdempotencyKey(string(m.A), string(m.B), string(m.C), string(m.D))
		},
		"generated_work_id": func(m misc) string { return literaryworks.VectorGeneratedWorkID(string(m.A), strs(m.L)) },
		"sidecar_entry":     func(m misc) string { return metadata.VectorSidecarEntryKey(string(m.A), m.N, m.M) },
		"sidecar_hash":      func(m misc) string { return metadata.VectorHashSidecarEntries(strs(m.L)) },
		"uploaded_source": func(m misc) string {
			sum := sha256.Sum256([]byte(m.A))
			return metadata.VectorUploadedSourcePrefix() + "sha256:" + hex.EncodeToString(sum[:])
		},
		"variant_revision": func(m misc) string {
			result := &imageutil.VariantResult{Ext: string(m.A)}
			for i, key := range m.L {
				result.Variants = append(result.Variants, imageutil.Variant{Key: string(key), Data: []byte(fmt.Sprintf("data-%d-%s", i%3, m.B))})
			}
			return imagecache.VectorVariantRevision(result)
		},
		"meili_schema_version": func(m misc) string {
			return strconv.Itoa(catalog.VectorMeiliSchemaVersion(string(m.A), strs(m.L), m.T, m.U))
		},
		"local_sidecar_lock": func(m misc) string {
			return strconv.FormatInt(metadata.VectorLocalSidecarLockKey(int(m.N), string(m.A)), 10)
		},
		"profile_refresh_lock": func(m misc) string {
			return strconv.FormatInt(recommendations.VectorProfileRefreshLock(int(m.N), string(m.A)), 10)
		},
		"rotation_uniform": func(m misc) string {
			return strconv.FormatUint(math.Float64bits(recommendations.VectorRotationUniform(string(m.A), string(m.B), string(m.C))), 16)
		},
		"rotation_index": func(m misc) string {
			count := int(m.N%20) + 1
			if m.T {
				count = 0
			}
			days := int(m.M%40) - 2
			return strconv.Itoa(recipes.RotationIndex(time.Unix(1_700_000_000+m.M*86400, 0).UTC(), string(m.A), count, days))
		},
		"cloudflare_url": func(m misc) string {
			return s3client.VectorCloudflareTokenURL(string(m.A), string(m.B), string(m.C), string(m.D), m.N)
		},
		"delivery_scope": func(m misc) string {
			return s3client.VectorDeliveryScope(string(m.A), string(m.B), string(m.C), string(m.D), string(m.E), string(m.F))
		},
		"webhook_signature": func(m misc) string { return notifications.SignGenericWebhook(string(m.A), m.N, []byte(m.B)) },
		"ebook_cache_key": func(m misc) string {
			return ebookconvert.SourceKey{FileID: int(m.N), Size: m.M, ModTimeNano: m.N + m.M, Checksum: string(m.A)}.CacheKey()
		},
		"ebook_module_version": func(misc) string { return ebookconvert.ModuleVersion() },
		"library_refresh_lock": func(m misc) string {
			return strconv.FormatInt(adminjob.VectorLibraryRefreshLockKey(int(m.N)-(1<<29)), 10)
		},
	}
	miscNames := sortedKeys(miscFns)
	det("persisted_hashes", "owning packages listed in the function names", 500*len(miscNames), func(r *rand.Rand, i int) misc {
		list := make([]S, r.IntN(5))
		for j := range list {
			list[j] = S(text(r))
		}
		return misc{miscNames[i%len(miscNames)], S(text(r)), S(text(r)), S(text(r)), S(text(r)), S(text(r)), S(text(r)), int64(r.IntN(1 << 30)), int64(r.IntN(1 << 20)), r.IntN(2) == 0, r.IntN(2) == 0, list}
	}, func(m misc) string { return miscFns[m.Fn](m) })

	type lockIn struct {
		FileID   int   `json:"file_id"`
		User     int   `json:"user"`
		Mutation S     `json:"mutation"`
		Day      int64 `json:"day"`
		Key      S     `json:"key"`
		Content  S     `json:"content"`
	}
	type lockOut struct {
		Chapter   string `json:"chapter"`
		Mutation  int32  `json:"mutation"`
		DailyMix  string `json:"daily_mix"`
		Backdrop  string `json:"backdrop"`
		Thumbnail string `json:"thumbnail"`
	}
	// These four are written inline in larger Go functions that need a database, so the expressions
	// are repeated here from the cited lines and pinned as vectors.
	det("inline_hash_expressions", "scanner/file_repo_chapter_lock.go:101, pgstore/setting_mutation_tx.go:43, sections/daily_mix.go:68, metadata/image_cache_processor.go:1041, chapterthumbs/service.go:953", 500, func(r *rand.Rand, _ int) lockIn {
		return lockIn{posInt(r), posInt(r), S(text(r)), r.Int64N(30000), S(text(r)), S(contentIDInput(r))}
	}, func(in lockIn) lockOut {
		d := sha256.Sum256([]byte("silo-chapter-thumbnails:" + strconv.Itoa(in.FileID)))
		h := fnvNew32a()
		_, _ = h.Write([]byte(strconv.Itoa(in.User)))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(in.Mutation))
		mix := sha256.Sum256([]byte(string(in.Key) + "|" + strconv.FormatInt(in.Day, 10) + "|" + string(in.Content)))
		data := sha256.Sum256([]byte(in.Content))
		pathD := sha256.Sum256([]byte(in.Key))
		return lockOut{
			strconv.FormatInt(int64(binary.BigEndian.Uint64(d[:8])), 10),
			int32(h.Sum32()),
			strconv.FormatUint(binary.BigEndian.Uint64(mix[:8]), 10),
			hex.EncodeToString(data[:4]) + "-" + hex.EncodeToString(pathD[:4]),
			fmt.Sprintf("%s%d/%s-%x/w%d.webp", "chapter-images/", in.FileID, in.Key, data, in.User%3000),
		}
	})

	det("uuid_v5_ids", "uuid.NewSHA1 at cmd/silo/main.go:963 and internal/config", 500, func(r *rand.Rand, i int) S {
		return S(text(r))
	}, func(in S) []string {
		return []string{
			uuid.NewSHA1(uuid.NameSpaceOID, []byte(in)).String(),
			uuid.NewSHA1(uuid.NameSpaceURL, []byte(in)).String(),
			uuid.NewSHA1(uuid.NameSpaceURL, []byte("https://silo.local/jellycompat")).String(),
			config.VectorDefaultServerID(),
		}
	})

	registerJCS()
	registerNormalization()
}

func registerJCS() {
	type jcsIn struct {
		Raw S `json:"raw"`
	}
	type jcsOut struct {
		Error     bool `json:"error"`
		Canonical S    `json:"canonical"`
		Public    S    `json:"public"`
	}
	det("settings_jcs", "internal/settingscontract canonicalize", 700, func(r *rand.Rand, i int) jcsIn {
		num := func() string {
			return pick(r, []string{"0", "-0", "1", "1.0", "1.50", "100", "1e21", "1e20", "1e-6", "1e-7", "0.000001", "123456789012345678901234", "4.35", "0.1", "1E+2", "-1.5e-9", "1e400", "5e-324", "1.7976931348623157e308", "9007199254740993"})
		}
		str := func() string {
			return pick(r, []string{`"plain"`, `"<&>"`, `"é"`, `"é"`, `"😀"`, `"😀"`, `"\u0007"`, `"\u001f"`, `"\b\f\n\r\t"`, `"\""`, `"\\"`, `"\/"`, `" "`, `"\ud800"`, `"\udc00"`, `"\ud800x"`, "\"\xff\""})
		}
		var val func(depth int) string
		val = func(depth int) string {
			switch r.IntN(7) {
			case 0:
				return num()
			case 1:
				return str()
			case 2:
				return pick(r, []string{"null", "true", "false"})
			case 3:
				if depth > 0 {
					return "[" + val(depth-1) + " , " + val(depth-1) + "]"
				}
			case 4, 5:
				if depth > 0 {
					keys := []string{`"b"`, `"a"`, `"é"`, `"éx"`, `"😀"`, `""`, `"notes"`, `"definitions"`, `"B"`}
					n := r.IntN(4)
					parts := []string{}
					for range n {
						parts = append(parts, pick(r, keys)+": "+val(depth-1))
					}
					return "{" + strings.Join(parts, ",") + "}"
				}
			}
			return `"leaf"`
		}
		doc := val(3)
		if i%10 == 0 {
			doc = `{"definitions":[{"key":"a","notes":"strip me","z":1.0},{"notes":null},3,"x"],"notes":"keep"}`
		}
		return jcsIn{S(doc)}
	}, func(in jcsIn) jcsOut {
		canonical, err := settingscontract.VectorCanonicalize([]byte(in.Raw))
		if err != nil {
			return jcsOut{Error: true}
		}
		public, err := settingscontract.VectorBuildPublic([]byte(in.Raw))
		if err != nil {
			return jcsOut{Error: true}
		}
		return jcsOut{Canonical: S(canonical), Public: S(public)}
	})

	det("settings_ecmascript_number", "internal/settingscontract formatECMAScript", 600, func(r *rand.Rand, _ int) uint64 {
		switch r.IntN(4) {
		case 0:
			return math.Float64bits(float64(r.Int64N(1 << 53)))
		case 1:
			return math.Float64bits(math.Pow(10, float64(r.IntN(600)-300)))
		case 2:
			return math.Float64bits(r.Float64() * math.Pow(10, float64(r.IntN(40)-20)))
		default:
			for {
				bits := r.Uint64()
				if f := math.Float64frombits(bits); !math.IsNaN(f) && !math.IsInf(f, 0) {
					return bits
				}
			}
		}
	}, func(bits uint64) string {
		s, err := settingscontract.VectorFormatECMAScript(math.Float64frombits(bits))
		if err != nil {
			panic(err)
		}
		return s
	})

	type contractOut struct {
		Canonical string `json:"canonical_sha256"`
		Public    string `json:"public_sha256"`
		ETag      string `json:"etag"`
		PublicTag string `json:"public_etag"`
	}
	det("settings_contract_etag", "internal/settingscontract ETag over contracts/settings/v1", 1, func(*rand.Rand, int) string {
		return "contracts/settings/v1"
	}, func(string) contractOut {
		canonical := must(settingscontract.CanonicalBytes())
		public := must(settingscontract.PublicBytes())
		c, p := sha256.Sum256(canonical), sha256.Sum256(public)
		return contractOut{hex.EncodeToString(c[:]), hex.EncodeToString(p[:]), must(settingscontract.ETag()), must(settingscontract.PublicETag())}
	})
}

func registerNormalization() {
	type nfcRow struct {
		CP  rune  `json:"cp"`
		CCC uint8 `json:"ccc"`
		NFC S     `json:"nfc"`
		NFD S     `json:"nfd"`
	}
	nondet("unicode_norm_table", "golang.org/x/text/unicode/norm", 1, func(*rand.Rand, int) int { return 0 }, func(int) ([]nfcRow, error) {
		var rows []nfcRow
		for cp := rune(0); cp <= 0x10FFFF; cp++ {
			if cp >= 0xD800 && cp < 0xE000 {
				continue
			}
			s := string(cp)
			nfc := norm.NFC.String(s)
			nfd := norm.NFD.String(s)
			ccc := norm.NFC.PropertiesString(s).CCC()
			if nfc != s || nfd != s || ccc != 0 {
				rows = append(rows, nfcRow{cp, ccc, S(nfc), S(nfd)})
			}
		}
		return rows, nil
	}, func(_ int, rows []nfcRow) error {
		for _, row := range rows {
			s := string(row.CP)
			if norm.NFC.String(s) != string(row.NFC) || norm.NFD.String(s) != string(row.NFD) || norm.NFC.PropertiesString(s).CCC() != row.CCC {
				return fmt.Errorf("row %x differs", row.CP)
			}
		}
		return nil
	})
}
