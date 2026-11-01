//go:build core_vectors

package main

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/rand/v2"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Silo-Server/silo-server/internal/api/handlers"
	"github.com/Silo-Server/silo-server/internal/auth"
	"github.com/Silo-Server/silo-server/internal/autoscan"
	"github.com/Silo-Server/silo-server/internal/blobstore"
	"github.com/Silo-Server/silo-server/internal/cache"
	"github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/downloads"
	"github.com/Silo-Server/silo-server/internal/imagecache"
	"github.com/Silo-Server/silo-server/internal/imageutil"
	"github.com/Silo-Server/silo-server/internal/metadata"
	"github.com/Silo-Server/silo-server/internal/models"
	"github.com/Silo-Server/silo-server/internal/naming"
	"github.com/Silo-Server/silo-server/internal/noderecipe"
	"github.com/Silo-Server/silo-server/internal/nodesessions"
	"github.com/Silo-Server/silo-server/internal/notifications"
	"github.com/Silo-Server/silo-server/internal/playback"
	"github.com/Silo-Server/silo-server/internal/playback/keyframes"
	"github.com/Silo-Server/silo-server/internal/ratelimit"
	"github.com/Silo-Server/silo-server/internal/recommendations/embeddings"
	"github.com/Silo-Server/silo-server/internal/s3client"
	"github.com/Silo-Server/silo-server/internal/settingscontract"
	"github.com/Silo-Server/silo-server/internal/watchtogether"
)

func registerMore() {
	type groupIn struct {
		Type  string `json:"type"`
		Title string `json:"title"`
		Year  int    `json:"year"`
		Root  string `json:"root"`
		Path  string `json:"path"`
	}
	type groupOut struct {
		Key        string `json:"key"`
		Comparable string `json:"comparable"`
	}
	titlePieces := []string{"The", "a", "An", "Matrix", "Part", "II", "iii", "Two", "first", "x²", "₃", "1", "007", "&", "What's", "S.H.I.E.L.D.", "shield", "Agents", "of", "Hunter", "Justice Is Gray", "Justice is Grey", "[tmdb-123]", "{imdb-tt1}", "[tvdbid={x}]", "Élan", "ÉCOLE", "日本語", "Ⅱ", "-", "_", ".", "ſ", "K"}
	det("naming_group_key", "internal/naming makeContentGroupKey", 900, func(r *rand.Rand, i int) groupIn {
		var title string
		switch i % 4 {
		case 0:
			title = text(r)
		default:
			parts := make([]string, 1+r.IntN(6))
			for j := range parts {
				parts[j] = pick(r, titlePieces)
			}
			title = strings.Join(parts, pick(r, []string{" ", ".", "_", "  "}))
		}
		return groupIn{pick(r, []string{"movie", "series"}), title, pick(r, []int{0, 7, 1999, 2024, -1, 12345}), pick(r, []string{"", "/media/movies", "/a/../b/", "rel/x/"}), "/media/" + text(r)}
	}, func(in groupIn) groupOut {
		return groupOut{naming.VectorMakeContentGroupKey(in.Type, in.Title, in.Year, in.Root, in.Path), naming.VectorNormalizeGroupComparable(in.Title)}
	})

	type presentationIn struct {
		Base    string `json:"base"`
		Matched string `json:"matched"`
	}
	det("naming_presentation_group", "internal/naming normalizePresentationGroup", 500, func(r *rand.Rand, _ int) presentationIn {
		base := text(r) + pick(r, []string{" CD1", ".part.2", "-disc_3", "  pt 4"})
		return presentationIn{base, pick(r, []string{"CD1", "part.2", "disc_3", " pt 4", "", "absent"})}
	}, func(in presentationIn) string { return naming.VectorNormalizePresentationGroup(in.Base, in.Matched) })

	type personIn struct {
		ID        int    `json:"id"`
		Name      string `json:"name"`
		Kind      int    `json:"kind"`
		Character string `json:"character"`
		Sort      int    `json:"sort"`
	}
	type embedIn struct {
		Type, Title, Overview, ContentRating, Tagline, Language string
		Year                                                    int
		Genres, Keywords, Studios, Networks, Countries          []string
		People                                                  []personIn
	}
	list := func(r *rand.Rand, n int) []string {
		out := make([]string, r.IntN(n))
		for i := range out {
			out[i] = text(r)
		}
		return out
	}
	det("embedding_text", "internal/recommendations/embeddings BuildEmbeddingText", 700, func(r *rand.Rand, i int) embedIn {
		in := embedIn{Type: pick(r, []string{"movie", "series", "audiobook", "ebook", "other"}), Title: text(r), Overview: pick(r, []string{"", text(r), strings.Repeat("é日", 700)}), ContentRating: pick(r, []string{"", "PG"}), Tagline: pick(r, []string{"", text(r)}), Language: pick(r, []string{"", "en"}), Year: pick(r, []int{0, 1999, -1}), Genres: list(r, 3), Keywords: list(r, 8), Studios: list(r, 3), Networks: list(r, 3), Countries: list(r, 4)}
		for range r.IntN(9) {
			in.People = append(in.People, personIn{r.IntN(5), pick(r, []string{"A", "B", "Ana", text(r)}), pick(r, []int{1, 2, 3, 4, 7, 8}), pick(r, []string{"", "Hero"}), r.IntN(3)})
		}
		return in
	}, func(in embedIn) string {
		item := &models.MediaItem{Type: in.Type, Title: in.Title, Overview: in.Overview, ContentRating: in.ContentRating, Tagline: in.Tagline, OriginalLanguage: in.Language, Year: in.Year, Genres: in.Genres, Keywords: in.Keywords, Studios: in.Studios, Networks: in.Networks, Countries: in.Countries}
		for _, p := range in.People {
			person := models.ItemPerson{Kind: models.PersonKind(p.Kind), Character: p.Character, SortOrder: p.Sort}
			person.ID = int64(p.ID)
			person.Name = p.Name
			item.People = append(item.People, person)
		}
		return embeddings.BuildEmbeddingText(item)
	})

	type planIn struct {
		Keyframes []float64 `json:"keyframes"`
		Segment   float64   `json:"segment"`
		End       float64   `json:"end"`
		Planned   bool      `json:"planned"`
	}
	type planOut struct {
		Starts    []float64 `json:"starts"`
		Durations []float64 `json:"durations"`
		Record    string    `json:"record"`
	}
	det("keyframe_plan", "internal/playback/keyframes and copyPlanRecord", 700, func(r *rand.Rand, i int) planIn {
		var frames []float64
		at := pick(r, []float64{0, 0.28, 1.001, 10.5})
		for range r.IntN(40) {
			frames = append(frames, at)
			at += float64(r.IntN(6000)) / 1000
		}
		return planIn{frames, pick(r, []float64{0, 2, 6, 4.004, -1}), at - float64(r.IntN(4000))/1000, r.IntN(2) == 0}
	}, func(in planIn) planOut {
		starts := keyframes.PlanSegments(in.Keyframes, in.Segment)
		durations := keyframes.SegmentDurations(starts, in.End)
		record := must(playback.VectorCopyPlanRecord(in.Planned, durations))
		return planOut{starts, durations, string(record)}
	})

	det("search_fold", "internal/catalog foldSearchDiacritics", 700, func(r *rand.Rand, i int) string {
		if i%3 == 0 {
			return pick(r, []string{"Pokémon", "Ærø", "Łódź", "straße", "ẞ", "ĦŦŀ", "œuvre", "Đoàn", "ı", "plain ascii", "é", "ñ"}) + text(r)
		}
		return text(r)
	}, catalog.VectorFoldSearchDiacritics)

	type blobIn struct {
		Key      S      `json:"key"`
		Endpoint string `json:"endpoint"`
		Prefix   string `json:"prefix"`
		ObjKey   string `json:"obj_key"`
	}
	type blobOut struct {
		Valid    bool   `json:"valid"`
		Endpoint string `json:"endpoint"`
		Prefix   string `json:"prefix"`
		Prefixed string `json:"prefixed"`
	}
	det("blobstore_keys", "internal/blobstore and s3client", 700, func(r *rand.Rand, i int) blobIn {
		key := pick(r, []string{"a/b.webp", "/a", "a//b", "a/./b", "a/../b", "a/.tmp-x", "a/.probe-1", "a\\b", "", "a\x01b", "a\u0085b", strings.Repeat("a", 1024), strings.Repeat("a", 1025), text(r)})
		endpoint := pick(r, []string{"https://S3.Example.COM", "HTTPS://s3.amazonaws.com/", "http://LOCALHOST:9000/Path/Sub", " https://A.b ", "not a url", "S3.AMAZONAWS.COM", "http://U:P@Host/x?y=Z", "https://host/a%20b", "", "://bad"})
		return blobIn{S(key), endpoint, pick(r, []string{"", "prefix", "/a/b/", " x/ "}), pick(r, []string{"k", "/k/l", "", "//"})}
	}, func(in blobIn) blobOut {
		return blobOut{blobstore.ValidateKey(string(in.Key)) == nil, blobstore.NormalizeEndpoint(in.Endpoint), s3client.NormalizeKeyPrefix(in.Prefix), s3client.VectorPrefixedKey(in.Prefix, in.ObjKey)}
	})

	type presignIn struct {
		Endpoint  string `json:"endpoint"`
		Region    string `json:"region"`
		Access    string `json:"access"`
		Secret    string `json:"secret"`
		PathStyle bool   `json:"path_style"`
		Bucket    string `json:"bucket"`
		Prefix    string `json:"prefix"`
		Key       S      `json:"key"`
		NowNanos  int64  `json:"now_nanos"`
		Expiry    int64  `json:"expiry_seconds"`
		Window    int64  `json:"window_seconds"`
	}
	type presignOut struct {
		URL        string `json:"url"`
		ExpiresSec int64  `json:"expires_unix"`
	}
	det("s3_presign", "internal/s3client PresignGetURLAt through aws-sdk-go-v2", 700, func(r *rand.Rand, i int) presignIn {
		key := pick(r, []string{"tmdb/movie/1/poster/original.abc.webp", "a b/c+d", "ünï/✓.webp", "x'y(z)!*", "a&b=c?d#e", "%zz", "a//b", "~tilde_-.", text(r) + "k"})
		return presignIn{pick(r, []string{"https://s3.example.com", "http://minio:9000", "https://s3.us-east-1.amazonaws.com"}), pick(r, []string{"us-east-1", "eu-west-2", "auto"}), "AK" + randHex(r, 8), randHex(r, 20), r.IntN(3) > 0, pick(r, []string{"artwork", "my-bucket"}), pick(r, []string{"", "pre/fix"}), S(key), 1_800_000_000_000_000_000 + r.Int64N(1e15), pick(r, []int64{60, 3600, 86400}), pick(r, []int64{0, 900, 3600, 600000})}
	}, func(in presignIn) presignOut {
		c := s3client.NewClient(s3client.BucketConfig{Endpoint: in.Endpoint, Region: in.Region, AccessKey: in.Access, SecretKey: in.Secret, PathStyle: in.PathStyle, Bucket: in.Bucket, KeyPrefix: in.Prefix})
		url, expires, err := c.PresignGetURLAt(context.Background(), in.Bucket, string(in.Key), time.Unix(0, in.NowNanos), time.Duration(in.Expiry)*time.Second, time.Duration(in.Window)*time.Second)
		if err != nil {
			return presignOut{"error", 0}
		}
		return presignOut{url, expires.Unix()}
	})

	type thumbIn struct {
		W   int `json:"w"`
		H   int `json:"h"`
		Pix H   `json:"pix"`
	}
	det("thumbhash", "imageutil scaleImage and go.n16f.net/thumbhash", 500, func(r *rand.Rand, i int) thumbIn {
		w, h := 1+r.IntN(30), 1+r.IntN(30)
		if i%10 == 0 {
			w, h = 90+r.IntN(40), 90+r.IntN(40)
		}
		pix := make([]byte, 4*w*h)
		mode := r.IntN(3)
		a, b := float64(r.IntN(255)), float64(r.IntN(255))
		for y := range h {
			for x := range w {
				p := pix[(y*w+x)*4:]
				p[0] = byte(int(a+float64(x)*2) % 256)
				p[1] = byte(int(b+float64(y)*3) % 256)
				p[2] = byte((x*y + r.IntN(8)) % 256)
				switch mode {
				case 0:
					p[3] = 255
				case 1:
					p[3] = byte(r.IntN(256))
				default:
					p[3] = pick(r, []byte{0, 255})
				}
			}
		}
		return thumbIn{w, h, H(pix)}
	}, func(in thumbIn) string { return imageutil.VectorThumbhash(in.W, in.H, in.Pix) })

	type channelIn struct {
		Channel string `json:"channel"`
		DB      int    `json:"db"`
		Type    string `json:"type"`
		Payload string `json:"payload"`
		Key     string `json:"key"`
		User    int    `json:"user"`
	}
	type channelOut struct {
		Channel string `json:"channel"`
		Event   string `json:"event"`
		Attempt string `json:"attempt"`
		Search  string `json:"search"`
	}
	det("redis_channels_events", "internal/cache, ratelimit, catalog", 600, func(r *rand.Rand, _ int) channelIn {
		return channelIn{pick(r, []string{cache.ChannelCatalog, cache.ChannelAdmin, cache.ChannelPlayback, cache.ChannelLogs, cache.ChannelEvents}), pick(r, []int{0, 1, 5, 15, -1}), text(r), text(r), text(r), smallInt(r)}
	}, func(in channelIn) channelOut {
		event, _ := json.Marshal(cache.Event{Type: in.Type, Payload: in.Payload})
		return channelOut{cache.VectorRedisChannel(in.Channel, in.DB), string(event), ratelimit.VectorAttemptKey(in.Key), catalog.VectorSearchSessionPrefix(in.User)}
	})

	type pushIn struct {
		User                                                 int
		Profile, Token, Environment, Topic, Mode, InstallKey string
		Remove                                               bool
	}
	type pushOut struct {
		Apple   string `json:"apple"`
		Android string `json:"android"`
		KeyHash string `json:"key_hash"`
	}
	// The Apple digest is inline in ApplyApplePushAndFinalize, at notifications/apple_push_ordering.go:96.
	det("push_intent", "internal/notifications apple_push_ordering and android_push_ordering", 500, func(r *rand.Rand, _ int) pushIn {
		return pushIn{posInt(r), text(r), " " + randHex(r, 16) + "AB ", pick(r, []string{"production", "sandbox"}), text(r), pick(r, []string{"alert", "silent"}), randHex(r, 16), r.IntN(2) == 0}
	}, func(in pushIn) pushOut {
		apple, _ := json.Marshal(struct {
			User                                         int
			Profile, TokenHash, Environment, Topic, Mode string
		}{in.User, in.Profile, notifications.VectorAPNsTokenHash(in.Token), in.Environment, in.Topic, in.Mode})
		return pushOut{
			notifications.VectorPushDigest(apple),
			notifications.VectorAndroidPushIntent(notifications.AndroidPushCommand{UserID: in.User, ProfileID: in.Profile, Token: in.Token, PushMode: in.Mode, Remove: in.Remove}),
			notifications.VectorPushDigest([]byte(in.InstallKey)),
		}
	})

	type digestIn struct {
		Manifest S            `json:"manifest"`
		Schemas  map[string]S `json:"schemas"`
	}
	det("settings_etag_digest", "internal/settingscontract digestWithSchemas", 500, func(r *rand.Rand, _ int) digestIn {
		schemas := map[string]S{}
		for range r.IntN(5) {
			schemas[pick(r, []string{"a.json", "b.json", "z.json", "é.json", "A.json", text(r) + ".json"})] = S(pick(r, []string{`{"b":1,"a":2}`, `[1.0,2]`, `"x"`, `{"é":"<&>"}`, `null`}))
		}
		return digestIn{S(`{"manifest":"` + randHex(r, 8) + `"}`), schemas}
	}, func(in digestIn) string {
		schemas := map[string][]byte{}
		for k, v := range in.Schemas {
			schemas[k] = []byte(v)
		}
		return must(settingscontract.VectorDigest([]byte(in.Manifest), schemas))
	})

	type baseIn struct {
		Provider, ContentType, ContentID, Language, Discriminator, ImageType string
		Season, Episode                                                      *int
	}
	imageTypes := map[string]metadata.ImageType{"poster": metadata.ImagePoster, "backdrop": metadata.ImageBackdrop, "logo": metadata.ImageLogo, "still": metadata.ImageStill, "profile": metadata.ImageProfile, "banner": metadata.ImageBanner, "thumb": metadata.ImageThumb, "clearart": metadata.ImageClearArt}
	typeNames := sortedKeys(imageTypes)
	det("artwork_base_path", "internal/imagecache buildBasePath", 500, func(r *rand.Rand, i int) baseIn {
		return baseIn{pick(r, []string{"tmdb", "local", text(r)}), pick(r, []string{"movie", "series"}), contentIDInput(r), pick(r, []string{"", "en", "pt-BR", "zh_Hant", " Ünï ", "a/b", "__x__", text(r)}), pick(r, []string{"", " ab12 ", "ab-cd"}), typeNames[i%len(typeNames)], optInt(r), optInt(r)}
	}, func(in baseIn) string {
		return imagecache.VectorBuildBasePath(imagecache.CacheRequest{ProviderID: in.Provider, ContentType: in.ContentType, ContentID: in.ContentID, Language: in.Language, KeyDiscriminator: in.Discriminator, ImageType: imageTypes[in.ImageType], SeasonNumber: in.Season, EpisodeNumber: in.Episode})
	})

	type mintedOut struct {
		APIKey       string `json:"api_key"`
		UserCode     string `json:"user_code"`
		QuickConnect string `json:"quick_connect"`
		LinkToken    string `json:"link_token"`
		LinkHash     string `json:"link_hash"`
		JWTSecret    string `json:"jwt_secret"`
	}
	nondet("minted_credentials", "internal/auth generators and cmd/silo/main.go:948", 500, func(r *rand.Rand, _ int) int { return r.IntN(1000) }, func(int) (mintedOut, error) {
		key := must(auth.VectorGenerateAPIKey())
		link, hash := must2(auth.NewLinkToken())
		secret := make([]byte, 32)
		_, _ = cryptorand.Read(secret)
		return mintedOut{key, must(auth.VectorRandomUserCode()), must(auth.VectorRandomQuickConnectSecret()), link, hash, base64.StdEncoding.EncodeToString(secret)}, nil
	}, func(_ int, m mintedOut) error {
		digits := func(s string) bool { return strings.Trim(s, "0123456789") == "" }
		upperHex := func(s string) bool { return strings.Trim(s, "0123456789ABCDEF") == "" }
		lowerHex := func(s string) bool { return strings.Trim(s, "0123456789abcdef") == "" }
		switch {
		case !strings.HasPrefix(m.APIKey, "sa_") || len(m.APIKey) != 67 || !lowerHex(m.APIKey[3:]):
			return fmt.Errorf("api key %q", m.APIKey)
		case len(m.UserCode) != 9 || m.UserCode[4] != '-' || !digits(m.UserCode[:4]) || !digits(m.UserCode[5:]) || auth.VectorFormatUserCode(m.UserCode) != m.UserCode:
			return fmt.Errorf("user code %q", m.UserCode)
		case len(m.QuickConnect) != 64 || !upperHex(m.QuickConnect):
			return fmt.Errorf("quick connect secret %q", m.QuickConnect)
		case len(must(base64.RawURLEncoding.DecodeString(m.LinkToken))) != 32 || auth.HashLinkToken(m.LinkToken) != m.LinkHash:
			return fmt.Errorf("link token %q", m.LinkToken)
		case len(must(base64.StdEncoding.DecodeString(m.JWTSecret))) != 32:
			return fmt.Errorf("jwt secret %q", m.JWTSecret)
		}
		return nil
	})

	nondet("advisory_lock_constants", "the literal lock integers in the Go sources", 1, func(*rand.Rand, int) int { return 0 }, func(int) (map[string]int64, error) {
		return readLockConstants()
	}, func(_ int, got map[string]int64) error {
		want, err := readLockConstants()
		if err != nil {
			return err
		}
		if len(got) != len(want) {
			return fmt.Errorf("%d constants, want %d", len(got), len(want))
		}
		for k, v := range want {
			if got[k] != v {
				return fmt.Errorf("%s = %d, want %d", k, got[k], v)
			}
		}
		return nil
	})

	type constantsOut struct {
		Hashes   map[string]string `json:"hashes"`
		Prefixes map[string]string `json:"prefixes"`
	}
	nondet("redis_contract", "the Lua scripts and key prefixes of each owning package", 1, func(*rand.Rand, int) int { return 0 }, func(int) (constantsOut, error) {
		out := constantsOut{Hashes: map[string]string{}, Prefixes: noderecipe.VectorPrefixes()}
		for _, m := range []map[string]string{autoscan.VectorScriptHashes(), ratelimit.VectorScriptHashes(), noderecipe.VectorScriptHashes(), downloads.VectorScriptHashes()} {
			for k, v := range m {
				out.Hashes[k] = v
			}
		}
		for _, m := range []map[string]string{notifications.VectorTicketPrefixes(), nodesessions.VectorPrefixes()} {
			for k, v := range m {
				out.Prefixes[k] = v
			}
		}
		out.Prefixes["SUPPRESS_KEY_PREFIX"] = autoscan.VectorSuppressKeyPrefix()
		out.Prefixes["ROOM_SOCKET_TICKET_PREFIX"] = watchtogether.VectorRoomSocketTicketPrefix()
		out.Prefixes["API_REPLICA_KEY_PREFIX"] = cache.VectorAPIReplicaKeyPrefix()
		out.Prefixes["STREAM_DENY_KEY_PREFIX"] = playback.VectorStreamDenyKeyPrefix()
		out.Prefixes["PLAYBACK_CONTROL_TICKET_PREFIX"] = handlers.VectorControlTicketPrefix()
		return out, nil
	}, func(_ int, got constantsOut) error {
		want := map[string]string{}
		for _, m := range []map[string]string{autoscan.VectorScriptHashes(), ratelimit.VectorScriptHashes(), noderecipe.VectorScriptHashes(), downloads.VectorScriptHashes()} {
			for k, v := range m {
				want[k] = v
			}
		}
		for k, v := range want {
			if got.Hashes[k] != v {
				return fmt.Errorf("script %s: %s, want %s", k, got.Hashes[k], v)
			}
		}
		return nil
	})
}

// lockConstants names every fixed advisory lock integer in the Go tree. Two replicas that disagree on
// one of these lose their mutual exclusion.
var lockConstants = []struct{ file, name, rust string }{
	{"internal/database/migrate.go", "schemaMigrationsLockID", "SCHEMA_MIGRATIONS"},
	{"internal/database/pglock/node_admission.go", "StorageNodeAdmissionLockKey", "STORAGE_NODE_ADMISSION"},
	{"internal/database/pglock/pglock.go", "ArtworkReconcileLockKey", "ARTWORK_RECONCILE"},
	{"internal/taskmanager/repository/postgres_history.go", "taskHistoryCleanupAdvisoryLock", "TASK_HISTORY_CLEANUP"},
	{"internal/taskmanager/tasks/reconcile_requests.go", "requestReconcileAdvisoryLock", "REQUEST_RECONCILE"},
	{"internal/taskmanager/tasks/reconcile_requests.go", "requestTargetWriteAdvisoryLock", "REQUEST_TARGET_WRITE"},
	{"internal/taskmanager/tasks/bulk_metadata_enrichment.go", "bulkMetadataEnrichmentAdvisoryLock", "BULK_METADATA_ENRICHMENT"},
	{"internal/taskmanager/tasks/refresh_all_library_metadata.go", "fullMetadataRefreshAdvisoryLock", "FULL_METADATA_REFRESH"},
	{"internal/taskmanager/tasks/detect_intro_markers.go", "detectMarkersAdvisoryLock", "DETECT_MARKERS"},
	{"internal/taskmanager/tasks/backfill_hdr10plus.go", "hdr10PlusBackfillAdvisoryLock", "HDR10PLUS_BACKFILL"},
	{"internal/taskmanager/tasks/backfill_matroska_track_numbers.go", "matroskaTrackBackfillAdvisoryLock", "MATROSKA_TRACK_BACKFILL"},
	{"internal/taskmanager/tasks/database_maintenance.go", "databaseMaintenanceAdvisoryLock", "DATABASE_MAINTENANCE"},
	{"internal/taskmanager/tasks/recheck_external_identities.go", "recheckExternalIdentitiesAdvisoryLock", "RECHECK_EXTERNAL_IDENTITIES"},
	{"internal/trickplay/service.go", "reconcileLock", "TRICKPLAY_RECONCILE"},
	{"internal/idgen/lease.go", "claimLockKey", "IDGEN_CLAIM"},
	{"internal/auth/repository.go", "InitialSetupAdvisoryLock", "INITIAL_SETUP"},
	{"internal/adminjob/library_refresh.go", "libraryRefreshAdvisoryLockNamespace", "LIBRARY_REFRESH_NAMESPACE"},
	{"internal/catalog/search_index_repo.go", "searchIndexMaintenanceLockID", "SEARCH_INDEX_MAINTENANCE"},
	{"internal/recommendations/embedding_reset.go", "EmbeddingWritersLock", "EMBEDDING_WRITERS"},
	{"internal/recommendations/jobs.go", "embeddingsJobLock", "RECS_EMBEDDINGS_JOB"},
	{"internal/recommendations/jobs.go", "tasteProfilesJobLock", "RECS_TASTE_PROFILES_JOB"},
	{"internal/recommendations/jobs.go", "cowatchJobLock", "RECS_COWATCH_JOB"},
	{"internal/recommendations/jobs.go", "cacheJobLock", "RECS_CACHE_JOB"},
	{"internal/recommendations/jobs.go", "staleSweepLock", "RECS_STALE_SWEEP"},
	{"internal/requests/repository.go", "quotaLockNamespace", "REQUEST_QUOTA_NAMESPACE"},
	{"internal/watchsync/repository.go", "ratingSyncLockClass", "WATCHSYNC_RATING_SYNC_CLASS"},
	{"internal/watchsync/repository.go", "tokenRefreshLockClass", "WATCHSYNC_TOKEN_REFRESH_CLASS"},
	{"internal/userstore/pgstore/setting_mutation_tx.go", "settingMutationAdvisoryClass", "SETTING_MUTATION_CLASS"},
	{"internal/userstore/pgstore/section_overrides.go", "sectionOverridesAdvisoryClass", "SECTION_OVERRIDES_CLASS"},
	{"internal/userstore/pgstore/preference_settings_tx.go", "preferenceSettingsAdvisoryClass", "PREFERENCE_SETTINGS_CLASS"},
	{"internal/scanqueue/repository.go", "libraryClaimAdvisoryLockID", "LIBRARY_CLAIM"},
	{"internal/storagetransition/service.go", "storageTransitionAdmissionLockKey", "STORAGE_TRANSITION_ADMISSION"},
	{"internal/diagnostics/repo.go", "diagnosticQuotaLockNamespace", "DIAGNOSTIC_QUOTA_NAMESPACE"},
	{"internal/apiusage/apiusage.go", "refreshLock", "API_USAGE_REFRESH"},
	{"internal/chapterthumbs/originals_cleanup.go", "originalsCleanupAdvisoryLock", "CHAPTER_ORIGINALS_CLEANUP"},
	{"internal/subtitles/ai/pgrepo.go", "transcribeQuotaLockNamespace", "TRANSCRIBE_QUOTA_NAMESPACE"},
	{"internal/blobgc/sweep.go", "sweepAdvisoryLock", "BLOB_GC_SWEEP"},
	{"internal/extrastills/generator.go", "lockKey", "EXTRA_STILLS"},
	{"internal/downloads/storage_repo.go", "storageMaintenanceLockClassID", "DOWNLOAD_STORAGE_MAINTENANCE_CLASS"},
	{"internal/downloads/repo.go", "downloadQuotaLockClassID", "DOWNLOAD_QUOTA_CLASS"},
	{"internal/metadata/artwork_storage_sweep.go", "artworkStorageSweepAdvisoryLock", "ARTWORK_STORAGE_SWEEP"},
	{"internal/metadata/artwork_release.go", "storedArtworkReleaseAdvisoryLock", "STORED_ARTWORK_RELEASE"},
}

// readLockConstants reads the literal values out of the Go sources.
func readLockConstants() (map[string]int64, error) {
	out := map[string]int64{}
	parsedFiles := map[string]*ast.File{}
	for _, c := range lockConstants {
		parsed := parsedFiles[c.file]
		if parsed == nil {
			var err error
			parsed, err = parser.ParseFile(token.NewFileSet(), c.file, nil, 0)
			if err != nil {
				return nil, err
			}
			parsedFiles[c.file] = parsed
		}
		found := false
		ast.Inspect(parsed, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok || len(spec.Names) != 1 || spec.Names[0].Name != c.name || len(spec.Values) != 1 {
				return true
			}
			if lit, isLit := spec.Values[0].(*ast.BasicLit); isLit {
				v, err := strconv.ParseInt(strings.ReplaceAll(lit.Value, "_", ""), 0, 64)
				if err != nil {
					panic(err)
				}
				out[c.rust] = v
				found = true
			}
			return true
		})
		if !found {
			return nil, fmt.Errorf("%s not found in %s", c.name, c.file)
		}
	}
	// Written inline in SQL at internal/autoscan/repository.go:922.
	out["AUTOSCAN_SOURCE_CLASS"] = 900173
	return out, nil
}

func writeLocks(path string) error {
	values, err := readLockConstants()
	if err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString("//! Every fixed advisory lock integer in the Go tree, read from its source by the format generator. Do\n//! not edit. Go and Rust replicas that disagree on one of these lose their mutual exclusion.\n\n")
	for _, c := range lockConstants {
		fmt.Fprintf(&b, "/// `%s` in `%s`.\npub const %s: i64 = %d;\n\n", c.name, c.file, c.rust, values[c.rust])
	}
	fmt.Fprintf(&b, "/// The literal in the SQL at `internal/autoscan/repository.go:922`.\npub const AUTOSCAN_SOURCE_CLASS: i64 = %d;\n", values["AUTOSCAN_SOURCE_CLASS"])
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func must2[A, B any](a A, b B, err error) (A, B) {
	if err != nil {
		panic(err)
	}
	return a, b
}

// writeLua copies the Lua text out of the Go sources into a Rust module, so nothing retypes it.
func writeLua(path string) error {
	files := []struct{ file, prefix string }{
		{"internal/autoscan/suppress.go", ""}, {"internal/ratelimit/attempts.go", ""}, {"internal/ratelimit/session_quota.go", ""},
		{"internal/ratelimit/redis.go", ""}, {"internal/noderecipe/store.go", ""}, {"internal/downloads/bandwidth.go", ""}, {"internal/catalog/search_session.go", ""},
	}
	names := map[string]string{
		"claimStateScript": "AUTOSCAN_CLAIM_STATE", "releaseStateScript": "AUTOSCAN_RELEASE_STATE", "attemptScript": "RATELIMIT_ATTEMPT",
		"quotaScript": "RATELIMIT_QUOTA", "rateLimitScript": "RATELIMIT_WINDOW", "putNodeRecipeScript": "NODERECIPE_PUT",
		"validateLegacyNodeRecipeScript": "NODERECIPE_VALIDATE_LEGACY", "revokeNodeScript": "NODERECIPE_REVOKE_NODE", "sharedBandwidthScript": "DOWNLOADS_SHARED_BANDWIDTH", "script": "CATALOG_SEARCH_SESSION_PUT",
	}
	var b strings.Builder
	b.WriteString("//! The Lua scripts, copied byte for byte by the format generator from the Go sources. Do not edit.\n\n")
	found := 0
	for _, f := range files {
		fset := token.NewFileSet()
		parsed, err := parser.ParseFile(fset, f.file, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok || len(spec.Names) != 1 || len(spec.Values) != 1 {
				return true
			}
			name, ok := names[spec.Names[0].Name]
			if !ok {
				return true
			}
			lit, ok := spec.Values[0].(*ast.BasicLit)
			if call, isCall := spec.Values[0].(*ast.CallExpr); isCall && len(call.Args) == 1 {
				lit, ok = call.Args[0].(*ast.BasicLit)
			}
			if !ok {
				return true
			}
			text, err := strconv.Unquote(lit.Value)
			if err != nil {
				panic(err)
			}
			fmt.Fprintf(&b, "/// `%s` in `%s`.\npub const %s: &str = %q;\n\n", spec.Names[0].Name, f.file, name, text)
			found++
			return true
		})
	}
	if found != len(names) {
		return fmt.Errorf("found %d of %d scripts", found, len(names))
	}
	return os.WriteFile(path, []byte(strings.TrimRight(b.String(), "\n")+"\n"), 0o644)
}
