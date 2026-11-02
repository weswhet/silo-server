// Command storediff replays rust/conformance/vectors/store/ops.json through the real internal/catalog
// settings repositories and internal/userstore/pgstore, writing one JSON outcome per line. The Rust
// side, rust/crates/silo-store/tests/differential.rs, replays the same file and compares outcomes and
// final table contents.
//
// Commands assume the repository root is the cwd:
//
//	GOTOOLCHAIN=go1.26.10 go run ./rust/conformance/harness/storediff <ops.json> <db-url> <secret-key> <out.jsonl>
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Silo-Server/silo-server/internal/catalog"
	"github.com/Silo-Server/silo-server/internal/secret"
	"github.com/Silo-Server/silo-server/internal/settingscontract"
	"github.com/Silo-Server/silo-server/internal/userstore"
	"github.com/Silo-Server/silo-server/internal/userstore/pgstore"
)

type identityJSON struct {
	Key          string `json:"key"`
	Scope        string `json:"scope"`
	ProfileID    string `json:"profile_id"`
	ClientFamily string `json:"client_family"`
	DeviceID     string `json:"device_id"`
	LibraryID    int    `json:"library_id"`
	SeriesID     string `json:"series_id"`
}

func (i identityJSON) identity() userstore.SettingIdentity {
	return userstore.SettingIdentity{
		Key: i.Key, Scope: settingscontract.Scope(i.Scope), ProfileID: i.ProfileID,
		ClientFamily: settingscontract.ClientFamily(i.ClientFamily), DeviceID: i.DeviceID,
		LibraryID: i.LibraryID, SeriesID: i.SeriesID,
	}
}

type op struct {
	ID               json.RawMessage   `json:"id"`
	Kind             string            `json:"kind"`
	User             string            `json:"user"`
	ExpectError      bool              `json:"expect_error"`
	Key              string            `json:"key"`
	Keys             []string          `json:"keys"`
	Value            json.RawMessage   `json:"value"`
	Values           map[string]string `json:"values"`
	DeriveKey        string            `json:"derive_key"`
	WriteKey         string            `json:"write_key"`
	Suffix           string            `json:"suffix"`
	Identity         identityJSON      `json:"identity"`
	RawValue         string            `json:"raw_value"`
	ExpectedRevision int64             `json:"expected_revision"`
	ProfileID        string            `json:"profile_id"`
	DeviceID         string            `json:"device_id"`
	LibraryID        int               `json:"library_id"`
	SeriesID         string            `json:"series_id"`
	Scope            string            `json:"scope"`
	MutationID       string            `json:"mutation_id"`
	RequestHash      string            `json:"request_hash"`
	Result           json.RawMessage   `json:"result"`
	ExpiresAt        string            `json:"expires_at"`
	Before           string            `json:"before"`
	Query            struct {
		Keys         []string `json:"keys"`
		ProfileIDs   []string `json:"profile_ids"`
		ClientFamily string   `json:"client_family"`
		DeviceID     string   `json:"device_id"`
		LibraryIDs   []int    `json:"library_ids"`
		SeriesIDs    []string `json:"series_ids"`
	} `json:"query"`
}

func (o op) text() string {
	var s string
	if err := json.Unmarshal(o.Value, &s); err != nil {
		log.Fatalf("op %s: value is not a string: %v", o.ID, err)
	}
	return s
}

// classify mirrors the Rust classifiers: the three userstore sentinels, else other_error.
func classify(err error) string {
	switch {
	case errors.Is(err, userstore.ErrSettingValueRevisionConflict):
		return "revision_conflict"
	case errors.Is(err, userstore.ErrInvalidSettingIdentity):
		return "invalid_identity"
	case errors.Is(err, userstore.ErrInvalidSettingValue):
		return "invalid_value"
	}
	return "other_error"
}

func identityMap(id userstore.SettingIdentity) map[string]any {
	return map[string]any{
		"key": id.Key, "scope": string(id.Scope), "profile_id": id.ProfileID, "client_family": string(id.ClientFamily),
		"device_id": id.DeviceID, "library_id": id.LibraryID, "series_id": id.SeriesID,
	}
}

func valueDetail(v *userstore.SettingValue) map[string]any {
	if v == nil {
		return map[string]any{"found": false}
	}
	return map[string]any{"found": true, "revision": v.Revision, "value": string(v.Value), "identity": identityMap(v.SettingIdentity)}
}

func valuesDetail(values []userstore.SettingValue) []map[string]any {
	key := func(v userstore.SettingValue) string {
		return strings.Join([]string{
			string(v.ClientFamily), v.DeviceID, v.Key, fmt.Sprint(v.LibraryID), v.ProfileID, string(v.Scope), v.SeriesID,
		}, "\x00")
	}
	sort.SliceStable(values, func(i, j int) bool { return key(values[i]) < key(values[j]) })
	out := make([]map[string]any, 0, len(values))
	for i := range values {
		out = append(out, valueDetail(&values[i]))
	}
	return out
}

func main() {
	log.SetFlags(0)
	if len(os.Args) != 5 {
		log.Fatal("usage: storediff <ops.json> <db-url> <secret-key> <out.jsonl>")
	}
	ctx := context.Background()
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	var file struct {
		Ops []op `json:"ops"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		log.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	cipher, err := secret.New([]byte(os.Args[3]))
	if err != nil {
		log.Fatal(err)
	}
	raw := catalog.NewServerSettingsRepo(pool)
	enc := catalog.NewEncryptedSettingsRepo(raw, cipher)
	provider := pgstore.NewPostgresProvider(pool)
	store := func(userID int) *pgstore.PostgresUserStore {
		s, err := provider.ForUser(ctx, userID)
		if err != nil {
			log.Fatal(err)
		}
		return s.(*pgstore.PostgresUserStore)
	}
	store1, store2 := store(1), store(2)

	out, err := os.Create(os.Args[4])
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()
	encoder := json.NewEncoder(out)
	for _, o := range file.Ops {
		s := store1
		if o.User == "other" {
			s = store2
		}
		if err := encoder.Encode(run(ctx, o, enc, raw, s)); err != nil {
			log.Fatal(err)
		}
	}
}

func run(ctx context.Context, o op, enc *catalog.EncryptedSettingsRepo, raw *catalog.ServerSettingsRepo, store *pgstore.PostgresUserStore) map[string]any {
	ok := func(detail any) map[string]any {
		m := map[string]any{"id": o.ID, "kind": o.Kind, "ok": true}
		if detail != nil {
			m["detail"] = detail
		}
		return m
	}
	fail := func(kind string) map[string]any {
		return map[string]any{"id": o.ID, "kind": o.Kind, "ok": false, "error_kind": kind}
	}
	result := func(detail any, err error) map[string]any {
		if err != nil {
			return fail(classify(err))
		}
		return ok(detail)
	}
	// uvResult applies expect_error before the outcome, as finish_uv does on the Rust side.
	uvResult := func(v *userstore.SettingValue, err error, withDetail bool) map[string]any {
		if o.ExpectError && err == nil {
			return fail("MISSING_EXPECTED_ERROR")
		}
		if err != nil {
			return fail(classify(err))
		}
		if withDetail {
			return ok(valueDetail(v))
		}
		return ok(valueDetail(nil))
	}

	switch o.Kind {
	case "settings_set":
		return result(nil, enc.Set(ctx, o.Key, o.text()))
	case "settings_raw_set":
		return result(nil, raw.Set(ctx, o.Key, o.text()))
	case "settings_get":
		v, err := enc.Get(ctx, o.Key)
		return result(map[string]any{"value": v}, err)
	case "settings_get_many":
		v, err := enc.GetMany(ctx, o.Keys...)
		return result(map[string]any{"values": v}, err)
	case "settings_get_all":
		all, err := enc.GetAll(ctx)
		filtered := map[string]string{}
		for k, v := range all {
			if strings.HasPrefix(k, "difftest.") {
				filtered[k] = v
			}
		}
		return result(map[string]any{"values": filtered}, err)
	case "settings_set_many":
		return result(nil, enc.SetMany(ctx, o.Values))
	case "settings_set_if_absent":
		inserted, err := enc.SetIfAbsent(ctx, o.Key, o.text())
		return result(map[string]any{"inserted": inserted}, err)
	case "settings_backfill":
		n, err := enc.BackfillSensitiveSettings(ctx)
		if err != nil {
			return fail("other_error")
		}
		return ok(map[string]any{"encrypted_count_nonzero": n > 0})
	case "settings_update_atomic":
		return result(nil, enc.UpdateAtomic(ctx, func(current map[string]string) (map[string]string, error) {
			return map[string]string{o.WriteKey: current[o.DeriveKey] + o.Suffix}, nil
		}))
	case "settings_update_atomic_fail":
		sentinel := errors.New("deliberate validator failure")
		err := enc.UpdateAtomic(ctx, func(map[string]string) (map[string]string, error) { return nil, sentinel })
		if errors.Is(err, sentinel) {
			return fail("validator_error")
		}
		return result(nil, err)
	case "uv_upsert":
		v, err := store.UpsertSettingValue(ctx, o.Identity.identity(), o.Value)
		return uvResult(v, err, true)
	case "uv_upsert_raw_value":
		_, err := store.UpsertSettingValue(ctx, o.Identity.identity(), json.RawMessage(o.RawValue))
		return uvResult(nil, err, false)
	case "uv_get":
		v, err := store.GetSettingValue(ctx, o.Identity.identity())
		return result(valueDetail(v), err)
	case "uv_compare_and_set":
		v, err := store.CompareAndSetSettingValue(ctx, o.Identity.identity(), o.Value, o.ExpectedRevision)
		return uvResult(v, err, true)
	case "uv_delete":
		deleted, err := store.DeleteSettingValue(ctx, o.Identity.identity())
		return result(map[string]any{"deleted": deleted}, err)
	case "uv_delete_for_profile":
		n, err := store.DeleteSettingValuesForProfile(ctx, o.ProfileID)
		return result(map[string]any{"count": n}, err)
	case "uv_delete_for_device":
		n, err := store.DeleteSettingValuesForDevice(ctx, o.ProfileID, o.DeviceID)
		return result(map[string]any{"count": n}, err)
	case "uv_delete_for_library":
		n, err := store.DeleteSettingValuesForLibrary(ctx, o.LibraryID)
		return result(map[string]any{"count": n}, err)
	case "uv_delete_for_series":
		n, err := store.DeleteSettingValuesForSeries(ctx, o.SeriesID)
		return result(map[string]any{"count": n}, err)
	case "uv_list_for_resolution":
		values, err := store.ListSettingValuesForResolution(ctx, userstore.SettingResolutionQuery{
			Keys: o.Query.Keys, ProfileIDs: o.Query.ProfileIDs, ClientFamily: settingscontract.ClientFamily(o.Query.ClientFamily),
			DeviceID: o.Query.DeviceID, LibraryIDs: o.Query.LibraryIDs, SeriesIDs: o.Query.SeriesIDs,
		})
		return result(map[string]any{"values": valuesDetail(values)}, err)
	case "uv_list_all":
		values, err := store.ListAllSettingValues(ctx)
		return result(map[string]any{"values": valuesDetail(values)}, err)
	case "uv_list_by_scope":
		values, err := store.ListSettingValuesByScope(ctx, o.ProfileID, settingscontract.Scope(o.Scope), o.Keys)
		return result(map[string]any{"values": valuesDetail(values)}, err)
	case "uv_mutation_put":
		expires, err := time.Parse(time.RFC3339, o.ExpiresAt)
		if err != nil {
			log.Fatal(err)
		}
		rec, inserted, err := store.PutSettingMutation(ctx, userstore.SettingMutationRecord{
			MutationID: o.MutationID, RequestHash: o.RequestHash, Result: o.Result, ExpiresAt: expires,
		})
		if o.ExpectError && err == nil {
			return fail("MISSING_EXPECTED_ERROR")
		}
		return result(map[string]any{
			"inserted": inserted, "mutation_id": rec.MutationID, "request_hash": rec.RequestHash, "result": string(rec.Result),
		}, err)
	case "uv_mutation_get":
		rec, err := store.GetSettingMutation(ctx, o.MutationID)
		if err != nil {
			return fail(classify(err))
		}
		if rec == nil {
			return ok(map[string]any{"found": false})
		}
		return ok(map[string]any{"found": true, "mutation_id": rec.MutationID, "request_hash": rec.RequestHash, "result": string(rec.Result)})
	case "uv_mutation_delete_expired":
		before, err := time.Parse(time.RFC3339, o.Before)
		if err != nil {
			log.Fatal(err)
		}
		n, err := store.DeleteExpiredSettingMutations(ctx, before)
		return result(map[string]any{"count": n}, err)
	}
	return fail("unknown_op_kind:" + o.Kind)
}
