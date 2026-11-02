// Command sessioncheck drives internal/auth.SessionRepository against a real Postgres database as
// an oracle for rust/crates/silo-auth's session.rs port. It imports internal/auth as a read-only
// caller; it does not modify it.
//
// Subcommands:
//
//	create  --db <url> --user <id> --session <id> [--device-id X] [--device-platform X] \
//	        [--purpose X] [--bound-profile X] [--ip X]
//	    Creates a session with SessionRepository.Create and prints it back as JSON
//	    (via GetByID, so the printed row is what Go itself reads).
//
//	get     --db <url> --session <id>
//	    Reads a session with SessionRepository.GetByID and prints it as JSON.
//
//	active  --db <url> --session <id> --user <id>
//	    Calls SessionRepository.ActiveSession and prints {"active": bool, "role": "...", ...}.
//
//	oversized --db <url> --session <id> --user <id>
//	    Calls every method that takes a user ID and prints, per method, whether Go returned an
//	    error. Used with a user ID that does not fit int4.
//
// Pin: GOTOOLCHAIN=go1.26.10 go run ./rust/conformance/harness/sessioncheck ...
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Silo-Server/silo-server/internal/auth"
	"github.com/Silo-Server/silo-server/internal/models"
)

type sessionJSON struct {
	ID                 string  `json:"id"`
	UserID             int     `json:"user_id"`
	DeviceName         *string `json:"device_name"`
	DeviceID           string  `json:"device_id"`
	DevicePlatform     string  `json:"device_platform"`
	IPAddress          string  `json:"ip_address"`
	ExpiresAt          string  `json:"expires_at"`
	RevokedAt          *string `json:"revoked_at"`
	ImpersonatorUserID *int    `json:"impersonator_user_id"`
	IdentityID         *int64  `json:"identity_id"`
	Purpose            string  `json:"purpose"`
	BoundProfileID     string  `json:"bound_profile_id"`
}

func toSessionJSON(s *models.AuthSession) sessionJSON {
	out := sessionJSON{
		ID:                 s.ID,
		UserID:             s.UserID,
		DeviceID:           s.DeviceID,
		DevicePlatform:     s.DevicePlatform,
		IPAddress:          s.IPAddress,
		ExpiresAt:          s.ExpiresAt.UTC().Format(time.RFC3339Nano),
		ImpersonatorUserID: s.ImpersonatorUserID,
		IdentityID:         s.IdentityID,
		Purpose:            s.Purpose,
		BoundProfileID:     s.BoundProfileID,
	}
	if s.DeviceName != "" {
		out.DeviceName = &s.DeviceName
	}
	if s.RevokedAt != nil {
		v := s.RevokedAt.UTC().Format(time.RFC3339Nano)
		out.RevokedAt = &v
	}
	return out
}

func mustPool(ctx context.Context, db string) *pgxpool.Pool {
	pool, err := pgxpool.New(ctx, db)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return pool
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: sessioncheck <create|get|active> ...")
		os.Exit(2)
	}
	sub := os.Args[1]
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	db := fs.String("db", "", "DATABASE_URL")
	userID := fs.Int("user", 0, "user id")
	sessionID := fs.String("session", "", "session id")
	deviceID := fs.String("device-id", "", "device id")
	devicePlatform := fs.String("device-platform", "", "device platform")
	purpose := fs.String("purpose", "", "session purpose")
	boundProfile := fs.String("bound-profile", "", "bound profile id")
	ip := fs.String("ip", "", "ip address")
	ttlSeconds := fs.Int("ttl-seconds", 3600, "expires_at = now + ttl")
	_ = fs.Parse(os.Args[2:])

	ctx := context.Background()
	pool := mustPool(ctx, *db)
	defer pool.Close()
	repo := auth.NewSessionRepository(pool)

	switch sub {
	case "create":
		s := models.AuthSession{
			ID:             *sessionID,
			UserID:         *userID,
			DeviceID:       *deviceID,
			DevicePlatform: *devicePlatform,
			Purpose:        *purpose,
			BoundProfileID: *boundProfile,
			IPAddress:      *ip,
			ExpiresAt:      time.Now().Add(time.Duration(*ttlSeconds) * time.Second),
		}
		if err := repo.Create(ctx, s); err != nil {
			fmt.Fprintln(os.Stderr, "create:", err)
			os.Exit(1)
		}
		got, err := repo.GetByID(ctx, s.ID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "get after create:", err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(toSessionJSON(got))
	case "get":
		got, err := repo.GetByID(ctx, *sessionID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "get:", err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(toSessionJSON(got))
	case "active":
		authority, active, err := repo.ActiveSession(ctx, *sessionID, *userID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "active:", err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"active":           active,
			"role":             authority.Role,
			"purpose":          authority.Purpose,
			"bound_profile_id": authority.BoundProfileID,
		})
	case "oversized":
		errored := func(err error) bool { return err != nil }
		results := map[string]bool{}
		_, _, err := repo.ActiveSession(ctx, *sessionID, *userID)
		results["active_session"] = errored(err)
		_, err = repo.ListByUser(ctx, *userID)
		results["list_by_user"] = errored(err)
		_, err = repo.ListByUserPage(ctx, *userID, nil, 10)
		results["list_by_user_page"] = errored(err)
		results["revoke_all_by_user"] = errored(repo.RevokeAllByUser(ctx, *userID))
		results["revoke_all_by_impersonator"] = errored(repo.RevokeAllByImpersonator(ctx, *userID))
		results["create"] = errored(repo.Create(ctx, models.AuthSession{
			ID: *sessionID + "-oversized", UserID: *userID, ExpiresAt: time.Now().Add(time.Hour),
		}))
		results["create_impersonator"] = errored(repo.Create(ctx, models.AuthSession{
			ID: *sessionID + "-oversized-imp", UserID: 1, ImpersonatorUserID: userID, ExpiresAt: time.Now().Add(time.Hour),
		}))
		json.NewEncoder(os.Stdout).Encode(results)
	case "valid":
		valid, err := repo.IsValid(ctx, *sessionID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "valid:", err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"valid": valid})
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand", sub)
		os.Exit(2)
	}
}
