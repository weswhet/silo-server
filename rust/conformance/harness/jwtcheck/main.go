// Command jwtcheck mints and validates tokens with the real internal/auth.JWTService, as an
// oracle/counterparty for rust/crates/silo-auth's claims.rs port's token-level half of this
// task's exit gate ("tokens ... created by Go are accepted by Rust and the reverse"). Read-only
// use of internal/auth; writes nothing under internal/.
//
// Subcommands:
//
//	mint   --secret S --user N --role R --session ID [--access-ttl-s N] [--refresh-ttl-s N]
//	    Prints {"access": "...", "refresh": "..."} minted by Go's JWTService.
//
//	validate --secret S --token T
//	    Parses T with Go's JWTService.ValidateToken and prints the decoded claims as JSON, or
//	    {"error": "..."} and a nonzero exit if Go refuses it.
//
// Pin: GOTOOLCHAIN=go1.26.10 go run ./rust/conformance/harness/jwtcheck ...
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Silo-Server/silo-server/internal/auth"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: jwtcheck <mint|validate> ...")
		os.Exit(2)
	}
	sub := os.Args[1]
	fs := flag.NewFlagSet(sub, flag.ExitOnError)
	secret := fs.String("secret", "", "HMAC secret")
	userID := fs.Int("user", 0, "user id")
	role := fs.String("role", "", "role")
	sessionID := fs.String("session", "", "session id")
	accessTTL := fs.Int("access-ttl-s", 900, "access token ttl seconds")
	refreshTTL := fs.Int("refresh-ttl-s", 2592000, "refresh token ttl seconds")
	token := fs.String("token", "", "token to validate")
	_ = fs.Parse(os.Args[2:])

	svc := auth.NewJWTService(*secret, time.Duration(*accessTTL)*time.Second, time.Duration(*refreshTTL)*time.Second)

	switch sub {
	case "mint":
		access, err := svc.GenerateAccessToken(*userID, *role, *sessionID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "access:", err)
			os.Exit(1)
		}
		refresh, err := svc.GenerateRefreshToken(*userID, *role, *sessionID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "refresh:", err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]string{"access": access, "refresh": refresh})
	case "validate":
		claims, err := svc.ValidateToken(*token)
		if err != nil {
			json.NewEncoder(os.Stdout).Encode(map[string]string{"error": err.Error()})
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{
			"user_id":    claims.UserID,
			"role":       claims.Role,
			"session_id": claims.SessionID,
			"token_type": claims.TokenType,
		})
	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand", sub)
		os.Exit(2)
	}
}
