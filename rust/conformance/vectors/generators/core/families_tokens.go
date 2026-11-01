//go:build core_vectors

package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/Silo-Server/silo-server/internal/access"
	"github.com/Silo-Server/silo-server/internal/apiv2"
	"github.com/Silo-Server/silo-server/internal/audiobooks/abs"
	"github.com/Silo-Server/silo-server/internal/auth"
	"github.com/Silo-Server/silo-server/internal/auth/passwordhash"
	"github.com/Silo-Server/silo-server/internal/streamtoken"
	"github.com/Silo-Server/silo-server/internal/themesongs"
	"github.com/Silo-Server/silo-server/internal/watchtogether"
)

// farFuture is a fixed expiry the real verifiers, which read the wall clock, accept for decades.
const farFuture = int64(4102444800)
const fixedIat = int64(1800000000)

func forgeCursor(secret string, scope apiv2.CursorScope, body string) string {
	mac := apiv2.VectorForge(apiv2.NewCursors([]byte(secret)), scope, []byte(body))
	return base64.RawURLEncoding.EncodeToString([]byte(body)) + "." + base64.RawURLEncoding.EncodeToString(mac)
}

// fill sets every exported field of a struct to a random value, leaving about half at zero.
func fill(r *rand.Rand, v reflect.Value) {
	t := v.Type()
	for i := range t.NumField() {
		f := v.Field(i)
		if t.Field(i).Anonymous || !f.CanSet() || r.IntN(2) == 0 {
			continue
		}
		switch f.Kind() {
		case reflect.String:
			f.SetString(text(r))
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int, reflect.Int64:
			f.SetInt(int64(smallInt(r)))
		case reflect.Float64:
			f.SetFloat(randFloat(r))
		case reflect.Pointer:
			if f.Type().Elem().Kind() == reflect.String {
				s := text(r)
				f.Set(reflect.ValueOf(&s))
			}
		}
	}
}

func decoded(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

type tokenOut struct {
	Token   string          `json:"token"`
	Decoded json.RawMessage `json:"decoded"`
}

func registerTokens() {
	type streamIn struct {
		Secret string             `json:"secret"`
		Iat    int64              `json:"iat"`
		Exp    int64              `json:"exp"`
		Claims streamtoken.Claims `json:"claims"`
	}
	signStream := func(in streamIn) string {
		c := in.Claims
		c.RegisteredClaims = jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Unix(in.Exp, 0)),
			IssuedAt:  jwt.NewNumericDate(time.Unix(in.Iat, 0)),
		}
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(in.Secret))
		if err != nil {
			panic(err)
		}
		return tok
	}
	det("token_stream", "internal/streamtoken", 600, func(r *rand.Rand, i int) streamIn {
		var c streamtoken.Claims
		fill(r, reflect.ValueOf(&c).Elem())
		c.MediaPath = "/media/" + text(r) + "\u0000<&>"
		c.OriginalStartedAtUnixNano = 1_700_000_000_000_000_000 + r.Int64N(1e15) + 1
		return streamIn{masterKey(r), fixedIat, farFuture, c}
	}, func(in streamIn) tokenOut {
		tok := signStream(in)
		claims, err := streamtoken.Verify(tok, in.Secret)
		if err != nil {
			panic(err)
		}
		return tokenOut{tok, decoded(claims)}
	})

	type accessIn struct {
		Secret                 string `json:"secret"`
		TokenType              string `json:"token_type"`
		UserID                 int    `json:"user_id"`
		Role                   string `json:"role"`
		SessionID              string `json:"session_id"`
		ProfileID              string `json:"profile_id"`
		Impersonator           *int   `json:"impersonator"`
		PasswordChangeRequired bool   `json:"password_change_required"`
		APIKeyID               int64  `json:"api_key_id"`
		RateTier               string `json:"rate_tier"`
		FileID                 int    `json:"file_id"`
		SessionPurpose         string `json:"session_purpose"`
		PinRevision            *int64 `json:"pin_revision"`
		Iat                    int64  `json:"iat"`
		Exp                    int64  `json:"exp"`
	}
	det("token_access", "internal/auth JWTService", 600, func(r *rand.Rand, _ int) accessIn {
		s := text
		return accessIn{masterKey(r), pick(r, []string{"access", "refresh", "plugin_access", "apple_push_display", "direct_download_link"}), smallInt(r), pick(r, []string{"admin", "user", s(r)}), s(r), s(r), optInt(r), r.IntN(2) == 0, int64(smallInt(r)), s(r), smallInt(r), s(r), optInt64(r), fixedIat, farFuture}
	}, func(in accessIn) tokenOut {
		c := auth.Claims{UserID: in.UserID, Role: in.Role, SessionID: in.SessionID, ProfileID: in.ProfileID, TokenType: in.TokenType, ImpersonatorUserID: in.Impersonator, PasswordChangeRequired: in.PasswordChangeRequired, APIKeyID: in.APIKeyID, RateTier: in.RateTier, FileID: in.FileID, SessionPurpose: in.SessionPurpose, ProfilePINRevision: in.PinRevision, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Unix(in.Exp, 0)), IssuedAt: jwt.NewNumericDate(time.Unix(in.Iat, 0))}}
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, &c).SignedString([]byte(in.Secret))
		if err != nil {
			panic(err)
		}
		got, err := auth.NewJWTService(in.Secret, time.Hour, time.Hour).ValidateToken(tok)
		if err != nil {
			panic(err)
		}
		return tokenOut{tok, decoded(got)}
	})

	type profileIn struct {
		Secret         string `json:"secret"`
		UserID         int    `json:"user_id"`
		SessionID      string `json:"session_id"`
		ProfileID      string `json:"profile_id"`
		PinRevision    int64  `json:"pin_revision"`
		PolicyRevision int64  `json:"policy_revision"`
		Iat            int64  `json:"iat"`
		Exp            *int64 `json:"exp"`
	}
	det("token_profile", "internal/access ProfileTokenService", 500, func(r *rand.Rand, i int) profileIn {
		var exp *int64
		if i%2 == 0 {
			v := farFuture
			exp = &v
		}
		return profileIn{masterKey(r), smallInt(r), text(r), text(r), int64(smallInt(r)), int64(smallInt(r)), fixedIat, exp}
	}, func(in profileIn) tokenOut {
		tok, err := access.VectorSign(access.ProfileTokenClaims{UserID: in.UserID, SessionID: in.SessionID, ProfileID: in.ProfileID, PINRevision: in.PinRevision, PolicyRevision: in.PolicyRevision}, in.Iat, in.Exp, in.Secret)
		if err != nil {
			panic(err)
		}
		got, err := access.NewProfileTokenService(in.Secret, 0).Validate(tok)
		if err != nil {
			panic(err)
		}
		return tokenOut{tok, decoded(got)}
	})

	type roomIn struct {
		Secret    string `json:"secret"`
		RoomID    string `json:"room_id"`
		UserID    int    `json:"user_id"`
		ProfileID string `json:"profile_id"`
		Iat       int64  `json:"iat"`
		Exp       int64  `json:"exp"`
	}
	det("token_room", "internal/watchtogether RoomTokenService", 500, func(r *rand.Rand, _ int) roomIn {
		return roomIn{masterKey(r), text(r), smallInt(r), text(r), fixedIat, farFuture}
	}, func(in roomIn) tokenOut {
		tok, err := watchtogether.VectorSign(watchtogether.RoomTokenClaims{RoomID: in.RoomID, UserID: in.UserID, ProfileID: in.ProfileID}, in.Iat, in.Exp, in.Secret)
		if err != nil {
			panic(err)
		}
		svc := watchtogether.NewRoomTokenService(in.Secret, time.Hour)
		got, err := svc.Validate(tok)
		if err != nil {
			panic(err)
		}
		proof, _, err := svc.ValidateSocketProof(tok)
		if err != nil || *proof != *got {
			panic(fmt.Sprintf("socket proof: %v", err))
		}
		return tokenOut{tok, decoded(got)}
	})

	type themeIn struct {
		Secret    string `json:"secret"`
		UserID    int    `json:"user_id"`
		ProfileID string `json:"profile_id"`
		SessionID string `json:"session_id"`
		Policy    int64  `json:"policy"`
		Owner     string `json:"owner"`
		Theme     string `json:"theme"`
		Size      int64  `json:"size"`
		Modified  int64  `json:"modified"`
		Converted bool   `json:"converted"`
		Iat       int64  `json:"iat"`
		Exp       int64  `json:"exp"`
	}
	type themeOut struct {
		Key       string          `json:"key"`
		Token     string          `json:"token"`
		Valid     bool            `json:"valid"`
		Converted bool            `json:"converted"`
		Decoded   json.RawMessage `json:"decoded"`
	}
	det("token_theme_grant", "internal/themesongs", 500, func(r *rand.Rand, i int) themeIn {
		return themeIn{masterKey(r), posInt(r), text(r) + "p", text(r) + "s", r.Int64N(1000), text(r), text(r) + "t", r.Int64N(1 << 40), 1_700_000_000_000_000_000 + r.Int64N(1e15), i%2 == 0, fixedIat, farFuture}
	}, func(in themeIn) themeOut {
		svc := themesongs.NewService(nil, in.Secret)
		aud := "theme-audio"
		if in.Converted {
			aud = "theme-audio-aac"
		}
		g := themesongs.Grant{Identity: themesongs.Identity{UserID: in.UserID, ProfileID: in.ProfileID, SessionID: in.SessionID, PolicyRevision: in.Policy}, OwnerID: in.Owner, ThemeID: in.Theme, Size: in.Size, Modified: in.Modified, RegisteredClaims: jwt.RegisteredClaims{Audience: jwt.ClaimStrings{aud}, ExpiresAt: jwt.NewNumericDate(time.Unix(in.Exp, 0)), IssuedAt: jwt.NewNumericDate(time.Unix(in.Iat, 0))}}
		key := themesongs.VectorKey(svc)
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, g).SignedString(key)
		if err != nil {
			panic(err)
		}
		got, err := svc.Validate(tok, in.Owner, in.Theme)
		out := themeOut{Key: fmt.Sprintf("%x", key), Token: tok, Valid: err == nil, Decoded: json.RawMessage("null")}
		if err == nil {
			out.Converted = got.Delivery == themesongs.DeliveryConverted
			out.Decoded = decoded(got)
		}
		return out
	})

	type absIn struct {
		Secret    string `json:"secret"`
		Type      string `json:"type"`
		UserID    string `json:"user_id"`
		ProfileID string `json:"profile_id"`
		PinRev    *int64 `json:"pin_rev"`
		JTI       string `json:"jti"`
		DeviceID  string `json:"device_id"`
		SessionID string `json:"session_id"`
		BookID    string `json:"book_id"`
		FileIdx   int    `json:"file_idx"`
		Iat       int64  `json:"iat"`
		Exp       int64  `json:"exp"`
	}
	det("token_abs", "internal/audiobooks/abs", 500, func(r *rand.Rand, _ int) absIn {
		return absIn{masterKey(r), pick(r, []string{"access", "refresh", "session"}), text(r), text(r), optInt64(r), randHex(r, 13), text(r), text(r), text(r), smallInt(r), fixedIat, farFuture}
	}, func(in absIn) tokenOut {
		c := abs.Claims{Type: in.Type, UserID: in.UserID, ProfileID: in.ProfileID, PINRevision: in.PinRev, JTI: in.JTI, DeviceID: in.DeviceID, SessionID: in.SessionID, BookID: in.BookID, FileIdx: in.FileIdx, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Unix(in.Exp, 0)), IssuedAt: jwt.NewNumericDate(time.Unix(in.Iat, 0))}}
		tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, c).SignedString([]byte(in.Secret))
		if err != nil {
			panic(err)
		}
		got, err := abs.ParseToken([]byte(in.Secret), tok)
		if err != nil {
			panic(err)
		}
		return tokenOut{tok, decoded(got)}
	})

	registerJWTSemantics()
	registerRS256()
	registerVAPID()
	registerBcrypt()
}

// probeClaims stands in for every struct claims type: strings, ints, an exact int64, a float, a
// pointer, and the embedded registered claims.
type probeClaims struct {
	Sid  string  `json:"sid"`
	Uid  int     `json:"uid"`
	Ostn int64   `json:"ostn,omitempty"`
	Seek float64 `json:"seek,omitempty"`
	Flag bool    `json:"flag,omitempty"`
	Rnp  *string `json:"rnp,omitempty"`
	jwt.RegisteredClaims
}

type semanticsIn struct {
	Token    S      `json:"token"`
	Secret   string `json:"secret"`
	Mode     string `json:"mode"`
	NowNanos int64  `json:"now_nanos"`
}

type semanticsOut struct {
	Class   string          `json:"class"`
	Expired bool            `json:"expired"`
	Decoded json.RawMessage `json:"decoded"`
}

func runSemantics(in semanticsIn) (out semanticsOut) {
	defer func() {
		if p := recover(); p != nil {
			out = semanticsOut{Class: "panic", Decoded: json.RawMessage("null")}
		}
	}()
	secret := []byte(in.Secret)
	now := time.Unix(0, in.NowNanos)
	opts := []jwt.ParserOption{jwt.WithTimeFunc(func() time.Time { return now })}
	var keyfunc jwt.Keyfunc
	switch in.Mode {
	case "any_hmac":
		keyfunc = func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return secret, nil
		}
	case "hs256_keyfunc":
		keyfunc = func(t *jwt.Token) (any, error) {
			if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
				return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
			}
			return secret, nil
		}
	case "hs256_required":
		keyfunc = func(*jwt.Token) (any, error) { return secret, nil }
		opts = append(opts, jwt.WithValidMethods([]string{"HS256"}), jwt.WithExpirationRequired())
	default:
		panic("mode")
	}
	claims := new(probeClaims)
	_, err := jwt.ParseWithClaims(string(in.Token), claims, keyfunc, opts...)
	out = semanticsOut{Class: "ok", Decoded: json.RawMessage("null")}
	switch {
	case err == nil:
		out.Decoded = decoded(claims)
	case errors.Is(err, jwt.ErrTokenMalformed):
		out.Class = "malformed"
	case errors.Is(err, jwt.ErrTokenUnverifiable):
		out.Class = "unverifiable"
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		out.Class = "signature_invalid"
	case errors.Is(err, jwt.ErrTokenInvalidClaims):
		out.Class = "invalid_claims"
		out.Expired = errors.Is(err, jwt.ErrTokenExpired)
	default:
		out.Class = "other"
	}
	return out
}

func registerJWTSemantics() {
	const now = int64(1_800_000_000)
	det("jwt_semantics", "github.com/golang-jwt/jwt/v5 under Silo's verifier options", 1500, func(r *rand.Rand, i int) semanticsIn {
		secret := masterKey(r)
		payloads := []string{
			`{"sid":"s","uid":1}`,
			fmt.Sprintf(`{"sid":"s","uid":1,"exp":%d}`, now+60),
			fmt.Sprintf(`{"sid":"s","uid":1,"exp":%d}`, now),
			fmt.Sprintf(`{"sid":"s","uid":1,"exp":%d}`, now-1),
			fmt.Sprintf(`{"exp":%d.9}`, now),
			fmt.Sprintf(`{"exp":%d.0}`, now+1),
			fmt.Sprintf(`{"exp":"%d"}`, now+5),
			`{"exp":"abc"}`, `{"exp":""}`, `{"exp":true}`, `{"exp":{}}`, `{"exp":null}`, `{"exp":0}`, `{"exp":-1}`, `{"exp":1e11}`, `{"exp":1e400}`,
			fmt.Sprintf(`{"nbf":%d}`, now), fmt.Sprintf(`{"nbf":%d}`, now+1), fmt.Sprintf(`{"nbf":%d,"exp":%d}`, now+5, now-5), fmt.Sprintf(`{"iat":%d}`, now+1000),
			`{"SID":"upper","UID":2}`, `{"Sid":"mixed","uId":3}`, `{"sid":"first","SID":"second"}`, `{"SID":"first","sid":"second"}`, `{"ſid":"long s"}`,
			`{"sid":"a","sid":null}`, `{"uid":5,"uid":null}`, `{"rnp":"x","rnp":null}`, `{"rnp":""}`, `{"rnp":null}`, `{"RNP":"folded"}`,
			`{"uid":1.0}`, `{"uid":1.5}`, `{"uid":"1"}`, `{"uid":1e2}`, `{"uid":-0}`, `{"uid":9223372036854775807}`, `{"uid":9223372036854775808}`, `{"ostn":1762345678123456789}`, `{"ostn":17623456781234567890}`,
			`{"seek":1}`, `{"seek":1.5e300}`, `{"seek":1e400}`, `{"seek":0.000001}`, `{"seek":"1"}`, `{"flag":1}`, `{"flag":true}`, `{"flag":"true"}`,
			`{"sid":1}`, `{"sid":null}`, `{"sid":["a"]}`, `{"sid":"bad\ud800surrogate"}`, `{"sid":"pair😀ok"}`, `{"sid":"bad\ud83dA"}`, `{"sid":"\u0000nul"}`, "{\"sid\":\"raw\xffbyte\"}", `{"sid":"<&> "}`,
			`{"aud":"one"}`, `{"aud":["one","two"]}`, `{"aud":[]}`, `{"aud":[1]}`, `{"aud":[null]}`, `{"aud":null}`, `{"aud":1}`, `{"AUD":"x"}`, `{"iss":1}`, `{"sub":"s","jti":"j","iss":"i"}`,
			`{"unknown":{"deep":[1,2,{"x":"y"}]},"sid":"after"}`, `{"unknown":1e999,"sid":"ok"}`, ` { "sid" : "ws" } `, `null`, `[]`, `1`, `"str"`, `true`, `{`, ``, `{"sid":"a"}trailing`, "\xef\xbb\xbf{}",
		}
		headers := []string{`{"alg":"HS256","typ":"JWT"}`, `{"alg":"HS256"}`, `{"alg":"HS384","typ":"JWT"}`, `{"alg":"HS512"}`, `{"typ":"JWT","alg":"HS256","kid":"x"}`, `{"alg":"none"}`, `{"alg":"RS256"}`, `{"alg":"ES256"}`, `{"alg":"PS256"}`, `{"alg":"EdDSA"}`, `{"alg":"XX"}`, `{"alg":1}`, `{"ALG":"HS256"}`, `{}`, `null`, `[]`, `"x"`, `{`, `{"alg":"HS256","alg":"HS512"}`, `{"alg":"hs256"}`}
		header := headers[0]
		if r.IntN(3) == 0 {
			header = pick(r, headers)
		}
		payload := payloads[i%len(payloads)]
		if i >= len(payloads) {
			payload = pick(r, payloads)
		}
		signing := "HS256"
		var m struct {
			Alg any `json:"alg"`
		}
		_ = json.Unmarshal([]byte(header), &m)
		if alg, ok := m.Alg.(string); ok && strings.HasPrefix(alg, "HS") && len(alg) == 5 {
			signing = alg
		}
		enc := base64.RawURLEncoding
		head, body := enc.EncodeToString([]byte(header)), enc.EncodeToString([]byte(payload))
		key := []byte(secret)
		if r.IntN(12) == 0 {
			key = []byte("wrong")
		}
		method := jwt.GetSigningMethod(signing)
		sig, err := method.Sign(head+"."+body, key)
		if err != nil {
			panic(err)
		}
		token := head + "." + body + "." + enc.EncodeToString(sig)
		switch r.IntN(20) {
		case 0:
			token = pick(r, []string{"", ".", "..", "a.b", "a.b.c.d", "a.b.c", token + ".", "." + token})
		case 1:
			token = head + "=." + body + "." + enc.EncodeToString(sig)
		case 2:
			token = head + "\n." + body + "\r\n." + enc.EncodeToString(sig)
		case 3:
			token = head + "." + body + "." + enc.EncodeToString(sig) + "="
		case 4:
			token = head + "." + body + "." + base64.StdEncoding.EncodeToString(sig)
		case 5:
			token = head + "." + body + "."
		case 6:
			t := []byte(token)
			if len(t) > 2 {
				t[len(t)-1] ^= 1
			}
			token = string(t)
		}
		return semanticsIn{S(token), secret, pick(r, []string{"any_hmac", "any_hmac", "hs256_keyfunc", "hs256_required"}), now*1e9 + r.Int64N(1e9)}
	}, runSemantics)
}

const testRSAKeyPEM = "rs256_test_key.pem"

func loadRSAKey() *rsa.PrivateKey {
	path := filepath.Join(outDir, testRSAKeyPEM)
	data, err := os.ReadFile(path)
	if err != nil {
		key, genErr := rsa.GenerateKey(cryptorand.Reader, 2048)
		if genErr != nil {
			panic(genErr)
		}
		data = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
		_ = os.MkdirAll(outDir, 0o755)
		if err := os.WriteFile(path, data, 0o644); err != nil {
			panic(err)
		}
	}
	block, _ := pem.Decode(data)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	return key
}

func registerRS256() {
	type identityClaims struct {
		jwt.RegisteredClaims
		Nonce string `json:"nonce"`
		Email string `json:"email"`
	}
	type rsIn struct {
		Issuer   string `json:"issuer"`
		ClientID string `json:"client_id"`
		Nonce    string `json:"nonce"`
		Kid      string `json:"kid"`
		TokenKid string `json:"token_kid"`
		N        string `json:"n"`
		E        string `json:"e"`
		Iss      string `json:"iss"`
		Aud      string `json:"aud"`
		Sub      string `json:"sub"`
		TokNonce string `json:"token_nonce"`
		Email    string `json:"email"`
		Exp      int64  `json:"exp"`
		NowNanos int64  `json:"now_nanos"`
		Alg      string `json:"alg"`
	}
	type rsOut struct {
		Token    string `json:"token"`
		Accepted bool   `json:"accepted"`
	}
	const issuer = "https://auth.openai.com"
	const now = int64(1_800_000_000)
	key := loadRSAKey()
	enc := base64.RawURLEncoding
	n := enc.EncodeToString(key.N.Bytes())
	e := enc.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	signRS := func(in rsIn) string {
		c := identityClaims{RegisteredClaims: jwt.RegisteredClaims{Issuer: in.Iss, Subject: in.Sub, ExpiresAt: jwt.NewNumericDate(time.Unix(in.Exp, 0))}, Nonce: in.TokNonce, Email: in.Email}
		if in.Aud != "" {
			c.Audience = jwt.ClaimStrings{in.Aud}
		}
		tok := jwt.NewWithClaims(jwt.GetSigningMethod(in.Alg), c)
		if in.TokenKid != "" {
			tok.Header["kid"] = in.TokenKid
		}
		s, err := tok.SignedString(key)
		if err != nil {
			panic(err)
		}
		return s
	}
	accept := func(raw string, in rsIn) bool {
		claims := new(identityClaims)
		instant := time.Unix(0, in.NowNanos)
		_, err := jwt.ParseWithClaims(raw, claims, func(token *jwt.Token) (any, error) {
			kid, _ := token.Header["kid"].(string)
			if in.Kid != kid || kid == "" {
				return nil, errors.New("identity")
			}
			nb, nErr := enc.DecodeString(in.N)
			eb, eErr := enc.DecodeString(in.E)
			if nErr != nil || eErr != nil || len(eb) > 4 || len(nb) < 256 {
				return nil, errors.New("identity")
			}
			return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}, nil
		}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(in.Issuer), jwt.WithAudience(in.ClientID), jwt.WithExpirationRequired(), jwt.WithTimeFunc(func() time.Time { return instant }))
		return err == nil && claims.Subject != "" && (in.Nonce == "" || in.Nonce == claims.Nonce)
	}
	det("jwt_rs256", "github.com/golang-jwt/jwt/v5 with internal/ai/chatgpt's options", 500, func(r *rand.Rand, i int) rsIn {
		in := rsIn{issuer, "client-" + randHex(r, 3), "n-" + randHex(r, 3), "k1", "k1", n, e, issuer, "", "sub-" + randHex(r, 3), "", text(r), now + 3600, now * 1e9, "RS256"}
		in.Aud, in.TokNonce = in.ClientID, in.Nonce
		switch i % 12 {
		case 1:
			in.Iss = "https://evil"
		case 2:
			in.Aud = "other"
		case 3:
			in.Exp = now
		case 4:
			in.Sub = ""
		case 5:
			in.TokNonce = "wrong"
		case 6:
			in.TokenKid = "unknown"
		case 7:
			in.TokenKid = ""
		case 8:
			in.Nonce = ""
		case 9:
			in.E = enc.EncodeToString([]byte{1, 0, 0, 0, 1})
		case 10:
			in.N = enc.EncodeToString(key.N.Bytes()[:128])
		case 11:
			in.Alg = "RS384"
		}
		return in
	}, func(in rsIn) rsOut {
		tok := signRS(in)
		return rsOut{tok, accept(tok, in)}
	})
}

type captureClient struct{ header string }

func (c *captureClient) Do(req *http.Request) (*http.Response, error) {
	c.header = req.Header.Get("Authorization")
	return &http.Response{StatusCode: 201, Body: http.NoBody}, nil
}

func registerVAPID() {
	type vapidIn struct {
		Endpoint   string `json:"endpoint"`
		Subscriber string `json:"subscriber"`
		Public     string `json:"public"`
		Private    string `json:"private"`
		Exp        int64  `json:"exp"`
	}
	sub := func() (string, string) {
		priv, err := ecdh.P256().GenerateKey(cryptorand.Reader)
		if err != nil {
			panic(err)
		}
		auth := make([]byte, 16)
		_, _ = cryptorand.Read(auth)
		return base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(auth)
	}
	nondet("jwt_vapid", "github.com/SherClockHolmes/webpush-go", 500, func(r *rand.Rand, i int) vapidIn {
		private, public, err := webpush.GenerateVAPIDKeys()
		if err != nil {
			panic(err)
		}
		if i%4 == 0 {
			private = base64.URLEncoding.EncodeToString(must(base64.RawURLEncoding.DecodeString(private)))
		}
		return vapidIn{pick(r, []string{"https://fcm.googleapis.com/fcm/send/" + randHex(r, 8), "https://updates.push.services.mozilla.com:443/wpush/v2/x?y=1", "https://web.push.apple.com/x", "HTTPS://Example.COM/a"}), pick(r, []string{"https://github.com/Silo-Server/silo-server", "admin@example.com", "https:x", "<a&b>@x"}), public, private, 1_900_000_000}
	}, func(in vapidIn) (string, error) {
		p256dh, authKey := sub()
		client := &captureClient{}
		resp, err := webpush.SendNotification([]byte("x"), &webpush.Subscription{Endpoint: in.Endpoint, Keys: webpush.Keys{P256dh: p256dh, Auth: authKey}}, &webpush.Options{HTTPClient: client, Subscriber: in.Subscriber, TTL: 30, VAPIDPublicKey: in.Public, VAPIDPrivateKey: in.Private})
		if err != nil {
			return "", err
		}
		_ = resp.Body.Close()
		return client.header, nil
	}, func(in vapidIn, header string) error {
		rest, ok := strings.CutPrefix(header, "vapid t=")
		if !ok {
			return fmt.Errorf("header %q", header)
		}
		tok, k, ok := strings.Cut(rest, ", k=")
		if !ok {
			return fmt.Errorf("header %q", header)
		}
		publicBytes, err := decodeVapid(in.Public)
		if err != nil {
			return err
		}
		if k != base64.RawURLEncoding.EncodeToString(publicBytes) {
			return fmt.Errorf("k=%q", k)
		}
		x, y := elliptic.Unmarshal(elliptic.P256(), publicBytes)
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		claims := jwt.MapClaims{}
		_, err = jwt.ParseWithClaims(tok, claims, func(*jwt.Token) (any, error) { return pub, nil }, jwt.WithValidMethods([]string{"ES256"}), jwt.WithExpirationRequired(), jwt.WithTimeFunc(func() time.Time { return time.Unix(1_000_000_000, 0) }))
		if err != nil {
			return err
		}
		wantSub := in.Subscriber
		if !strings.HasPrefix(wantSub, "https:") {
			wantSub = "mailto:" + wantSub
		}
		if claims["sub"] != wantSub {
			return fmt.Errorf("sub=%v", claims["sub"])
		}
		u := in.Endpoint
		scheme, after, _ := strings.Cut(u, "://")
		host := strings.SplitN(strings.SplitN(after, "/", 2)[0], "?", 2)[0]
		if claims["aud"] != strings.ToLower(scheme)+"://"+host {
			return fmt.Errorf("aud=%v", claims["aud"])
		}
		return nil
	})
}

func decodeVapid(key string) ([]byte, error) {
	if b, err := base64.URLEncoding.DecodeString(key); err == nil {
		return b, nil
	}
	return base64.RawURLEncoding.DecodeString(key)
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func registerBcrypt() {
	type bcIn struct {
		Password S   `json:"password"`
		Cost     int `json:"cost"`
	}
	passwords := func(r *rand.Rand) S {
		switch r.IntN(6) {
		case 0:
			return S(strings.Repeat("a", 72))
		case 1:
			return S("nul\x00tail")
		case 2:
			return S(rawBytes(r))
		case 3:
			return ""
		default:
			return S(text(r))
		}
	}
	nondet("bcrypt_generate", "golang.org/x/crypto/bcrypt through internal/auth/passwordhash", 500, func(r *rand.Rand, i int) bcIn {
		cost := 4
		if i%50 == 0 {
			cost = 10
		}
		return bcIn{passwords(r), cost}
	}, func(in bcIn) (S, error) {
		hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), in.Cost)
		return S(hash), err
	}, func(in bcIn, hash S) error {
		p, err := passwordhash.Admit(context.Background())
		if err != nil {
			return err
		}
		defer p.Release()
		ok, err := p.Matches([]byte(hash), []byte(in.Password))
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("mismatch")
		}
		if ok, _ := p.Matches([]byte(hash), []byte(string(in.Password)+"x")); ok && len(in.Password) < 72 {
			return errors.New("a different password matched")
		}
		return nil
	})

	type cmpIn struct {
		Hash     S `json:"hash"`
		Password S `json:"password"`
	}
	base := must(bcrypt.GenerateFromPassword([]byte("secret"), 4))
	over := must(bcrypt.GenerateFromPassword([]byte(strings.Repeat("a", 72)), 4))
	det("bcrypt_compare", "golang.org/x/crypto/bcrypt CompareHashAndPassword", 500, func(r *rand.Rand, i int) cmpIn {
		h := string(base)
		switch i % 15 {
		case 1:
			h = "$2b$" + h[4:]
		case 2:
			h = "$2y$" + h[4:]
		case 3:
			h = "$2$" + h[4:]
		case 4:
			h = "$3a$" + h[4:]
		case 5:
			h = "x" + h[1:]
		case 6:
			h = h[:58]
		case 7:
			h = h[:59]
		case 8:
			h = h + "extra"
		case 9:
			h = "$2a$03$" + h[7:]
		case 10:
			h = "$2a$+4$" + h[7:]
		case 11:
			h = "$2a$04X" + h[7:]
		case 12:
			h = h[:10] + "!" + h[11:]
		case 13:
			h = h[:len(h)-1] + "."
		case 14:
			return cmpIn{S(over), S(strings.Repeat("a", 72) + pick(r, []string{"", "#1234"}))}
		}
		return cmpIn{S(h), S(pick(r, []string{"secret", "Secret", "", "secret\x00"}))}
	}, func(in cmpIn) string {
		err := bcrypt.CompareHashAndPassword([]byte(in.Hash), []byte(in.Password))
		switch {
		case err == nil:
			return "ok"
		case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
			return "mismatch"
		default:
			return "unreadable"
		}
	})
}
