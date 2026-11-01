//go:build core_vectors

package main

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"

	"github.com/Silo-Server/silo-server/internal/auth"
	"github.com/Silo-Server/silo-server/internal/autoscan"
	"github.com/Silo-Server/silo-server/internal/historyimport"
	"github.com/Silo-Server/silo-server/internal/jellycompat"
	"github.com/Silo-Server/silo-server/internal/notifications"
	"github.com/Silo-Server/silo-server/internal/plugins"
	"github.com/Silo-Server/silo-server/internal/requests"
	"github.com/Silo-Server/silo-server/internal/secret"
	"github.com/Silo-Server/silo-server/internal/subtitles"
	"github.com/Silo-Server/silo-server/internal/watchsync"
	"github.com/Silo-Server/silo-server/internal/webhooksync"
)

func cipherFor(master string) *secret.Cipher {
	c, err := secret.New([]byte(master))
	if err != nil {
		panic(err)
	}
	return c
}

func registerSecret() {
	type encIn struct {
		Master    string `json:"master"`
		Plaintext S      `json:"plaintext"`
		AAD       S      `json:"aad"`
		WrongAAD  S      `json:"wrong_aad"`
	}
	nondet("secret_enc_v1", "internal/secret", 800, func(r *rand.Rand, i int) encIn {
		key := "auth.jwt_secret"
		aad := secret.SettingsAAD(key)
		wrong := secret.SettingsAAD("auth.jwt_secret2")
		if i%2 == 1 {
			aad = secret.RowAAD(text(r), text(r), text(r))
			wrong = aad + "x"
		}
		plain := text(r)
		switch i % 5 {
		case 1:
			plain = rawBytes(r)
		case 2:
			plain = "enc:v1:" + text(r)
		case 3:
			plain = strings.Repeat(text(r)+"x", 200)
		}
		return encIn{masterKey(r), S(plain), S(aad), S(wrong)}
	}, func(in encIn) (S, error) {
		ct, err := cipherFor(in.Master).Encrypt(string(in.Plaintext), string(in.AAD))
		return S(ct), err
	}, func(in encIn, ct S) error {
		c := cipherFor(in.Master)
		if in.Plaintext == "" {
			if ct != "" {
				return fmt.Errorf("empty plaintext was wrapped")
			}
			return nil
		}
		plain, err := c.Decrypt(string(ct), string(in.AAD))
		if err != nil {
			return err
		}
		if plain != string(in.Plaintext) {
			return errors.New("plaintext differs")
		}
		if !secret.IsEncrypted(string(ct)) {
			return errors.New("not recognized as encrypted")
		}
		if _, err := c.Decrypt(string(ct), string(in.WrongAAD)); err == nil {
			return errors.New("a different AAD decrypted")
		}
		if _, err := cipherFor(in.Master+"x").Decrypt(string(ct), string(in.AAD)); err == nil {
			return errors.New("a different key decrypted")
		}
		return nil
	})

	type readIn struct {
		Master string `json:"master"`
		Value  S      `json:"value"`
		AAD    S      `json:"aad"`
	}
	type readOut struct {
		Decrypt        *S     `json:"decrypt"`
		DecryptErr     string `json:"decrypt_err"`
		IfEncrypted    *S     `json:"if_encrypted"`
		IfEncryptedErr string `json:"if_encrypted_err"`
		IsEncrypted    bool   `json:"is_encrypted"`
	}
	errClass := func(err error) string {
		switch {
		case err == nil:
			return ""
		case errors.Is(err, secret.ErrUnknownVersion):
			return "unknown_version"
		default:
			return "error"
		}
	}
	det("secret_read_contract", "internal/secret", 700, func(r *rand.Rand, i int) readIn {
		master := masterKey(r)
		aad := text(r)
		ct, _ := cipherFor(master).Encrypt("value-"+text(r), aad)
		value := ct
		switch i % 12 {
		case 1:
			value = ""
		case 2:
			value = text(r)
		case 3:
			value = "enc:v2:" + ct[7:]
		case 4:
			value = "enc:v1:" + text(r)
		case 5:
			value = "enc:v1:"
		case 6:
			value = ct + "A"
		case 7:
			value = "enc:" + text(r)
		case 8:
			value = ct[:len(ct)/2] + "\n" + ct[len(ct)/2:]
		case 9:
			value = ct[:len(ct)-3]
		case 10:
			aad += "x"
		case 11:
			value = "ENC:v1:" + ct[7:]
		}
		return readIn{master, S(value), S(aad)}
	}, func(in readIn) readOut {
		c := cipherFor(in.Master)
		out := readOut{IsEncrypted: secret.IsEncrypted(string(in.Value))}
		v, err := c.Decrypt(string(in.Value), string(in.AAD))
		out.DecryptErr = errClass(err)
		if err == nil {
			s := S(v)
			out.Decrypt = &s
		}
		v, err = c.DecryptIfEncrypted(string(in.Value), string(in.AAD))
		out.IfEncryptedErr = errClass(err)
		if err == nil {
			s := S(v)
			out.IfEncrypted = &s
		}
		return out
	})

	type aadIn struct {
		Fn string `json:"fn"`
		A  S      `json:"a"`
		B  S      `json:"b"`
		C  S      `json:"c"`
		N  int    `json:"n"`
	}
	fns := map[string]func(aadIn) string{
		"settings":                func(a aadIn) string { return secret.SettingsAAD(string(a.A)) },
		"row":                     func(a aadIn) string { return secret.RowAAD(string(a.A), string(a.B), string(a.C)) },
		"jellycompat_access":      func(a aadIn) string { return jellycompat.VectorTokenAAD("streamapp_access_token", string(a.A)) },
		"jellycompat_refresh":     func(a aadIn) string { return jellycompat.VectorTokenAAD("streamapp_refresh_token", string(a.A)) },
		"webhook_sync":            func(a aadIn) string { return webhooksync.VectorTokenAAD(string(a.A)) },
		"autoscan_secret":         func(a aadIn) string { return autoscan.VectorWebhookSecretAAD(string(a.A)) },
		"autoscan_connection":     func(a aadIn) string { return autoscan.VectorConnectionAPIKeyAAD(string(a.A)) },
		"request_integration":     func(a aadIn) string { return requests.VectorAPIKeyAAD(string(a.A)) },
		"plugin_refresh_state":    func(a aadIn) string { return auth.VectorRefreshStateAAD(int64(a.N)) },
		"history_source":          func(a aadIn) string { return historyimport.VectorSourceAdminTokenAAD(a.N) },
		"history_connect_session": func(a aadIn) string { return historyimport.VectorConnectSessionAAD(string(a.A)) },
		"history_connect_server":  func(a aadIn) string { return historyimport.VectorConnectServerAAD(string(a.A), a.N, string(a.B)) },
		"history_plex_session":    func(a aadIn) string { return historyimport.VectorPlexSessionAAD(string(a.A)) },
		"history_plex_server":     func(a aadIn) string { return historyimport.VectorPlexServerAAD(string(a.A), a.N, string(a.B)) },
		"history_run":             func(a aadIn) string { return historyimport.VectorPersonalCredentialAAD(string(a.A)) },
		"watch_access":            func(a aadIn) string { return watchsync.TokenAAD("access_token", string(a.A), a.N, string(a.B)) },
		"watch_refresh":           func(a aadIn) string { return watchsync.TokenAAD("refresh_token", string(a.A), a.N, string(a.B)) },
		"watch_plugin":            func(a aadIn) string { return watchsync.TokenAAD("plugin_credentials", string(a.A), a.N, string(a.B)) },
		"watch_auth_state":        func(a aadIn) string { return watchsync.VectorAuthStateAAD(string(a.A), a.N, string(a.B)) },
		"subtitle_api_key":        func(a aadIn) string { return subtitles.VectorProviderSecretAAD("api_key", string(a.A)) },
		"subtitle_password":       func(a aadIn) string { return subtitles.VectorProviderSecretAAD("password", string(a.A)) },
		"push_apns":               func(a aadIn) string { return notifications.VectorAPNsAAD(string(a.A)) },
		"push_fcm":                func(a aadIn) string { return notifications.VectorFCMAAD(string(a.A)) },
		"plugin_runtime":          func(a aadIn) string { return plugins.VectorRuntimeConfigAAD(a.N, string(a.A)) },
		"plugin_instance":         func(a aadIn) string { return plugins.VectorInstanceStateAAD(a.N, string(a.A), string(a.B)) },
		"webhook_url":             func(a aadIn) string { return notifications.VectorWebhookURLAAD(string(a.A)) },
		"webhook_secret":          func(a aadIn) string { return notifications.VectorWebhookSecretAAD(string(a.A)) },
		"channel_url":             func(a aadIn) string { return notifications.VectorServerChannelURLAAD(string(a.A)) },
		"channel_secret":          func(a aadIn) string { return notifications.VectorServerChannelSecretAAD(string(a.A)) },
		"email_verification":      func(a aadIn) string { return notifications.VectorEmailVerificationAAD(string(a.A)) },
		"oauth_pending":           func(a aadIn) string { return auth.VectorPendingLinkAAD(string(a.A)) },
	}
	names := sortedKeys(fns)
	det("secret_aad_strings", "the AAD builders of every owning package", 620, func(r *rand.Rand, i int) aadIn {
		return aadIn{names[i%len(names)], S(text(r)), S(text(r)), S(text(r)), smallInt(r)}
	}, func(in aadIn) string { return fns[in.Fn](in) })

	type stateIn struct {
		Master string `json:"master"`
		ID     int    `json:"id"`
		Scope  S      `json:"scope"`
		Key    S      `json:"key"`
		Value  S      `json:"value"`
	}
	nondet("secret_plugin_state", "internal/plugins InstanceStateStore", 500, func(r *rand.Rand, i int) stateIn {
		value := S(text(r))
		if i%3 == 0 {
			value = ""
		}
		return stateIn{masterKey(r), posInt(r), S(pick(r, []string{"api", "node:7", text(r) + "x"})), S(text(r)), value}
	}, func(in stateIn) (S, error) {
		out, err := plugins.VectorSealInstanceState(cipherFor(in.Master), in.ID, string(in.Scope), string(in.Key), []byte(in.Value))
		return S(out), err
	}, func(in stateIn, stored S) error {
		got, err := plugins.VectorOpenInstanceState(cipherFor(in.Master), in.ID, string(in.Scope), string(in.Key), []byte(stored))
		if err != nil {
			return err
		}
		if string(got) != string(in.Value) {
			return errors.New("value differs")
		}
		if _, err := plugins.VectorOpenInstanceState(cipherFor(in.Master), in.ID+1, string(in.Scope), string(in.Key), []byte(stored)); err == nil {
			return errors.New("opened under another installation")
		}
		return nil
	})

	type configIn struct {
		Master    string `json:"master"`
		ID        int    `json:"id"`
		Key       S      `json:"key"`
		Plaintext S      `json:"plaintext"`
	}
	nondet("secret_plugin_config", "internal/plugins runtime config", 500, func(r *rand.Rand, _ int) configIn {
		return configIn{masterKey(r), posInt(r), S(text(r)), S(fmt.Sprintf(`{"a":%d,"b":"c<d&e>","n":1.50,"big":123456789012345678901}`, r.IntN(100)))}
	}, func(in configIn) (S, error) {
		out, err := plugins.VectorEncodeRuntimeConfig(cipherFor(in.Master), in.ID, string(in.Key), []byte(in.Plaintext))
		return S(out), err
	}, func(in configIn, stored S) error {
		got, err := plugins.VectorDecodeRuntimeConfig(cipherFor(in.Master), in.ID, string(in.Key), []byte(stored))
		if err != nil {
			return err
		}
		if fmt.Sprint(got["big"]) != "123456789012345678901" || fmt.Sprint(got["n"]) != "1.50" {
			return fmt.Errorf("numbers lost their text: %v", got)
		}
		if !strings.HasPrefix(string(stored), `{"__silo_encrypted_runtime_config_v1":"enc:v1:`) {
			return fmt.Errorf("wrapper %q", stored)
		}
		if _, err := plugins.VectorDecodeRuntimeConfig(cipherFor(in.Master), in.ID+1, string(in.Key), []byte(stored)); err == nil {
			return errors.New("opened under another installation")
		}
		return nil
	})

	det("secret_backfill_targets", "internal/secret ColumnBackfillTargets", 1, func(*rand.Rand, int) string { return "all" }, func(string) [][4]string {
		out := [][4]string{}
		for _, t := range secret.ColumnBackfillTargets() {
			exprs := t.VectorExprs()
			out = append(out, [4]string{t.Table, t.Column, exprs[0], exprs[1]})
		}
		return out
	})

	type completionIn struct {
		Material  H `json:"material"`
		Plaintext S `json:"plaintext"`
		AAD       S `json:"aad"`
	}
	nondet("oauth_completion_aead", "internal/auth PGOAuthStore", 500, func(r *rand.Rand, i int) completionIn {
		material := H(randBytes(r, 32))
		if i%10 == 0 {
			material = H{}
		}
		return completionIn{material, S(text(r) + "x"), S(auth.VectorPendingLinkAAD(randHex(r, 16)))}
	}, func(in completionIn) (string, error) {
		return auth.VectorCompletionSeal(in.Material, []byte(in.Plaintext), string(in.AAD))
	}, func(in completionIn, ct string) error {
		got, err := auth.VectorCompletionOpen(in.Material, ct, string(in.AAD))
		if err != nil {
			return err
		}
		if string(got) != string(in.Plaintext) {
			return errors.New("plaintext differs")
		}
		if _, err := auth.VectorCompletionOpen(in.Material, ct, string(in.AAD)+"x"); err == nil {
			return errors.New("a different AAD opened")
		}
		return nil
	})
}
