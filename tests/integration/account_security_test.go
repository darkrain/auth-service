package integration

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func verifiedAccount(t *testing.T, login, password string) (int64, string) {
	t.Helper()
	registrationToken := registerUser(t, login, password)
	verifyUser(t, login, "account-security-device", registrationToken)
	token := loginUser(t, login, password)
	me := doRequest("GET", "/auth/me", nil, token)
	if me.Code != http.StatusOK {
		t.Fatalf("load current user: expected 200, got %d: %s", me.Code, me.Body.String())
	}
	userID, ok := parseJSON(me)["id"].(float64)
	if !ok || userID <= 0 {
		t.Fatalf("current user must include a numeric id: %s", me.Body.String())
	}
	return int64(userID), token
}

func TestAccountPasswordChangeRevokesOtherSessions(t *testing.T) {
	truncateTables(t)
	login := "security-password@example.com"
	password := "Password1"
	userID, currentToken := verifiedAccount(t, login, password)

	secondLogin := doRequest("POST", "/auth/login", map[string]string{
		"login": login, "password": password, "device_uid": "other-password-device",
	}, "")
	if secondLogin.Code != http.StatusOK {
		t.Fatalf("second login: expected 200, got %d: %s", secondLogin.Code, secondLogin.Body.String())
	}
	secondToken, _ := parseJSON(secondLogin)["token"].(string)
	if secondToken == "" {
		t.Fatalf("second login token missing: %s", secondLogin.Body.String())
	}

	mismatch := doRequest("POST", fmt.Sprintf("/auth/account_password/id/%d", userID), map[string]string{
		"current_password": password, "new_password": "NewPassword2", "confirmation": "different",
	}, currentToken)
	if mismatch.Code != http.StatusBadRequest {
		t.Fatalf("password mismatch: expected 400, got %d: %s", mismatch.Code, mismatch.Body.String())
	}
	if errors, ok := parseJSON(mismatch)["errors"].(map[string]interface{}); !ok || errors["confirmation"] == nil {
		t.Fatalf("password mismatch must identify confirmation field: %s", mismatch.Body.String())
	}

	changed := doRequest("POST", fmt.Sprintf("/auth/account_password/id/%d", userID), map[string]string{
		"current_password": password, "new_password": "NewPassword2", "confirmation": "NewPassword2",
	}, currentToken)
	if changed.Code != http.StatusOK {
		t.Fatalf("change password: expected 200, got %d: %s", changed.Code, changed.Body.String())
	}

	if w := doRequest("GET", "/auth/me", nil, secondToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("other session must be revoked after password change, got %d: %s", w.Code, w.Body.String())
	}
	if w := doRequest("GET", "/auth/me", nil, currentToken); w.Code != http.StatusOK {
		t.Fatalf("current session must remain active after password change, got %d: %s", w.Code, w.Body.String())
	}
	if w := doRequest("POST", "/auth/login", map[string]string{"login": login, "password": "NewPassword2", "device_uid": "new-password-device"}, ""); w.Code != http.StatusOK {
		t.Fatalf("new password must authenticate: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAccountTwoFactorLoginChallenge(t *testing.T) {
	truncateTables(t)
	login := "security-totp@example.com"
	password := "Password1"
	userID, token := verifiedAccount(t, login, password)
	secret := "JBSWY3DPEHPK3PXP"
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	enable := doRequest("POST", fmt.Sprintf("/auth/account_two_factor/id/%d", userID), map[string]interface{}{
		"two_factor_enabled": true,
		"two_factor_secret":  secret,
		"two_factor_code":    code,
	}, token)
	if enable.Code != http.StatusOK {
		t.Fatalf("enable two factor: expected 200, got %d: %s", enable.Code, enable.Body.String())
	}

	var enabled bool
	var encrypted string
	if err := testPool.QueryRowContext(context.Background(), `SELECT two_factor_enabled, COALESCE(two_factor_secret_encrypted, '') FROM users WHERE id=$1`, userID).Scan(&enabled, &encrypted); err != nil {
		t.Fatal(err)
	}
	if !enabled || encrypted == "" || encrypted == secret {
		t.Fatalf("two-factor secret must be enabled and encrypted: enabled=%v encrypted=%q", enabled, encrypted)
	}

	deviceUID := "totp-login-device"
	passwordStep := doRequest("POST", "/auth/login", map[string]string{
		"login": login, "password": password, "device_uid": deviceUID,
	}, "")
	if passwordStep.Code != http.StatusAccepted {
		t.Fatalf("two-factor password step: expected 202, got %d: %s", passwordStep.Code, passwordStep.Body.String())
	}
	challenge, _ := parseJSON(passwordStep)["challenge_token"].(string)
	if challenge == "" {
		t.Fatalf("two-factor password step must return a challenge token: %s", passwordStep.Body.String())
	}

	invalid := doRequest("POST", "/auth/login/verify-2fa", map[string]string{
		"challenge_token": challenge, "code": "000000", "device_uid": deviceUID,
	}, "")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid TOTP: expected 400, got %d: %s", invalid.Code, invalid.Body.String())
	}

	code, err = totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	verified := doRequest("POST", "/auth/login/verify-2fa", map[string]string{
		"challenge_token": challenge, "code": code, "device_uid": deviceUID,
	}, "")
	if verified.Code != http.StatusOK {
		t.Fatalf("valid TOTP: expected 200, got %d: %s", verified.Code, verified.Body.String())
	}
	if sessionToken, _ := parseJSON(verified)["token"].(string); sessionToken == "" {
		t.Fatalf("TOTP verification must create a session: %s", verified.Body.String())
	}
}

func TestAccountDeactivationRevokesAllSessions(t *testing.T) {
	truncateTables(t)
	login := "security-deactivate@example.com"
	password := "Password1"
	userID, token := verifiedAccount(t, login, password)

	otherLogin := doRequest("POST", "/auth/login", map[string]string{
		"login": login, "password": password, "device_uid": "deactivation-other-device",
	}, "")
	if otherLogin.Code != http.StatusOK {
		t.Fatalf("other login: expected 200, got %d: %s", otherLogin.Code, otherLogin.Body.String())
	}
	otherToken, _ := parseJSON(otherLogin)["token"].(string)

	deactivated := doRequest("POST", fmt.Sprintf("/auth/account_deactivation/id/%d", userID), map[string]string{
		"current_password": password,
		"confirmation":     "DEACTIVATE",
	}, token)
	if deactivated.Code != http.StatusOK {
		t.Fatalf("deactivate account: expected 200, got %d: %s", deactivated.Code, deactivated.Body.String())
	}
	for _, sessionToken := range []string{token, otherToken} {
		if w := doRequest("GET", "/auth/me", nil, sessionToken); w.Code != http.StatusUnauthorized {
			t.Fatalf("deactivated account session must be invalid, got %d: %s", w.Code, w.Body.String())
		}
	}
	if w := doRequest("POST", "/auth/login", map[string]string{"login": login, "password": password, "device_uid": "deactivated-device"}, ""); w.Code != http.StatusForbidden {
		t.Fatalf("deactivated account must not authenticate, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAccountDeactivationConstraintDoesNotRevokeSessions(t *testing.T) {
	truncateTables(t)
	userID, token := verifiedAccount(t, "deactivation-blocked@example.com", "Password1")
	// Simulate a domain-owned database constraint; auth does not query wallets.
	_, err := testPool.Exec(`CREATE OR REPLACE FUNCTION test_block_deactivation() RETURNS TRIGGER LANGUAGE plpgsql AS $$ BEGIN IF NEW.deactivated_at IS NOT NULL THEN RAISE EXCEPTION 'wallet.errors.pending_payout'; END IF; RETURN NEW; END $$`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = testPool.Exec(`CREATE TRIGGER test_block_deactivation BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION test_block_deactivation()`)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = testPool.Exec(`DROP TRIGGER test_block_deactivation ON users`)
		_, _ = testPool.Exec(`DROP FUNCTION test_block_deactivation()`)
	})
	w := doRequest("POST", fmt.Sprintf("/auth/account_deactivation/id/%d?lang=ru", userID), map[string]string{"current_password": "Password1", "confirmation": "DEACTIVATE"}, token)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "дождитесь завершения") {
		t.Fatalf("expected localized refusal: %d %s", w.Code, w.Body.String())
	}
	if w := doRequest("GET", "/auth/me", nil, token); w.Code != http.StatusOK {
		t.Fatalf("failed deactivation revoked session: %d %s", w.Code, w.Body.String())
	}
	var blocked bool
	if err = testPool.QueryRow(`SELECT blocked FROM sessions WHERE token=$1`, token).Scan(&blocked); err != nil || blocked {
		t.Fatal("session changed despite rollback", err)
	}
}

func TestAccountDeactivationRejectsInvalidCredentialsAndForeignAccount(t *testing.T) {
	truncateTables(t)
	userID, token := verifiedAccount(t, "deactivation-credentials@example.com", "Password1")
	otherID, _ := verifiedAccount(t, "deactivation-other@example.com", "Password1")
	for _, input := range []map[string]string{
		{},
		{"current_password": "wrong", "confirmation": "DEACTIVATE"},
		{"current_password": "Password1", "confirmation": ""},
		{"verify_status": "deactivated", "deactivated_at": "2026-09-09T00:00:00Z"},
	} {
		w := doRequest("POST", fmt.Sprintf("/auth/account_deactivation/id/%d?lang=ru", userID), input, token)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("invalid credentials accepted: %d %s", w.Code, w.Body.String())
		}
		if w := doRequest("GET", "/auth/me", nil, token); w.Code != http.StatusOK {
			t.Fatalf("failed validation revoked session: %d %s", w.Code, w.Body.String())
		}
	}
	w := doRequest("POST", fmt.Sprintf("/auth/account_deactivation/id/%d", otherID), map[string]string{"current_password": "Password1", "confirmation": "DEACTIVATE"}, token)
	if w.Code == http.StatusOK {
		t.Fatal("deactivated another account")
	}
	var count int
	if err := testPool.QueryRow(`SELECT count(*) FROM users WHERE id IN ($1,$2) AND deactivated_at IS NOT NULL`, userID, otherID).Scan(&count); err != nil || count != 0 {
		t.Fatal("invalid request changed an account", count, err)
	}
}

func TestCachedSessionCannotBypassCommittedAccountState(t *testing.T) {
	truncateTables(t)
	userID, token := verifiedAccount(t, "cached-deactivation@example.com", "Password1")
	if w := doRequest("GET", "/auth/me", nil, token); w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	if _, err := testPool.Exec(`UPDATE users SET verify_status='deactivated',deactivated_at=now() WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	// Deliberately do not invalidate Redis: PostgreSQL is the authority.
	if w := doRequest("GET", "/auth/me", nil, token); w.Code != http.StatusUnauthorized {
		t.Fatalf("stale cache authenticated removed account: %d %s", w.Code, w.Body.String())
	}
}

func TestAccountDeactivationRequiresTwoFactorWhenEnabled(t *testing.T) {
	truncateTables(t)
	userID, token := verifiedAccount(t, "deactivation-totp@example.com", "Password1")
	secret := "JBSWY3DPEHPK3PXP"
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	w := doRequest("POST", fmt.Sprintf("/auth/account_two_factor/id/%d", userID), map[string]interface{}{"two_factor_enabled": true, "two_factor_secret": secret, "two_factor_code": code}, token)
	if w.Code != http.StatusOK {
		t.Fatal(w.Body.String())
	}
	for _, invalid := range []string{"", "invalid"} {
		w = doRequest("POST", fmt.Sprintf("/auth/account_deactivation/id/%d", userID), map[string]string{"current_password": "Password1", "confirmation": "DEACTIVATE", "two_factor_code": invalid}, token)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("missing/invalid TOTP accepted: %d %s", w.Code, w.Body.String())
		}
	}
	code, err = totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	w = doRequest("POST", fmt.Sprintf("/auth/account_deactivation/id/%d", userID), map[string]string{"current_password": "Password1", "confirmation": "DEACTIVATE", "two_factor_code": code}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("valid TOTP rejected: %d %s", w.Code, w.Body.String())
	}
}

func TestAccountSessionsListAndRevoke(t *testing.T) {
	truncateTables(t)
	login := "security-sessions@example.com"
	password := "Password1"
	userID, token := verifiedAccount(t, login, password)

	otherLogin := doRequest("POST", "/auth/login", map[string]string{
		"login": login, "password": password, "device_uid": "sessions-other-device",
	}, "")
	if otherLogin.Code != http.StatusOK {
		t.Fatalf("other login: expected 200, got %d: %s", otherLogin.Code, otherLogin.Body.String())
	}
	otherToken, _ := parseJSON(otherLogin)["token"].(string)
	var otherSessionID int64
	if err := testPool.QueryRowContext(context.Background(), `SELECT id FROM sessions WHERE user_id=$1 AND token=$2`, userID, otherToken).Scan(&otherSessionID); err != nil {
		t.Fatal(err)
	}

	listed := doRequest("GET", "/auth/account_sessions?size=100", nil, token)
	if listed.Code != http.StatusOK {
		t.Fatalf("list sessions: expected 200, got %d: %s", listed.Code, listed.Body.String())
	}
	if strings.Contains(listed.Body.String(), otherToken) {
		t.Fatalf("session list must never expose session tokens: %s", listed.Body.String())
	}
	if !strings.Contains(listed.Body.String(), "sessions-other-device") {
		t.Fatalf("session list must contain the other device: %s", listed.Body.String())
	}

	revoked := doRequest("DELETE", fmt.Sprintf("/auth/account_sessions/delete/id/%d", otherSessionID), nil, token)
	if revoked.Code != http.StatusOK {
		t.Fatalf("revoke session: expected 200, got %d: %s", revoked.Code, revoked.Body.String())
	}
	if w := doRequest("GET", "/auth/me", nil, otherToken); w.Code != http.StatusUnauthorized {
		t.Fatalf("revoked session must be unauthorized, got %d: %s", w.Code, w.Body.String())
	}
}
