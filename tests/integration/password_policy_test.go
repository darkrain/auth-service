package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// withPasswordPolicy runs the rest of a test with the given complexity flags
// and restores the test config afterwards.
func withPasswordPolicy(t *testing.T, requireDigits, requireSpecial bool) {
	t.Helper()
	digits, special := testCfg.PasswordRequireDigits, testCfg.PasswordRequireSpecial
	testCfg.PasswordRequireDigits, testCfg.PasswordRequireSpecial = requireDigits, requireSpecial
	t.Cleanup(func() { testCfg.PasswordRequireDigits, testCfg.PasswordRequireSpecial = digits, special })
}

// expectPasswordOutcome checks a route that sets a password: wantCode "" means
// it must succeed with okStatus, otherwise it must refuse with 400 and the
// stable error code (or, for the generator-backed password change that has no
// codes, a new_password field error).
func expectPasswordOutcome(t *testing.T, route string, w *httptest.ResponseRecorder, okStatus int, wantCode string) {
	t.Helper()
	if wantCode == "" {
		if w.Code != okStatus {
			t.Fatalf("%s: expected %d, got %d: %s", route, okStatus, w.Code, w.Body.String())
		}
		return
	}
	if w.Code != http.StatusBadRequest {
		t.Fatalf("%s: expected 400 %s, got %d: %s", route, wantCode, w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if route == "change" {
		fields, _ := body["errors"].(map[string]interface{})
		if fields["new_password"] == nil {
			t.Fatalf("change: refusal must name new_password: %s", w.Body.String())
		}
		return
	}
	if body["code"] != wantCode {
		t.Fatalf("%s: expected code %s, got %s", route, wantCode, w.Body.String())
	}
}

// One password policy: a password is accepted or refused alike at
// registration, password change and password reset.
func TestPasswordPolicySameForRegistrationChangeAndReset(t *testing.T) {
	truncateTables(t)

	const login = "policy-owner@example.com"
	current := "Password1"
	userID, token := verifiedAccount(t, login, current)

	for i, tc := range []struct {
		name                          string
		requireDigits, requireSpecial bool
		password                      string
		wantCode                      string
	}{
		{name: "letters only without complexity flags", password: "lettersonly", wantCode: ""},
		{name: "too short", password: "ab1!", wantCode: "ERR_PASSWORD_TOO_SHORT"},
		{name: "too long", password: "Aa1!" + strings.Repeat("x", 130), wantCode: "ERR_PASSWORD_TOO_LONG"},
		{name: "special required and missing", requireSpecial: true, password: "Password2", wantCode: "ERR_WEAK_PASSWORD"},
		{name: "special required and present", requireSpecial: true, password: "Password2!", wantCode: ""},
		{name: "digit required and missing", requireDigits: true, password: "Password!", wantCode: "ERR_WEAK_PASSWORD"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withPasswordPolicy(t, tc.requireDigits, tc.requireSpecial)
			device := "policy-device-" + strconv.Itoa(i)

			registered := doRequest("POST", "/auth/register", map[string]interface{}{
				"login": "policy-" + strconv.Itoa(i) + "@example.com", "password": tc.password, "device_uid": device,
			}, "")
			expectPasswordOutcome(t, "register", registered, http.StatusCreated, tc.wantCode)

			changed := doRequest("POST", fmt.Sprintf("/auth/account_password/id/%d", userID), map[string]string{
				"current_password": current, "new_password": tc.password, "confirmation": tc.password,
			}, token)
			expectPasswordOutcome(t, "change", changed, http.StatusOK, tc.wantCode)
			if tc.wantCode == "" {
				current = tc.password
			}

			if w := doRequestWithDevice("POST", "/auth/password/reset-request", map[string]string{"login": login, "device_uid": device}, "", device); w.Code != http.StatusOK {
				t.Fatalf("reset-request: expected 200, got %d: %s", w.Code, w.Body.String())
			}
			setKnownResetCode(t, login, device)
			reset := doRequestWithDevice("POST", "/auth/password/reset-confirm", map[string]interface{}{
				"login": login, "code": knownResetCode, "device_uid": device, "new_password": tc.password,
			}, "", device)
			expectPasswordOutcome(t, "reset", reset, http.StatusOK, tc.wantCode)

			// The reset ends every session; sign in again with the password
			// in effect, which also proves it is the stored one.
			token = loginUser(t, login, current)
		})
	}
}

// A password that predates the policy keeps signing in: the policy applies
// only when a password is set.
func TestPasswordPolicyDoesNotBlockExistingShortPassword(t *testing.T) {
	truncateTables(t)

	const login, legacy = "policy-legacy@example.com", "abc"
	registrationToken := registerUser(t, login, "Password1")
	verifyUser(t, login, "policy-legacy", registrationToken)
	hash, err := bcrypt.GenerateFromPassword([]byte(testCfg.PasswordSalt+legacy), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.ExecContext(context.Background(), `UPDATE users SET password=$1 WHERE email=$2`, string(hash), login); err != nil {
		t.Fatal(err)
	}
	loginUser(t, login, legacy)
}

// Password change trims the new password like registration, reset and sign-in
// do, so the changed password signs in.
func TestPasswordChangeTrimsLikeSignIn(t *testing.T) {
	truncateTables(t)

	const login = "policy-trim@example.com"
	userID, token := verifiedAccount(t, login, "Password1")
	changed := doRequest("POST", fmt.Sprintf("/auth/account_password/id/%d", userID), map[string]string{
		"current_password": "Password1", "new_password": "  Spaced123  ", "confirmation": "  Spaced123  ",
	}, token)
	if changed.Code != http.StatusOK {
		t.Fatalf("change password: expected 200, got %d: %s", changed.Code, changed.Body.String())
	}
	loginUser(t, login, "Spaced123")
}
