package integration

import (
	"context"
	"net/http"
	"testing"
)

// getResetCode reads the password reset code directly from the DB for a given login + device.
func getResetCode(t *testing.T, login, deviceUID string) string {
	t.Helper()
	ctx := context.Background()
	var code string
	err := testPool.QueryRow(ctx,
		`SELECT code FROM confirm_codes WHERE recipient=$1 AND device_uid=$2 AND auth_type='password_reset' LIMIT 1`,
		login, deviceUID,
	).Scan(&code)
	if err != nil {
		t.Fatalf("getResetCode(%s, %s): %v", login, deviceUID, err)
	}
	return code
}

// TestPasswordReset_HappyPath tests the full flow:
// request reset → confirm → login with new password.
func TestPasswordReset_HappyPath(t *testing.T) {
	truncateTables(t)

	login := "reset-test@example.com" // TestAccount with fixed code 777777
	password := "OldPass1"
	newPassword := "NewPass2"
	deviceUID := "device-reset-happy"

	// Register and verify user
	regToken := registerUser(t, login, password)
	verifyUser(t, login, deviceUID, regToken)

	// Step 1: request password reset
	w := doRequestWithDevice("POST", "/auth/password/reset-request", map[string]string{
		"login":     login,
		"device_uid": deviceUID,
	}, "", deviceUID)
	if w.Code != http.StatusOK {
		t.Fatalf("reset-request: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Step 2: confirm reset with fixed test code 777777
	w = doRequestWithDevice("POST", "/auth/password/reset-confirm", map[string]interface{}{
		"login":        login,
		"code":         "777777",
		"device_uid":   deviceUID,
		"new_password": newPassword,
	}, "", deviceUID)
	if w.Code != http.StatusOK {
		t.Fatalf("reset-confirm: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Step 3: login with new password should succeed
	w = doRequest("POST", "/auth/login", map[string]string{
		"login":    login,
		"password": newPassword,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("login after reset: expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["token"] == nil {
		t.Error("expected token in login response after reset")
	}

	// Step 4: old password should no longer work
	w = doRequest("POST", "/auth/login", map[string]string{
		"login":    login,
		"password": password,
	}, "")
	if w.Code == http.StatusOK {
		t.Error("old password should not work after reset")
	}
}

// TestPasswordReset_WrongCode tests that a wrong code returns 400 ERR_INVALID_CODE.
func TestPasswordReset_WrongCode(t *testing.T) {
	truncateTables(t)

	login := "reset-wrongcode@example.com"
	password := "OldPass1"
	deviceUID := "device-reset-wrongcode"

	regToken := registerUser(t, login, password)
	verifyUser(t, login, deviceUID, regToken)

	// Request reset
	w := doRequestWithDevice("POST", "/auth/password/reset-request", map[string]string{
		"login":     login,
		"device_uid": deviceUID,
	}, "", deviceUID)
	if w.Code != http.StatusOK {
		t.Fatalf("reset-request: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Confirm with wrong code
	w = doRequestWithDevice("POST", "/auth/password/reset-confirm", map[string]interface{}{
		"login":        login,
		"code":         "000000",
		"device_uid":   deviceUID,
		"new_password": "NewPass2",
	}, "", deviceUID)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong code: expected 400, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["code"] != "ERR_INVALID_CODE" {
		t.Errorf("expected ERR_INVALID_CODE, got %v", body["code"])
	}
}

// TestPasswordReset_NonExistentUser tests that reset-request returns 200 for non-existent user (no enumeration).
func TestPasswordReset_NonExistentUser(t *testing.T) {
	truncateTables(t)

	w := doRequestWithDevice("POST", "/auth/password/reset-request", map[string]string{
		"login":     "nobody@nonexistent.example.com",
		"device_uid": "device-reset-nouser",
	}, "", "device-reset-nouser")
	if w.Code != http.StatusOK {
		t.Fatalf("no-enumeration: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestPasswordReset_WeakPassword tests that a weak new password returns 400 ERR_WEAK_PASSWORD.
func TestPasswordReset_WeakPassword(t *testing.T) {
	truncateTables(t)

	login := "reset-test@example.com" // TestAccount with fixed code 777777
	password := "OldPass1"
	deviceUID := "device-reset-weak"

	regToken := registerUser(t, login, password)
	verifyUser(t, login, deviceUID, regToken)

	// Request reset
	w := doRequestWithDevice("POST", "/auth/password/reset-request", map[string]string{
		"login":     login,
		"device_uid": deviceUID,
	}, "", deviceUID)
	if w.Code != http.StatusOK {
		t.Fatalf("reset-request: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Confirm with valid code but weak password (too short / no digit)
	w = doRequestWithDevice("POST", "/auth/password/reset-confirm", map[string]interface{}{
		"login":        login,
		"code":         "777777",
		"device_uid":   deviceUID,
		"new_password": "abc", // too short, no digit
	}, "", deviceUID)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("weak password: expected 400, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["code"] != "ERR_WEAK_PASSWORD" {
		t.Errorf("expected ERR_WEAK_PASSWORD, got %v", body["code"])
	}
}

// TestPasswordReset_SessionsInvalidated tests that existing sessions are invalidated after reset.
func TestPasswordReset_SessionsInvalidated(t *testing.T) {
	truncateTables(t)

	login := "reset-test@example.com" // TestAccount with fixed code 777777
	password := "OldPass1"
	newPassword := "NewPass3"
	deviceUID := "device-reset-session"

	regToken := registerUser(t, login, password)
	verifyUser(t, login, deviceUID, regToken)

	// Login to get a session token
	oldToken := loginUser(t, login, password)

	// Verify /auth/me works with old token
	w := doRequest("GET", "/auth/me", nil, oldToken)
	if w.Code != http.StatusOK {
		t.Fatalf("me before reset: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Request password reset
	w = doRequestWithDevice("POST", "/auth/password/reset-request", map[string]string{
		"login":     login,
		"device_uid": deviceUID,
	}, "", deviceUID)
	if w.Code != http.StatusOK {
		t.Fatalf("reset-request: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Confirm reset
	w = doRequestWithDevice("POST", "/auth/password/reset-confirm", map[string]interface{}{
		"login":        login,
		"code":         "777777",
		"device_uid":   deviceUID,
		"new_password": newPassword,
	}, "", deviceUID)
	if w.Code != http.StatusOK {
		t.Fatalf("reset-confirm: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Old token should no longer work
	w = doRequest("GET", "/auth/me", nil, oldToken)
	if w.Code == http.StatusOK {
		t.Error("old session token should be invalidated after password reset")
	}
}
