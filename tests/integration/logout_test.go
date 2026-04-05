package integration

import (
	"net/http"
	"testing"
)

func TestLogout_Success(t *testing.T) {
	truncateTables(t)

	login := "logout@example.com"
	password := "Password1"
	deviceUID := "device-logout"

	registerUser(t, login, password)
	verifyUser(t, login, deviceUID)
	token := loginUser(t, login, password)

	// Logout
	w := doRequest("POST", "/auth/logout", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogout_SessionInvalidated(t *testing.T) {
	truncateTables(t)

	login := "session-invalidate@example.com"
	password := "Password1"
	deviceUID := "device-session-invalidate"

	registerUser(t, login, password)
	verifyUser(t, login, deviceUID)
	token := loginUser(t, login, password)

	// Verify token works before logout
	w := doRequest("GET", "/auth/me", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on /auth/me before logout, got %d: %s", w.Code, w.Body.String())
	}

	// Logout
	w = doRequest("POST", "/auth/logout", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on logout, got %d: %s", w.Code, w.Body.String())
	}

	// Token should now be invalid
	w = doRequest("GET", "/auth/me", nil, token)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after logout, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogout_NoToken(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/logout", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogout_InvalidToken(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/logout", nil, "not-a-real-token")
	// Logout with invalid token should still succeed (idempotent) or return error
	// Our service does UPDATE sessions SET blocked=true WHERE token=$1 — 0 rows affected but no error
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for invalid token logout (idempotent), got %d: %s", w.Code, w.Body.String())
	}
}
