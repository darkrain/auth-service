package integration

import (
	"net/http"
	"testing"
)

func TestLogin_Success(t *testing.T) {
	truncateTables(t)

	login := "logintest@example.com"
	password := "Password1"
	deviceUID := "device-login-success"

	registerUser(t, login, password)
	verifyUser(t, login, deviceUID)

	w := doRequest("POST", "/auth/login", map[string]string{
		"login":    login,
		"password": password,
	}, "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["token"] == nil {
		t.Errorf("expected token in response")
	}
	if body["expire_date"] == nil {
		t.Errorf("expected expire_date in response")
	}
}

func TestLogin_UnverifiedUser_Blocked(t *testing.T) {
	truncateTables(t)

	login := "unverified@example.com"
	password := "Password1"

	registerUser(t, login, password)
	// Do NOT verify — user is in 'registered' status

	w := doRequest("POST", "/auth/login", map[string]string{
		"login":    login,
		"password": password,
	}, "")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unverified user, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["error"] == nil {
		t.Errorf("expected error field")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	truncateTables(t)

	login := "wrongpass@example.com"
	password := "Password1"
	deviceUID := "device-login-wrongpass"

	registerUser(t, login, password)
	verifyUser(t, login, deviceUID)

	w := doRequest("POST", "/auth/login", map[string]string{
		"login":    login,
		"password": "WrongPass999",
	}, "")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_UserNotFound(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/login", map[string]string{
		"login":    "nonexistent@example.com",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for unknown user, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_EmptyCredentials(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/login", map[string]string{
		"login":    "",
		"password": "",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty credentials, got %d: %s", w.Code, w.Body.String())
	}
}

func TestLogin_InvalidJSON(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/login", nil, "")

	// nil body should fail binding
	if w.Code == http.StatusOK {
		t.Fatalf("expected non-200 for invalid body, got %d", w.Code)
	}
}
