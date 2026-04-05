package integration

import (
	"net/http"
	"testing"
)

func TestRegister_Success_Email(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "user@example.com",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["message"] == nil {
		t.Errorf("expected message in response, got: %s", w.Body.String())
	}
}

func TestRegister_Success_Phone(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "+79001234567",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_DuplicateEmail(t *testing.T) {
	truncateTables(t)

	registerUser(t, "dup@example.com", "Password1")

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "dup@example.com",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for duplicate, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["error"] == nil {
		t.Errorf("expected error field in response")
	}
}

func TestRegister_WeakPassword_TooShort(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "short@example.com",
		"password": "a1",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for short password, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_WeakPassword_NoDigit(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "nodigit@example.com",
		"password": "PasswordNoDigit",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for password without digit, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_EmptyLogin(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty login, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_EmptyPassword(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "user2@example.com",
		"password": "",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty password, got %d: %s", w.Code, w.Body.String())
	}
}
