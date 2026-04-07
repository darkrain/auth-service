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

func TestRegister_InvalidEmail(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "notanemail",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid email, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["error"] == nil {
		t.Errorf("expected error field in response")
	}
}

func TestRegister_InvalidEmailMissingAt(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "@domain.com",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid email @domain.com, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_InvalidPhone_NoPlus(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "89991234567",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid phone without +, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["error"] == nil {
		t.Errorf("expected error field in response")
	}
}

func TestRegister_InvalidPhone_TooShort(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "+7",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for too short phone, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_WithRole_Model(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]interface{}{
		"login":    "rolemodel@example.com",
		"password": "Password1",
		"role":     "model",
	}, "")

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for role=model, got %d: %s", w.Code, w.Body.String())
	}
}

func TestRegister_WithRole_Admin_Forbidden(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]interface{}{
		"login":    "adminrole@example.com",
		"password": "Password1",
		"role":     "admin",
	}, "")

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for role=admin, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if code, ok := body["code"].(string); !ok || code != "ERR_ROLE_RESERVED" {
		t.Errorf("expected code ERR_ROLE_RESERVED, got: %s", w.Body.String())
	}
}

func TestRegister_WithRole_Unknown_Invalid(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]interface{}{
		"login":    "unknownrole@example.com",
		"password": "Password1",
		"role":     "unknown_role",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for role=unknown_role, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if code, ok := body["code"].(string); !ok || code != "ERR_ROLE_INVALID" {
		t.Errorf("expected code ERR_ROLE_INVALID, got: %s", w.Body.String())
	}
}

func TestRegister_NoRole_DefaultsToFirstAllowedRole(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    "norole@example.com",
		"password": "Password1",
	}, "")

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for empty role (default), got %d: %s", w.Code, w.Body.String())
	}
}
