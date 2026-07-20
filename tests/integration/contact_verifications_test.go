package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func TestContactVerifications_Defrec(t *testing.T) {
	truncateTables(t)
	token := verifiedLoginToken(t, "cv-defrec@example.com")

	w := doRequest("GET", "/auth/contact_verifications/defrec/?lang=ru", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["fields"] == nil {
		t.Fatalf("expected fields in defrec response: %s", w.Body.String())
	}
	rendererInfo, ok := body["renderer"].(map[string]interface{})
	if !ok || rendererInfo["name"] != "UniversalRenderer" {
		t.Fatalf("expected UniversalRenderer identity in defrec response: %s", w.Body.String())
	}
	formPage, ok := body["form_page"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected form_page in defrec response: %s", w.Body.String())
	}
	context, ok := formPage["context"].(map[string]interface{})
	if !ok || context["field_flow"] == nil {
		t.Fatalf("expected field_flow metadata in form_page context: %s", w.Body.String())
	}
	fields, ok := body["fields"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected fields map in defrec response: %s", w.Body.String())
	}
	recipient, ok := fields["recipient"].(map[string]interface{})
	if !ok || recipient["title"] != "Контакт" {
		t.Fatalf("expected localized recipient title, got: %v", recipient)
	}
	contactType, ok := fields["contact_type"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected contact_type field in defrec response: %s", w.Body.String())
	}
	options, ok := contactType["options"].([]interface{})
	if !ok || len(options) == 0 {
		t.Fatalf("expected localized contact_type options, got: %v", contactType["options"])
	}
	firstOption, ok := options[0].(map[string]interface{})
	if !ok || firstOption["label"] != "Email" {
		t.Fatalf("expected localized contact_type option, got: %v", options[0])
	}
}

func TestContactVerifications_TranslationsEndpoint(t *testing.T) {
	w := doRequest("GET", "/api/lang/ru", nil, "")
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["contact_verifications.pages.form.title"] != "Подтвердить контакт" {
		t.Fatalf("expected auth-service contact verification translation, got: %v", body["contact_verifications.pages.form.title"])
	}
}

func TestContactVerifications_EmailChangeFlow(t *testing.T) {
	truncateTables(t)
	token := verifiedLoginToken(t, "cv-email-old@example.com")
	newEmail := "cv-email-new@example.com"
	deviceUID := "cv-email-device"

	w := doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
		"contact_type":   "email",
		"recipient":      newEmail,
		"device_uid":     deviceUID,
		"allow_fallback": true,
	}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("add expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	value, ok := body["value"].(float64)
	if !ok || value <= 0 {
		t.Fatalf("expected created id value: %s", w.Body.String())
	}
	id := int64(value)
	code := getContactVerificationCode(t, id)

	w = doRequest("POST", "/auth/contact_verifications/id/"+intToString(id), map[string]interface{}{
		"code": code,
	}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("confirm expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var email string
	var verified bool
	err := testPool.QueryRow(context.Background(), `SELECT email, email_verified FROM users WHERE email=$1`, newEmail).Scan(&email, &verified)
	if err != nil {
		t.Fatalf("expected user email to be updated: %v", err)
	}
	if email != newEmail || !verified {
		t.Fatalf("expected verified email %s, got %s verified=%v", newEmail, email, verified)
	}
}

func TestContactVerifications_WrongCode(t *testing.T) {
	truncateTables(t)
	token := verifiedLoginToken(t, "cv-wrong-old@example.com")

	w := doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
		"contact_type": "phone",
		"recipient":    "+79001112233",
		"device_uid":   "cv-phone-device",
	}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("add expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	id := int64(body["value"].(float64))

	w = doRequest("POST", "/auth/contact_verifications/id/"+intToString(id), map[string]interface{}{
		"code": "000000",
	}, token)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("wrong code expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func verifiedLoginToken(t *testing.T, login string) string {
	t.Helper()
	password := "Password1"
	registrationToken := registerUser(t, login, password)
	verifyUser(t, login, "verify-"+login, registrationToken)
	return loginUser(t, login, password)
}

func getContactVerificationCode(t *testing.T, id int64) string {
	t.Helper()
	var code string
	err := testPool.QueryRow(context.Background(), `SELECT code FROM contact_verifications WHERE id=$1`, id).Scan(&code)
	if err != nil {
		t.Fatalf("getContactVerificationCode(%d): %v", id, err)
	}
	return code
}

func intToString(v int64) string {
	return fmt.Sprintf("%d", v)
}
