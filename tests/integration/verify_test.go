package integration

import (
	"net/http"
	"testing"
)

func TestSendCode_Success(t *testing.T) {
	truncateTables(t)

	login := "sendcode@example.com"
	password := "Password1"
	deviceUID := "device-sendcode"

	registerUser(t, login, password)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["message"] == nil {
		t.Errorf("expected message field")
	}
}

func TestSendCode_EmptyRecipient(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "",
		"device_uid": "some-device",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty recipient, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmail_Success(t *testing.T) {
	truncateTables(t)

	login := "verifyemail@example.com"
	password := "Password1"
	deviceUID := "device-verify-email"

	registerUser(t, login, password)

	// Send code
	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get code from DB
	code := getConfirmCode(t, login, deviceUID)

	// Verify
	w = doRequest("POST", "/auth/verify/email", map[string]string{
		"recipient":  login,
		"code":       code,
		"device_uid": deviceUID,
	}, "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmail_WrongCode(t *testing.T) {
	truncateTables(t)

	login := "wrongcode@example.com"
	password := "Password1"
	deviceUID := "device-wrong-code"

	registerUser(t, login, password)

	// Send code
	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d", w.Code)
	}

	// Use wrong code
	w = doRequest("POST", "/auth/verify/email", map[string]string{
		"recipient":  login,
		"code":       "000000",
		"device_uid": deviceUID,
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong code, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmail_CodeNotFound(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/verify/email", map[string]string{
		"recipient":  "nocode@example.com",
		"code":       "123456",
		"device_uid": "no-device",
	}, "")

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for missing code, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyPhone_Success(t *testing.T) {
	truncateTables(t)

	login := "+79001112233"
	password := "Password1"
	deviceUID := "device-verify-phone"

	registerUser(t, login, password)

	// Send code
	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get code from DB
	code := getConfirmCode(t, login, deviceUID)

	// Verify
	w = doRequest("POST", "/auth/verify/phone", map[string]string{
		"recipient":  login,
		"code":       code,
		"device_uid": deviceUID,
	}, "")

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmail_AfterVerify_CanLogin(t *testing.T) {
	truncateTables(t)

	login := "verifiedlogin@example.com"
	password := "Password1"
	deviceUID := "device-verified-login"

	registerUser(t, login, password)
	verifyUser(t, login, deviceUID)

	// Now login should succeed
	token := loginUser(t, login, password)
	if token == "" {
		t.Fatal("expected non-empty token after verification")
	}
}
