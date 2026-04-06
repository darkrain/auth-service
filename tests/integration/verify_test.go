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

	// CRIT-2: verify now requires auth token
	token := createTempSession(t, login)

	// Verify
	w = doRequest("POST", "/auth/verify/email", map[string]string{
		"recipient":  login,
		"code":       code,
		"device_uid": deviceUID,
	}, token)

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

	// CRIT-2: verify now requires auth token
	token := createTempSession(t, login)

	// Use wrong code
	w = doRequest("POST", "/auth/verify/email", map[string]string{
		"recipient":  login,
		"code":       "000000",
		"device_uid": deviceUID,
	}, token)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong code, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmail_CodeNotFound(t *testing.T) {
	truncateTables(t)

	// CRIT-2: verify now requires auth token; use the system user token for this test
	// (testing that a code-not-found error is returned, not auth failure)
	systemToken := loginSystemUser(t)

	w := doRequest("POST", "/auth/verify/email", map[string]string{
		"recipient":  testCfg.SystemUserEmail,
		"code":       "123456",
		"device_uid": "no-device",
	}, systemToken)

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

	// CRIT-2: verify now requires auth token
	token := createTempSession(t, login)

	// Verify
	w = doRequest("POST", "/auth/verify/phone", map[string]string{
		"recipient":  login,
		"code":       code,
		"device_uid": deviceUID,
	}, token)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSendCode_InvalidEmail(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "notanemail",
		"device_uid": "some-device",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid email in send-code, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["error"] == nil {
		t.Errorf("expected error field in response")
	}
}

func TestSendCode_InvalidPhone(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "89991234567",
		"device_uid": "some-device",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid phone in send-code, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSendCode_Garbage(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "not-valid!!!",
		"device_uid": "some-device",
	}, "")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for garbage recipient in send-code, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmail_AfterVerify_CanLogin(t *testing.T) {
	truncateTables(t)

	login := "verifiedlogin@example.com"
	password := "Password1"
	deviceUID := "device-verified-login"

	registrationToken := registerUser(t, login, password)
	verifyUser(t, login, deviceUID, registrationToken)

	// Now login should succeed
	token := loginUser(t, login, password)
	if token == "" {
		t.Fatal("expected non-empty token after verification")
	}
}

// TestRegistrationToken_CannotAccessMe verifies that a registration token
// cannot be used to access protected non-verify endpoints (GET /auth/me → 403).
func TestRegistrationToken_CannotAccessMe(t *testing.T) {
	truncateTables(t)

	login := "regtoken_me@example.com"
	password := "Password1"

	registrationToken := registerUser(t, login, password)
	if registrationToken == "" {
		t.Fatal("expected registration_token in register response")
	}

	w := doRequest("GET", "/auth/me", nil, registrationToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for registration token on /auth/me, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["error"] == nil {
		t.Errorf("expected error field in 403 response")
	}
}

// TestRegistrationToken_InvalidatedAfterVerification verifies that after successful
// email verification the registration token is blocked and cannot be reused.
func TestRegistrationToken_InvalidatedAfterVerification(t *testing.T) {
	truncateTables(t)

	login := "regtoken_inv@example.com"
	password := "Password1"
	deviceUID := "device-regtoken-inv"

	registrationToken := registerUser(t, login, password)
	if registrationToken == "" {
		t.Fatal("expected registration_token in register response")
	}

	// Verify using the registration token
	verifyUser(t, login, deviceUID, registrationToken)

	// After verification the registration token should be blocked (401)
	w := doRequest("POST", "/auth/verify/email", map[string]string{
		"recipient":  login,
		"code":       "000000",
		"device_uid": deviceUID,
	}, registrationToken)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after registration token invalidation, got %d: %s", w.Code, w.Body.String())
	}
}
