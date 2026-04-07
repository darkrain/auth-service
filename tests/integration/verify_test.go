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

	registrationToken := registerUser(t, login, password)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, registrationToken)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["message"] == nil {
		t.Errorf("expected message field")
	}
}

// TestSendCode_WrongRecipient verifies that /auth/send-code returns 403
// when the recipient does not belong to the authenticated user (HIGH-NEW-1).
func TestSendCode_WrongRecipient(t *testing.T) {
	truncateTables(t)

	login := "owner@example.com"
	password := "Password1"
	deviceUID := "device-wrong-recipient"

	// Register user with login email
	registrationToken := registerUser(t, login, password)

	// Try to send code to a different recipient (not the user's email)
	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "other@example.com",
		"device_uid": deviceUID,
	}, registrationToken)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for wrong recipient, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["error"] == nil {
		t.Errorf("expected error field in 403 response")
	}
}

// TestSendCode_NoToken verifies that /auth/send-code requires authentication.
func TestSendCode_NoToken(t *testing.T) {
	truncateTables(t)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "test@example.com",
		"device_uid": "some-device",
	}, "")

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token on /auth/send-code, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	if body["error"] == nil {
		t.Errorf("expected error field in 401 response")
	}
}

func TestSendCode_EmptyRecipient(t *testing.T) {
	truncateTables(t)

	// NEW-2: /auth/send-code now requires auth; use system user token to test validation
	systemToken := loginSystemUser(t)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "",
		"device_uid": "some-device",
	}, systemToken)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for empty recipient, got %d: %s", w.Code, w.Body.String())
	}
}

func TestVerifyEmail_Success(t *testing.T) {
	truncateTables(t)

	login := "verifyemail@example.com"
	password := "Password1"
	deviceUID := "device-verify-email"

	registrationToken := registerUser(t, login, password)

	// NEW-2: /auth/send-code now requires auth; use registration token
	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, registrationToken)
	if w.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get code from DB
	code := getConfirmCode(t, login, deviceUID)

	// CRIT-2: verify now requires auth token
	token := registrationToken

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

	registrationToken := registerUser(t, login, password)

	// NEW-2: /auth/send-code now requires auth; use registration token
	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, registrationToken)
	if w.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d", w.Code)
	}

	// CRIT-2: verify now requires auth token
	token := registrationToken

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

	registrationToken := registerUser(t, login, password)

	// NEW-2: /auth/send-code now requires auth; use registration token
	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, registrationToken)
	if w.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Get code from DB
	code := getConfirmCode(t, login, deviceUID)

	// CRIT-2: verify now requires auth token
	token := registrationToken

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

	// NEW-2: /auth/send-code now requires auth; use system user token to test validation
	systemToken := loginSystemUser(t)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "notanemail",
		"device_uid": "some-device",
	}, systemToken)

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

	// NEW-2: /auth/send-code now requires auth; use system user token to test validation
	systemToken := loginSystemUser(t)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "89991234567",
		"device_uid": "some-device",
	}, systemToken)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid phone in send-code, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSendCode_Garbage(t *testing.T) {
	truncateTables(t)

	// NEW-2: /auth/send-code now requires auth; use system user token to test validation
	systemToken := loginSystemUser(t)

	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  "not-valid!!!",
		"device_uid": "some-device",
	}, systemToken)

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

// TestFixedVerificationCode verifies that a test account uses the fixed verification code
// and skips RabbitMQ (code is saved to DB directly).
func TestFixedVerificationCode(t *testing.T) {
	truncateTables(t)

	login := "testaccount@example.com"
	password := "Password1"
	deviceUID := "device-fixed-code"

	// Register with the test account email
	registrationToken := registerUser(t, login, password)
	if registrationToken == "" {
		t.Fatal("expected registration_token in register response")
	}

	// Call send-code — should use fixed code "111111" and NOT publish to RabbitMQ
	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, registrationToken)
	if w.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify with the fixed code "111111" → should succeed
	w = doRequest("POST", "/auth/verify/email", map[string]string{
		"recipient":  login,
		"code":       "111111",
		"device_uid": deviceUID,
	}, registrationToken)
	if w.Code != http.StatusOK {
		t.Fatalf("verify with fixed code: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// TestFixedVerificationCode_WrongCode verifies that a wrong code for a test account still fails.
func TestFixedVerificationCode_WrongCode(t *testing.T) {
	truncateTables(t)

	login := "testaccount@example.com"
	password := "Password1"
	deviceUID := "device-fixed-code-wrong"

	// Register with the test account email
	registrationToken := registerUser(t, login, password)
	if registrationToken == "" {
		t.Fatal("expected registration_token in register response")
	}

	// Call send-code
	w := doRequest("POST", "/auth/send-code", map[string]string{
		"recipient":  login,
		"device_uid": deviceUID,
	}, registrationToken)
	if w.Code != http.StatusOK {
		t.Fatalf("send-code: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify with a wrong code → should fail with 400
	w = doRequest("POST", "/auth/verify/email", map[string]string{
		"recipient":  login,
		"code":       "000000",
		"device_uid": deviceUID,
	}, registrationToken)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("verify with wrong code: expected 400, got %d: %s", w.Code, w.Body.String())
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
