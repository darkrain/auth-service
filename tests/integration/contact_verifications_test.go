package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func TestContactVerificationRegistrationAndSecondContact(t *testing.T) {
	truncateTables(t)

	registration := doRequest("POST", "/auth/register", map[string]interface{}{
		"login": "testaccount@example.com", "password": "Password1", "device_uid": "contact-flow-device",
	}, "")
	if registration.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", registration.Code, registration.Body.String())
	}
	registered := parseJSON(registration)
	registrationToken, _ := registered["registration_token"].(string)
	verificationID, ok := registered["verification_id"].(float64)
	if registrationToken == "" || !ok || verificationID <= 0 {
		t.Fatalf("register must return registration token and verification id: %s", registration.Body.String())
	}

	confirmed := doRequest("POST", "/auth/contact_verifications/id/"+numberPath(verificationID), map[string]string{"code": "111111"}, registrationToken)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("registration confirmation: expected 200, got %d: %s", confirmed.Code, confirmed.Body.String())
	}

	login := doRequest("POST", "/auth/login", map[string]string{"login": "testaccount@example.com", "password": "Password1", "device_uid": "contact-flow-device"}, "")
	if login.Code != http.StatusOK {
		t.Fatalf("login after verification: expected 200, got %d: %s", login.Code, login.Body.String())
	}
	accountToken, _ := parseJSON(login)["token"].(string)

	requested := doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
		"contact_type": "phone", "recipient": "+79990000001", "device_uid": "contact-flow-device", "allow_fallback": true,
	}, accountToken)
	if requested.Code != http.StatusOK {
		t.Fatalf("second contact request: expected 200, got %d: %s", requested.Code, requested.Body.String())
	}
	requestID, ok := parseJSON(requested)["value"].(float64)
	if !ok || requestID <= 0 {
		t.Fatalf("request must return id: %s", requested.Body.String())
	}

	confirmed = doRequest("POST", "/auth/contact_verifications/id/"+numberPath(requestID), map[string]string{"code": "222222"}, accountToken)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("second contact confirmation: expected 200, got %d: %s", confirmed.Code, confirmed.Body.String())
	}

	var phone, codeHash string
	var verified bool
	if err := testPool.QueryRowContext(context.Background(), `
		SELECT u.phone, u.phone_verified, cv.code_hash
		FROM users u JOIN contact_verifications cv ON cv.user_id=u.id
		WHERE u.email=$1 AND cv.id=$2`, "testaccount@example.com", int64(requestID),
	).Scan(&phone, &verified, &codeHash); err != nil {
		t.Fatal(err)
	}
	if phone != "+79990000001" || !verified {
		t.Fatalf("phone was not verified: phone=%q verified=%v", phone, verified)
	}
	if codeHash == "222222" {
		t.Fatal("verification code must not be stored in plaintext")
	}
}

func TestRegistrationTokenCanResendOnlyOriginalContact(t *testing.T) {
	truncateTables(t)

	registration := doRequest("POST", "/auth/register", map[string]interface{}{
		"login": "resend-registration@example.com", "password": "Password1", "device_uid": "resend-device",
	}, "")
	if registration.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", registration.Code, registration.Body.String())
	}
	registered := parseJSON(registration)
	registrationToken, _ := registered["registration_token"].(string)
	initialID, _ := registered["verification_id"].(float64)

	immediateResend := doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
		"contact_type": "email", "recipient": "resend-registration@example.com", "device_uid": "resend-device", "allow_fallback": true,
	}, registrationToken)
	if immediateResend.Code != http.StatusTooManyRequests {
		t.Fatalf("immediate resend: expected 429, got %d: %s", immediateResend.Code, immediateResend.Body.String())
	}
	if immediateResend.Header().Get("Retry-After") == "" {
		t.Fatalf("immediate resend must expose Retry-After: %s", immediateResend.Header())
	}
	if _, err := testPool.ExecContext(context.Background(), `UPDATE contact_verifications SET sent_ts=NOW() - INTERVAL '61 seconds' WHERE id=$1`, int64(initialID)); err != nil {
		t.Fatal(err)
	}

	resend := doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
		"contact_type": "email", "recipient": "resend-registration@example.com", "device_uid": "resend-device", "allow_fallback": true,
	}, registrationToken)
	if resend.Code != http.StatusOK {
		t.Fatalf("resend: expected 200, got %d: %s", resend.Code, resend.Body.String())
	}
	resendID, ok := parseJSON(resend)["value"].(float64)
	if !ok || resendID <= initialID {
		t.Fatalf("resend must return a new verification id: %s", resend.Body.String())
	}

	wrongRecipient := doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
		"contact_type": "email", "recipient": "other@example.com", "device_uid": "resend-device", "allow_fallback": true,
	}, registrationToken)
	if wrongRecipient.Code < http.StatusBadRequest || wrongRecipient.Code >= http.StatusInternalServerError {
		t.Fatalf("registration token must reject another recipient, got %d: %s", wrongRecipient.Code, wrongRecipient.Body.String())
	}
}

func numberPath(value float64) string { return fmt.Sprintf("%.0f", value) }
