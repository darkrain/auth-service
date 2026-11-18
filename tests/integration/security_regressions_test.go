package integration

// Regression tests for the security audit of 18.11.2026:
// theGHub1/docs#155 (SEC-04), #156 (SEC-05), #157 (SEC-06), #158 (SEC-07),
// #159 (SEC-08) and #173 (SEC-22).

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/darkrain/auth-service/internal/service"
	"github.com/pquerna/otp/totp"
)

func totpCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func enableTwoFactor(t *testing.T, userID int64, token, secret string) {
	t.Helper()
	w := doRequest("POST", fmt.Sprintf("/auth/account_two_factor/id/%d", userID), map[string]interface{}{
		"two_factor_enabled": true, "two_factor_secret": secret, "two_factor_code": totpCode(t, secret),
	}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("enable two factor: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

func storedTwoFactorSecret(t *testing.T, userID int64) string {
	t.Helper()
	var encrypted string
	if err := testPool.QueryRowContext(context.Background(), `SELECT COALESCE(two_factor_secret_encrypted, '') FROM users WHERE id=$1`, userID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	return encrypted
}

func sessionBlocked(t *testing.T, token string) bool {
	t.Helper()
	var blocked bool
	if err := testPool.QueryRowContext(context.Background(), `SELECT blocked FROM sessions WHERE token=$1`, token).Scan(&blocked); err != nil {
		t.Fatal(err)
	}
	return blocked
}

// pendingHandoff stores a device-handoff code the way the API does
// (api/app/modules/device_handoff.go): a blocked session row that a phone may
// still redeem.
func pendingHandoff(t *testing.T, userID int64) string {
	t.Helper()
	token := fmt.Sprintf("handoff-%d-%d", userID, time.Now().UnixNano())
	if _, err := testPool.ExecContext(context.Background(), `INSERT INTO sessions (user_id, token, expire_date, auth_type, ip, device_uid, blocked)
		VALUES ($1, $2, NOW() + INTERVAL '10 minutes', 'handoff', '127.0.0.1', 'handoff:pending', TRUE)`, userID, token); err != nil {
		t.Fatal(err)
	}
	return token
}

func handoffExists(t *testing.T, token string) bool {
	t.Helper()
	var exists bool
	if err := testPool.QueryRowContext(context.Background(), `SELECT EXISTS(SELECT 1 FROM sessions WHERE token=$1)`, token).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	return exists
}

// SEC-04: an enabled authenticator cannot be replaced by a new secret.
func TestSEC04EnabledTwoFactorCannotBeReplaced(t *testing.T) {
	truncateTables(t)
	login, password := "sec04@example.com", "Password1"
	userID, token := verifiedAccount(t, login, password)
	other := loginUser(t, login, password)
	original, replacement := "JBSWY3DPEHPK3PXP", "KRSXG5CTMVRXEZLU"
	enableTwoFactor(t, userID, token, original)
	stored := storedTwoFactorSecret(t, userID)

	replaced := doRequest("POST", fmt.Sprintf("/auth/account_two_factor/id/%d", userID), map[string]interface{}{
		"two_factor_enabled": true, "two_factor_secret": replacement, "two_factor_code": totpCode(t, replacement),
	}, token)
	if replaced.Code != http.StatusBadRequest {
		t.Fatalf("replacing an enabled secret: expected 400, got %d: %s", replaced.Code, replaced.Body.String())
	}
	if storedTwoFactorSecret(t, userID) != stored {
		t.Fatal("stored two-factor secret changed without the current factor")
	}
	if sessionBlocked(t, other) {
		t.Fatal("a refused replacement must not touch other sessions")
	}

	// The allowed way: disable with the current code, then enable a new one.
	disabled := doRequest("POST", fmt.Sprintf("/auth/account_two_factor/id/%d", userID), map[string]interface{}{
		"two_factor_enabled": false, "two_factor_code": totpCode(t, original),
	}, token)
	if disabled.Code != http.StatusOK {
		t.Fatalf("disable two factor: expected 200, got %d: %s", disabled.Code, disabled.Body.String())
	}
	if !sessionBlocked(t, other) {
		t.Fatal("other sessions must be revoked when the authenticator is replaced")
	}
	enableTwoFactor(t, userID, token, replacement)
	if storedTwoFactorSecret(t, userID) == stored {
		t.Fatal("new secret must be stored after disable and enable")
	}
}

// SEC-05: changing or adding a login contact needs the current password (and
// the authenticator code with 2FA); confirmation ends other sessions.
func TestSEC05ContactChangeRequiresStepUpAndRevokesSessions(t *testing.T) {
	truncateTables(t)
	login, password := "sec05@example.com", "Password1"
	userID, token := verifiedAccount(t, login, password)
	other := loginUser(t, login, password)

	request := func(extra map[string]interface{}) map[string]interface{} {
		body := map[string]interface{}{"contact_type": "email", "recipient": "corrected@example.com", "device_uid": "sec05-device", "allow_fallback": true}
		for k, v := range extra {
			body[k] = v
		}
		return body
	}
	for name, extra := range map[string]map[string]interface{}{
		"no password":    nil,
		"wrong password": {"current_password": "WrongPassword9"},
	} {
		w := doRequest("PUT", "/auth/contact_verifications", request(extra), token)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d: %s", name, w.Code, w.Body.String())
		}
		if errs, _ := parseJSON(w)["errors"].(map[string]interface{}); errs["current_password"] == nil {
			t.Fatalf("%s: error must point at current_password: %s", name, w.Body.String())
		}
	}
	var pending int
	if err := testPool.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM contact_verifications WHERE user_id=$1 AND purpose='verification'`, userID).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if pending != 0 {
		t.Fatalf("a refused request must not create a verification, got %d", pending)
	}

	requested := doRequest("PUT", "/auth/contact_verifications", request(map[string]interface{}{"current_password": password}), token)
	if requested.Code != http.StatusOK {
		t.Fatalf("request with password: expected 200, got %d: %s", requested.Code, requested.Body.String())
	}
	requestID, _ := parseJSON(requested)["value"].(float64)
	confirmed := doRequest("POST", "/auth/contact_verifications/id/"+numberPath(requestID), map[string]string{"code": "333333"}, token)
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm: expected 200, got %d: %s", confirmed.Code, confirmed.Body.String())
	}
	var email string
	if err := testPool.QueryRowContext(context.Background(), `SELECT email FROM users WHERE id=$1`, userID).Scan(&email); err != nil {
		t.Fatal(err)
	}
	if email != "corrected@example.com" {
		t.Fatalf("email must change after confirmation, got %q", email)
	}
	if w := doRequest("GET", "/auth/me", nil, other); w.Code != http.StatusUnauthorized {
		t.Fatalf("other session must be revoked after a contact change, got %d", w.Code)
	}
	if w := doRequest("GET", "/auth/me", nil, token); w.Code != http.StatusOK {
		t.Fatalf("current session must stay after a contact change, got %d: %s", w.Code, w.Body.String())
	}
}

func TestSEC05ContactChangeWithTwoFactorNeedsCode(t *testing.T) {
	truncateTables(t)
	login, password := "sec05-totp@example.com", "Password1"
	userID, token := verifiedAccount(t, login, password)
	secret := "JBSWY3DPEHPK3PXP"
	enableTwoFactor(t, userID, token, secret)
	body := map[string]interface{}{"contact_type": "phone", "recipient": "+79990000001", "device_uid": "sec05-totp", "allow_fallback": true, "current_password": password}

	w := doRequest("PUT", "/auth/contact_verifications", body, token)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("without TOTP: expected 400, got %d: %s", w.Code, w.Body.String())
	}
	if errs, _ := parseJSON(w)["errors"].(map[string]interface{}); errs["two_factor_code"] == nil {
		t.Fatalf("error must point at two_factor_code: %s", w.Body.String())
	}
	body["two_factor_code"] = totpCode(t, secret)
	if w := doRequest("PUT", "/auth/contact_verifications", body, token); w.Code != http.StatusOK {
		t.Fatalf("with password and TOTP: expected 200, got %d: %s", w.Code, w.Body.String())
	}
}

// SEC-06: every revocation path removes device-handoff codes still waiting.
func TestSEC06RevocationRemovesPendingHandoffs(t *testing.T) {
	password := "Password1"
	t.Run("password change", func(t *testing.T) {
		truncateTables(t)
		userID, token := verifiedAccount(t, "sec06-password@example.com", password)
		code := pendingHandoff(t, userID)
		w := doRequest("POST", fmt.Sprintf("/auth/account_password/id/%d", userID), map[string]string{
			"current_password": password, "new_password": "NewPassword2", "confirmation": "NewPassword2",
		}, token)
		if w.Code != http.StatusOK {
			t.Fatalf("change password: %d %s", w.Code, w.Body.String())
		}
		if handoffExists(t, code) {
			t.Fatal("pending handoff must be removed by a password change")
		}
	})
	t.Run("two factor disable", func(t *testing.T) {
		truncateTables(t)
		userID, token := verifiedAccount(t, "sec06-totp@example.com", password)
		secret := "JBSWY3DPEHPK3PXP"
		enableTwoFactor(t, userID, token, secret)
		code := pendingHandoff(t, userID)
		w := doRequest("POST", fmt.Sprintf("/auth/account_two_factor/id/%d", userID), map[string]interface{}{
			"two_factor_enabled": false, "two_factor_code": totpCode(t, secret),
		}, token)
		if w.Code != http.StatusOK {
			t.Fatalf("disable two factor: %d %s", w.Code, w.Body.String())
		}
		if handoffExists(t, code) {
			t.Fatal("pending handoff must be removed when two-factor is disabled")
		}
	})
	t.Run("password reset", func(t *testing.T) {
		truncateTables(t)
		login, device := "reset-test@example.com", "sec06-reset-device"
		regToken := registerUser(t, login, password)
		verifyUser(t, login, device, regToken)
		var userID int64
		if err := testPool.QueryRowContext(context.Background(), `SELECT id FROM users WHERE email=$1`, login).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		code := pendingHandoff(t, userID)
		if w := doRequestWithDevice("POST", "/auth/password/reset-request", map[string]string{"login": login, "device_uid": device}, "", device); w.Code != http.StatusOK {
			t.Fatalf("reset-request: %d %s", w.Code, w.Body.String())
		}
		if w := doRequestWithDevice("POST", "/auth/password/reset-confirm", map[string]interface{}{
			"login": login, "code": "777777", "device_uid": device, "new_password": "NewPass2",
		}, "", device); w.Code != http.StatusOK {
			t.Fatalf("reset-confirm: %d %s", w.Code, w.Body.String())
		}
		if handoffExists(t, code) {
			t.Fatal("pending handoff must be removed by a password reset")
		}
	})
	t.Run("admin block", func(t *testing.T) {
		truncateTables(t)
		userID, _ := verifiedAccount(t, "sec06-block@example.com", password)
		_, adminToken := adminAccount(t, "sec06-admin@example.com", password)
		code := pendingHandoff(t, userID)
		blockRequest(t, adminToken, userID, true)
		if handoffExists(t, code) {
			t.Fatal("pending handoff must be removed by an administrative block")
		}
	})
}

// SEC-07: wrong contact codes are counted in the database and the request
// expires at MaxAttempts, so even the right code is refused afterwards.
func TestSEC07ContactCodeAttemptsArePersisted(t *testing.T) {
	truncateTables(t)
	login, password := "sec07@example.com", "Password1"
	_, token := verifiedAccount(t, login, password)
	requested := doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
		"contact_type": "email", "recipient": "corrected@example.com", "device_uid": "sec07-device", "allow_fallback": true, "current_password": password,
	}, token)
	if requested.Code != http.StatusOK {
		t.Fatalf("request: %d %s", requested.Code, requested.Body.String())
	}
	requestID, _ := parseJSON(requested)["value"].(float64)
	path := "/auth/contact_verifications/id/" + numberPath(requestID)
	max := testCfg.RateLimit.Code.MaxAttempts
	if max <= 1 {
		t.Fatalf("test config needs MaxAttempts > 1, got %d", max)
	}

	if w := doRequest("POST", path, map[string]string{"code": "000000"}, token); w.Code == http.StatusOK {
		t.Fatal("wrong code must be refused")
	}
	var counter int
	var status string
	if err := testPool.QueryRowContext(context.Background(), `SELECT counter, status FROM contact_verifications WHERE id=$1`, int64(requestID)).Scan(&counter, &status); err != nil {
		t.Fatal(err)
	}
	if counter != 1 || status != "pending" {
		t.Fatalf("one wrong attempt must be stored: counter=%d status=%q", counter, status)
	}
	for i := 1; i < max; i++ {
		if w := doRequest("POST", path, map[string]string{"code": "000000"}, token); w.Code == http.StatusOK {
			t.Fatal("wrong code must be refused")
		}
	}
	if err := testPool.QueryRowContext(context.Background(), `SELECT counter, status FROM contact_verifications WHERE id=$1`, int64(requestID)).Scan(&counter, &status); err != nil {
		t.Fatal(err)
	}
	if counter != max || status != "expired" {
		t.Fatalf("after MaxAttempts the request must expire: counter=%d status=%q", counter, status)
	}
	if w := doRequest("POST", path, map[string]string{"code": "333333"}, token); w.Code == http.StatusOK {
		t.Fatalf("the right code must be refused after MaxAttempts: %s", w.Body.String())
	}
	var email string
	if err := testPool.QueryRowContext(context.Background(), `SELECT email FROM users WHERE email=$1`, login).Scan(&email); err != nil {
		t.Fatalf("email must not change: %v", err)
	}
}

func TestSEC07ExpiredContactCodeIsMarkedExpired(t *testing.T) {
	truncateTables(t)
	login, password := "sec07-expired@example.com", "Password1"
	_, token := verifiedAccount(t, login, password)
	requested := doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
		"contact_type": "email", "recipient": "corrected@example.com", "device_uid": "sec07-device", "allow_fallback": true, "current_password": password,
	}, token)
	if requested.Code != http.StatusOK {
		t.Fatalf("request: %d %s", requested.Code, requested.Body.String())
	}
	requestID, _ := parseJSON(requested)["value"].(float64)
	if _, err := testPool.ExecContext(context.Background(), `UPDATE contact_verifications SET expires_at=NOW() - INTERVAL '1 second' WHERE id=$1`, int64(requestID)); err != nil {
		t.Fatal(err)
	}
	if w := doRequest("POST", "/auth/contact_verifications/id/"+numberPath(requestID), map[string]string{"code": "333333"}, token); w.Code == http.StatusOK {
		t.Fatal("an expired code must be refused")
	}
	var status string
	if err := testPool.QueryRowContext(context.Background(), `SELECT status FROM contact_verifications WHERE id=$1`, int64(requestID)).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "expired" {
		t.Fatalf("expired code must be stored as expired, got %q", status)
	}
}

// SEC-08: parallel wrong reset codes cannot exceed MaxAttempts.
func TestSEC08ParallelResetAttemptsRespectLimit(t *testing.T) {
	truncateTables(t)
	login, password, device := "reset-test@example.com", "OldPass1", "sec08-device"
	regToken := registerUser(t, login, password)
	verifyUser(t, login, device, regToken)
	if w := doRequestWithDevice("POST", "/auth/password/reset-request", map[string]string{"login": login, "device_uid": device}, "", device); w.Code != http.StatusOK {
		t.Fatalf("reset-request: %d %s", w.Code, w.Body.String())
	}
	max := testCfg.RateLimit.Code.MaxAttempts
	workers := 2*max + 4
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := map[string]int{}
	start := make(chan struct{})
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := service.ConfirmPasswordReset(context.Background(), testPool, testCfg, nil, login, "000000", device, "NewPass2")
			key := "other"
			switch {
			case errors.Is(err, service.ErrInvalidCode):
				key = "invalid"
			case errors.Is(err, service.ErrTooManyCodeAttempts):
				key = "too_many"
			}
			mu.Lock()
			results[key]++
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	var counter int
	if err := testPool.QueryRowContext(context.Background(), `SELECT counter FROM confirm_codes WHERE recipient=$1 AND device_uid=$2 AND auth_type='password_reset'`, login, device).Scan(&counter); err != nil {
		t.Fatal(err)
	}
	if results["invalid"] > max || counter > max || results["other"] != 0 {
		t.Fatalf("at most %d attempts may be checked: results=%v counter=%d", max, results, counter)
	}
	if results["too_many"] != workers-results["invalid"] {
		t.Fatalf("every attempt over the limit must be refused as too many: %v", results)
	}
	// The right code is refused once the attempts are spent.
	if err := service.ConfirmPasswordReset(context.Background(), testPool, testCfg, nil, login, "777777", device, "NewPass2"); !errors.Is(err, service.ErrTooManyCodeAttempts) {
		t.Fatalf("right code after the limit: expected too many attempts, got %v", err)
	}
}

func TestSEC08RightResetCodeWithinLimitWorks(t *testing.T) {
	truncateTables(t)
	login, password, device := "reset-test@example.com", "OldPass1", "sec08-ok-device"
	regToken := registerUser(t, login, password)
	verifyUser(t, login, device, regToken)
	if w := doRequestWithDevice("POST", "/auth/password/reset-request", map[string]string{"login": login, "device_uid": device}, "", device); w.Code != http.StatusOK {
		t.Fatalf("reset-request: %d %s", w.Code, w.Body.String())
	}
	if err := service.ConfirmPasswordReset(context.Background(), testPool, testCfg, nil, login, "000000", device, "NewPass2"); !errors.Is(err, service.ErrInvalidCode) {
		t.Fatalf("wrong code: expected invalid, got %v", err)
	}
	if err := service.ConfirmPasswordReset(context.Background(), testPool, testCfg, nil, login, "777777", device, "NewPass2"); err != nil {
		t.Fatalf("right code within the limit: %v", err)
	}
	loginUser(t, login, "NewPass2")
}

// SEC-22: routes that send codes are rate limited, and one account cannot
// send codes to more than the daily number of different contacts.
func TestSEC22ContactCodeSendingIsRateLimited(t *testing.T) {
	limits := testCfg.RateLimit
	t.Cleanup(func() { testCfg.RateLimit = limits })
	testCfg.RateLimit.IP.SendCodeMaxAttempts = 2
	testCfg.RateLimit.IP.SendCodeWindowSec = 60

	t.Run("contact verifications", func(t *testing.T) {
		truncateTables(t)
		login, password := "sec22@example.com", "Password1"
		_, token := verifiedAccount(t, login, password)
		var last int
		for i := 0; i < 3; i++ {
			w := doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
				"contact_type": "email", "recipient": fmt.Sprintf("sec22-%d@example.test", i), "device_uid": "sec22-device", "allow_fallback": true, "current_password": password,
			}, token)
			last = w.Code
			if i < 2 && w.Code != http.StatusOK {
				t.Fatalf("request %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
			}
		}
		if last != http.StatusTooManyRequests {
			t.Fatalf("request over the SendCode limit: expected 429, got %d", last)
		}
	})
	t.Run("registration contact", func(t *testing.T) {
		truncateTables(t)
		registration := doRequest("POST", "/auth/register", map[string]interface{}{
			"login": "sec22-registration@example.test", "password": "Password1", "device_uid": "sec22-reg-device",
		}, "")
		if registration.Code != http.StatusCreated {
			t.Fatalf("register: %d %s", registration.Code, registration.Body.String())
		}
		registrationToken, _ := parseJSON(registration)["registration_token"].(string)
		var last int
		for i := 0; i < 3; i++ {
			w := doRequest("PUT", "/auth/registration/contact", map[string]interface{}{
				"login": fmt.Sprintf("sec22-reg-%d@example.test", i), "device_uid": "sec22-reg-device", "allow_fallback": true,
			}, registrationToken)
			last = w.Code
			if i < 2 && w.Code != http.StatusOK {
				t.Fatalf("change %d: expected 200, got %d: %s", i, w.Code, w.Body.String())
			}
		}
		if last != http.StatusTooManyRequests {
			t.Fatalf("registration contact over the SendCode limit: expected 429, got %d", last)
		}
	})
}

func TestSEC22DistinctRecipientsPerDayAreCapped(t *testing.T) {
	truncateTables(t)
	login, password := "sec22-cap@example.com", "Password1"
	_, token := verifiedAccount(t, login, password)
	limit := service.ContactRecipientsPerDay(context.Background(), testPool)
	if limit <= 0 {
		t.Fatalf("the default recipient limit must be on, got %d", limit)
	}
	send := func(i int) int {
		return doRequest("PUT", "/auth/contact_verifications", map[string]interface{}{
			"contact_type": "email", "recipient": fmt.Sprintf("sec22-cap-%d@example.test", i), "device_uid": "sec22-cap-device", "allow_fallback": true, "current_password": password,
		}, token).Code
	}
	// The registration code went to the login itself; it counts as one.
	for i := 1; i < limit; i++ {
		if code := send(i); code != http.StatusOK {
			t.Fatalf("recipient %d of %d: expected 200, got %d", i+1, limit, code)
		}
	}
	if code := send(limit); code != http.StatusTooManyRequests {
		t.Fatalf("recipient over the daily limit: expected 429, got %d", code)
	}
}

func TestSEC22RecipientLimitSetting(t *testing.T) {
	ctx := context.Background()
	var exists bool
	if err := testPool.QueryRowContext(ctx, `SELECT to_regclass('public.settings') IS NOT NULL`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := testPool.ExecContext(ctx, `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = testPool.ExecContext(ctx, `DROP TABLE settings`) })
	} else {
		t.Cleanup(func() {
			_, _ = testPool.ExecContext(ctx, `DELETE FROM settings WHERE key=$1`, service.ContactRecipientsPerDaySetting)
		})
	}
	if got := service.ContactRecipientsPerDay(ctx, testPool); got != service.DefaultContactRecipientsPerDay {
		t.Fatalf("missing setting: expected default %d, got %d", service.DefaultContactRecipientsPerDay, got)
	}
	if _, err := testPool.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES ($1, '2')`, service.ContactRecipientsPerDaySetting); err != nil {
		t.Fatal(err)
	}
	if got := service.ContactRecipientsPerDay(ctx, testPool); got != 2 {
		t.Fatalf("setting 2: got %d", got)
	}
}
