package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
)

func adminAccount(t *testing.T, login, password string) (int64, string) {
	t.Helper()
	id, _ := verifiedAccount(t, login, password)
	if _, err := testPool.ExecContext(context.Background(), `UPDATE users SET role='admin' WHERE id=$1`, id); err != nil {
		t.Fatalf("make admin: %v", err)
	}
	return id, loginUser(t, login, password)
}

func blockRequest(t *testing.T, token string, userID int64, block bool) map[string]interface{} {
	t.Helper()
	w := doRequest("POST", fmt.Sprintf("/admin/users/%d/block", userID), map[string]bool{"block": block}, token)
	if w.Code != http.StatusOK {
		t.Fatalf("block=%v: expected 200, got %d: %s", block, w.Code, w.Body.String())
	}
	return parseJSON(w)
}

func countBlockLogs(t *testing.T, userID int64) int {
	t.Helper()
	var n int
	if err := testPool.QueryRowContext(context.Background(), `SELECT count(*) FROM change_logs WHERE table_name='users' AND object_id=$1`, userID).Scan(&n); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	return n
}

func TestAdminBlockRevokesSessionsAndUnblockRestoresStatus(t *testing.T) {
	truncateTables(t)
	password := "Password1"
	userID, token := verifiedAccount(t, "block-target@example.com", password)
	other := loginUser(t, "block-target@example.com", password)
	adminID, adminToken := adminAccount(t, "block-admin@example.com", password)

	// Both sessions are cached in Redis by a request before the block.
	for _, session := range []string{token, other} {
		if w := doRequest("GET", "/auth/me", nil, session); w.Code != http.StatusOK {
			t.Fatalf("session before block: %d", w.Code)
		}
	}

	body := blockRequest(t, adminToken, userID, true)
	if body["verify_status"] != "banned" || body["blocked"] != true || body["changed"] != true {
		t.Fatalf("unexpected block result: %v", body)
	}
	for _, session := range []string{token, other} {
		if w := doRequest("GET", "/auth/me", nil, session); w.Code != http.StatusUnauthorized {
			t.Fatalf("blocked account session must be refused, got %d: %s", w.Code, w.Body.String())
		}
	}
	if w := doRequest("POST", "/auth/login", map[string]string{"login": "block-target@example.com", "password": password, "device_uid": "blocked-device"}, ""); w.Code != http.StatusForbidden {
		t.Fatalf("blocked account must not log in, got %d: %s", w.Code, w.Body.String())
	}
	var actor int64
	var from, to string
	if err := testPool.QueryRowContext(context.Background(), `SELECT user_id, value_from, value_to FROM change_logs WHERE object_id=$1 ORDER BY id DESC LIMIT 1`, userID).Scan(&actor, &from, &to); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if actor != adminID || from != `{"verify_status":"verified"}` || to != `{"action":"admin_block","verify_status":"banned"}` {
		t.Fatalf("unexpected audit: actor=%d from=%s to=%s", actor, from, to)
	}

	// A repeated block changes nothing and writes no second audit row.
	if body := blockRequest(t, adminToken, userID, true); body["changed"] != false {
		t.Fatalf("repeated block must not change: %v", body)
	}
	if n := countBlockLogs(t, userID); n != 1 {
		t.Fatalf("expected one audit row, got %d", n)
	}

	body = blockRequest(t, adminToken, userID, false)
	if body["verify_status"] != "verified" || body["blocked"] != false || body["changed"] != true {
		t.Fatalf("unexpected unblock result: %v", body)
	}
	// Old sessions stay revoked; a new login works.
	if w := doRequest("GET", "/auth/me", nil, token); w.Code != http.StatusUnauthorized {
		t.Fatalf("unblock must not revive an old session, got %d", w.Code)
	}
	fresh := loginUser(t, "block-target@example.com", password)
	if w := doRequest("GET", "/auth/me", nil, fresh); w.Code != http.StatusOK {
		t.Fatalf("unblocked account must work, got %d", w.Code)
	}
	if body := blockRequest(t, adminToken, userID, false); body["changed"] != false {
		t.Fatalf("repeated unblock must not change: %v", body)
	}
	if n := countBlockLogs(t, userID); n != 2 {
		t.Fatalf("expected two audit rows, got %d", n)
	}
}

func TestAdminBlockPermissionsAndLimits(t *testing.T) {
	truncateTables(t)
	password := "Password1"
	userID, userToken := verifiedAccount(t, "block-limits-user@example.com", password)
	adminID, adminToken := adminAccount(t, "block-limits-admin@example.com", password)
	path := func(id int64) string { return fmt.Sprintf("/admin/users/%d/block", id) }

	if w := doRequest("POST", path(adminID), map[string]bool{"block": true}, userToken); w.Code != http.StatusForbidden {
		t.Fatalf("customer must not block, got %d", w.Code)
	}
	if w := doRequest("POST", path(userID), map[string]bool{"block": true}, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous must not block, got %d", w.Code)
	}
	if w := doRequest("POST", path(adminID), map[string]bool{"block": true}, adminToken); w.Code != http.StatusForbidden {
		t.Fatalf("self block must be refused, got %d", w.Code)
	}
	for _, body := range []interface{}{map[string]string{"block": "yes"}, map[string]interface{}{}, map[string]interface{}{"block": true, "extra": 1}} {
		if w := doRequest("POST", path(userID), body, adminToken); w.Code != http.StatusBadRequest {
			t.Fatalf("invalid body %v must be refused, got %d", body, w.Code)
		}
	}
	if w := doRequest("POST", path(999999999), map[string]bool{"block": true}, adminToken); w.Code != http.StatusNotFound {
		t.Fatalf("missing user must be 404, got %d", w.Code)
	}
	// A ban that came from elsewhere has no recorded status to restore.
	if _, err := testPool.ExecContext(context.Background(), `UPDATE users SET verify_status='banned' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if w := doRequest("POST", path(userID), map[string]bool{"block": false}, adminToken); w.Code != http.StatusConflict {
		t.Fatalf("unblock without audit must conflict, got %d: %s", w.Code, w.Body.String())
	}
	if _, err := testPool.ExecContext(context.Background(), `UPDATE users SET verify_status='deactivated' WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if w := doRequest("POST", path(userID), map[string]bool{"block": true}, adminToken); w.Code != http.StatusConflict {
		t.Fatalf("deactivated account block must conflict, got %d", w.Code)
	}
}
