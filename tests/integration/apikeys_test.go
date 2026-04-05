package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKey_Create(t *testing.T) {
	truncateTables(t)

	token := loginSystemUser(t)

	w := doRequest("POST", "/auth/api-keys", nil, token)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	body := parseJSON(w)
	if body["id"] == nil {
		t.Errorf("expected id in response")
	}
	if body["token"] == nil {
		t.Errorf("expected token in response")
	}
	if body["created_at"] == nil {
		t.Errorf("expected created_at in response")
	}
}

func TestAPIKey_List(t *testing.T) {
	truncateTables(t)

	token := loginSystemUser(t)

	// Create a couple of keys
	for i := 0; i < 2; i++ {
		w := doRequest("POST", "/auth/api-keys", nil, token)
		if w.Code != http.StatusCreated {
			t.Fatalf("create key %d: expected 201, got %d: %s", i, w.Code, w.Body.String())
		}
	}

	// List
	w := doRequest("GET", "/auth/api-keys", nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var keys []interface{}
	if err := parseJSONArray(w, &keys); err != nil {
		t.Fatalf("failed to parse response as array: %v, body: %s", err, w.Body.String())
	}
	if len(keys) < 2 {
		t.Errorf("expected at least 2 keys, got %d", len(keys))
	}
}

func TestAPIKey_Revoke(t *testing.T) {
	truncateTables(t)

	token := loginSystemUser(t)

	// Create a key
	w := doRequest("POST", "/auth/api-keys", nil, token)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", w.Code, w.Body.String())
	}
	body := parseJSON(w)
	keyID := int(body["id"].(float64))
	apiKeyToken := body["token"].(string)

	// Verify new key works
	w = doRequest("GET", "/auth/me", nil, apiKeyToken)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for api key auth before revoke, got %d: %s", w.Code, w.Body.String())
	}

	// Revoke
	w = doRequest("DELETE", fmt.Sprintf("/auth/api-keys/%d", keyID), nil, token)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 on revoke, got %d: %s", w.Code, w.Body.String())
	}

	// Key should no longer work
	w = doRequest("GET", "/auth/me", nil, apiKeyToken)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after revoke, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKey_Revoke_NotFound(t *testing.T) {
	truncateTables(t)

	token := loginSystemUser(t)

	w := doRequest("DELETE", "/auth/api-keys/999999", nil, token)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for non-existent key, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKey_Create_Unauthorized(t *testing.T) {
	truncateTables(t)

	// Regular user should be forbidden
	login := "regularuser@example.com"
	password := "Password1"
	deviceUID := "device-apikey-unauth"

	registerUser(t, login, password)
	verifyUser(t, login, deviceUID)
	userToken := loginUser(t, login, password)

	w := doRequest("POST", "/auth/api-keys", nil, userToken)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for regular user creating API key, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAPIKey_List_Unauthenticated(t *testing.T) {
	truncateTables(t)

	w := doRequest("GET", "/auth/api-keys", nil, "")
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token, got %d: %s", w.Code, w.Body.String())
	}
}

// parseJSONArray parses response body as a JSON array into dst.
func parseJSONArray(w *httptest.ResponseRecorder, dst *[]interface{}) error {
	return json.Unmarshal(w.Body.Bytes(), dst)
}
