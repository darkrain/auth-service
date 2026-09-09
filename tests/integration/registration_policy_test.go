package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegistrationAdmissionIsAtomic(t *testing.T) {
	truncateTables(t)
	old := testCfg.RegistrationPolicyFunction
	testCfg.RegistrationPolicyFunction = "public.test_registration_admission"
	t.Cleanup(func() {
		testCfg.RegistrationPolicyFunction = old
		_, _ = testPool.Exec(`DROP FUNCTION IF EXISTS public.test_registration_admission(jsonb)`)
	})
	_, err := testPool.Exec(`CREATE OR REPLACE FUNCTION public.test_registration_admission(input jsonb) RETURNS void LANGUAGE plpgsql AS $$
 BEGIN
 IF input->>'invitation'<>'accepted' OR coalesce(input->>'ip','')='' OR input->>'device_uid'<>'admission-device' THEN
 RAISE EXCEPTION 'private policy details must not escape' USING ERRCODE='23514'; END IF;
 IF NOT EXISTS(SELECT 1 FROM users WHERE id=(input->>'user_id')::bigint AND role=input->>'role') THEN RAISE EXCEPTION 'user must be in transaction'; END IF;
 END $$`)
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]string{"login": "admission@example.com", "password": "Password1", "role": "client", "device_uid": "admission-device", "invitation": "rejected"}
	request := func() *httptest.ResponseRecorder {
		body, _ := json.Marshal(input)
		r := httptest.NewRequest("POST", "/auth/register", bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		testRouter.ServeHTTP(w, r)
		return w
	}
	res := request()
	if res.Code != http.StatusBadRequest || parseJSON(res)["code"] != "ERR_REGISTRATION_POLICY" {
		t.Fatalf("unexpected rejection: %d %s", res.Code, res.Body.String())
	}
	var count int
	if err = testPool.QueryRow(`SELECT count(*) FROM users WHERE email='admission@example.com'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rejected admission left occupied login: %d %v", count, err)
	}
	input["invitation"] = "accepted"
	res = request()
	if res.Code != http.StatusCreated {
		t.Fatalf("retry same contact: %d %s", res.Code, res.Body.String())
	}
	if err = testPool.QueryRow(`SELECT count(*) FROM sessions s JOIN users u ON u.id=s.user_id WHERE u.email='admission@example.com' AND s.auth_type='registration' AND s.device_uid='admission-device' AND coalesce(s.ip,'')<>''`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("session not committed with account: %d %v", count, err)
	}
	registrationAdmissionPreview(t)
}

// Optional isolated browser harness. Not a deployed endpoint or public E2E.
func registrationAdmissionPreview(t *testing.T) {
	dist := os.Getenv("AUTH_VISUAL_DIST")
	if dist == "" {
		return
	}
	if _, err := os.Stat(filepath.Join(dist, "index.html")); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var once sync.Once
	files := http.StripPrefix("/v2/", http.FileServer(http.Dir(dist)))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/__stop" && r.Method == "POST":
			once.Do(func() { close(stop) })
			w.WriteHeader(204)
		case strings.HasPrefix(r.URL.Path, "/auth/api/"):
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/auth/api")
			testRouter.ServeHTTP(w, r)
		case strings.HasPrefix(r.URL.Path, "/v2/auth/api/"):
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/v2/auth/api")
			testRouter.ServeHTTP(w, r)
		case r.URL.Path == "/api/lang/ru":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{}`)
		case strings.HasPrefix(r.URL.Path, "/v2/assets/"):
			files.ServeHTTP(w, r)
		default:
			http.ServeFile(w, r, filepath.Join(dist, "index.html"))
		}
	}))
	defer server.Close()
	fmt.Println("AUTH_VISUAL_URL=" + server.URL)
	select {
	case <-stop:
	case <-time.After(3 * time.Minute):
	}
}

func TestRegistrationAdmissionConfigurationCannotInjectSQL(t *testing.T) {
	old := testCfg.RegistrationPolicyFunction
	t.Cleanup(func() { testCfg.RegistrationPolicyFunction = old })
	for _, fn := range []string{"public.policy;select 1", "public.policy($1)", "policy", "public.\"policy\""} {
		testCfg.RegistrationPolicyFunction = fn
		if err := testCfg.Validate(); err == nil {
			t.Fatalf("unsafe function accepted: %q", fn)
		}
	}
}
