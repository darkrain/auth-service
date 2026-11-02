package integration

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkrain/auth-service/internal/middleware"
	"github.com/darkrain/auth-service/internal/service"
	"github.com/gin-gonic/gin"
)

func TestRegistrationBrandAndDomainLoginPolicy(t *testing.T) {
	truncateTables(t)
	ctx := context.Background()
	top := *testCfg
	top.RegistrationBrand = "topmember"
	top.AllowedRoles = []string{"client"}
	top.AllowedLoginRoles = []string{"client", "admin", "system"}
	top.MessageBroker.PublishMode = "disabled"
	login, password := "brand@example.invalid", "Password1"
	_, err := service.Register(ctx, testPool, nil, &top, service.RegisterRequest{Login: login, Password: password, Role: "client", DeviceUID: "brand-fixture"})
	if err != nil {
		t.Fatal(err)
	}
	var brand string
	if err := testPool.QueryRow("SELECT registration_brand FROM users WHERE email=$1", login).Scan(&brand); err != nil || brand != "topmember" {
		t.Fatalf("brand=%q err=%v", brand, err)
	}
	if _, err := testPool.Exec("UPDATE users SET verify_status='verified',email_verified=true WHERE email=$1", login); err != nil {
		t.Fatal(err)
	}
	main := top
	main.RegistrationBrand = "iamfree"
	main.AllowedRoles = []string{"model", "agency", "manager"}
	main.AllowedLoginRoles = []string{"model", "agency", "manager", "admin", "system"}
	if _, err := service.Login(ctx, testPool, &main, nil, login, password, "fixture", "127.0.0.1"); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("main accepted TopMember: %v", err)
	}
	if err := service.ConfirmPasswordReset(ctx, testPool, &main, nil, login, "123456", "fixture", password); !errors.Is(err, service.ErrForbidden) {
		t.Fatalf("main accepted TopMember password reset: %v", err)
	}
	session, err := service.Login(ctx, testPool, &top, nil, login, password, "fixture", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Fill the shared Redis cache through the allowed domain, then try the same
	// token on the forbidden domain. Repeat after clearing cache for the SQL path.
	for _, useCache := range []bool{true, false} {
		for _, row := range []struct {
			roles []string
			want  int
		}{{top.AllowedLoginRoles, 200}, {main.AllowedLoginRoles, 403}} {
			r := gin.New()
			cache := testCache
			if !useCache {
				cache = nil
			}
			r.GET("/auth/me", middleware.Auth(testPool, cache, row.roles), func(c *gin.Context) { c.Status(200) })
			req := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
			req.Header.Set("Authorization", "Bearer "+session.Token)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			if w.Code != row.want {
				t.Fatalf("cache=%v status=%d want=%d", useCache, w.Code, row.want)
			}
		}
	}
	if err := testPool.QueryRow("SELECT registration_brand FROM users WHERE email=$1", login).Scan(&brand); err != nil || brand != "topmember" {
		t.Fatal("login changed registration brand")
	}
}
