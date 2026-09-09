package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"database/sql"
	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/db"
	"github.com/darkrain/auth-service/internal/handler"
	"github.com/darkrain/auth-service/internal/middleware"
	authmodules "github.com/darkrain/auth-service/internal/modules"
	rg "github.com/darkrain/request-generator"
	"github.com/darkrain/request-generator/actions"
	rgdb "github.com/darkrain/request-generator/db"
	"github.com/darkrain/request-generator/locale"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var (
	testCfg    *config.Config
	testPool   *sql.DB
	testCache  *cache.Client
	testRouter *gin.Engine
)

// repoRoot returns the absolute path to the repository root.
func repoRoot() string {
	_, filename, _, _ := runtime.Caller(0)
	// tests/integration/helpers_test.go -> ../../
	return filepath.Join(filepath.Dir(filename), "..", "..")
}

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)

	// Load config from auth-service.test.json
	cfgPath := filepath.Join(repoRoot(), "auth-service.test.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		panic(fmt.Sprintf("failed to load test config: %v", err))
	}
	testCfg = cfg

	// Connect to PostgreSQL
	pool, err := db.Connect(cfg)
	if err != nil {
		panic(fmt.Sprintf("failed to connect to PostgreSQL: %v", err))
	}
	testPool = pool
	defer testPool.Close()

	// Run migrations (pass absolute path)
	migrationsDir := filepath.Join(repoRoot(), "migrations")
	if err := db.Migrate(pool, migrationsDir); err != nil {
		panic(fmt.Sprintf("failed to run migrations: %v", err))
	}

	// Seed system user
	if err := db.Seed(pool, cfg); err != nil {
		panic(fmt.Sprintf("failed to seed: %v", err))
	}

	// Set up cache client
	testCache = cache.NewClient(cfg)

	// Set up Gin router (nil broker — same as main but without RabbitMQ)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// nil broker — RabbitMQ not available in tests
	r.POST("/auth/register",
		middleware.RateLimit(testCache, nil, "/auth/register",
			cfg.RateLimit.IP.RegisterMaxAttempts, cfg.RateLimit.IP.RegisterWindowSec,
			cfg.RateLimit.Device.RegisterMaxAttempts, cfg.RateLimit.Device.RegisterWindowSec),
		handler.Register(pool, nil, cfg))
	r.POST("/auth/login",
		middleware.RateLimit(testCache, nil, "/auth/login",
			cfg.RateLimit.IP.LoginMaxAttempts, cfg.RateLimit.IP.LoginWindowSec,
			cfg.RateLimit.Device.LoginMaxAttempts, cfg.RateLimit.Device.LoginWindowSec),
		handler.Login(pool, nil, cfg, testCache))
	r.POST("/auth/logout", handler.Logout(pool, testCache))
	r.POST("/auth/login/verify-2fa", handler.VerifyLogin2FA(pool, cfg, testCache))

	// Password reset (public — no auth required)
	r.POST("/auth/password/reset-request", handler.ResetRequest(pool, nil, cfg, testCache))
	r.POST("/auth/password/reset-confirm", handler.ResetConfirm(pool, cfg, testCache))

	// Protected routes
	authRequired := r.Group("/")
	authRequired.Use(middleware.Auth(pool, testCache))
	authRequired.PUT("/auth/registration/contact", handler.ChangeRegistrationContact(pool, nil, cfg, testCache))

	moduleDB := rgdb.NewDB(pool)
	moduleRoutes := r.Group("/")
	var generator *rg.Generator
	moduleRoutes.Use(func(c *gin.Context) { middleware.GeneratorContext(generator)(c) })
	generator = rg.NewGenerator(
		func(*rg.BaseModule) rgdb.DBExecutor { return moduleDB },
		*moduleRoutes,
		[]*rg.BaseModule{
			authmodules.ContactVerificationsModule(pool, nil, testCache, cfg),
			authmodules.AccountSecurityModule(pool, cfg),
			authmodules.AccountPasswordModule(pool, testCache, cfg),
			authmodules.AccountTwoFactorModule(pool, testCache, cfg),
			authmodules.AccountSessionsModule(pool, testCache, cfg),
			authmodules.AccountDeactivationModule(pool, testCache, cfg),
		},
		func(_ actions.ModuleAction, roles []actions.Role) gin.HandlerFunc {
			allowed := make([]string, 0, len(roles))
			for _, role := range roles {
				allowed = append(allowed, string(role))
			}
			return middleware.RequireRole(allowed...)
		},
		func(actions.ModuleAction) gin.HandlerFunc { return middleware.Auth(pool, testCache) },
	)
	generator.Locales = []locale.Lang{locale.RU, locale.EN}
	generator.DefaultLocale = locale.EN
	if err := generator.LoadTranslationsFile(locale.RU, filepath.Join(repoRoot(), "locales/ru.json")); err != nil {
		panic(err)
	}
	if err := generator.LoadTranslationsFile(locale.EN, filepath.Join(repoRoot(), "locales/en.json")); err != nil {
		panic(err)
	}
	generator.Run()

	// API key management (admin and system only)
	apiKeys := authRequired.Group("/auth/api-keys")
	apiKeys.Use(middleware.RequireRole("admin", "system"))
	apiKeys.POST("", handler.CreateAPIKey(pool))
	apiKeys.GET("", handler.ListAPIKeys(pool))
	apiKeys.DELETE("/:id", handler.RevokeAPIKey(pool, testCache))

	// Authenticated user info
	authRequired.GET("/auth/me", handler.Me())

	testRouter = r

	os.Exit(m.Run())
}

// truncateTables clears all user data tables and flushes Redis.
func truncateTables(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	// Execute each statement separately — pgx doesn't support multi-statement in one Exec
	statements := []string{
		`DELETE FROM contact_verifications`,
		`DELETE FROM confirm_codes`,
		`DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE role != 'system')`,
		`DELETE FROM users WHERE role != 'system'`,
	}
	for _, stmt := range statements {
		if _, err := testPool.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("truncateTables %q: %v", stmt, err)
		}
	}

	// Flush all Redis keys (test environment only)
	if err := testCache.FlushTestDB(ctx); err != nil {
		t.Logf("WARNING: redis flush failed: %v", err)
	}
}

// doRequest makes an HTTP request to testRouter and returns the ResponseRecorder.
func doRequest(method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		req, _ = http.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, _ = http.NewRequest(method, path, nil)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// doRequestWithDevice makes an HTTP request with X-Device-ID header.
func doRequestWithDevice(method, path string, body interface{}, token, deviceUID string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		b, _ := json.Marshal(body)
		req, _ = http.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, _ = http.NewRequest(method, path, nil)
	}

	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if deviceUID != "" {
		req.Header.Set("X-Device-ID", deviceUID)
	}

	w := httptest.NewRecorder()
	testRouter.ServeHTTP(w, req)
	return w
}

// parseJSON parses the response body into a map.
func parseJSON(w *httptest.ResponseRecorder) map[string]interface{} {
	var result map[string]interface{}
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	return result
}

// registerUser registers a user via POST /auth/register. Fails test on non-201.
// Returns the registration_token from the response for use in verify calls.
func registerUser(t *testing.T, login, password string) string {
	t.Helper()
	w := doRequest("POST", "/auth/register", map[string]string{
		"login":    login,
		"password": password,
	}, "")
	if w.Code != http.StatusCreated {
		t.Fatalf("registerUser(%s): expected 201, got %d: %s", login, w.Code, w.Body.String())
	}
	body := parseJSON(w)
	token, _ := body["registration_token"].(string)
	return token
}

// createTempSession inserts a temporary session for an unverified user and returns the token.
// Used for testing verify endpoints that now require authentication.
func createTempSession(t *testing.T, recipient string) string {
	t.Helper()
	ctx := context.Background()

	// Find user ID
	var userID int64
	var query string
	if strings.Contains(recipient, "@") {
		query = `SELECT id FROM users WHERE email=$1 LIMIT 1`
	} else {
		query = `SELECT id FROM users WHERE phone=$1 LIMIT 1`
	}
	if err := testPool.QueryRowContext(ctx, query, recipient).Scan(&userID); err != nil {
		t.Fatalf("createTempSession: user not found for %s: %v", recipient, err)
	}

	// Insert a temporary session (30 days expiry)
	token := fmt.Sprintf("test-temp-session-%d", userID)
	_, err := testPool.ExecContext(ctx,
		`INSERT INTO sessions (user_id, token, expire_date, auth_type, ip, blocked)
		 VALUES ($1, $2, NOW() + INTERVAL '30 days', 'registration', '127.0.0.1', false)
		 ON CONFLICT DO NOTHING`,
		userID, token,
	)
	if err != nil {
		t.Fatalf("createTempSession: insert session: %v", err)
	}
	return token
}

// verifyUser completes the same generator-backed contact verification route
// that browser registration and account settings use. Tests replace the
// one-time hash only inside the isolated test database.
func verifyUser(t *testing.T, recipient, deviceUID string, registrationToken ...string) {
	t.Helper()
	_ = deviceUID

	// Use registration token if provided, otherwise fall back to temporary session
	var authToken string
	if len(registrationToken) > 0 && registrationToken[0] != "" {
		authToken = registrationToken[0]
	} else {
		authToken = createTempSession(t, recipient)
	}

	var verificationID int64
	if err := testPool.QueryRowContext(context.Background(), `
		SELECT cv.id
		FROM contact_verifications cv
		JOIN users u ON u.id=cv.user_id
		WHERE cv.recipient=$1
		ORDER BY cv.id DESC
		LIMIT 1`, recipient).Scan(&verificationID); err != nil {
		t.Fatalf("verifyUser load contact verification(%s): %v", recipient, err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("verifyUser hash code: %v", err)
	}
	if _, err = testPool.ExecContext(context.Background(), `UPDATE contact_verifications SET code_hash=$1 WHERE id=$2`, string(hash), verificationID); err != nil {
		t.Fatalf("verifyUser set test code: %v", err)
	}

	w := doRequest("POST", "/auth/contact_verifications/id/"+strconv.FormatInt(verificationID, 10), map[string]string{"code": "123456"}, authToken)
	if w.Code != http.StatusOK {
		t.Fatalf("verifyUser confirm(%s): expected 200, got %d: %s", recipient, w.Code, w.Body.String())
	}
}

// loginUser logs in and returns the token. Fails test on non-200.
func loginUser(t *testing.T, login, password string) string {
	t.Helper()
	w := doRequest("POST", "/auth/login", map[string]string{
		"login":    login,
		"password": password,
	}, "")
	if w.Code != http.StatusOK {
		t.Fatalf("loginUser(%s): expected 200, got %d: %s", login, w.Code, w.Body.String())
	}
	result := parseJSON(w)
	token, ok := result["token"].(string)
	if !ok || token == "" {
		t.Fatalf("loginUser(%s): no token in response: %s", login, w.Body.String())
	}
	return token
}

// loginSystemUser logs in the system user and returns the token.
func loginSystemUser(t *testing.T) string {
	t.Helper()
	return loginUser(t, testCfg.SystemUserEmail, testCfg.SystemUserPassword)
}
