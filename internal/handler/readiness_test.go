package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestReadinessDependenciesAndRecovery(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var redisError error
	redisPing := func(context.Context) error { return redisError }
	ok := func(context.Context) error { return nil }
	router := gin.New()
	router.GET("/ready", Readiness(ok, redisPing))
	for _, unavailable := range []bool{false, true, false} {
		redisError = nil
		want := http.StatusOK
		if unavailable {
			redisError = errors.New("WRONGPASS private connection details")
			want = http.StatusServiceUnavailable
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
		if response.Code != want {
			t.Fatalf("got %d: %s; want %d", response.Code, response.Body, want)
		}
		if strings.Contains(response.Body.String(), "WRONGPASS") || strings.Contains(response.Body.String(), "private") {
			t.Fatal("readiness exposed dependency error details")
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("readiness must not be cached")
		}
	}
}

func TestReadinessMissingDatabaseAndTimeout(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, name := range []string{"missing database", "redis timeout"} {
		t.Run(name, func(t *testing.T) {
			ok := func(context.Context) error { return nil }
			postgres, redis := ok, ok
			if name == "missing database" {
				postgres = nil
			} else {
				redis = func(ctx context.Context) error {
					<-ctx.Done()
					return ctx.Err()
				}
			}
			router := gin.New()
			router.GET("/ready", readiness(postgres, redis, 20*time.Millisecond))
			response := httptest.NewRecorder()
			started := time.Now()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/ready", nil))
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("got %d: %s", response.Code, response.Body)
			}
			if time.Since(started) > time.Second {
				t.Fatal("readiness did not respect its deadline")
			}
		})
	}
}
