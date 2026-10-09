package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Readiness checks the dependencies needed to authenticate requests. Unlike
// liveness or an anonymous /auth/me request, it detects a broken session cache.
func Readiness(postgres, redis func(context.Context) error) gin.HandlerFunc {
	return readiness(postgres, redis, 2*time.Second)
}

func readiness(postgres, redis func(context.Context) error, timeout time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()
		checks := map[string]string{}
		status := http.StatusOK
		for _, dependency := range []struct {
			name string
			ping func(context.Context) error
		}{{"postgres", postgres}, {"redis", redis}} {
			checks[dependency.name] = "ok"
			if dependency.ping == nil || dependency.ping(ctx) != nil {
				checks[dependency.name] = "unavailable"
				status = http.StatusServiceUnavailable
			}
		}
		state := "ready"
		if status != http.StatusOK {
			state = "not_ready"
		}
		c.Header("Cache-Control", "no-store")
		c.JSON(status, gin.H{"status": state, "checks": checks})
	}
}
