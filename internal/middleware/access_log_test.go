package middleware

import (
	"bytes"
	"errors"
	"github.com/gin-gonic/gin"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAccessLoggerPreservesHandlerAndImportantLogs(t *testing.T) {
	for _, tt := range []struct {
		name, method                         string
		status                               int
		filtered, handlerError, slow, logged bool
	}{
		{"default read", "GET", 200, false, false, false, true},
		{"routine read", "GET", 200, true, false, false, false},
		{"denied", "GET", 401, true, false, false, true},
		{"failed", "GET", 500, true, false, false, true},
		{"redirect", "GET", 302, true, false, false, true},
		{"mutation", "POST", 200, true, false, false, true},
		{"handler error", "GET", 200, true, true, false, true},
		{"slow", "GET", 200, true, false, true, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var output bytes.Buffer
			router := gin.New()
			router.Use(AccessLogger(&output, tt.filtered))
			calls := 0
			router.Handle(tt.method, "/test", func(c *gin.Context) {
				calls++
				if tt.slow {
					time.Sleep(time.Second)
				}
				if tt.handlerError {
					_ = c.Error(errors.New("test handler error"))
				}
				c.String(tt.status, "handler response")
			})
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(tt.method, "/test", nil))
			if calls != 1 || response.Code != tt.status || response.Body.String() != "handler response" {
				t.Fatalf("handler changed: calls=%d response=%v", calls, response)
			}
			if (output.Len() > 0) != tt.logged {
				t.Errorf("log=%q want logged=%v", output.String(), tt.logged)
			}
		})
	}
}
