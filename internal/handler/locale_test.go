package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/gin-gonic/gin"
)

func TestCodeLocalePrecedence(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{CodeDelivery: config.CodeDeliveryConfig{Locales: []string{"en", "ru", "zh"}}}
	for _, tc := range []struct {
		name, body, query, header, want string
	}{
		{name: "nothing", want: ""},
		{name: "header only", header: "en-US,en;q=0.9", want: "en"},
		{name: "query beats header", query: "ru", header: "en-US,en;q=0.9", want: "ru"},
		{name: "body beats query", body: "zh", query: "ru", header: "en", want: "zh"},
		{name: "query without header", query: "en", want: "en"},
		{name: "query region", query: "ru-RU", header: "en", want: "ru"},
		{name: "unsupported query falls back to header", query: "fr", header: "en", want: "en"},
		{name: "garbage query falls back to header", query: "<script>", header: "ru", want: "ru"},
		{name: "unsupported body uses query", body: "de", query: "ru", header: "en", want: "ru"},
		{name: "unsupported everywhere", body: "de", query: "fr", header: "es", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			target := "/auth/register"
			if tc.query != "" {
				target += "?lang=" + tc.query
			}
			c.Request = httptest.NewRequest(http.MethodPost, target, nil)
			if tc.header != "" {
				c.Request.Header.Set("Accept-Language", tc.header)
			}
			if got := CodeLocale(c, cfg, tc.body); got != tc.want {
				t.Fatalf("CodeLocale(body %q, lang %q, Accept-Language %q) = %q, want %q", tc.body, tc.query, tc.header, got, tc.want)
			}
		})
	}
}
