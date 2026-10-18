package middleware

import (
	"context"

	module "github.com/darkrain/request-generator"
	"github.com/darkrain/request-generator/icontext"
	"github.com/darkrain/request-generator/locale"
	"github.com/gin-gonic/gin"
)

type translatorKey struct{}

// Atomic domain operations receive context.Context rather than Gin. Bridge
// authenticated identity and the generator's request-local translation there.
func setAuthenticatedContext(c *gin.Context, userID int64, role string) {
	ctx := icontext.SetUser(c.Request.Context(), &icontext.UserInfo{ID: userID, Role: role})
	c.Request = c.Request.WithContext(ctx)
}

// This pinned generator version does not initialize translation on atomic
// updates. Resolve the same supported locales using its public API.
func GeneratorContext(generator *module.Generator) gin.HandlerFunc {
	return func(c *gin.Context) {
		lang := locale.ParseAcceptLanguage(c.GetHeader("Accept-Language"), generator.Locales, generator.DefaultLocale)
		for _, supported := range generator.Locales {
			if string(supported) == c.Query("lang") {
				lang = supported
				break
			}
		}
		translate := module.Translator(func(key, fallback string) string { return generator.TranslateWithFallback(lang, key, fallback) })
		c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), translatorKey{}, translate))
		c.Next()
	}
}

func TranslateContext(ctx context.Context, key, fallback string) string {
	if translate, ok := ctx.Value(translatorKey{}).(module.Translator); ok {
		return translate(key, fallback)
	}
	return fallback
}
