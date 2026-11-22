package handler

import (
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"github.com/gin-gonic/gin"
)

// CodeLocale is the language of the code or notice message a request
// triggers: the body's "locale" (bodyLocale), else the "lang" query parameter
// (the language chosen in the client app), else the Accept-Language header,
// else "" for message-delivery's default. Every source is validated by
// delivery.RequestLocale against CodeDelivery.Locales.
func CodeLocale(c *gin.Context, cfg *config.Config, bodyLocale string) string {
	return delivery.RequestLocale(bodyLocale, c.Query("lang"), c.GetHeader("Accept-Language"), cfg.CodeDelivery.Locales)
}
