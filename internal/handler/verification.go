package handler

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/service"
	"github.com/gin-gonic/gin"
)

type verifyLogin2FARequest struct {
	ChallengeToken string `json:"challenge_token" example:"short-lived-login-challenge"`
	Code           string `json:"code" example:"123456"`
	DeviceUID      string `json:"device_uid" example:"device-uuid-1234"`
}

// VerifyLogin2FA handles POST /auth/login/verify-2fa.
//
//	@Summary		Verify 2FA code during login
//	@Description	Completes the password-authenticated login challenge with a TOTP code from an authenticator app.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		verifyLogin2FARequest	true	"Challenge token, authenticator code and device UID"
//	@Success		200		{object}	loginResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		404		{object}	errorResponse
//	@Failure		429		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/auth/login/verify-2fa [post]
func VerifyLogin2FA(pool *sql.DB, cfg *config.Config, cacheClient *cache.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req verifyLogin2FARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, "invalid request body"))
			return
		}

		ip := c.GetHeader("X-Real-IP")
		if ip == "" {
			ip = c.Request.RemoteAddr
		}

		result, err := service.LoginVerify2FA(c.Request.Context(), pool, cfg, cacheClient, service.Login2FARequest{
			ChallengeToken: req.ChallengeToken, Code: req.Code, DeviceUID: req.DeviceUID, IP: ip,
		})
		if err != nil {
			handleVerifyError(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{"token": result.Token, "expire_date": result.ExpireDate})
	}
}

func handleVerifyError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidEmail):
		c.JSON(http.StatusBadRequest, errResp(CodeInvalidEmail, "Invalid email format"))
	case errors.Is(err, service.ErrInvalidPhone):
		c.JSON(http.StatusBadRequest, errResp(CodeInvalidPhone, "Invalid phone format. Use international format: +79991234567"))
	case errors.Is(err, service.ErrTooManyRequests):
		c.JSON(http.StatusTooManyRequests, errResp(CodeTooManyRequests, err.Error()))
	case errors.Is(err, service.ErrValidation):
		c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, err.Error()))
	case errors.Is(err, service.ErrForbidden):
		c.JSON(http.StatusForbidden, errResp(CodeForbidden, strings.TrimPrefix(err.Error(), "forbidden: ")))
	case errors.Is(err, service.ErrNotFound):
		c.JSON(http.StatusNotFound, errResp(CodeCodeNotFound, err.Error()))
	case errors.Is(err, service.ErrUnauthorized):
		c.JSON(http.StatusBadRequest, errResp(CodeCodeInvalid, "invalid verification code"))
	default:
		c.JSON(http.StatusInternalServerError, errResp(CodeInternal, "internal server error"))
	}
}
