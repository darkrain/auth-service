package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	amqp "github.com/rabbitmq/amqp091-go"
)

type resetRequestBody struct {
	Login     string `json:"login"      example:"user@example.com"`
	DeviceUID string `json:"device_uid" example:"device-uuid-1234"`
}

type resetConfirmBody struct {
	Login       string `json:"login"        example:"user@example.com"`
	Code        string `json:"code"         example:"123456"`
	DeviceUID   string `json:"device_uid"   example:"device-uuid-1234"`
	NewPassword string `json:"new_password" example:"NewSecret123!"`
}

// ResetRequest handles POST /auth/password/reset-request
//
//	@Summary		Request password reset code
//	@Description	Sends a one-time password reset code to the user's email or phone. Always returns 200 to avoid user enumeration.
//	@Tags			password-reset
//	@Accept			json
//	@Produce		json
//	@Param			request	body		resetRequestBody	true	"Login and device UID"
//	@Success		200		{object}	messageResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/auth/password/reset-request [post]
func ResetRequest(pool *pgxpool.Pool, conn *amqp.Connection, cfg *config.Config, cacheClient *cache.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req resetRequestBody
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, "invalid request body"))
			return
		}

		req.Login = strings.TrimSpace(req.Login)
		req.DeviceUID = strings.TrimSpace(req.DeviceUID)

		if req.Login == "" {
			c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, "login is required"))
			return
		}

		ip := c.GetHeader("X-Real-IP")
		if ip == "" {
			ip = c.Request.RemoteAddr
		}

		// Always return 200 regardless of result (no user enumeration)
		_ = service.RequestPasswordReset(c.Request.Context(), pool, conn, cfg, cacheClient, req.Login, req.DeviceUID, ip)

		c.JSON(http.StatusOK, gin.H{"message": "If an account with that login exists, a reset code has been sent."})
	}
}

// ResetConfirm handles POST /auth/password/reset-confirm
//
//	@Summary		Confirm password reset
//	@Description	Verifies the reset code and sets a new password. Invalidates all existing sessions.
//	@Tags			password-reset
//	@Accept			json
//	@Produce		json
//	@Param			request	body		resetConfirmBody	true	"Login, code, device UID and new password"
//	@Success		200		{object}	messageResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		404		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/auth/password/reset-confirm [post]
func ResetConfirm(pool *pgxpool.Pool, cfg *config.Config, cacheClient *cache.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req resetConfirmBody
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, "invalid request body"))
			return
		}

		req.Login = strings.TrimSpace(req.Login)
		req.Code = strings.TrimSpace(req.Code)
		req.DeviceUID = strings.TrimSpace(req.DeviceUID)

		if req.Login == "" || req.Code == "" || req.NewPassword == "" {
			c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, "login, code and new_password are required"))
			return
		}

		err := service.ConfirmPasswordReset(c.Request.Context(), pool, cfg, cacheClient, req.Login, req.Code, req.DeviceUID, req.NewPassword)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrNotFound):
				c.JSON(http.StatusBadRequest, errResp(CodeInvalidCode, "invalid reset code"))
			case errors.Is(err, service.ErrCodeExpired):
				c.JSON(http.StatusBadRequest, errResp(CodeCodeExpired, "reset code has expired"))
			case errors.Is(err, service.ErrInvalidCode):
				c.JSON(http.StatusBadRequest, errResp(CodeInvalidCode, "invalid reset code"))
			case errors.Is(err, service.ErrWeakPassword):
				c.JSON(http.StatusBadRequest, errResp(CodeWeakPassword, strings.TrimPrefix(err.Error(), "validation error: ")))
			case errors.Is(err, service.ErrValidation):
				c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, err.Error()))
			default:
				c.JSON(http.StatusInternalServerError, errResp(CodeInternal, "internal server error"))
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Password reset successfully. Please log in with your new password."})
	}
}
