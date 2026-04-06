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

type sendCodeRequest struct {
	Recipient string `json:"recipient" example:"user@example.com"`
	DeviceUID string `json:"device_uid" example:"device-uuid-1234"`
}

type verifyCodeRequest struct {
	Recipient string `json:"recipient" example:"user@example.com"`
	Code      string `json:"code" example:"123456"`
	DeviceUID string `json:"device_uid" example:"device-uuid-1234"`
}

type verifyLogin2FARequest struct {
	Login     string `json:"login" example:"user@example.com"`
	Code      string `json:"code" example:"123456"`
	DeviceUID string `json:"device_uid" example:"device-uuid-1234"`
}

// SendCode handles POST /auth/send-code
//
//	@Summary		Send verification code
//	@Description	Sends a verification code to the specified email or phone number.
//	@Tags			verification
//	@Accept			json
//	@Produce		json
//	@Param			request	body		sendCodeRequest	true	"Recipient and device UID"
//	@Success		200		{object}	messageResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		429		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/auth/send-code [post]
func SendCode(pool *pgxpool.Pool, conn *amqp.Connection, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req sendCodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		req.Recipient = strings.TrimSpace(req.Recipient)
		req.DeviceUID = strings.TrimSpace(req.DeviceUID)

		if req.Recipient == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "recipient is required"})
			return
		}

		// HIGH-NEW-1: extract authenticated user ID for ownership check
		var userID int64
		if uid, exists := c.Get("user_id"); exists {
			switch v := uid.(type) {
			case int:
				userID = int64(v)
			case int64:
				userID = v
			}
		}

		err := service.SendCode(c.Request.Context(), pool, conn, cfg, req.Recipient, req.DeviceUID, userID)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrInvalidEmail):
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
			case errors.Is(err, service.ErrInvalidPhone):
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone format. Use international format: +79991234567"})
			case errors.Is(err, service.ErrTooManyRequests):
				c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
			case errors.Is(err, service.ErrValidation):
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			case errors.Is(err, service.ErrForbiddenRecipient):
				c.JSON(http.StatusForbidden, gin.H{"error": err.Error()})
			case errors.Is(err, service.ErrForbidden):
				c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Code sent"})
	}
}

// VerifyEmail handles POST /auth/verify/email
//
//	@Summary		Verify email address
//	@Description	Verifies a user's email address using a code sent to them. Requires Bearer token.
//	@Tags			verification
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			request	body		verifyCodeRequest	true	"Email, code and device UID"
//	@Success		200		{object}	messageResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		401		{object}	errorResponse
//	@Failure		403		{object}	errorResponse
//	@Failure		404		{object}	errorResponse
//	@Failure		429		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/auth/verify/email [post]
func VerifyEmail(pool *pgxpool.Pool, cfg *config.Config, cacheClient ...*cache.Client) gin.HandlerFunc {
	var cc *cache.Client
	if len(cacheClient) > 0 {
		cc = cacheClient[0]
	}
	return func(c *gin.Context) {
		var req verifyCodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		// Get authenticated user ID from context (set by Auth middleware)
		var userID int64
		if uid, exists := c.Get("user_id"); exists {
			switch v := uid.(type) {
			case int:
				userID = int64(v)
			case int64:
				userID = v
			}
		}

		err := service.VerifyCode(c.Request.Context(), pool, cfg, cc, req.Recipient, req.Code, req.DeviceUID, "email", userID)
		if err != nil {
			handleVerifyError(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Verified successfully"})
	}
}

// VerifyPhone handles POST /auth/verify/phone
//
//	@Summary		Verify phone number
//	@Description	Verifies a user's phone number using a code sent to them. Requires Bearer token.
//	@Tags			verification
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			request	body		verifyCodeRequest	true	"Phone, code and device UID"
//	@Success		200		{object}	messageResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		401		{object}	errorResponse
//	@Failure		403		{object}	errorResponse
//	@Failure		404		{object}	errorResponse
//	@Failure		429		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/auth/verify/phone [post]
func VerifyPhone(pool *pgxpool.Pool, cfg *config.Config, cacheClient ...*cache.Client) gin.HandlerFunc {
	var cc *cache.Client
	if len(cacheClient) > 0 {
		cc = cacheClient[0]
	}
	return func(c *gin.Context) {
		var req verifyCodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		// Get authenticated user ID from context (set by Auth middleware)
		var userID int64
		if uid, exists := c.Get("user_id"); exists {
			switch v := uid.(type) {
			case int:
				userID = int64(v)
			case int64:
				userID = v
			}
		}

		err := service.VerifyCode(c.Request.Context(), pool, cfg, cc, req.Recipient, req.Code, req.DeviceUID, "phone", userID)
		if err != nil {
			handleVerifyError(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Verified successfully"})
	}
}

// VerifyLogin2FA handles POST /auth/login/verify-2fa
//
//	@Summary		Verify 2FA code during login
//	@Description	Completes the login process by verifying a 2FA code. Returns a JWT token on success.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		verifyLogin2FARequest	true	"Login, 2FA code and device UID"
//	@Success		200		{object}	loginResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		404		{object}	errorResponse
//	@Failure		429		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/auth/login/verify-2fa [post]
func VerifyLogin2FA(pool *pgxpool.Pool, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req verifyLogin2FARequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		ip := c.GetHeader("X-Real-IP")
		if ip == "" {
			ip = c.Request.RemoteAddr
		}

		result, err := service.LoginVerify2FA(c.Request.Context(), pool, cfg, service.Login2FARequest{
			Login:     req.Login,
			Code:      req.Code,
			DeviceUID: req.DeviceUID,
			IP:        ip,
		})
		if err != nil {
			handleVerifyError(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":       result.Token,
			"expire_date": result.ExpireDate,
		})
	}
}

// handleVerifyError maps service errors to HTTP responses.
func handleVerifyError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidEmail):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
	case errors.Is(err, service.ErrInvalidPhone):
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid phone format. Use international format: +79991234567"})
	case errors.Is(err, service.ErrTooManyRequests):
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
	case errors.Is(err, service.ErrValidation):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, service.ErrForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": strings.TrimPrefix(err.Error(), "forbidden: ")})
	case errors.Is(err, service.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, service.ErrUnauthorized):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid verification code"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}
