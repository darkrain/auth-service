package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	amqp "github.com/rabbitmq/amqp091-go"
)

type sendCodeRequest struct {
	Recipient string `json:"recipient"`
	DeviceUID string `json:"device_uid"`
}

// SendCode handles POST /auth/send-code
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

		err := service.SendCode(c.Request.Context(), pool, conn, cfg, req.Recipient, req.DeviceUID)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrTooManyRequests):
				c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
			case errors.Is(err, service.ErrValidation):
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Code sent"})
	}
}

type verifyCodeRequest struct {
	Recipient string `json:"recipient"`
	Code      string `json:"code"`
	DeviceUID string `json:"device_uid"`
}

// VerifyEmail handles POST /auth/verify/email
func VerifyEmail(pool *pgxpool.Pool, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req verifyCodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		err := service.VerifyCode(c.Request.Context(), pool, cfg, req.Recipient, req.Code, req.DeviceUID, "email")
		if err != nil {
			handleVerifyError(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Verified successfully"})
	}
}

// VerifyPhone handles POST /auth/verify/phone
func VerifyPhone(pool *pgxpool.Pool, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req verifyCodeRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		err := service.VerifyCode(c.Request.Context(), pool, cfg, req.Recipient, req.Code, req.DeviceUID, "phone")
		if err != nil {
			handleVerifyError(c, err)
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Verified successfully"})
	}
}

type verifyLogin2FARequest struct {
	Login     string `json:"login"`
	Code      string `json:"code"`
	DeviceUID string `json:"device_uid"`
}

// VerifyLogin2FA handles POST /auth/login/verify-2fa
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
	case errors.Is(err, service.ErrTooManyRequests):
		c.JSON(http.StatusTooManyRequests, gin.H{"error": err.Error()})
	case errors.Is(err, service.ErrValidation):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, service.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
	case errors.Is(err, service.ErrUnauthorized):
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid verification code"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}
}
