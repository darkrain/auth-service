package handler

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"github.com/darkrain/auth-service/internal/service"
	"github.com/gin-gonic/gin"
	amqp "github.com/rabbitmq/amqp091-go"
)

type registrationContactRequest struct {
	Login         string `json:"login" example:"corrected@example.com"`
	DeviceUID     string `json:"device_uid" example:"device-uuid-1234"`
	Provider      string `json:"provider,omitempty" example:"email"`
	AllowFallback bool   `json:"allow_fallback"`
}

type registrationContactResponse struct {
	Message        string `json:"message"`
	Login          string `json:"login" example:"corrected@example.com"`
	VerificationID int64  `json:"verification_id" example:"43"`
	ResendAfterSec int    `json:"resend_after_sec" example:"60"`
}

// ChangeRegistrationContact handles PUT /auth/registration/contact.
//
//	@Summary		Change the contact of an unfinished registration
//	@Description	Replaces the email or phone on the existing registered user, invalidates older registration codes and sends a new code. Requires a registration token.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			request	body	registrationContactRequest	true	"New registration contact"
//	@Success		200	{object}	registrationContactResponse
//	@Failure		400	{object}	errorResponse
//	@Failure		401	{object}	errorResponse
//	@Failure		403	{object}	errorResponse
//	@Router			/auth/registration/contact [put]
func ChangeRegistrationContact(pool *sql.DB, conn *amqp.Connection, cfg *config.Config, cacheClient *cache.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		authType, _ := c.Get("auth_type")
		if authType != "registration" {
			c.JSON(http.StatusForbidden, errResp(CodeRegistrationToken, "A registration token is required"))
			return
		}
		userID, ok := contextUserID(c)
		if !ok {
			c.JSON(http.StatusUnauthorized, errResp(CodeUnauthorized, "registration not found"))
			return
		}

		var req registrationContactRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, "invalid request body"))
			return
		}
		req.Login = strings.TrimSpace(req.Login)
		contactType := "phone"
		if strings.Contains(req.Login, "@") {
			contactType = "email"
		}

		result, err := service.ChangeRegistrationContact(c.Request.Context(), pool, conn, cfg, service.ContactVerificationRequest{
			UserID: userID, ContactType: contactType, Recipient: req.Login, DeviceUID: req.DeviceUID,
			Provider: req.Provider, AllowFallback: req.AllowFallback, Purpose: delivery.PurposeRegistrationVerification,
		})
		if err != nil {
			switch {
			case errors.Is(err, service.ErrInvalidEmail):
				c.JSON(http.StatusBadRequest, errResp(CodeInvalidEmail, "Invalid email format"))
			case errors.Is(err, service.ErrInvalidPhone):
				c.JSON(http.StatusBadRequest, errResp(CodeInvalidPhone, "Invalid phone format. Use international format: +79991234567"))
			case errors.Is(err, service.ErrAlreadyExists):
				c.JSON(http.StatusConflict, errResp(CodeLoginExists, "Login already registered"))
			case errors.Is(err, service.ErrTooManyRequests):
				c.JSON(http.StatusTooManyRequests, errResp(CodeVerificationCooldown, "A verification code was sent recently"))
			case errors.Is(err, service.ErrForbidden):
				c.JSON(http.StatusForbidden, errResp(CodeRegistrationToken, "Registration is already completed"))
			case errors.Is(err, service.ErrNotFound):
				c.JSON(http.StatusNotFound, errResp(CodeUserNotFound, "Registration not found"))
			case errors.Is(err, service.ErrValidation):
				c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, err.Error()))
			default:
				c.JSON(http.StatusInternalServerError, errResp(CodeInternal, "internal server error"))
			}
			return
		}

		if token, ok := c.Get("token"); ok && cacheClient != nil {
			_ = cacheClient.DeleteSession(c.Request.Context(), strings.TrimSpace(fmt.Sprint(token)))
		}
		c.JSON(http.StatusOK, gin.H{
			"message":          "Registration contact changed. Please verify the new contact.",
			"login":            result.Login,
			"verification_id":  result.VerificationID,
			"resend_after_sec": result.ResendAfterSec,
		})
	}
}

func contextUserID(c *gin.Context) (int64, bool) {
	value, ok := c.Get("user_id")
	if !ok {
		return 0, false
	}
	switch id := value.(type) {
	case int:
		return int64(id), id > 0
	case int64:
		return id, id > 0
	default:
		return 0, false
	}
}
