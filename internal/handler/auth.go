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

type loginRequest struct {
	Login     string `json:"login" example:"user@example.com"`
	Password  string `json:"password" example:"Secret123!"`
	DeviceUID string `json:"device_uid" example:"device-uuid-1234"`
}

type loginResponse struct {
	Token      string `json:"token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	ExpireDate string `json:"expire_date" example:"2025-01-01T00:00:00Z"`
}

type login2FAResponse struct {
	Message     string `json:"message" example:"Code sent to your email/phone. Please verify."`
	Requires2FA bool   `json:"requires_2fa" example:"true"`
}

type registerRequest struct {
	Login    string `json:"login" example:"user@example.com"`
	Password string `json:"password" example:"Secret123!"`
}

type messageResponse struct {
	Message string `json:"message" example:"Operation successful"`
}

type errorResponse struct {
	Error string `json:"error" example:"error description"`
}

// Login handles POST /auth/login
//
//	@Summary		Login with email/phone and password
//	@Description	Authenticates a user by login (email or phone) and password. Returns a JWT token on success, or 202 if 2FA is required.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		loginRequest	true	"Login credentials"
//	@Success		200		{object}	loginResponse
//	@Success		202		{object}	login2FAResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		401		{object}	errorResponse
//	@Failure		403		{object}	errorResponse
//	@Failure		404		{object}	errorResponse
//	@Failure		429		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/auth/login [post]
func Login(pool *pgxpool.Pool, conn *amqp.Connection, cfg *config.Config, cacheClient *cache.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req loginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		// Determine client IP
		ip := c.GetHeader("X-Real-IP")
		if ip == "" {
			ip = c.Request.RemoteAddr
		}

		result, err := service.Login(c.Request.Context(), pool, cfg, cacheClient, req.Login, req.Password, ip)
		if err != nil {
			switch {
			case errors.Is(err, service.Err2FA):
				// Send code and return 202
				_ = service.SendCode(c.Request.Context(), pool, conn, cfg, req.Login, req.DeviceUID)
				c.JSON(http.StatusAccepted, gin.H{
					"message":      "Code sent to your email/phone. Please verify.",
					"requires_2fa": true,
				})
			case errors.Is(err, service.ErrAccountLocked):
				c.JSON(http.StatusTooManyRequests, gin.H{"error": "Account temporarily locked due to too many failed attempts"})
			case errors.Is(err, service.ErrValidation):
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			case errors.Is(err, service.ErrNotFound):
				c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
			case errors.Is(err, service.ErrForbidden):
				msg := strings.TrimPrefix(err.Error(), "forbidden: ")
				c.JSON(http.StatusForbidden, gin.H{"error": msg})
			case errors.Is(err, service.ErrUnauthorized):
				c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
			default:
				c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"token":       result.Token,
			"expire_date": result.ExpireDate,
		})
	}
}

// Logout handles POST /auth/logout
//
//	@Summary		Logout and invalidate token
//	@Description	Invalidates the current session token. Requires a Bearer token in the Authorization header.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	messageResponse
//	@Failure		401	{object}	errorResponse
//	@Failure		500	{object}	errorResponse
//	@Router			/auth/logout [post]
func Logout(pool *pgxpool.Pool, cacheClient *cache.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization token required"})
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		token = strings.TrimSpace(token)
		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "authorization token required"})
			return
		}

		if err := service.Logout(c.Request.Context(), pool, cacheClient, token); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}

type meResponse struct {
	ID           int    `json:"id" example:"1"`
	Email        string `json:"email" example:"user@example.com"`
	Phone        string `json:"phone" example:"+79001234567"`
	Role         string `json:"role" example:"user"`
	VerifyStatus string `json:"verify_status" example:"verified"`
}

// Me handles GET /auth/me — returns current user data from session context.
//
//	@Summary		Get current user info
//	@Description	Returns information about the currently authenticated user based on the session token.
//	@Tags			auth
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{object}	meResponse
//	@Failure		401	{object}	errorResponse
//	@Router			/auth/me [get]
func Me() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, _ := c.Get("user_id")
		email, _ := c.Get("email")
		phone, _ := c.Get("phone")
		role, _ := c.Get("role")
		verifyStatus, _ := c.Get("verify_status")

		c.JSON(http.StatusOK, gin.H{
			"id":            userID,
			"email":         email,
			"phone":         phone,
			"role":          role,
			"verify_status": verifyStatus,
		})
	}
}

// Register handles POST /auth/register
//
//	@Summary		Register a new user
//	@Description	Creates a new user account. Login can be an email address or a phone number. A verification code will be sent to the provided contact.
//	@Tags			auth
//	@Accept			json
//	@Produce		json
//	@Param			request	body		registerRequest	true	"Registration data"
//	@Success		201		{object}	messageResponse
//	@Failure		400		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/auth/register [post]
func Register(pool *pgxpool.Pool, conn *amqp.Connection, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req registerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}

		req.Login = strings.TrimSpace(req.Login)
		req.Password = strings.TrimSpace(req.Password)

		isEmail := strings.Contains(req.Login, "@")
		loginType := "phone"
		if isEmail {
			loginType = "email"
		}

		err := service.Register(c.Request.Context(), pool, conn, cfg, service.RegisterRequest{
			Login:    req.Login,
			Password: req.Password,
		})
		if err != nil {
			if errors.Is(err, service.ErrValidation) {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			if errors.Is(err, service.ErrAlreadyExists) {
				c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "Registration successful. Please verify your " + loginType + ".",
		})
	}
}
