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

type loginRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Login handles POST /auth/login
func Login(pool *pgxpool.Pool, cfg *config.Config) gin.HandlerFunc {
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

		result, err := service.Login(c.Request.Context(), pool, cfg, req.Login, req.Password, ip)
		if err != nil {
			switch {
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
func Logout(pool *pgxpool.Pool) gin.HandlerFunc {
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

		if err := service.Logout(c.Request.Context(), pool, token); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "Logged out successfully"})
	}
}

type registerRequest struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

// Register handles POST /auth/register
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
