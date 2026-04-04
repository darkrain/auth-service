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
