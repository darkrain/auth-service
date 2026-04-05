package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/darkrain/auth-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CreateAPIKey handles POST /auth/api-keys
func CreateAPIKey(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}
		userID, ok := userIDVal.(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user id"})
			return
		}

		key, err := service.CreateAPIKey(c.Request.Context(), pool, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create API key"})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"id":         key.ID,
			"token":      key.Token,
			"created_at": key.CreatedAt,
		})
	}
}

// ListAPIKeys handles GET /auth/api-keys
func ListAPIKeys(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}
		userID, ok := userIDVal.(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user id"})
			return
		}

		keys, err := service.ListAPIKeys(c.Request.Context(), pool, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list API keys"})
			return
		}

		c.JSON(http.StatusOK, keys)
	}
}

// RevokeAPIKey handles DELETE /auth/api-keys/:id
func RevokeAPIKey(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}
		userID, ok := userIDVal.(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid user id"})
			return
		}

		keyIDStr := c.Param("id")
		keyID, err := strconv.Atoi(keyIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid key id"})
			return
		}

		if err := service.RevokeAPIKey(c.Request.Context(), pool, keyID, userID); err != nil {
			if errors.Is(err, service.ErrNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "API key not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke API key"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "API key revoked"})
	}
}
