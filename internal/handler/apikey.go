package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/service"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type apiKeyResponse struct {
	ID        int    `json:"id" example:"1"`
	Token     string `json:"token" example:"ak_..."`
	CreatedAt string `json:"created_at" example:"2025-01-01T00:00:00Z"`
}

// CreateAPIKey handles POST /auth/api-keys
//
//	@Summary		Create a new API key
//	@Description	Creates a new API key for the authenticated user. Requires admin or system role.
//	@Tags			api-keys
//	@Produce		json
//	@Security		BearerAuth
//	@Success		201	{object}	apiKeyResponse
//	@Failure		401	{object}	errorResponse
//	@Failure		500	{object}	errorResponse
//	@Router			/auth/api-keys [post]
func CreateAPIKey(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, errResp(CodeUnauthorized, "not authenticated"))
			return
		}
		userID, ok := userIDVal.(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, errResp(CodeUnauthorized, "invalid user id"))
			return
		}

		key, err := service.CreateAPIKey(c.Request.Context(), pool, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, errResp(CodeInternal, "failed to create API key"))
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
//
//	@Summary		List API keys
//	@Description	Returns all API keys belonging to the authenticated user. Requires admin or system role.
//	@Tags			api-keys
//	@Produce		json
//	@Security		BearerAuth
//	@Success		200	{array}		apiKeyResponse
//	@Failure		401	{object}	errorResponse
//	@Failure		500	{object}	errorResponse
//	@Router			/auth/api-keys [get]
func ListAPIKeys(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, errResp(CodeUnauthorized, "not authenticated"))
			return
		}
		userID, ok := userIDVal.(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, errResp(CodeUnauthorized, "invalid user id"))
			return
		}

		keys, err := service.ListAPIKeys(c.Request.Context(), pool, userID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, errResp(CodeInternal, "failed to list API keys"))
			return
		}

		c.JSON(http.StatusOK, keys)
	}
}

// RevokeAPIKey handles DELETE /auth/api-keys/:id
//
//	@Summary		Revoke an API key
//	@Description	Revokes and deletes an API key by ID. Requires admin or system role.
//	@Tags			api-keys
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id	path		int	true	"API key ID"
//	@Success		200	{object}	messageResponse
//	@Failure		400	{object}	errorResponse
//	@Failure		401	{object}	errorResponse
//	@Failure		404	{object}	errorResponse
//	@Failure		500	{object}	errorResponse
//	@Router			/auth/api-keys/{id} [delete]
func RevokeAPIKey(pool *pgxpool.Pool, cacheClient *cache.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, errResp(CodeUnauthorized, "not authenticated"))
			return
		}
		userID, ok := userIDVal.(int)
		if !ok {
			c.JSON(http.StatusUnauthorized, errResp(CodeUnauthorized, "invalid user id"))
			return
		}

		keyIDStr := c.Param("id")
		keyID, err := strconv.Atoi(keyIDStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, "invalid key id"))
			return
		}

		if err := service.RevokeAPIKey(c.Request.Context(), pool, cacheClient, keyID, userID); err != nil {
			if errors.Is(err, service.ErrNotFound) {
				c.JSON(http.StatusNotFound, errResp(CodeUserNotFound, "API key not found"))
				return
			}
			c.JSON(http.StatusInternalServerError, errResp(CodeInternal, "failed to revoke API key"))
			return
		}

		c.JSON(http.StatusOK, gin.H{"message": "API key revoked"})
	}
}
