package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/service"
	"github.com/gin-gonic/gin"
)

type accountBlockRequest struct {
	Block *bool `json:"block" example:"true"`
}

// BlockUser handles POST /admin/users/{id}/block
//
//	@Summary		Block or unblock a customer account
//	@Description	{"block":true} bans the account and revokes all its sessions and API keys; {"block":false} restores the status recorded before the latest administrative block. Requires admin or sudo role.
//	@Tags			admin
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		int					true	"User ID"
//	@Param			body	body		accountBlockRequest	true	"Block or unblock"
//	@Success		200		{object}	service.AccountBlockResult
//	@Failure		400		{object}	errorResponse
//	@Failure		401		{object}	errorResponse
//	@Failure		403		{object}	errorResponse
//	@Failure		404		{object}	errorResponse
//	@Failure		409		{object}	errorResponse
//	@Failure		500		{object}	errorResponse
//	@Router			/admin/users/{id}/block [post]
func BlockUser(pool *sql.DB, cacheClient *cache.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		actorID, ok := c.Get("user_id")
		actor, isInt := actorID.(int)
		if !ok || !isInt {
			c.JSON(http.StatusUnauthorized, errResp(CodeUnauthorized, "not authenticated"))
			return
		}
		userID, err := strconv.ParseInt(c.Param("id"), 10, 64)
		var input accountBlockRequest
		decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 1024))
		decoder.DisallowUnknownFields()
		if err != nil || userID <= 0 || decoder.Decode(&input) != nil || input.Block == nil || decoder.Decode(new(any)) != io.EOF {
			c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, "invalid block request"))
			return
		}
		result, err := service.SetAccountBlocked(c.Request.Context(), pool, cacheClient, int64(actor), userID, *input.Block, c.ClientIP())
		switch {
		case err == nil:
			c.JSON(http.StatusOK, result)
		case errors.Is(err, service.ErrValidation):
			c.JSON(http.StatusBadRequest, errResp(CodeInvalidRequest, "invalid block request"))
		case errors.Is(err, service.ErrNotFound):
			c.JSON(http.StatusNotFound, errResp(CodeUserNotFound, "user not found"))
		case errors.Is(err, service.ErrForbidden):
			c.JSON(http.StatusForbidden, errResp(CodeForbidden, "this account cannot be blocked"))
		case errors.Is(err, service.ErrConflict):
			c.JSON(http.StatusConflict, errResp(CodeConflict, err.Error()))
		default:
			log.Printf("admin block user %d: %v", userID, err)
			c.JSON(http.StatusInternalServerError, errResp(CodeInternal, "failed to change the account block"))
		}
	}
}
