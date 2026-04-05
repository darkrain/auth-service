package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Auth middleware validates Bearer token or X-API-Key header.
// It checks the sessions table and loads user info into gin context.
func Auth(pool *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		var token string

		// Try Authorization: Bearer <token>
		authHeader := c.GetHeader("Authorization")
		if strings.HasPrefix(authHeader, "Bearer ") {
			token = strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		}

		// Fallback to X-API-Key header
		if token == "" {
			token = strings.TrimSpace(c.GetHeader("X-API-Key"))
		}

		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization token required"})
			return
		}

		if pool == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "database unavailable"})
			return
		}

		var userID int
		var role string
		var verifyStatus string
		var blocked bool
		var expireDate *time.Time

		err := pool.QueryRow(c.Request.Context(), `
			SELECT s.user_id, u.role, u.verify_status, s.blocked, s.expire_date
			FROM sessions s
			JOIN users u ON u.id = s.user_id
			WHERE s.token = $1
		`, token).Scan(&userID, &role, &verifyStatus, &blocked, &expireDate)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
			return
		}

		if blocked {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token has been revoked"})
			return
		}

		if expireDate != nil && time.Now().After(*expireDate) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token has expired"})
			return
		}

		c.Set("user_id", userID)
		c.Set("role", role)
		c.Set("verify_status", verifyStatus)
		c.Set("token", token)

		c.Next()
	}
}

// RequireRole middleware checks that the authenticated user has one of the allowed roles.
func RequireRole(roles ...string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		allowed[r] = struct{}{}
	}

	return func(c *gin.Context) {
		role, exists := c.Get("role")
		if !exists {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authenticated"})
			return
		}

		roleStr, ok := role.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid role"})
			return
		}

		if _, ok := allowed[roleStr]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "access denied: insufficient role"})
			return
		}

		c.Next()
	}
}
