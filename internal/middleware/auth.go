package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Auth middleware validates Bearer token or X-API-Key header.
// It checks the Redis cache first; on cache miss it queries the sessions table,
// then caches the result with TTL = expire_date - now.
func Auth(pool *pgxpool.Pool, cacheClient *cache.Client) gin.HandlerFunc {
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

		// 1. Check Redis cache
		if cacheClient != nil {
			if sd, err := cacheClient.GetSession(c.Request.Context(), token); err == nil && sd != nil {
				c.Set("user_id", sd.UserID)
				c.Set("email", sd.Email)
				c.Set("phone", sd.Phone)
				c.Set("role", sd.Role)
				c.Set("verify_status", sd.VerifyStatus)
				c.Set("token", token)
				c.Next()
				return
			}
		}

		// 2. Cache miss — query DB
		if pool == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "database unavailable"})
			return
		}

		var userID int
		var email, phone, role, verifyStatus string
		var blocked bool
		var expireDate *time.Time

		err := pool.QueryRow(c.Request.Context(), `
			SELECT s.user_id, COALESCE(u.email,''), COALESCE(u.phone,''), u.role, u.verify_status, s.blocked, s.expire_date
			FROM sessions s
			JOIN users u ON u.id = s.user_id
			WHERE s.token = $1
		`, token).Scan(&userID, &email, &phone, &role, &verifyStatus, &blocked, &expireDate)

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

		// 3. Store in Redis cache with TTL = expire_date - now
		if cacheClient != nil {
			sd := &cache.SessionData{
				UserID:       userID,
				Email:        email,
				Phone:        phone,
				Role:         role,
				VerifyStatus: verifyStatus,
			}
			var ttl time.Duration
			if expireDate != nil {
				ttl = time.Until(*expireDate)
			} else {
				ttl = 24 * time.Hour // default TTL for API keys without expiry
			}
			// Cap TTL at 15 minutes so bans/role changes take effect quickly (HIGH-5)
			const maxCacheTTL = 15 * time.Minute
			if ttl > maxCacheTTL {
				ttl = maxCacheTTL
			}
			if ttl > 0 {
				_ = cacheClient.SetSession(c.Request.Context(), token, sd, ttl)
			}
		}

		c.Set("user_id", userID)
		c.Set("email", email)
		c.Set("phone", phone)
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
