package middleware

import (
	"net/http"
	"strings"
	"time"

	"database/sql"
	"github.com/darkrain/auth-service/internal/cache"
	"github.com/gin-gonic/gin"
)

// Error code constants for middleware responses
const (
	codeUnauthorized      = "ERR_UNAUTHORIZED"
	codeForbidden         = "ERR_FORBIDDEN"
	codeRegistrationToken = "ERR_REGISTRATION_TOKEN"
)

// Auth middleware validates Bearer token or X-API-Key header.
// It checks the Redis cache first; on cache miss it queries the sessions table,
// then caches the result with TTL = expire_date - now.
func Auth(pool *sql.DB, cacheClient *cache.Client) gin.HandlerFunc {
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
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authorization token required", "code": codeUnauthorized})
			return
		}

		// 1. Check Redis cache
		if cacheClient != nil {
			if sd, err := cacheClient.GetSession(c.Request.Context(), token); err == nil && sd != nil {
				if sd.AuthType != "registration" && sd.VerifyStatus != "verified" {
					c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "account is not active", "code": codeUnauthorized})
					return
				}
				// Restrict registration tokens
				if sd.AuthType == "registration" {
					if !registrationVerificationRequest(c.Request.Method, c.FullPath()) {
						c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Registration token can only be used for account verification", "code": codeRegistrationToken})
						return
					}
				}
				c.Set("user_id", sd.UserID)
				c.Set("session_id", sd.SessionID)
				c.Set("email", sd.Email)
				c.Set("phone", sd.Phone)
				c.Set("role", sd.Role)
				c.Set("verify_status", sd.VerifyStatus)
				c.Set("auth_type", sd.AuthType)
				c.Set("token", token)
				touchSession(c, pool, cacheClient, sd.SessionID, sd.AuthType)
				c.Next()
				return
			}
		}

		// 2. Cache miss — query DB
		if pool == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "database unavailable", "code": codeUnauthorized})
			return
		}

		var sessionID int64
		var userID int
		var email, phone, role, verifyStatus, authType string
		var blocked bool
		var expireDate *time.Time

		err := pool.QueryRowContext(c.Request.Context(), `
			SELECT s.id, s.user_id, COALESCE(u.email,''), COALESCE(u.phone,''), u.role, u.verify_status, s.blocked, s.expire_date, COALESCE(s.auth_type,'')
			FROM sessions s
			JOIN users u ON u.id = s.user_id
			WHERE s.token = $1
		`, token).Scan(&sessionID, &userID, &email, &phone, &role, &verifyStatus, &blocked, &expireDate, &authType)

		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token", "code": codeUnauthorized})
			return
		}

		if blocked {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token has been revoked", "code": codeUnauthorized})
			return
		}

		if expireDate != nil && time.Now().After(*expireDate) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "token has expired", "code": codeUnauthorized})
			return
		}
		if authType != "registration" && verifyStatus != "verified" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "account is not active", "code": codeUnauthorized})
			return
		}

		// Restrict registration tokens to verification endpoints only
		if authType == "registration" {
			if !registrationVerificationRequest(c.Request.Method, c.FullPath()) {
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Registration token can only be used for account verification", "code": codeRegistrationToken})
				return
			}
		}

		// 3. Store in Redis cache with TTL = expire_date - now
		if cacheClient != nil {
			sd := &cache.SessionData{
				SessionID:    sessionID,
				UserID:       userID,
				Email:        email,
				Phone:        phone,
				Role:         role,
				VerifyStatus: verifyStatus,
				AuthType:     authType,
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
		c.Set("session_id", sessionID)
		c.Set("email", email)
		c.Set("phone", phone)
		c.Set("role", role)
		c.Set("verify_status", verifyStatus)
		c.Set("auth_type", authType)
		c.Set("token", token)
		touchSession(c, pool, cacheClient, sessionID, authType)

		c.Next()
	}
}

func touchSession(c *gin.Context, pool *sql.DB, cacheClient *cache.Client, sessionID int64, authType string) {
	if pool == nil || sessionID <= 0 || authType == "registration" {
		return
	}
	if cacheClient != nil {
		shouldUpdate, err := cacheClient.MarkSessionSeen(c.Request.Context(), sessionID, 5*time.Minute)
		if err != nil || !shouldUpdate {
			return
		}
	}
	_, _ = pool.ExecContext(c.Request.Context(), `UPDATE sessions SET last_seen_at=NOW(), update_date=NOW() WHERE id=$1 AND blocked=false`, sessionID)
}

func registrationVerificationRequest(method, path string) bool {
	return (method == http.MethodPost && path == "/auth/contact_verifications/:bykey/:value") ||
		(method == http.MethodPut && path == "/auth/contact_verifications") ||
		(method == http.MethodPut && path == "/auth/registration/contact")
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
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "not authenticated", "code": codeUnauthorized})
			return
		}

		roleStr, ok := role.(string)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid role", "code": codeUnauthorized})
			return
		}

		if _, ok := allowed[roleStr]; !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "access denied: insufficient role", "code": codeForbidden})
			return
		}

		c.Next()
	}
}
