package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/gin-gonic/gin"
	amqp "github.com/rabbitmq/amqp091-go"
)

const codeTooManyRequests = "ERR_TOO_MANY_REQUESTS"

// RateLimit returns a Gin middleware that applies sliding window rate limiting
// by IP and optionally by device_uid (X-Device-ID header).
//
// endpoint: path string used as part of Redis key (e.g. "/auth/login")
// ipMax, ipWindowSec: IP-based limits (0 = skip IP check)
// deviceMax, deviceWindowSec: device-based limits (0 = skip device check)
func RateLimit(cacheClient *cache.Client, conn *amqp.Connection, endpoint string,
	ipMax, ipWindowSec, deviceMax, deviceWindowSec int) gin.HandlerFunc {

	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// 1. Get client IP (prefer X-Real-IP, strip port from RemoteAddr)
		ip := c.GetHeader("X-Real-IP")
		if ip == "" {
			host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
			if err != nil {
				ip = c.Request.RemoteAddr
			} else {
				ip = host
			}
		}

		// 2. Get device_uid from X-Device-ID header
		deviceUID := c.GetHeader("X-Device-ID")

		// 3. Check IP rate limit
		if ipMax > 0 && ipWindowSec > 0 && cacheClient != nil {
			key := fmt.Sprintf("rl:ip:%s:%s", endpoint, ip)
			count, err := cacheClient.SlidingWindowIncr(ctx, key, ipWindowSec)
			if err == nil && count > int64(ipMax) {
				publishSecurityEvent(conn, "rate_limit_exceeded", map[string]interface{}{
					"type":     "ip",
					"endpoint": endpoint,
					"ip":       ip,
					"count":    count,
					"ts":       time.Now().Unix(),
				})
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests. Try again later.", "code": codeTooManyRequests})
				return
			}
		}

		// 4. Check device rate limit (only if device_uid is provided)
		if deviceUID != "" && deviceMax > 0 && deviceWindowSec > 0 && cacheClient != nil {
			key := fmt.Sprintf("rl:device:%s:%s", endpoint, deviceUID)
			count, err := cacheClient.SlidingWindowIncr(ctx, key, deviceWindowSec)
			if err == nil && count > int64(deviceMax) {
				publishSecurityEvent(conn, "rate_limit_exceeded", map[string]interface{}{
					"type":      "device",
					"endpoint":  endpoint,
					"device_id": deviceUID,
					"ip":        ip,
					"count":     count,
					"ts":        time.Now().Unix(),
				})
				c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests. Try again later.", "code": codeTooManyRequests})
				return
			}
		}

		c.Next()
	}
}

// publishSecurityEvent publishes a security event to RabbitMQ asynchronously.
// Does not block the main request.
func publishSecurityEvent(conn *amqp.Connection, eventType string, payload map[string]interface{}) {
	if conn == nil {
		return
	}
	go func() {
		payload["event"] = eventType

		body, err := json.Marshal(payload)
		if err != nil {
			return
		}

		ch, err := conn.Channel()
		if err != nil {
			return
		}
		defer ch.Close()

		_, err = ch.QueueDeclare("security", true, false, false, false, nil)
		if err != nil {
			return
		}

		_ = ch.PublishWithContext(
			context.Background(),
			"",
			"security",
			false,
			false,
			amqp.Publishing{
				ContentType: "application/json",
				Body:        body,
			},
		)
	}()
}
