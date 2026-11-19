package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/darkrain/auth-service/internal/broker"
	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/gin-gonic/gin"
	amqp "github.com/rabbitmq/amqp091-go"
)

const codeTooManyRequests = "ERR_TOO_MANY_REQUESTS"

// RateLimit returns a Gin middleware that applies sliding window rate limiting
// by IP and optionally by device_uid (X-Device-ID header). See Allow.
func RateLimit(cacheClient *cache.Client, conn broker.ChannelProvider, endpoint string,
	ipMax, ipWindowSec, deviceMax, deviceWindowSec int) gin.HandlerFunc {

	return func(c *gin.Context) {
		if !Allow(c, cacheClient, conn, endpoint, ipMax, ipWindowSec, deviceMax, deviceWindowSec, c.GetHeader("X-Device-ID")) {
			return
		}
		c.Next()
	}
}

// SendCodeRateLimit applies the SendCode limits from cfg, read on every
// request, to a route that sends a verification code.
func SendCodeRateLimit(cacheClient *cache.Client, conn broker.ChannelProvider, endpoint string, cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !AllowSendCode(c, cacheClient, conn, endpoint, cfg, c.GetHeader("X-Device-ID")) {
			return
		}
		c.Next()
	}
}

// AllowSendCode is SendCodeRateLimit for code that runs inside a handler or a
// generator hook, where a middleware cannot be attached.
func AllowSendCode(c *gin.Context, cacheClient *cache.Client, conn broker.ChannelProvider, endpoint string, cfg *config.Config, deviceUID string) bool {
	if cfg == nil {
		return true
	}
	limits := cfg.RateLimit
	return Allow(c, cacheClient, conn, endpoint, limits.IP.SendCodeMaxAttempts, limits.IP.SendCodeWindowSec,
		limits.Device.SendCodeMaxAttempts, limits.Device.SendCodeWindowSec, deviceUID)
}

// Allow counts the request in sliding windows by IP and, when deviceUID is
// set, by device. Over a limit it answers 429, aborts the request and returns
// false.
//
// endpoint: path string used as part of Redis key (e.g. "/auth/login")
// ipMax, ipWindowSec: IP-based limits (0 = skip IP check)
// deviceMax, deviceWindowSec: device-based limits (0 = skip device check)
func Allow(c *gin.Context, cacheClient *cache.Client, conn broker.ChannelProvider, endpoint string,
	ipMax, ipWindowSec, deviceMax, deviceWindowSec int, deviceUID string) bool {
	ctx := c.Request.Context()

	// 1. Get client IP. Reading X-Real-IP directly handed the caller its own
	// rate-limit bucket: a new value per request meant no limit at all, and
	// the service port is reachable without passing the proxy that overwrites
	// the header. ClientIP honours forwarded headers only from the proxies
	// SetTrustedProxies names and otherwise uses the peer address.
	ip := c.ClientIP()
	if ip == "" {
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			ip = c.Request.RemoteAddr
		} else {
			ip = host
		}
	}

	// 2. Check IP rate limit
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
			return false
		}
	}

	// 3. Check device rate limit (only if a device is known)
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
			return false
		}
	}
	return true
}

// publishSecurityEvent publishes a security event to RabbitMQ asynchronously.
// Does not block the main request.
func publishSecurityEvent(conn broker.ChannelProvider, eventType string, payload map[string]interface{}) {
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
