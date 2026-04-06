package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/redis/go-redis/v9"
)

// SessionData holds the cached user session info.
type SessionData struct {
	UserID       int    `json:"user_id"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Role         string `json:"role"`
	VerifyStatus string `json:"verify_status"`
	AuthType     string `json:"auth_type"`
}

// Client wraps a redis.Client with session-specific helpers.
type Client struct {
	rdb *redis.Client
}

// NewClient creates a Redis client from config.
func NewClient(cfg *config.Config) *Client {
	rdb := redis.NewClient(&redis.Options{
		Network: cfg.RedisDatabaseNetwork,
		Addr:    cfg.RedisDatabaseHost + ":" + cfg.RedisDatabasePort,
	})
	return &Client{rdb: rdb}
}

func sessionKey(token string) string {
	return "session:" + token
}

// GetSession retrieves session data from Redis cache.
// Returns nil, nil if not found.
func (c *Client) GetSession(ctx context.Context, token string) (*SessionData, error) {
	val, err := c.rdb.Get(ctx, sessionKey(token)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}

	var data SessionData
	if err := json.Unmarshal([]byte(val), &data); err != nil {
		return nil, err
	}
	return &data, nil
}

// SetSession stores session data in Redis with a TTL.
func (c *Client) SetSession(ctx context.Context, token string, data *SessionData, ttl time.Duration) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, sessionKey(token), b, ttl).Err()
}

// DeleteSession removes session data from Redis cache.
func (c *Client) DeleteSession(ctx context.Context, token string) error {
	return c.rdb.Del(ctx, sessionKey(token)).Err()
}

// SlidingWindowIncr increments a sliding window counter in Redis.
// Uses INCR + EXPIRE pattern: if key is new (count==1), set TTL to windowSec.
// Returns the current count after increment.
func (c *Client) SlidingWindowIncr(ctx context.Context, key string, windowSec int) (int64, error) {
	count, err := c.rdb.Incr(ctx, key).Result()
	if err != nil {
		return 0, err
	}
	if count == 1 {
		_ = c.rdb.Expire(ctx, key, time.Duration(windowSec)*time.Second).Err()
	}
	return count, nil
}

// IsAccountLocked checks whether an account is temporarily locked.
// Key: "lock:user:{userID}"
func (c *Client) IsAccountLocked(ctx context.Context, userID int) (bool, error) {
	key := fmt.Sprintf("lock:user:%d", userID)
	exists, err := c.rdb.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return exists > 0, nil
}

// LockAccount temporarily locks an account for durationSec seconds.
// Key: "lock:user:{userID}"
func (c *Client) LockAccount(ctx context.Context, userID int, durationSec int) error {
	key := fmt.Sprintf("lock:user:%d", userID)
	return c.rdb.Set(ctx, key, 1, time.Duration(durationSec)*time.Second).Err()
}

// IncrFailedLogin increments the failed login counter for a user.
// If the counter reaches maxAttempts, the account is locked for lockDurationSec seconds.
// Key: "failedlogin:{userID}"
func (c *Client) IncrFailedLogin(ctx context.Context, userID int, maxAttempts int, lockDurationSec int) error {
	key := fmt.Sprintf("failedlogin:%d", userID)
	count, err := c.rdb.Incr(ctx, key).Result()
	if err != nil {
		return err
	}
	// Set TTL on first increment to auto-expire the counter
	if count == 1 {
		_ = c.rdb.Expire(ctx, key, time.Duration(lockDurationSec)*time.Second).Err()
	}
	if maxAttempts > 0 && count >= int64(maxAttempts) {
		if lockErr := c.LockAccount(ctx, userID, lockDurationSec); lockErr != nil {
			return lockErr
		}
		_ = c.rdb.Del(ctx, key).Err()
	}
	return nil
}

// ResetFailedLogin resets the failed login counter on successful login.
// Key: "failedlogin:{userID}"
func (c *Client) ResetFailedLogin(ctx context.Context, userID int) error {
	key := fmt.Sprintf("failedlogin:%d", userID)
	return c.rdb.Del(ctx, key).Err()
}

// FlushTestDB flushes all keys from the current Redis database.
// ONLY use in tests — never call this in production code.
func (c *Client) FlushTestDB(ctx context.Context) error {
	return c.rdb.FlushDB(ctx).Err()
}
