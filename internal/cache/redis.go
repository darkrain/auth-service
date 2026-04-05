package cache

import (
	"context"
	"encoding/json"
	"errors"
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
