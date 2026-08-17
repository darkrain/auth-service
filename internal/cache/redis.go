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
	SessionID    int64  `json:"session_id"`
	UserID       int    `json:"user_id"`
	Email        string `json:"email"`
	Phone        string `json:"phone"`
	Role         string `json:"role"`
	VerifyStatus string `json:"verify_status"`
	AuthType     string `json:"auth_type"`
}

// LoginChallenge is a short-lived, single-purpose proof that the password
// step succeeded. It prevents the TOTP endpoint from becoming an alternative
// passwordless login endpoint.
type LoginChallenge struct {
	UserID    int64  `json:"user_id"`
	DeviceUID string `json:"device_uid"`
	IP        string `json:"ip"`
}

// Client wraps a redis.Client with session-specific helpers.
type Client struct {
	rdb *redis.Client
}

// NewClient creates a Redis client from config.
func NewClient(cfg *config.Config) *Client {
	rdb := redis.NewClient(&redis.Options{
		Network:  cfg.RedisDatabaseNetwork,
		Addr:     cfg.RedisDatabaseHost + ":" + cfg.RedisDatabasePort,
		Password: cfg.RedisPassword,
	})
	return &Client{rdb: rdb}
}

// Ping checks the Redis connection.
func (c *Client) Ping(ctx context.Context) error {
	return c.rdb.Ping(ctx).Err()
}

func sessionKey(token string) string {
	return "session:" + token
}

func loginChallengeKey(token string) string {
	return "login_challenge:" + token
}

func loginChallengeAttemptsKey(token string) string {
	return "login_challenge_attempts:" + token
}

func sessionSeenKey(sessionID int64) string {
	return fmt.Sprintf("session_seen:%d", sessionID)
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

func (c *Client) SetLoginChallenge(ctx context.Context, token string, challenge LoginChallenge, ttl time.Duration) error {
	b, err := json.Marshal(challenge)
	if err != nil {
		return err
	}
	return c.rdb.Set(ctx, loginChallengeKey(token), b, ttl).Err()
}

func (c *Client) GetLoginChallenge(ctx context.Context, token string) (*LoginChallenge, error) {
	value, err := c.rdb.Get(ctx, loginChallengeKey(token)).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, nil
		}
		return nil, err
	}
	var challenge LoginChallenge
	if err := json.Unmarshal([]byte(value), &challenge); err != nil {
		return nil, err
	}
	return &challenge, nil
}

func (c *Client) DeleteLoginChallenge(ctx context.Context, token string) error {
	return c.rdb.Del(ctx, loginChallengeKey(token), loginChallengeAttemptsKey(token)).Err()
}

func (c *Client) IncrementLoginChallengeAttempts(ctx context.Context, token string, ttl time.Duration) (int64, error) {
	seconds := int(ttl.Round(time.Second).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return luaIncrExpire.Run(ctx, c.rdb, []string{loginChallengeAttemptsKey(token)}, seconds).Int64()
}

// MarkSessionSeen marks a session as recently updated. The caller writes its
// timestamp to PostgreSQL only when this returns true, avoiding a write for
// every authenticated request while keeping the active-session list useful.
func (c *Client) MarkSessionSeen(ctx context.Context, sessionID int64, interval time.Duration) (bool, error) {
	if sessionID <= 0 {
		return false, nil
	}
	return c.rdb.SetNX(ctx, sessionSeenKey(sessionID), "1", interval).Result()
}

// luaIncrExpire atomically increments a key and sets its TTL on first increment.
// This prevents a race condition where EXPIRE could be lost if the process crashes
// between INCR and EXPIRE, causing the counter to never expire.
var luaIncrExpire = redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if current == 1 then
  redis.call('EXPIRE', KEYS[1], tonumber(ARGV[1]))
end
return current
`)

// SlidingWindowIncr increments a sliding window counter in Redis.
// Uses an atomic Lua script to set TTL on first increment, preventing counter leak.
// Returns the current count after increment.
func (c *Client) SlidingWindowIncr(ctx context.Context, key string, windowSec int) (int64, error) {
	count, err := luaIncrExpire.Run(ctx, c.rdb, []string{key}, windowSec).Int64()
	if err != nil {
		return 0, err
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
// Uses an atomic Lua script to set TTL on first increment, preventing counter leak.
// Key: "failedlogin:{userID}"
func (c *Client) IncrFailedLogin(ctx context.Context, userID int, maxAttempts int, lockDurationSec int) error {
	key := fmt.Sprintf("failedlogin:%d", userID)
	count, err := luaIncrExpire.Run(ctx, c.rdb, []string{key}, lockDurationSec).Int64()
	if err != nil {
		return err
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
