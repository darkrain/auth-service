package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// APIKey is returned when a new API key is created.
type APIKey struct {
	ID        int       `json:"id"`
	Token     string    `json:"token"`
	CreatedAt time.Time `json:"created_at"`
}

// APIKeyInfo is returned in list (no token field).
type APIKeyInfo struct {
	ID        int       `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateAPIKey generates a new API key and stores it in sessions.
func CreateAPIKey(ctx context.Context, pool *pgxpool.Pool, userID int) (*APIKey, error) {
	// Generate 32 random bytes → hex string (64 chars)
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate api key: %w", err)
	}
	token := hex.EncodeToString(raw)

	if pool == nil {
		return nil, fmt.Errorf("database unavailable")
	}

	var id int
	var createdAt time.Time

	err := pool.QueryRow(ctx, `
		INSERT INTO sessions (user_id, token, auth_type, blocked)
		VALUES ($1, $2, 'api', false)
		RETURNING id, creation_date
	`, userID, token).Scan(&id, &createdAt)
	if err != nil {
		return nil, fmt.Errorf("db: insert api key: %w", err)
	}

	return &APIKey{
		ID:        id,
		Token:     token,
		CreatedAt: createdAt,
	}, nil
}

// ListAPIKeys returns all active API keys for a user (without the token value).
func ListAPIKeys(ctx context.Context, pool *pgxpool.Pool, userID int) ([]APIKeyInfo, error) {
	if pool == nil {
		return nil, fmt.Errorf("database unavailable")
	}

	rows, err := pool.Query(ctx, `
		SELECT id, creation_date
		FROM sessions
		WHERE user_id = $1 AND auth_type = 'api' AND blocked = false
		ORDER BY creation_date DESC
	`, userID)
	if err != nil {
		return nil, fmt.Errorf("db: list api keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKeyInfo
	for rows.Next() {
		var k APIKeyInfo
		if err := rows.Scan(&k.ID, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("db: scan api key: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("db: rows error: %w", err)
	}

	if keys == nil {
		keys = []APIKeyInfo{}
	}

	return keys, nil
}

// RevokeAPIKey sets blocked=true for the given API key owned by userID.
func RevokeAPIKey(ctx context.Context, pool *pgxpool.Pool, keyID, userID int) error {
	if pool == nil {
		return fmt.Errorf("database unavailable")
	}

	tag, err := pool.Exec(ctx, `
		UPDATE sessions SET blocked = true
		WHERE id = $1 AND user_id = $2 AND auth_type = 'api'
	`, keyID, userID)
	if err != nil {
		return fmt.Errorf("db: revoke api key: %w", err)
	}

	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: api key not found", ErrNotFound)
	}

	return nil
}
