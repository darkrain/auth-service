package db

import (
	"context"
	"fmt"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func Seed(pool *pgxpool.Pool, cfg *config.Config) error {
	// Hash password (must use same salt prefix as Login service: cfg.PasswordSalt + password)
	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.PasswordSalt+cfg.SystemUserPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("seed: hash password: %w", err)
	}

	// Check if system user already exists
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM users WHERE email = $1 AND role = 'system'`,
		cfg.SystemUserEmail,
	).Scan(&count); err != nil {
		return fmt.Errorf("seed: check system user: %w", err)
	}

	if count > 0 {
		// Update password to ensure it matches current config (handles salt changes)
		_, err = pool.Exec(context.Background(),
			`UPDATE users SET password=$1, email_verified=true, verify_status='verified' WHERE email=$2 AND role='system'`,
			string(hash), cfg.SystemUserEmail,
		)
		if err != nil {
			return fmt.Errorf("seed: update system user password: %w", err)
		}
		return nil
	}

	// Insert new system user
	_, err = pool.Exec(context.Background(), `
		INSERT INTO users (email, email_verified, password, role, verify_status)
		VALUES ($1, true, $2, 'system', 'verified')
	`, cfg.SystemUserEmail, string(hash))
	if err != nil {
		return fmt.Errorf("seed: insert system user: %w", err)
	}

	fmt.Println("seed: created system user")
	return nil
}
