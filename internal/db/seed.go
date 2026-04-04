package db

import (
	"context"
	"fmt"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func Seed(pool *pgxpool.Pool, cfg *config.Config) error {
	// Check if system user exists
	var count int
	err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM users WHERE email = $1 AND role = 'system'`,
		cfg.SystemUserEmail,
	).Scan(&count)
	if err != nil {
		return fmt.Errorf("seed: check system user: %w", err)
	}

	if count > 0 {
		return nil
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(cfg.SystemUserPassword), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("seed: hash password: %w", err)
	}

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
