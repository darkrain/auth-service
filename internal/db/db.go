package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/darkrain/auth-service/internal/config"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func DSN(cfg *config.Config) string {
	sslMode := cfg.PostgreSQLSSLMode
	if sslMode == "" {
		sslMode = "disable"
	}
	return fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.PostgreSqlHost,
		cfg.PostgreSqlPort,
		cfg.PostgreSqlUserName,
		cfg.PostgreSqlPassword,
		cfg.PostgreSqlDatabase,
		sslMode,
	)
}

func Connect(cfg *config.Config) (*sql.DB, error) {
	pool, err := sql.Open("pgx", DSN(cfg))
	if err != nil {
		return nil, fmt.Errorf("db: open: %w", err)
	}

	if err := pool.PingContext(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	return pool, nil
}

// CleanupExpiredSessionsAndRegistrations releases contacts held by abandoned
// registrations after their registration token expires, then removes expired
// sessions. It is intentionally limited to verify_status=registered accounts.
func CleanupExpiredSessionsAndRegistrations(ctx context.Context, pool *sql.DB, registrationTTLMin int) (int64, int64, error) {
	if registrationTTLMin <= 0 {
		registrationTTLMin = 30
	}
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin auth cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	registrations, err := tx.ExecContext(ctx, `
		DELETE FROM users u
		WHERE u.verify_status='registered'
		  AND u.creation_date < NOW() - ($1 * INTERVAL '1 minute')
		  AND NOT EXISTS (
			SELECT 1 FROM sessions s
			WHERE s.user_id=u.id AND s.auth_type='registration'
			  AND s.blocked=false AND (s.expire_date IS NULL OR s.expire_date >= NOW())
		  )`, registrationTTLMin)
	if err != nil {
		return 0, 0, fmt.Errorf("delete abandoned registrations: %w", err)
	}
	deletedRegistrations, err := registrations.RowsAffected()
	if err != nil {
		return 0, 0, fmt.Errorf("abandoned registrations rows affected: %w", err)
	}

	sessions, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE expire_date < NOW()")
	if err != nil {
		return 0, 0, fmt.Errorf("delete expired sessions: %w", err)
	}
	deletedSessions, err := sessions.RowsAffected()
	if err != nil {
		return 0, 0, fmt.Errorf("expired sessions rows affected: %w", err)
	}
	if err = tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit auth cleanup: %w", err)
	}
	return deletedRegistrations, deletedSessions, nil
}

// StartSessionCleanup starts a background cleanup immediately and repeats it
// hourly, so an abandoned login is not held for another day after token expiry.
// It stops when ctx is cancelled (e.g. on SIGTERM).
func StartSessionCleanup(ctx context.Context, pool *sql.DB, logger *log.Logger, registrationTTLMin int) {
	ticker := time.NewTicker(time.Hour)
	cleanup := func() {
		registrations, sessions, err := CleanupExpiredSessionsAndRegistrations(ctx, pool, registrationTTLMin)
		if err != nil {
			logger.Printf("auth cleanup error: %v", err)
			return
		}
		logger.Printf("auth cleanup: deleted %d abandoned registrations and %d expired sessions", registrations, sessions)
	}
	go func() {
		cleanup()
		for {
			select {
			case <-ticker.C:
				cleanup()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
