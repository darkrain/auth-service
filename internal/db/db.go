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

// StartSessionCleanup starts a background goroutine that deletes expired sessions every 24 hours.
// It stops when ctx is cancelled (e.g. on SIGTERM).
func StartSessionCleanup(ctx context.Context, pool *sql.DB, logger *log.Logger) {
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for {
			select {
			case <-ticker.C:
				result, err := pool.ExecContext(ctx, "DELETE FROM sessions WHERE expire_date < NOW()")
				if err != nil {
					logger.Printf("session cleanup error: %v", err)
				} else {
					deleted, err := result.RowsAffected()
					if err != nil {
						logger.Printf("session cleanup rows affected error: %v", err)
						continue
					}
					logger.Printf("session cleanup: deleted %d expired sessions", deleted)
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
