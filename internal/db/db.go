package db

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/jackc/pgx/v5/pgxpool"
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

func Connect(cfg *config.Config) (*pgxpool.Pool, error) {
	pool, err := pgxpool.New(context.Background(), DSN(cfg))
	if err != nil {
		return nil, fmt.Errorf("db: create pool: %w", err)
	}

	if err := pool.Ping(context.Background()); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}

	return pool, nil
}

func ConnectSQL(cfg *config.Config) (*sql.DB, error) {
	sqlDB, err := sql.Open("pgx", DSN(cfg))
	if err != nil {
		return nil, fmt.Errorf("db: open sql: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("db: ping sql: %w", err)
	}
	return sqlDB, nil
}

// StartSessionCleanup starts a background goroutine that deletes expired sessions every 24 hours.
// It stops when ctx is cancelled (e.g. on SIGTERM).
func StartSessionCleanup(ctx context.Context, pool *pgxpool.Pool, logger *log.Logger) {
	ticker := time.NewTicker(24 * time.Hour)
	go func() {
		for {
			select {
			case <-ticker.C:
				tag, err := pool.Exec(ctx, "DELETE FROM sessions WHERE expire_date < NOW()")
				if err != nil {
					logger.Printf("session cleanup error: %v", err)
				} else {
					logger.Printf("session cleanup: deleted %d expired sessions", tag.RowsAffected())
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
