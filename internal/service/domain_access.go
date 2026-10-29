package service

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/darkrain/auth-service/internal/config"
)

// Check again at session issuance: a TOTP challenge created on another brand
// must not bypass this instance's login policy.
func checkLoginRole(ctx context.Context, pool *sql.DB, cfg *config.Config, userID int64) error {
	if len(cfg.AllowedLoginRoles) == 0 {
		return nil
	}
	if pool == nil {
		return fmt.Errorf("database unavailable")
	}
	var role string
	if err := pool.QueryRowContext(ctx, "SELECT role FROM users WHERE id=$1", userID).Scan(&role); err != nil {
		return err
	}
	for _, allowed := range cfg.AllowedLoginRoles {
		if role == allowed {
			return nil
		}
	}
	return fmt.Errorf("%w: account is not available on this domain", ErrForbidden)
}
