package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/darkrain/auth-service/internal/cache"
)

// ErrConflict is returned when the account state does not allow the change.
var ErrConflict = errors.New("conflict")

// Staff and system accounts are never blocked from here; only customer roles.
var blockableRoles = map[string]bool{"model": true, "agency": true, "manager": true, "client": true}

// The statuses a working account has. A block keeps it in the audit row and an
// unblock puts it back; a deactivated account stays deactivated.
var blockableStatuses = map[string]bool{"verified": true, "registered": true, "unverified": true, "draft": true, "onverify": true}

// The audit rows of an administrative block in the platform's change_logs.
// value_to is compared as text, so these are written exactly so.
const (
	accountBlockLogTable = "users"
	accountBlockValueTo  = `{"action":"admin_block","verify_status":"banned"}`
)

// AccountBlockResult is the state of the account after a block or an unblock.
type AccountBlockResult struct {
	UserID       int64  `json:"user_id"`
	VerifyStatus string `json:"verify_status"`
	Blocked      bool   `json:"blocked"`
	Changed      bool   `json:"changed"`
}

// SetAccountBlocked blocks or unblocks a customer account for an administrator.
// A block sets verify_status to banned, revokes every session and API key of
// the account and drops them from the session cache, so the next request of
// any of its devices is refused; new logins are refused by the banned status.
// The status before the block, the actor and the IP go to change_logs in the
// same transaction. An unblock restores the status recorded by the latest
// administrative block and revives no session: the user signs in again.
// Repeating a block or an unblock changes nothing and writes no audit row.
func SetAccountBlocked(ctx context.Context, pool *sql.DB, cacheClient *cache.Client, actorID, userID int64, block bool, ip string) (*AccountBlockResult, error) {
	if pool == nil {
		return nil, fmt.Errorf("database is unavailable")
	}
	if userID <= 0 {
		return nil, fmt.Errorf("%w: invalid user id", ErrValidation)
	}
	if actorID == userID {
		return nil, fmt.Errorf("%w: an account cannot block itself", ErrForbidden)
	}
	tx, err := pool.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin account block: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var role, status string
	if err := tx.QueryRowContext(ctx, `SELECT role, verify_status FROM users WHERE id=$1 FOR UPDATE`, userID).Scan(&role, &status); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: user not found", ErrNotFound)
		}
		return nil, fmt.Errorf("read account: %w", err)
	}
	if !blockableRoles[role] {
		return nil, fmt.Errorf("%w: this account cannot be blocked", ErrForbidden)
	}
	result := &AccountBlockResult{UserID: userID, VerifyStatus: status, Blocked: status == "banned"}
	var revoked []string

	switch {
	case block && status == "banned":
		// Already blocked: only make sure nothing it holds still works.
		if revoked, err = revokeSessionsTx(ctx, tx, userID); err != nil {
			return nil, err
		}
	case block:
		if !blockableStatuses[status] {
			return nil, fmt.Errorf("%w: account status %q cannot be blocked", ErrConflict, status)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET verify_status='banned', update_date=NOW() WHERE id=$1`, userID); err != nil {
			return nil, fmt.Errorf("block account: %w", err)
		}
		if err := insertAccountBlockLog(ctx, tx, actorID, userID, ip, statusJSON(status, ""), accountBlockValueTo); err != nil {
			return nil, err
		}
		if revoked, err = revokeSessionsTx(ctx, tx, userID); err != nil {
			return nil, err
		}
		result.VerifyStatus, result.Blocked, result.Changed = "banned", true, true
	case status != "banned":
		// Not blocked: nothing to restore.
	default:
		var from string
		err := tx.QueryRowContext(ctx, `SELECT COALESCE(value_from, '') FROM change_logs
			WHERE table_name=$1 AND object_id=$2 AND value_to=$3 ORDER BY id DESC LIMIT 1`,
			accountBlockLogTable, userID, accountBlockValueTo).Scan(&from)
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: no administrative block is recorded for this account", ErrConflict)
		}
		if err != nil {
			return nil, fmt.Errorf("read account block: %w", err)
		}
		var previous struct {
			VerifyStatus string `json:"verify_status"`
		}
		if json.Unmarshal([]byte(from), &previous) != nil || !blockableStatuses[previous.VerifyStatus] {
			return nil, fmt.Errorf("%w: the status before the block is not recorded", ErrConflict)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET verify_status=$2, update_date=NOW() WHERE id=$1`, userID, previous.VerifyStatus); err != nil {
			return nil, fmt.Errorf("unblock account: %w", err)
		}
		if err := insertAccountBlockLog(ctx, tx, actorID, userID, ip, `{"verify_status":"banned"}`, statusJSON(previous.VerifyStatus, "admin_unblock")); err != nil {
			return nil, err
		}
		result.VerifyStatus, result.Blocked, result.Changed = previous.VerifyStatus, false, true
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit account block: %w", err)
	}
	if cacheClient != nil {
		for _, token := range revoked {
			_ = cacheClient.DeleteSession(ctx, token)
		}
	}
	return result, nil
}

func statusJSON(status, action string) string {
	value := map[string]string{"verify_status": status}
	if action != "" {
		value["action"] = action
	}
	raw, _ := json.Marshal(value)
	return string(raw)
}

// No session token is written to the audit row.
func insertAccountBlockLog(ctx context.Context, tx *sql.Tx, actorID, userID int64, ip, from, to string) error {
	var actor interface{}
	if actorID > 0 {
		actor = actorID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO change_logs (table_name, object_id, ip, value_from, value_to, user_id)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6)`, accountBlockLogTable, userID, ip, from, to, actor); err != nil {
		return fmt.Errorf("audit account block: %w", err)
	}
	return nil
}

func revokeSessionsTx(ctx context.Context, tx *sql.Tx, userID int64) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `UPDATE sessions SET blocked=true, update_date=NOW() WHERE user_id=$1 AND blocked=false RETURNING token`, userID)
	if err != nil {
		return nil, fmt.Errorf("revoke account sessions: %w", err)
	}
	defer rows.Close()
	var tokens []string
	for rows.Next() {
		var token string
		if err := rows.Scan(&token); err != nil {
			return nil, fmt.Errorf("read revoked session: %w", err)
		}
		tokens = append(tokens, token)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	if err := deletePendingHandoffs(ctx, tx, userID); err != nil {
		return nil, err
	}
	return tokens, nil
}
