package modules

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/middleware"
	"github.com/darkrain/auth-service/internal/service"
	module "github.com/darkrain/request-generator"
	"github.com/darkrain/request-generator/actions"
	"github.com/darkrain/request-generator/fields"
	"github.com/darkrain/request-generator/icontext"
	"github.com/darkrain/request-generator/renderer"
	"github.com/gin-gonic/gin"
	pg "github.com/go-jet/jet/v2/postgres"
	"github.com/jackc/pgx/v5/pgconn"
)

type accountSessionsTable struct {
	pg.Table
	ID                                               pg.ColumnInteger
	UserID                                           pg.ColumnInteger
	Token, AuthType, IP, DeviceUID                   pg.ColumnString
	CreationDate, UpdateDate, ExpireDate, LastSeenAt pg.ColumnTimestampz
	Blocked                                          pg.ColumnBool
}

func accountSessions() accountSessionsTable {
	t := accountSessionsTable{
		ID: pg.IntegerColumn("id"), UserID: pg.IntegerColumn("user_id"), Token: pg.StringColumn("token"),
		AuthType: pg.StringColumn("auth_type"), IP: pg.StringColumn("ip"), DeviceUID: pg.StringColumn("device_uid"),
		CreationDate: pg.TimestampzColumn("creation_date"), UpdateDate: pg.TimestampzColumn("update_date"), ExpireDate: pg.TimestampzColumn("expire_date"), LastSeenAt: pg.TimestampzColumn("last_seen_at"),
		Blocked: pg.BoolColumn("blocked"),
	}
	t.Table = pg.NewTable("public", "sessions", "", t.ID, t.UserID, t.Token, t.AuthType, t.IP, t.DeviceUID, t.CreationDate, t.UpdateDate, t.ExpireDate, t.LastSeenAt, t.Blocked)
	return t
}

func AccountPasswordModule(pool *sql.DB, cacheClient *cache.Client, cfg *config.Config) *module.BaseModule {
	t := accountSecurityUsers()
	permissions := authenticatedRoles(cfg)
	return &module.BaseModule{
		Name: "account_password", Label: "account_security.password.label", Table: t, PrimaryKey: t.ID, Path: "/auth",
		Fields: []fields.ModuleField{
			{Column: t.ID, Title: "account_security.fields.id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeOnlyView},
			{Column: t.Password, Title: "account_security.password.new_password", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeHidden},
			{Column: t.PasswordUpdatedAt, Title: "account_security.fields.password_updated_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		},
		Actions: []actions.ModuleAction{actions.UpdateModuleAction{
			Label: "account_security.password.action", Columns: []pg.Column{t.Password, t.PasswordUpdatedAt}, Permission: permissions, Auth: true, By: []pg.Column{t.ID}, Where: ownedUser(t), ViewAfterUpdate: boolRef(false),
			BeforeAction: accountPasswordBefore(pool, cacheClient, cfg),
		}},
		RoleWhere: []actions.RoleWhere{{Role: actions.RoleAll, Where: ownedUser(t)}},
	}
}

func AccountTwoFactorModule(pool *sql.DB, cacheClient *cache.Client, cfg *config.Config) *module.BaseModule {
	t := accountSecurityUsers()
	permissions := authenticatedRoles(cfg)
	return &module.BaseModule{
		Name: "account_two_factor", Label: "account_security.two_factor.label", Table: t, PrimaryKey: t.ID, Path: "/auth",
		Fields: []fields.ModuleField{
			{Column: t.ID, Title: "account_security.fields.id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeOnlyView},
			{Column: t.TwoFactorEnabled, Title: "account_security.fields.two_factor_enabled", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
			{Column: t.TwoFactorSecretEncrypted, Title: "account_security.two_factor.secret", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeHidden},
			{Column: t.TwoFactorConfirmedAt, Title: "account_security.two_factor.confirmed_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		},
		Actions: []actions.ModuleAction{actions.UpdateModuleAction{
			Label: "account_security.two_factor.action", Columns: []pg.Column{t.TwoFactorEnabled, t.TwoFactorSecretEncrypted, t.TwoFactorConfirmedAt}, Permission: permissions, Auth: true, By: []pg.Column{t.ID}, Where: ownedUser(t), ViewAfterUpdate: boolRef(false),
			BeforeAction: accountTwoFactorBefore(pool, cacheClient, cfg),
		}},
		RoleWhere: []actions.RoleWhere{{Role: actions.RoleAll, Where: ownedUser(t)}},
	}
}

func AccountSessionsModule(pool *sql.DB, cacheClient *cache.Client, cfg *config.Config) *module.BaseModule {
	t := accountSessions()
	permissions := authenticatedRoles(cfg)
	visibleColumns := []pg.Column{t.ID, t.AuthType, t.IP, t.DeviceUID, t.CreationDate, t.LastSeenAt, t.ExpireDate, t.Blocked}
	return &module.BaseModule{
		Name: "account_sessions", Label: "account_security.sessions.label", Table: t, PrimaryKey: t.ID, Path: "/auth",
		Fields: []fields.ModuleField{
			{Column: t.ID, Title: "account_security.sessions.fields.id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeOnlyView},
			{Column: t.AuthType, Title: "account_security.sessions.fields.auth_type", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
			{Column: t.DeviceUID, Title: "account_security.sessions.fields.device_uid", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
			{Column: t.IP, Title: "account_security.sessions.fields.ip", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
			{Column: t.CreationDate, Title: "account_security.sessions.fields.creation_date", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Presentation: &renderer.FieldPresentation{Style: "date"}},
			{Column: t.LastSeenAt, Title: "account_security.sessions.fields.last_seen_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Presentation: &renderer.FieldPresentation{Style: "date"}},
			{Column: t.ExpireDate, Title: "account_security.sessions.fields.expire_date", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Presentation: &renderer.FieldPresentation{Style: "date"}},
			{Column: t.Blocked, Title: "account_security.sessions.fields.blocked", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Presentation: verificationBadge()},
		},
		Actions: []actions.ModuleAction{
			actions.ListModuleAction{Label: "account_security.sessions.actions.list", Columns: visibleColumns, Permission: permissions, Auth: true, Where: ownedSession(t), Sort: []pg.Column{t.LastSeenAt, t.CreationDate}, SortDefault: t.LastSeenAt, SortDefaultDirection: actions.SortDESC, Size: 20, Maxsize: 100},
			actions.DeleteModuleAction{Label: "account_security.sessions.actions.delete", Permission: permissions, Auth: true, By: []pg.Column{t.ID}, Where: ownedSession(t), BeforeAction: accountSessionDeleteBefore(pool, cacheClient)},
		},
		RoleWhere: []actions.RoleWhere{{Role: actions.RoleAll, Where: ownedSession(t)}},
		Render:    renderer.Universal{List: &renderer.ListPage{ID: "account-sessions", Title: "account_security.sessions.label", Pagination: &renderer.Pagination{Mode: renderer.PaginationServer}}},
	}
}

func AccountDeactivationModule(pool *sql.DB, _ *cache.Client, cfg *config.Config) *module.BaseModule {
	t := accountSecurityUsers()
	// Command inputs, not persisted user columns. Only the atomic operation
	// decides which actual columns can change.
	password := pg.StringColumn("current_password")
	confirmation := pg.StringColumn("confirmation")
	twoFactorCode := pg.StringColumn("two_factor_code")
	permissions := authenticatedRoles(cfg)
	return &module.BaseModule{
		Name: "account_deactivation", Label: "account_security.deactivate.label", Table: t, PrimaryKey: t.ID, Path: "/auth",
		Fields: []fields.ModuleField{
			{Column: password, Title: "account_security.password.current_password", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeHidden},
			{Column: confirmation, Title: "account_security.deactivate.confirmation", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeHidden},
			{Column: twoFactorCode, Title: "account_security.two_factor.code", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeHidden},
			{Column: t.ID, Title: "account_security.fields.id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeOnlyView},
			{Column: t.VerifyStatus, Title: "account_security.fields.verify_status", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeHidden},
			{Column: t.DeactivatedAt, Title: "account_security.deactivate.deactivated_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		},
		Actions: []actions.ModuleAction{actions.UpdateModuleAction{
			Label: "account_security.deactivate.action", Columns: []pg.Column{password, confirmation, twoFactorCode}, Permission: permissions, Auth: true, By: []pg.Column{t.ID}, Where: ownedUser(t), ViewAfterUpdate: boolRef(false),
			Mode: actions.UpdateModeAtomic,
			Atomic: &actions.AtomicUpdateConfig{Operation: func(ctx context.Context, ex actions.AtomicExecutor, input actions.AtomicUpdateInput) (actions.AtomicRecord, error) {
				actor, ok := icontext.GetUser(ctx)
				if !ok || input.Selector.ByKey != "id" || input.Selector.Value.Int == nil || *input.Selector.Value.Int != actor.ID {
					return actions.AtomicRecord{}, accountDeactivationError(ctx, nil)
				}
				currentPassword, _ := input.Input.String("current_password")
				confirmed, _ := input.Input.String("confirmation")
				code, _ := input.Input.String("two_factor_code")
				if _, err := service.PrepareAccountDeactivation(ctx, pool, cfg, actor.ID, currentPassword, confirmed, code); err != nil {
					return actions.AtomicRecord{}, fmt.Errorf("%s", middleware.TranslateContext(ctx, "account_security.deactivate.credentials_invalid", "Check your current password, confirmation and two-factor code."))
				}
				n, err := ex.Update(ctx, actions.AtomicUpdate{Table: t, Where: t.ID.EQ(pg.Int(actor.ID)), Fields: []actions.AtomicUpdateField{
					{Column: t.VerifyStatus, Operation: actions.AtomicUpdateSet, Value: actions.AtomicString("deactivated")},
					{Column: t.DeactivatedAt, Operation: actions.AtomicUpdateSet, Value: actions.AtomicTime(time.Now().UTC())},
				}})
				if err != nil || n != 1 {
					return actions.AtomicRecord{}, accountDeactivationError(ctx, err)
				}
				s := accountSessions()
				_, err = ex.Update(ctx, actions.AtomicUpdate{Table: s, Where: s.UserID.EQ(pg.Int(actor.ID)), Fields: []actions.AtomicUpdateField{{Column: s.Blocked, Operation: actions.AtomicUpdateSet, Value: actions.AtomicBool(true)}}})
				if err != nil {
					return actions.AtomicRecord{}, accountDeactivationError(ctx, err)
				}
				return actions.AtomicRecord{Value: actor.ID, PrimaryKey: "id"}, nil
			}},
		}},
		RoleWhere: []actions.RoleWhere{{Role: actions.RoleAll, Where: ownedUser(t)}},
	}
}

func ownedSession(t accountSessionsTable) func(*gin.Context) pg.BoolExpression {
	return func(c *gin.Context) pg.BoolExpression {
		id, ok := userID(c)
		if !ok {
			return t.UserID.EQ(pg.Int(-1))
		}
		return t.UserID.EQ(pg.Int64(id))
	}
}

func accountPasswordBefore(pool *sql.DB, cacheClient *cache.Client, cfg *config.Config) func(*gin.Context) error {
	return func(c *gin.Context) error {
		userID, ok := userID(c)
		if !ok {
			return accountActionError(c, "authentication is required", nil)
		}
		input, err := body(c)
		if err != nil {
			return accountActionError(c, "invalid request body", nil)
		}
		output, err := service.ChangePassword(c.Request.Context(), pool, cfg, cacheClient, userID, contextToken(c), inputString(input, "current_password"), inputString(input, "new_password"), inputString(input, "confirmation"), inputString(input, "two_factor_code"))
		if err != nil {
			return accountActionError(c, err.Error(), map[string]string{accountSecurityErrorField(err, "current_password"): err.Error()})
		}
		return replaceBody(c, output)
	}
}

func accountTwoFactorBefore(pool *sql.DB, cacheClient *cache.Client, cfg *config.Config) func(*gin.Context) error {
	return func(c *gin.Context) error {
		userID, ok := userID(c)
		if !ok {
			return accountActionError(c, "authentication is required", nil)
		}
		input, err := body(c)
		if err != nil {
			return accountActionError(c, "invalid request body", nil)
		}
		enabled, ok := input["two_factor_enabled"].(bool)
		if !ok {
			return accountActionError(c, "two_factor_enabled is required", map[string]string{"two_factor_enabled": "two_factor_enabled is required"})
		}
		output, err := service.ConfigureTwoFactor(c.Request.Context(), pool, cfg, cacheClient, userID, contextToken(c), enabled, inputString(input, "two_factor_secret"), inputString(input, "two_factor_code"))
		if err != nil {
			return accountActionError(c, err.Error(), map[string]string{accountSecurityErrorField(err, "two_factor_code"): err.Error()})
		}
		return replaceBody(c, output)
	}
}

func accountDeactivationError(ctx context.Context, err error) error {
	translate := func(key, fallback string) string { return middleware.TranslateContext(ctx, key, fallback) }
	var policy *pgconn.PgError
	if errors.As(err, &policy) && policy.Code == "P0001" {
		if message := translate(policy.Message, ""); message != "" && message != policy.Message {
			return fmt.Errorf("%s", message)
		}
	}
	message := "The account could not be deactivated. No account changes were saved."
	message = translate("account_security.deactivate.unavailable", message)
	return fmt.Errorf("%s", message)
}

func accountSessionDeleteBefore(pool *sql.DB, cacheClient *cache.Client) func(*gin.Context) error {
	return func(c *gin.Context) error {
		userID, ok := userID(c)
		if !ok {
			return accountActionError(c, "authentication is required", nil)
		}
		sessionID, err := strconv.ParseInt(c.Param("value"), 10, 64)
		if err != nil {
			return accountActionError(c, "session not found", nil)
		}
		var token string
		if err := pool.QueryRowContext(c.Request.Context(), `SELECT token FROM sessions WHERE id=$1 AND user_id=$2`, sessionID, userID).Scan(&token); err != nil {
			return accountActionError(c, "session not found", nil)
		}
		if cacheClient != nil {
			_ = cacheClient.DeleteSession(c.Request.Context(), token)
		}
		return nil
	}
}

func accountActionError(c *gin.Context, message string, fieldErrors map[string]string) error {
	payload := gin.H{"error": message}
	if len(fieldErrors) > 0 {
		payload["errors"] = fieldErrors
	}
	c.JSON(http.StatusBadRequest, payload)
	return fmt.Errorf("%s", message)
}

func accountSecurityErrorField(err error, fallback string) string {
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "confirmation"):
		return "confirmation"
	case strings.Contains(message, "password must"):
		return "new_password"
	case strings.Contains(message, "current password"):
		return "current_password"
	case strings.Contains(message, "two-factor") || strings.Contains(message, "two factor"):
		return "two_factor_code"
	default:
		return fallback
	}
}

func contextToken(c *gin.Context) string {
	value, _ := c.Get("token")
	return strings.TrimSpace(fmt.Sprint(value))
}

func boolRef(value bool) *bool {
	return &value
}
