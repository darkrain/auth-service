package modules

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"github.com/darkrain/auth-service/internal/validator"
	module "github.com/darkrain/request-generator"
	"github.com/darkrain/request-generator/actions"
	"github.com/darkrain/request-generator/fields"
	"github.com/darkrain/request-generator/icontext"
	"github.com/darkrain/request-generator/renderer"
	"github.com/gin-gonic/gin"
	pg "github.com/go-jet/jet/v2/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
	amqp "github.com/rabbitmq/amqp091-go"
)

const (
	RoleAll    actions.Role = actions.RoleAll
	RoleAdmin  actions.Role = "admin"
	RoleSudo   actions.Role = "sudo"
	RoleSystem actions.Role = "system"
)

type contactVerificationsTable struct {
	pg.Table
	ID            pg.ColumnInteger
	CreationDate  pg.ColumnTimestampz
	UpdateDate    pg.ColumnTimestampz
	UserID        pg.ColumnInteger
	ContactType   pg.ColumnString
	Recipient     pg.ColumnString
	DeviceUID     pg.ColumnString
	Provider      pg.ColumnString
	AllowFallback pg.ColumnBool
	Status        pg.ColumnString
	Code          pg.ColumnString
	Counter       pg.ColumnInteger
	SentTS        pg.ColumnTimestampz
	ExpiresAt     pg.ColumnTimestampz
	ConfirmedAt   pg.ColumnTimestampz
}

func newContactVerificationsTable() contactVerificationsTable {
	t := contactVerificationsTable{
		ID:            pg.IntegerColumn("id"),
		CreationDate:  pg.TimestampzColumn("creation_date"),
		UpdateDate:    pg.TimestampzColumn("update_date"),
		UserID:        pg.IntegerColumn("user_id"),
		ContactType:   pg.StringColumn("contact_type"),
		Recipient:     pg.StringColumn("recipient"),
		DeviceUID:     pg.StringColumn("device_uid"),
		Provider:      pg.StringColumn("provider"),
		AllowFallback: pg.BoolColumn("allow_fallback"),
		Status:        pg.StringColumn("status"),
		Code:          pg.StringColumn("code"),
		Counter:       pg.IntegerColumn("counter"),
		SentTS:        pg.TimestampzColumn("sent_ts"),
		ExpiresAt:     pg.TimestampzColumn("expires_at"),
		ConfirmedAt:   pg.TimestampzColumn("confirmed_at"),
	}
	t.Table = pg.NewTable("", "contact_verifications", "", t.ID, t.CreationDate, t.UpdateDate, t.UserID, t.ContactType, t.Recipient, t.DeviceUID, t.Provider, t.AllowFallback, t.Status, t.Code, t.Counter, t.SentTS, t.ExpiresAt, t.ConfirmedAt)
	return t
}

func ContactVerificationsModule(pool *pgxpool.Pool, conn *amqp.Connection, cfg *config.Config, cacheClient *cache.Client) *module.BaseModule {
	t := newContactVerificationsTable()
	adminRoles := []actions.Role{RoleAdmin, RoleSudo, RoleSystem}
	userRoles := []actions.Role{RoleAll}

	statusOptions := []fields.ModuleFieldOptions{
		{Value: "pending", Label: "contact_verifications.options.status.pending"},
		{Value: "confirmed", Label: "contact_verifications.options.status.confirmed"},
		{Value: "cancelled", Label: "contact_verifications.options.status.cancelled"},
		{Value: "expired", Label: "contact_verifications.options.status.expired"},
	}
	typeOptions := []fields.ModuleFieldOptions{
		{Value: "email", Label: "contact_verifications.options.contact_type.email"},
		{Value: "phone", Label: "contact_verifications.options.contact_type.phone"},
	}

	moduleFields := []fields.ModuleField{
		{Column: t.ID, Title: "contact_verifications.fields.id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeHidden, Extra: displayExtra("code")},
		{Column: t.CreationDate, Title: "contact_verifications.fields.creation_date", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Extra: displayExtra("date")},
		{Column: t.UpdateDate, Title: "contact_verifications.fields.update_date", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Extra: displayExtra("date")},
		{Column: t.UserID, Title: "contact_verifications.fields.user_id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeHidden},
		{Column: t.ContactType, Title: "contact_verifications.fields.contact_type", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeSelect, Options: typeOptions, Check: []fields.CheckRules{fields.RequiredRule(t.ContactType, []fields.Scenario{fields.ScenarioAdd})}},
		{Column: t.Recipient, Title: "contact_verifications.fields.recipient", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeText, Check: []fields.CheckRules{fields.RequiredRule(t.Recipient, []fields.Scenario{fields.ScenarioAdd})}},
		{Column: t.DeviceUID, Title: "contact_verifications.fields.device_uid", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeText, Check: []fields.CheckRules{fields.RequiredRule(t.DeviceUID, []fields.Scenario{fields.ScenarioAdd})}},
		{Column: t.Provider, Title: "contact_verifications.fields.provider", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeText},
		{Column: t.AllowFallback, Title: "contact_verifications.fields.allow_fallback", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeCheckBox, Extra: displayExtra("boolean")},
		{Column: t.Status, Title: "contact_verifications.fields.status", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeSelect, Options: statusOptions, Extra: displayExtra("badge")},
		{Column: t.Code, Title: "contact_verifications.fields.code", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeHidden},
		{Column: t.Counter, Title: "contact_verifications.fields.counter", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.SentTS, Title: "contact_verifications.fields.sent_ts", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Extra: displayExtra("date")},
		{Column: t.ExpiresAt, Title: "contact_verifications.fields.expires_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Extra: displayExtra("date")},
		{Column: t.ConfirmedAt, Title: "contact_verifications.fields.confirmed_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Extra: displayExtra("date")},
	}

	return &module.BaseModule{
		Name:       "contact_verifications",
		Label:      "contact_verifications.label",
		Table:      t,
		PrimaryKey: t.ID,
		Path:       "/auth",
		Fields:     moduleFields,
		Render:     contactVerificationsRender(),
		RoleWhere: []actions.RoleWhere{
			{Role: RoleAdmin, Where: func(c *gin.Context) pg.BoolExpression { return nil }},
			{Role: RoleSudo, Where: func(c *gin.Context) pg.BoolExpression { return nil }},
			{Role: RoleSystem, Where: func(c *gin.Context) pg.BoolExpression { return nil }},
			{Role: RoleAll, Where: ownContactVerificationWhere(t)},
		},
		Actions: []actions.ModuleAction{
			actions.ListModuleAction{
				Label:                "contact_verifications.actions.list",
				Fields:               []actions.RoleContext{{Role: RoleAll, Columns: []pg.Column{t.ID, t.CreationDate, t.UpdateDate, t.ContactType, t.Recipient, t.Provider, t.AllowFallback, t.Status, t.Counter, t.SentTS, t.ExpiresAt, t.ConfirmedAt}}},
				Permission:           userRoles,
				Auth:                 true,
				Size:                 20,
				Maxsize:              100,
				Filter:               []pg.Column{t.ContactType, t.Status},
				Sort:                 []pg.Column{t.CreationDate, t.UpdateDate, t.ExpiresAt},
				SortDefault:          t.CreationDate,
				SortDefaultDirection: actions.SortDESC,
				Where:                ownContactVerificationWhere(t),
			},
			actions.ViewModuleAction{
				Label:      "contact_verifications.actions.view",
				Fields:     []actions.RoleContext{{Role: RoleAll, Columns: []pg.Column{t.ID, t.CreationDate, t.UpdateDate, t.ContactType, t.Recipient, t.Provider, t.AllowFallback, t.Status, t.Counter, t.SentTS, t.ExpiresAt, t.ConfirmedAt}}},
				Permission: userRoles,
				Auth:       true,
				By:         []pg.Column{t.ID},
			},
			actions.AddModuleAction{
				Label: "contact_verifications.actions.add",
				Fields: []actions.RoleContext{{
					Role:    RoleAll,
					Columns: []pg.Column{t.UserID, t.ContactType, t.Recipient, t.DeviceUID, t.Provider, t.AllowFallback, t.Status, t.Code, t.Counter, t.SentTS, t.ExpiresAt},
				}},
				Permission:   userRoles,
				Auth:         true,
				BeforeAction: beforeContactVerificationAdd(pool, conn, cfg),
			},
			actions.UpdateModuleAction{
				Label: "contact_verifications.actions.update",
				Fields: []actions.RoleContext{{
					Role:    RoleAll,
					Columns: []pg.Column{t.Status, t.ConfirmedAt},
				}},
				Permission:   userRoles,
				Auth:         true,
				By:           []pg.Column{t.ID},
				Where:        ownContactVerificationWhere(t),
				BeforeAction: beforeContactVerificationConfirm(pool, cfg, cacheClient),
			},
			actions.DeleteModuleAction{
				Label:      "contact_verifications.actions.delete",
				Permission: adminRoles,
				Auth:       true,
				By:         []pg.Column{t.ID},
			},
		},
		Defrec: actions.DefrecModuleAction{
			Label: "contact_verifications.actions.defrec",
		},
	}
}

func ownContactVerificationWhere(t contactVerificationsTable) func(*gin.Context) pg.BoolExpression {
	return func(c *gin.Context) pg.BoolExpression {
		user, ok := icontext.GetUser(c.Request.Context())
		if !ok || user.ID == 0 {
			return t.UserID.EQ(pg.Int64(-1))
		}
		if user.Role == "admin" || user.Role == "sudo" || user.Role == "system" {
			return nil
		}
		return t.UserID.EQ(pg.Int64(user.ID))
	}
}

func contactVerificationsRender() renderer.Universal {
	return renderer.Universal{
		List: &renderer.ListPage{
			ID:       "contact-verifications-list",
			Title:    "contact_verifications.pages.list.title",
			Subtitle: "contact_verifications.pages.list.subtitle",
			Layout: &renderer.Layout{
				Type:  renderer.LayoutOneColumn,
				Align: renderer.AlignStretch,
				Gap:   renderer.SpacingMD,
			},
			Filters: &renderer.Filters{
				Enabled:          true,
				PrimaryPlacement: "topbar",
				Primary:          []string{"contact_type", "status"},
			},
			Pagination: &renderer.Pagination{
				Mode: renderer.PaginationServer,
			},
			Actions: []renderer.Action{
				{
					ID:         "request_contact_verification",
					Type:       renderer.ActionRoute,
					LabelKey:   "contact_verifications.actions.add",
					Variant:    renderer.ActionVariantPrimary,
					Appearance: renderer.ActionAppearanceSolid,
				},
			},
			Context: contactVerificationsContext("list"),
		},
		Form: &renderer.FormPage{
			ID:       "contact-verifications-form",
			Title:    "contact_verifications.pages.form.title",
			Subtitle: "contact_verifications.pages.form.subtitle",
			Layout:   renderer.LayoutOneColumn,
			Sections: []renderer.FormSection{
				{
					ID:     "contact",
					Title:  "contact_verifications.sections.contact",
					Fields: []string{"contact_type", "recipient", "device_uid", "provider", "allow_fallback"},
					Block: &renderer.Block{
						Type:    renderer.BlockPanel,
						Variant: renderer.BlockVariantDefault,
					},
				},
				{
					ID:     "confirm",
					Title:  "contact_verifications.sections.confirm",
					Fields: []string{"code"},
					Block: &renderer.Block{
						Type:    renderer.BlockPanel,
						Variant: renderer.BlockVariantCompact,
					},
				},
			},
			Context: contactVerificationsContext("defrec"),
		},
		Record: &renderer.RecordPage{
			Layout: &renderer.Layout{
				Type:  renderer.LayoutOneColumn,
				Align: renderer.AlignStretch,
				Gap:   renderer.SpacingMD,
			},
			Sections: []renderer.RecordSection{
				{ID: "contact", Renderer: "table", Order: 10, Extra: map[string]interface{}{"title": "contact_verifications.sections.contact", "fields": []string{"contact_type", "recipient", "provider", "allow_fallback", "status"}}},
				{ID: "audit", Renderer: "table", Order: 20, Extra: map[string]interface{}{"title": "contact_verifications.sections.audit", "fields": []string{"id", "creation_date", "update_date", "sent_ts", "expires_at", "confirmed_at", "counter"}}},
			},
			Context: contactVerificationsContext("view"),
		},
	}
}

func contactVerificationsContext(action string) map[string]interface{} {
	return map[string]interface{}{
		"namespace": "auth-service",
		"module":    "contact_verifications",
		"source": map[string]interface{}{
			"id":        "auth",
			"base_path": "/auth",
		},
		"action": action,
		"field_flow": map[string]interface{}{
			"type": "verified_contact",
			"module_ref": map[string]interface{}{
				"namespace": "auth-service",
				"source":    "auth",
				"base_path": "/auth",
				"module":    "contact_verifications",
			},
			"request": map[string]interface{}{"action": "add", "method": "PUT"},
			"confirm": map[string]interface{}{"action": "update", "method": "POST", "by": "id"},
		},
	}
}

func displayExtra(displayType string) *fields.FieldExtra {
	display := map[string]interface{}{"display": map[string]interface{}{"type": displayType}}
	return &fields.FieldExtra{
		List: display,
		View: display,
	}
}

func beforeContactVerificationAdd(pool *pgxpool.Pool, conn *amqp.Connection, cfg *config.Config) func(*gin.Context) error {
	return func(c *gin.Context) error {
		userID, err := currentUserID(c)
		if err != nil {
			return err
		}
		input, err := readJSONBody(c)
		if err != nil {
			return err
		}

		contactType := strings.TrimSpace(stringValue(input["contact_type"]))
		recipient := strings.TrimSpace(stringValue(input["recipient"]))
		deviceUID := strings.TrimSpace(stringValue(input["device_uid"]))
		provider := strings.TrimSpace(stringValue(input["provider"]))
		allowFallback := boolValue(input["allow_fallback"], true)

		if err := validateContact(contactType, recipient); err != nil {
			return err
		}
		if deviceUID == "" {
			return fmt.Errorf("device_uid is required")
		}
		if pool == nil {
			return fmt.Errorf("database unavailable")
		}
		if err := ensureContactAvailable(c.Request.Context(), pool, contactType, recipient, userID); err != nil {
			return err
		}
		if err := expirePreviousPending(c.Request.Context(), pool, cfg, userID, contactType); err != nil {
			return err
		}

		code, err := generateCode()
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		ttl := cfg.RateLimit.Code.TTLSec
		if ttl <= 0 {
			ttl = 300
		}
		expiresAt := now.Add(time.Duration(ttl) * time.Second)

		recipientType := delivery.RecipientTypePhone
		if contactType == "email" {
			recipientType = delivery.RecipientTypeEmail
		}
		if err := delivery.PublishCode(c.Request.Context(), conn, cfg, delivery.CodeRequest{
			Template:         delivery.TemplateAuthVerificationCode,
			Purpose:          delivery.PurposeVerification,
			RecipientType:    recipientType,
			Recipient:        recipient,
			Code:             code,
			TTLSec:           ttl,
			UserID:           userID,
			DeviceUID:        deviceUID,
			SelectedProvider: provider,
			AllowFallback:    allowFallback,
		}); err != nil {
			return err
		}

		input["user_id"] = userID
		input["contact_type"] = contactType
		input["recipient"] = recipient
		input["device_uid"] = deviceUID
		input["provider"] = provider
		input["allow_fallback"] = allowFallback
		input["status"] = "pending"
		input["code"] = code
		input["counter"] = 0
		input["sent_ts"] = now.Format(time.RFC3339Nano)
		input["expires_at"] = expiresAt.Format(time.RFC3339Nano)
		return replaceJSONBody(c, input)
	}
}

func beforeContactVerificationConfirm(pool *pgxpool.Pool, cfg *config.Config, cacheClient *cache.Client) func(*gin.Context) error {
	return func(c *gin.Context) error {
		userID, err := currentUserID(c)
		if err != nil {
			return err
		}
		id, err := strconv.ParseInt(c.Param("value"), 10, 64)
		if err != nil || id <= 0 {
			return fmt.Errorf("invalid verification id")
		}
		input, err := readJSONBody(c)
		if err != nil {
			return err
		}
		code := strings.TrimSpace(stringValue(input["code"]))
		if code == "" {
			return fmt.Errorf("code is required")
		}
		if pool == nil {
			return fmt.Errorf("database unavailable")
		}

		var contactType, recipient, storedCode, status string
		var counter int64
		var expiresAt time.Time
		err = pool.QueryRow(c.Request.Context(),
			`SELECT contact_type, recipient, code, counter, status, expires_at
			   FROM contact_verifications
			  WHERE id=$1 AND user_id=$2`,
			id, userID,
		).Scan(&contactType, &recipient, &storedCode, &counter, &status, &expiresAt)
		if err != nil {
			return fmt.Errorf("verification request not found")
		}
		if status != "pending" {
			return fmt.Errorf("verification request is not pending")
		}
		if time.Now().After(expiresAt) {
			_, _ = pool.Exec(c.Request.Context(), `UPDATE contact_verifications SET status='expired', update_date=NOW() WHERE id=$1`, id)
			return fmt.Errorf("verification code has expired")
		}
		if cfg.RateLimit.Code.MaxAttempts > 0 && counter >= int64(cfg.RateLimit.Code.MaxAttempts) {
			return fmt.Errorf("too many attempts")
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(storedCode)) != 1 {
			_, _ = pool.Exec(c.Request.Context(), `UPDATE contact_verifications SET counter=counter+1, update_date=NOW() WHERE id=$1`, id)
			return fmt.Errorf("invalid verification code")
		}
		if err := ensureContactAvailable(c.Request.Context(), pool, contactType, recipient, userID); err != nil {
			return err
		}
		if err := applyVerifiedContact(c.Request.Context(), pool, userID, contactType, recipient); err != nil {
			return err
		}
		if cacheClient != nil {
			if token, ok := c.Get("token"); ok {
				_ = cacheClient.DeleteSession(c.Request.Context(), fmt.Sprint(token))
			}
		}

		input = map[string]interface{}{
			"status":       "confirmed",
			"confirmed_at": time.Now().UTC().Format(time.RFC3339Nano),
		}
		return replaceJSONBody(c, input)
	}
}

func currentUserID(c *gin.Context) (int64, error) {
	user, ok := icontext.GetUser(c.Request.Context())
	if ok && user.ID > 0 {
		return user.ID, nil
	}
	raw, ok := c.Get("user_id")
	if !ok {
		return 0, fmt.Errorf("not authenticated")
	}
	switch v := raw.(type) {
	case int:
		return int64(v), nil
	case int64:
		return v, nil
	case float64:
		return int64(v), nil
	default:
		return 0, fmt.Errorf("invalid authenticated user")
	}
}

func validateContact(contactType, recipient string) error {
	switch contactType {
	case "email":
		if !validator.IsValidEmail(recipient) {
			return fmt.Errorf("invalid email format")
		}
	case "phone":
		if !validator.IsValidPhone(recipient) {
			return fmt.Errorf("invalid phone format")
		}
	default:
		return fmt.Errorf("contact_type must be email or phone")
	}
	return nil
}

func ensureContactAvailable(ctx context.Context, pool *pgxpool.Pool, contactType, recipient string, userID int64) error {
	column := "phone"
	if contactType == "email" {
		column = "email"
	}
	query := fmt.Sprintf(`SELECT id FROM users WHERE %s=$1 AND id<>$2 LIMIT 1`, column)
	var existing int64
	err := pool.QueryRow(ctx, query, recipient, userID).Scan(&existing)
	if err == nil {
		return fmt.Errorf("%s is already registered", contactType)
	}
	return nil
}

func expirePreviousPending(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, userID int64, contactType string) error {
	var sentTS time.Time
	err := pool.QueryRow(ctx,
		`SELECT sent_ts FROM contact_verifications WHERE user_id=$1 AND contact_type=$2 AND status='pending' ORDER BY sent_ts DESC LIMIT 1`,
		userID, contactType,
	).Scan(&sentTS)
	if err == nil && cfg.RateLimit.Code.TTLSec > 0 && time.Now().Before(sentTS.Add(time.Duration(cfg.RateLimit.Code.TTLSec)*time.Second)) {
		return fmt.Errorf("code already sent, please wait before requesting a new one")
	}
	_, err = pool.Exec(ctx,
		`UPDATE contact_verifications SET status='expired', update_date=NOW() WHERE user_id=$1 AND contact_type=$2 AND status='pending'`,
		userID, contactType,
	)
	return err
}

func applyVerifiedContact(ctx context.Context, pool *pgxpool.Pool, userID int64, contactType, recipient string) error {
	if contactType == "email" {
		_, err := pool.Exec(ctx,
			`UPDATE users SET email=$1, email_verified=true, verify_status='verified' WHERE id=$2`,
			recipient, userID,
		)
		return err
	}
	_, err := pool.Exec(ctx,
		`UPDATE users SET phone=$1, phone_verified=true, verify_status='verified' WHERE id=$2`,
		recipient, userID,
	)
	return err
}

func generateCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func readJSONBody(c *gin.Context) (map[string]interface{}, error) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return nil, err
	}
	var input map[string]interface{}
	if len(bytes.TrimSpace(body)) == 0 {
		input = map[string]interface{}{}
	} else if err := json.Unmarshal(body, &input); err != nil {
		return nil, fmt.Errorf("invalid request body")
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	return input, nil
}

func replaceJSONBody(c *gin.Context, input map[string]interface{}) error {
	body, err := json.Marshal(input)
	if err != nil {
		return err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	c.Request.ContentLength = int64(len(body))
	return nil
}

func stringValue(value interface{}) string {
	if value == nil {
		return ""
	}
	return fmt.Sprint(value)
}

func boolValue(value interface{}, fallback bool) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		if v == "" {
			return fallback
		}
		return v == "true" || v == "1" || strings.EqualFold(v, "yes")
	default:
		return fallback
	}
}
