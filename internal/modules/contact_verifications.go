package modules

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/service"
	module "github.com/darkrain/request-generator"
	"github.com/darkrain/request-generator/actions"
	"github.com/darkrain/request-generator/fields"
	"github.com/darkrain/request-generator/renderer"
	"github.com/gin-gonic/gin"
	pg "github.com/go-jet/jet/v2/postgres"
	amqp "github.com/rabbitmq/amqp091-go"
)

type contactVerificationsTable struct {
	pg.Table
	ID                                                                     pg.ColumnInteger
	CreationDate, UpdateDate                                               pg.ColumnTimestampz
	UserID                                                                 pg.ColumnInteger
	ContactType, Recipient, DeviceUID, Provider, Purpose, Status, CodeHash pg.ColumnString
	AllowFallback                                                          pg.ColumnBool
	Counter                                                                pg.ColumnInteger
	SentTS, ExpiresAt, ConfirmedAt                                         pg.ColumnTimestampz
}

func contactTable() contactVerificationsTable {
	t := contactVerificationsTable{
		ID: pg.IntegerColumn("id"), CreationDate: pg.TimestampzColumn("creation_date"), UpdateDate: pg.TimestampzColumn("update_date"),
		UserID: pg.IntegerColumn("user_id"), ContactType: pg.StringColumn("contact_type"), Recipient: pg.StringColumn("recipient"),
		DeviceUID: pg.StringColumn("device_uid"), Provider: pg.StringColumn("provider"), Purpose: pg.StringColumn("purpose"),
		Status: pg.StringColumn("status"), CodeHash: pg.StringColumn("code_hash"), AllowFallback: pg.BoolColumn("allow_fallback"),
		Counter: pg.IntegerColumn("counter"), SentTS: pg.TimestampzColumn("sent_ts"), ExpiresAt: pg.TimestampzColumn("expires_at"), ConfirmedAt: pg.TimestampzColumn("confirmed_at"),
	}
	t.Table = pg.NewTable("public", "contact_verifications", "", t.ID, t.CreationDate, t.UpdateDate, t.UserID, t.ContactType, t.Recipient, t.DeviceUID, t.Provider, t.Purpose, t.Status, t.CodeHash, t.AllowFallback, t.Counter, t.SentTS, t.ExpiresAt, t.ConfirmedAt)
	return t
}

// ContactVerificationsModule exposes the standard generator CRUD contract.
// The browser can only request a code and submit a code; recipient ownership,
// code generation and contact updates stay on the server.
func ContactVerificationsModule(pool *sql.DB, conn *amqp.Connection, cacheClient *cache.Client, cfg *config.Config) *module.BaseModule {
	t := contactTable()
	permissions := authenticatedRoles(cfg)
	read := []pg.Column{t.ID, t.CreationDate, t.UpdateDate, t.ContactType, t.Recipient, t.Provider, t.AllowFallback, t.Purpose, t.Status, t.Counter, t.SentTS, t.ExpiresAt, t.ConfirmedAt}
	return &module.BaseModule{Name: "contact_verifications", Label: "contact_verifications.label", Table: t, PrimaryKey: t.ID, Path: "/auth", Fields: []fields.ModuleField{
		{Column: t.ID, Title: "contact_verifications.fields.id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.UserID, Title: "contact_verifications.fields.user_id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeHidden},
		{Column: t.ContactType, Title: "contact_verifications.fields.contact_type", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeSelect, Options: []fields.ModuleFieldOptions{{Value: "email", Label: "contact_verifications.options.email"}, {Value: "phone", Label: "contact_verifications.options.phone"}}, Check: []fields.CheckRules{fields.RequiredRule(t.ContactType, []fields.Scenario{fields.ScenarioAdd})}},
		{Column: t.Recipient, Title: "contact_verifications.fields.recipient", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeText, Check: []fields.CheckRules{fields.RequiredRule(t.Recipient, []fields.Scenario{fields.ScenarioAdd})}},
		{Column: t.DeviceUID, Title: "contact_verifications.fields.device_uid", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeHidden, Check: []fields.CheckRules{fields.RequiredRule(t.DeviceUID, []fields.Scenario{fields.ScenarioAdd})}},
		{Column: t.Provider, Title: "contact_verifications.fields.provider", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeSelect},
		{Column: t.AllowFallback, Title: "contact_verifications.fields.allow_fallback", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeCheckBox},
		{Column: t.Purpose, Title: "contact_verifications.fields.purpose", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.Status, Title: "contact_verifications.fields.status", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Presentation: &renderer.FieldPresentation{Renderer: renderer.RendererBadge}},
		{Column: t.CodeHash, Title: "contact_verifications.fields.code", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeHidden},
		{Column: t.Counter, Title: "contact_verifications.fields.counter", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.SentTS, Title: "contact_verifications.fields.sent_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.CreationDate, Title: "contact_verifications.fields.creation_date", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.ExpiresAt, Title: "contact_verifications.fields.expires_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
	}, Actions: []actions.ModuleAction{
		actions.ListModuleAction{Label: "contact_verifications.actions.list", Columns: read, Permission: permissions, Auth: true, Where: owned(t), Filter: []pg.Column{t.ContactType, t.Status}, Sort: []pg.Column{t.CreationDate, t.ExpiresAt}, SortDefault: t.CreationDate, SortDefaultDirection: actions.SortDESC, Size: 20, Maxsize: 100},
		actions.ViewModuleAction{Label: "contact_verifications.actions.view", Columns: read, Permission: permissions, Auth: true, By: []pg.Column{t.ID}},
		actions.AddModuleAction{Label: "contact_verifications.actions.add", Columns: []pg.Column{t.UserID, t.ContactType, t.Recipient, t.DeviceUID, t.Provider, t.AllowFallback, t.Purpose, t.Status, t.CodeHash, t.Counter, t.SentTS, t.ExpiresAt}, Permission: permissions, Auth: true, BeforeAction: requestContactVerification(pool, conn, cfg)},
		actions.UpdateModuleAction{Label: "contact_verifications.actions.update", Columns: []pg.Column{t.Status, t.ConfirmedAt}, Permission: permissions, Auth: true, By: []pg.Column{t.ID}, Where: owned(t), BeforeAction: confirmContactVerification(pool, cacheClient, cfg)},
	}, RoleWhere: []actions.RoleWhere{{Role: actions.RoleAll, Where: owned(t)}}, Defrec: actions.DefrecModuleAction{Label: "contact_verifications.actions.defrec"}, Render: renderer.Universal{
		List:   &renderer.ListPage{ID: "contact-verifications", Title: "contact_verifications.label", Filters: &renderer.Filters{Enabled: true, Primary: []string{"contact_type", "status"}}, Pagination: &renderer.Pagination{Mode: renderer.PaginationServer}},
		Form:   &renderer.FormPage{ID: "contact-verification-form", Title: "contact_verifications.label", Layout: renderer.LayoutOneColumn, Sections: []renderer.FormSection{{ID: "contact", Fields: []string{"contact_type", "recipient", "provider", "allow_fallback"}, Block: &renderer.Block{Type: renderer.BlockPanel}}}},
		Record: &renderer.RecordPage{ID: "contact-verification", Sections: []renderer.RecordSection{{ID: "details", Renderer: renderer.RecordRendererDisplay, Components: []renderer.DisplayComponent{{ID: "fields", Type: renderer.DisplayDataList, Fields: []string{"contact_type", "recipient", "provider", "allow_fallback", "status", "expires_at"}}}}}},
	}}
}

func authenticatedRoles(cfg *config.Config) []actions.Role {
	roles := make([]actions.Role, 0, len(cfg.AllowedRoles)+3)
	seen := map[actions.Role]struct{}{}
	for _, role := range append(append([]string(nil), cfg.AllowedRoles...), "admin", "system", "sudo") {
		value := actions.Role(role)
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		roles = append(roles, value)
	}
	return roles
}

func owned(t contactVerificationsTable) func(*gin.Context) pg.BoolExpression {
	return func(c *gin.Context) pg.BoolExpression {
		id, ok := userID(c)
		if !ok {
			return t.UserID.EQ(pg.Int(-1))
		}
		return t.UserID.EQ(pg.Int64(id))
	}
}

func requestContactVerification(pool *sql.DB, conn *amqp.Connection, cfg *config.Config) func(*gin.Context) error {
	return func(c *gin.Context) error {
		userID, ok := userID(c)
		if !ok {
			return fmt.Errorf("authentication is required")
		}
		input, err := body(c)
		if err != nil {
			return err
		}
		fallback, _ := input["allow_fallback"].(bool)
		prepared, err := service.PrepareContactVerification(c.Request.Context(), pool, cfg, service.ContactVerificationRequest{
			UserID: userID, ContactType: inputString(input, "contact_type"), Recipient: inputString(input, "recipient"),
			DeviceUID: inputString(input, "device_uid"), Provider: inputString(input, "provider"), AllowFallback: fallback,
			Purpose: "verification",
		})
		if err != nil {
			return err
		}
		if err = service.PublishContactVerification(c.Request.Context(), conn, cfg, prepared); err != nil {
			return err
		}
		input = map[string]interface{}{
			"user_id": prepared.UserID, "contact_type": prepared.ContactType, "recipient": prepared.Recipient, "device_uid": prepared.DeviceUID,
			"provider": prepared.Provider, "allow_fallback": prepared.AllowFallback, "purpose": prepared.Purpose, "status": prepared.Status,
			"code_hash": prepared.CodeHash, "counter": prepared.Counter, "sent_ts": prepared.SentAt.Format(time.RFC3339Nano), "expires_at": prepared.ExpiresAt.Format(time.RFC3339Nano),
		}
		return replaceBody(c, input)
	}
}

func confirmContactVerification(pool *sql.DB, cacheClient *cache.Client, cfg *config.Config) func(*gin.Context) error {
	return func(c *gin.Context) error {
		userID, ok := userID(c)
		if !ok {
			return fmt.Errorf("authentication is required")
		}
		input, err := body(c)
		if err != nil {
			return err
		}
		verificationID, err := strconv.ParseInt(c.Param("value"), 10, 64)
		if err != nil {
			return fmt.Errorf("verification request not found")
		}
		if err = service.ConfirmContactVerification(c.Request.Context(), pool, cfg, userID, verificationID, inputString(input, "code")); err != nil {
			return err
		}
		if token, ok := c.Get("token"); ok && cacheClient != nil {
			_ = cacheClient.DeleteSession(c.Request.Context(), fmt.Sprint(token))
		}
		return replaceBody(c, map[string]interface{}{"status": "confirmed", "confirmed_at": time.Now().UTC().Format(time.RFC3339Nano)})
	}
}

func inputString(input map[string]interface{}, key string) string {
	value, ok := input[key]
	if !ok || value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func userID(c *gin.Context) (int64, bool) {
	v, ok := c.Get("user_id")
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int64:
		return n, n > 0
	case int:
		return int64(n), n > 0
	}
	return 0, false
}

func body(c *gin.Context) (map[string]interface{}, error) {
	var input map[string]interface{}
	if err := json.NewDecoder(c.Request.Body).Decode(&input); err != nil {
		return nil, err
	}
	return input, nil
}

func replaceBody(c *gin.Context, input map[string]interface{}) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(raw))
	c.Request.ContentLength = int64(len(raw))
	return nil
}
