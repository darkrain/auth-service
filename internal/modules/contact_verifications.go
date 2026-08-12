package modules

import (
	"bytes"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"strconv"
	"strings"
	"time"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"github.com/darkrain/auth-service/internal/validator"
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
	ID                                                        pg.ColumnInteger
	CreationDate, UpdateDate                                  pg.ColumnTimestampz
	UserID                                                    pg.ColumnInteger
	ContactType, Recipient, DeviceUID, Provider, Status, Code pg.ColumnString
	AllowFallback                                             pg.ColumnBool
	Counter                                                   pg.ColumnInteger
	SentTS, ExpiresAt, ConfirmedAt                            pg.ColumnTimestampz
}

func contactTable() contactVerificationsTable {
	t := contactVerificationsTable{ID: pg.IntegerColumn("id"), CreationDate: pg.TimestampzColumn("creation_date"), UpdateDate: pg.TimestampzColumn("update_date"), UserID: pg.IntegerColumn("user_id"), ContactType: pg.StringColumn("contact_type"), Recipient: pg.StringColumn("recipient"), DeviceUID: pg.StringColumn("device_uid"), Provider: pg.StringColumn("provider"), AllowFallback: pg.BoolColumn("allow_fallback"), Status: pg.StringColumn("status"), Code: pg.StringColumn("code"), Counter: pg.IntegerColumn("counter"), SentTS: pg.TimestampzColumn("sent_ts"), ExpiresAt: pg.TimestampzColumn("expires_at"), ConfirmedAt: pg.TimestampzColumn("confirmed_at")}
	t.Table = pg.NewTable("public", "contact_verifications", "", t.ID, t.CreationDate, t.UpdateDate, t.UserID, t.ContactType, t.Recipient, t.DeviceUID, t.Provider, t.AllowFallback, t.Status, t.Code, t.Counter, t.SentTS, t.ExpiresAt, t.ConfirmedAt)
	return t
}

func ContactVerificationsModule(pool *sql.DB, conn *amqp.Connection, cfg *config.Config) *module.BaseModule {
	t := contactTable()
	read := []pg.Column{t.ID, t.CreationDate, t.UpdateDate, t.ContactType, t.Recipient, t.Provider, t.AllowFallback, t.Status, t.Counter, t.SentTS, t.ExpiresAt, t.ConfirmedAt}
	return &module.BaseModule{Name: "contact_verifications", Label: "contact_verifications.label", Table: t, PrimaryKey: t.ID, Path: "/auth", Fields: []fields.ModuleField{
		{Column: t.ID, Title: "contact_verifications.fields.id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.ContactType, Title: "contact_verifications.fields.contact_type", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeSelect, Options: []fields.ModuleFieldOptions{{Value: "email", Label: "contact_verifications.options.email"}, {Value: "phone", Label: "contact_verifications.options.phone"}}, Check: []fields.CheckRules{fields.RequiredRule(t.ContactType, []fields.Scenario{fields.ScenarioAdd})}},
		{Column: t.Recipient, Title: "contact_verifications.fields.recipient", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeText, Check: []fields.CheckRules{fields.RequiredRule(t.Recipient, []fields.Scenario{fields.ScenarioAdd})}},
		{Column: t.DeviceUID, Title: "contact_verifications.fields.device_uid", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeText, Check: []fields.CheckRules{fields.RequiredRule(t.DeviceUID, []fields.Scenario{fields.ScenarioAdd})}},
		{Column: t.Provider, Title: "contact_verifications.fields.provider", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeText},
		{Column: t.AllowFallback, Title: "contact_verifications.fields.allow_fallback", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeCheckBox},
		{Column: t.Status, Title: "contact_verifications.fields.status", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Presentation: &renderer.FieldPresentation{Renderer: renderer.RendererBadge}},
		{Column: t.Code, Title: "contact_verifications.fields.code", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeText},
		{Column: t.CreationDate, Title: "contact_verifications.fields.creation_date", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.ExpiresAt, Title: "contact_verifications.fields.expires_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
	}, Actions: []actions.ModuleAction{
		actions.ListModuleAction{Label: "contact_verifications.actions.list", Columns: read, Permission: []actions.Role{actions.RoleAll}, Auth: true, Where: owned(t), Filter: []pg.Column{t.ContactType, t.Status}, Sort: []pg.Column{t.CreationDate, t.ExpiresAt}, SortDefault: t.CreationDate, SortDefaultDirection: actions.SortDESC, Size: 20, Maxsize: 100},
		actions.ViewModuleAction{Label: "contact_verifications.actions.view", Columns: read, Permission: []actions.Role{actions.RoleAll}, Auth: true, By: []pg.Column{t.ID}},
		actions.AddModuleAction{Label: "contact_verifications.actions.add", Columns: []pg.Column{t.UserID, t.ContactType, t.Recipient, t.DeviceUID, t.Provider, t.AllowFallback, t.Status, t.Code, t.Counter, t.SentTS, t.ExpiresAt}, Permission: []actions.Role{actions.RoleAll}, Auth: true, BeforeAction: requestContactVerification(pool, conn, cfg)},
		actions.UpdateModuleAction{Label: "contact_verifications.actions.update", Columns: []pg.Column{t.Status, t.ConfirmedAt}, Permission: []actions.Role{actions.RoleAll}, Auth: true, By: []pg.Column{t.ID}, Where: owned(t), BeforeAction: confirmContactVerification(pool, cfg)},
	}, RoleWhere: []actions.RoleWhere{{Role: actions.RoleAll, Where: owned(t)}}, Defrec: actions.DefrecModuleAction{Label: "contact_verifications.actions.defrec"}, Render: renderer.Universal{
		List:   &renderer.ListPage{ID: "contact-verifications", Title: "contact_verifications.label", Filters: &renderer.Filters{Enabled: true, Primary: []string{"contact_type", "status"}}, Pagination: &renderer.Pagination{Mode: renderer.PaginationServer}},
		Form:   &renderer.FormPage{ID: "contact-verification-form", Title: "contact_verifications.label", Layout: renderer.LayoutOneColumn, Sections: []renderer.FormSection{{ID: "contact", Fields: []string{"contact_type", "recipient", "device_uid", "provider", "allow_fallback", "code"}, Block: &renderer.Block{Type: renderer.BlockPanel}}}},
		Record: &renderer.RecordPage{ID: "contact-verification", Sections: []renderer.RecordSection{{ID: "details", Renderer: renderer.RecordRendererDisplay, Components: []renderer.DisplayComponent{{ID: "fields", Type: renderer.DisplayDataList, Fields: []string{"contact_type", "recipient", "provider", "allow_fallback", "status", "expires_at"}}}}}},
	}}
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
		id, ok := userID(c)
		if !ok {
			return fmt.Errorf("authentication is required")
		}
		input, err := body(c)
		if err != nil {
			return err
		}
		kind, recipient := strings.TrimSpace(fmt.Sprint(input["contact_type"])), strings.TrimSpace(fmt.Sprint(input["recipient"]))
		device := strings.TrimSpace(fmt.Sprint(input["device_uid"]))
		provider := strings.TrimSpace(fmt.Sprint(input["provider"]))
		fallback, _ := input["allow_fallback"].(bool)
		if device == "" {
			return fmt.Errorf("device_uid is required")
		}
		if kind == "email" {
			if !validator.IsValidEmail(recipient) {
				return fmt.Errorf("invalid email")
			}
		} else if kind == "phone" {
			if !validator.IsValidPhone(recipient) {
				return fmt.Errorf("invalid phone")
			}
		} else {
			return fmt.Errorf("contact_type must be email or phone")
		}
		var exists bool
		query := "SELECT EXISTS(SELECT 1 FROM users WHERE email=$1 AND id<>$2)"
		if kind == "phone" {
			query = "SELECT EXISTS(SELECT 1 FROM users WHERE phone=$1 AND id<>$2)"
		}
		if err := pool.QueryRowContext(c.Request.Context(), query, recipient, id).Scan(&exists); err != nil || exists {
			return fmt.Errorf("contact is already in use")
		}
		n, err := rand.Int(rand.Reader, big.NewInt(1000000))
		if err != nil {
			return err
		}
		code := fmt.Sprintf("%06d", n.Int64())
		ttl := cfg.RateLimit.Code.TTLSec
		if ttl <= 0 {
			ttl = 300
		}
		rtype := delivery.RecipientTypeEmail
		if kind == "phone" {
			rtype = delivery.RecipientTypePhone
		}
		if err := delivery.NewPublisher(conn, cfg).PublishCode(c.Request.Context(), delivery.CodeRequest{Template: delivery.TemplateAuthVerificationCode, Purpose: delivery.PurposeVerification, RecipientType: rtype, Recipient: recipient, Code: code, TTLSec: ttl, UserID: id, DeviceUID: device, SelectedProvider: provider, AllowFallback: fallback}); err != nil {
			return err
		}
		input["user_id"], input["status"], input["code"], input["counter"], input["sent_ts"], input["expires_at"] = id, "pending", code, 0, time.Now().UTC().Format(time.RFC3339Nano), time.Now().UTC().Add(time.Duration(ttl)*time.Second).Format(time.RFC3339Nano)
		return replaceBody(c, input)
	}
}

func confirmContactVerification(pool *sql.DB, cfg *config.Config) func(*gin.Context) error {
	return func(c *gin.Context) error {
		id, ok := userID(c)
		if !ok {
			return fmt.Errorf("authentication is required")
		}
		input, err := body(c)
		if err != nil {
			return err
		}
		code := strings.TrimSpace(fmt.Sprint(input["code"]))
		recordID, err := strconv.ParseInt(c.Param("value"), 10, 64)
		if err != nil || code == "" {
			return fmt.Errorf("verification code is required")
		}
		var kind, recipient, stored, status string
		var expires time.Time
		err = pool.QueryRowContext(c.Request.Context(), "SELECT contact_type,recipient,code,status,expires_at FROM contact_verifications WHERE id=$1 AND user_id=$2", recordID, id).Scan(&kind, &recipient, &stored, &status, &expires)
		if err != nil || status != "pending" {
			return fmt.Errorf("verification request not found")
		}
		if time.Now().After(expires) {
			return fmt.Errorf("verification code has expired")
		}
		if code != stored {
			return fmt.Errorf("invalid verification code")
		}
		column := "email"
		verified := "email_verified"
		if kind == "phone" {
			column = "phone"
			verified = "phone_verified"
		}
		if _, err = pool.ExecContext(c.Request.Context(), fmt.Sprintf("UPDATE users SET %s=$1, %s=true, verify_status='verified', update_date=NOW() WHERE id=$2", column, verified), recipient, id); err != nil {
			return err
		}
		input = map[string]interface{}{"status": "confirmed", "confirmed_at": time.Now().UTC().Format(time.RFC3339Nano)}
		return replaceBody(c, input)
	}
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
	if err == nil {
		c.Request.Body = io.NopCloser(bytes.NewReader(raw))
		c.Request.ContentLength = int64(len(raw))
	}
	return err
}
