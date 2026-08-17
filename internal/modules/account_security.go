package modules

import (
	"database/sql"

	"github.com/darkrain/auth-service/internal/config"
	module "github.com/darkrain/request-generator"
	"github.com/darkrain/request-generator/actions"
	"github.com/darkrain/request-generator/fields"
	"github.com/darkrain/request-generator/renderer"
	"github.com/gin-gonic/gin"
	pg "github.com/go-jet/jet/v2/postgres"
)

type accountSecurityTable struct {
	pg.Table
	ID                                                                   pg.ColumnInteger
	Email, Phone, Password, Role, VerifyStatus, TwoFactorSecretEncrypted pg.ColumnString
	EmailVerified, PhoneVerified, TwoFactorEnabled                       pg.ColumnBool
	PasswordUpdatedAt, TwoFactorConfirmedAt, DeactivatedAt               pg.ColumnTimestampz
}

func accountSecurityUsers() accountSecurityTable {
	t := accountSecurityTable{
		ID: pg.IntegerColumn("id"), Email: pg.StringColumn("email"), Phone: pg.StringColumn("phone"), Password: pg.StringColumn("password"),
		Role: pg.StringColumn("role"), VerifyStatus: pg.StringColumn("verify_status"), TwoFactorSecretEncrypted: pg.StringColumn("two_factor_secret_encrypted"),
		EmailVerified: pg.BoolColumn("email_verified"), PhoneVerified: pg.BoolColumn("phone_verified"), TwoFactorEnabled: pg.BoolColumn("two_factor_enabled"),
		PasswordUpdatedAt: pg.TimestampzColumn("password_updated_at"), TwoFactorConfirmedAt: pg.TimestampzColumn("two_factor_confirmed_at"), DeactivatedAt: pg.TimestampzColumn("deactivated_at"),
	}
	t.Table = pg.NewTable("public", "users", "", t.ID, t.Email, t.Phone, t.Password, t.Role, t.VerifyStatus, t.TwoFactorSecretEncrypted, t.EmailVerified, t.PhoneVerified, t.TwoFactorEnabled, t.PasswordUpdatedAt, t.TwoFactorConfirmedAt, t.DeactivatedAt)
	return t
}

// AccountSecurityModule is a read-only account projection for settings. The
// write flow is the standard contact_verifications add/update module.
func AccountSecurityModule(_ *sql.DB, cfg *config.Config) *module.BaseModule {
	t := accountSecurityUsers()
	permissions := authenticatedRoles(cfg)
	return &module.BaseModule{Name: "account_security", Label: "account_security.label", Table: t, PrimaryKey: t.ID, Path: "/auth", Fields: []fields.ModuleField{
		{Column: t.ID, Title: "account_security.fields.id", Type: fields.ModuleFieldTypeInt, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.Email, Title: "account_security.fields.email", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.EmailVerified, Title: "account_security.fields.email_verified", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Options: verificationOptions(), Presentation: verificationBadge()},
		{Column: t.Phone, Title: "account_security.fields.phone", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.PhoneVerified, Title: "account_security.fields.phone_verified", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Options: verificationOptions(), Presentation: verificationBadge()},
		{Column: t.Role, Title: "account_security.fields.role", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView},
		{Column: t.TwoFactorEnabled, Title: "account_security.fields.two_factor_enabled", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Options: verificationOptions(), Presentation: verificationBadge()},
		{Column: t.PasswordUpdatedAt, Title: "account_security.fields.password_updated_at", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Presentation: &renderer.FieldPresentation{Style: "date"}},
		{Column: t.VerifyStatus, Title: "account_security.fields.verify_status", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Presentation: &renderer.FieldPresentation{Renderer: renderer.RendererBadge}},
	}, Actions: []actions.ModuleAction{
		actions.ViewModuleAction{Label: "account_security.actions.view", Columns: []pg.Column{t.ID, t.Email, t.EmailVerified, t.Phone, t.PhoneVerified, t.TwoFactorEnabled, t.PasswordUpdatedAt, t.Role, t.VerifyStatus}, Permission: permissions, Auth: true, By: []pg.Column{t.ID}, PageType: renderer.PageTypeForm},
	}, RoleWhere: []actions.RoleWhere{{Role: actions.RoleAll, Where: ownedUser(t)}}, Render: renderer.Universal{Form: &renderer.FormPage{
		ID: "account-security", Title: "account_security.label", Subtitle: "account_security.subtitle", Layout: renderer.LayoutOneColumn,
		Fields: []string{"email", "email_verified", "phone", "phone_verified", "two_factor_enabled", "password_updated_at"},
		Sections: []renderer.FormSection{{
			ID: "contacts", Title: "account_security.contacts.title", Subtitle: "account_security.contacts.subtitle", Renderer: renderer.RendererUniversalSection,
			Columns: renderer.FieldMatrixColumnsTwo, Fields: []string{"email", "email_verified", "phone", "phone_verified"},
		}},
		Actions: []renderer.Action{
			contactAction("email", "mail", "account_security.contacts.email.action"),
			contactAction("phone", "phone", "account_security.contacts.phone.action"),
			accountAction("change_password", "lock", "account_security.password.action", "account.password", map[string]interface{}{"request": map[string]interface{}{"method": "POST", "endpoint": "/auth/account_password/id/{id}"}}),
			accountAction("manage_two_factor", "shield", "account_security.two_factor.action", "account.two_factor", map[string]interface{}{"request": map[string]interface{}{"method": "POST", "endpoint": "/auth/account_two_factor/id/{id}"}, "issuer": cfg.TwoFactorIssuer, "available": cfg.TwoFactorEnabled}),
			accountAction("manage_sessions", "user", "account_security.sessions.action", "account.sessions", map[string]interface{}{"list": map[string]interface{}{"method": "GET", "endpoint": "/auth/account_sessions"}, "delete": map[string]interface{}{"method": "DELETE", "endpoint": "/auth/account_sessions/delete/id/{id}"}}),
			accountAction("deactivate_account", "warning", "account_security.deactivate.action", "account.deactivate", map[string]interface{}{"request": map[string]interface{}{"method": "POST", "endpoint": "/auth/account_deactivation/id/{id}"}}),
		},
	}}}
}

func verificationBadge() *renderer.FieldPresentation {
	return &renderer.FieldPresentation{Renderer: renderer.RendererBadge, ToneByValue: []renderer.FieldValueTone{
		{Value: renderer.TypedValue{Type: renderer.TypedValueString, String: "true"}, Tone: "success"},
		{Value: renderer.TypedValue{Type: renderer.TypedValueString, String: "false"}, Tone: "warning"},
	}}
}

func verificationOptions() []fields.ModuleFieldOptions {
	return []fields.ModuleFieldOptions{{Value: true, Label: "account_security.status.verified"}, {Value: false, Label: "account_security.status.not_verified"}}
}

func contactAction(contactType, icon, label string) renderer.Action {
	return renderer.Action{
		ID: "manage_" + contactType, Type: renderer.ActionModal, Label: label,
		ActionPresentation: renderer.ActionPresentation{Icon: icon, Variant: renderer.ActionVariantSecondary, Appearance: renderer.ActionAppearanceOutline},
		Modal: &renderer.ModalAction{Renderer: renderer.RendererKey("account.contact_verification"), Title: label, Data: map[string]interface{}{
			"contact_type": contactType,
			"request":      map[string]interface{}{"method": "PUT", "endpoint": "/auth/contact_verifications"},
			"confirm":      map[string]interface{}{"method": "POST", "endpoint": "/auth/contact_verifications/id/{verification_id}"},
		}},
	}
}

func accountAction(id, icon, label, modalRenderer string, data map[string]interface{}) renderer.Action {
	return renderer.Action{
		ID: id, Type: renderer.ActionModal, Label: label,
		ActionPresentation: renderer.ActionPresentation{Icon: icon, Variant: renderer.ActionVariantSecondary, Appearance: renderer.ActionAppearanceOutline},
		Modal:              &renderer.ModalAction{Renderer: renderer.RendererKey(modalRenderer), Title: label, Data: data},
	}
}

func ownedUser(t accountSecurityTable) func(*gin.Context) pg.BoolExpression {
	return func(c *gin.Context) pg.BoolExpression {
		id, ok := userID(c)
		if !ok {
			return t.ID.EQ(pg.Int(-1))
		}
		return t.ID.EQ(pg.Int64(id))
	}
}
