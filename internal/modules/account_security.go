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
	ID                               pg.ColumnInteger
	Email, Phone, Role, VerifyStatus pg.ColumnString
	EmailVerified, PhoneVerified     pg.ColumnBool
}

func accountSecurityUsers() accountSecurityTable {
	t := accountSecurityTable{
		ID: pg.IntegerColumn("id"), Email: pg.StringColumn("email"), Phone: pg.StringColumn("phone"),
		Role: pg.StringColumn("role"), VerifyStatus: pg.StringColumn("verify_status"),
		EmailVerified: pg.BoolColumn("email_verified"), PhoneVerified: pg.BoolColumn("phone_verified"),
	}
	t.Table = pg.NewTable("public", "users", "", t.ID, t.Email, t.Phone, t.Role, t.VerifyStatus, t.EmailVerified, t.PhoneVerified)
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
		{Column: t.VerifyStatus, Title: "account_security.fields.verify_status", Type: fields.ModuleFieldTypeString, FormType: fields.ModuleFieldFormTypeOnlyView, Presentation: &renderer.FieldPresentation{Renderer: renderer.RendererBadge}},
	}, Actions: []actions.ModuleAction{
		actions.ViewModuleAction{Label: "account_security.actions.view", Columns: []pg.Column{t.ID, t.Email, t.EmailVerified, t.Phone, t.PhoneVerified, t.Role, t.VerifyStatus}, Permission: permissions, Auth: true, By: []pg.Column{t.ID}, PageType: renderer.PageTypeForm},
	}, RoleWhere: []actions.RoleWhere{{Role: actions.RoleAll, Where: func(c *gin.Context) pg.BoolExpression {
		id, ok := userID(c)
		if !ok {
			return t.ID.EQ(pg.Int(-1))
		}
		return t.ID.EQ(pg.Int64(id))
	}}}, Render: renderer.Universal{Form: &renderer.FormPage{
		ID: "account-security", Title: "account_security.label", Subtitle: "account_security.subtitle", Layout: renderer.LayoutOneColumn,
		Fields: []string{"email", "email_verified", "phone", "phone_verified"},
		Sections: []renderer.FormSection{{
			ID: "contacts", Title: "account_security.contacts.title", Subtitle: "account_security.contacts.subtitle", Renderer: renderer.RendererUniversalSection,
			Columns: renderer.FieldMatrixColumnsTwo, Fields: []string{"email", "email_verified", "phone", "phone_verified"},
		}},
		Actions: []renderer.Action{
			contactAction("email", "mail", "account_security.contacts.email.action"),
			contactAction("phone", "phone", "account_security.contacts.phone.action"),
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
