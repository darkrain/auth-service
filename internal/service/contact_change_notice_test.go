package service

import (
	"testing"

	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
)

// SEC-05 (theGHub1/docs#156): the previous e-mail is warned after a confirmed
// change, and only then.
func TestContactChangeNotice(t *testing.T) {
	notice, ok := ContactChangeNotice(7, &ContactChange{ContactType: "email", Recipient: "new.owner@example.com", PreviousRecipient: "owner@example.com", Purpose: delivery.PurposeVerification})
	if !ok {
		t.Fatal("changed e-mail must warn the previous address")
	}
	if notice.Recipient != "owner@example.com" || notice.Template != delivery.TemplateAuthContactChanged || notice.RecipientType != delivery.RecipientTypeEmail || notice.UserID != 7 {
		t.Fatalf("unexpected notice: %+v", notice)
	}
	if notice.Variables["new_contact"] != "ne***@example.com" {
		t.Fatalf("new contact must be masked, got %q", notice.Variables["new_contact"])
	}
	for name, change := range map[string]*ContactChange{
		"registration": {ContactType: "email", Recipient: "a@example.com", PreviousRecipient: "b@example.com", Purpose: delivery.PurposeRegistrationVerification},
		"first email":  {ContactType: "email", Recipient: "a@example.com", Purpose: delivery.PurposeVerification},
		"same email":   {ContactType: "email", Recipient: "A@example.com", PreviousRecipient: "a@example.com", Purpose: delivery.PurposeVerification},
		"phone":        {ContactType: "phone", Recipient: "+79990000001", PreviousRecipient: "+79990000002", Purpose: delivery.PurposeVerification},
		"nil":          nil,
	} {
		if _, ok := ContactChangeNotice(7, change); ok {
			t.Fatalf("%s: no notice expected", name)
		}
	}
	event, err := delivery.NewNoticeEvent(&config.Config{CodeDelivery: config.CodeDeliveryConfig{Email: config.CodeDeliveryEmailConfig{DefaultProvider: "email", AllowedProviders: []string{"email"}}}}, notice)
	if err != nil {
		t.Fatal(err)
	}
	if event.Variables["code"] != "" || event.Template != delivery.TemplateAuthContactChanged || event.Recipient != "owner@example.com" {
		t.Fatalf("unexpected notice event: %+v", event)
	}
}

func TestMaskContact(t *testing.T) {
	for in, want := range map[string]string{"john@example.com": "jo***@example.com", "j@example.com": "j***@example.com", "+79991234567": "+7999***67", "123": "***"} {
		if got := MaskContact(in); got != want {
			t.Fatalf("MaskContact(%q) = %q, want %q", in, got, want)
		}
	}
}
