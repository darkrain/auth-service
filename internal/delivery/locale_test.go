package delivery

import (
	"strings"
	"testing"

	"github.com/darkrain/auth-service/internal/config"
)

func TestRequestLocale(t *testing.T) {
	supported := []string{"en", "ru", "zh"}
	for _, tc := range []struct {
		name, explicit, header string
		allowed                []string
		want                   string
	}{
		{name: "nothing", want: ""},
		{name: "plain header", header: "ru", want: "ru"},
		{name: "region subtag", header: "ru-RU", want: "ru"},
		{name: "underscore and case", header: "ZH_cn", want: "zh"},
		{name: "script subtag", header: "zh-Hans-CN", want: "zh"},
		{name: "first of equal weight", header: "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7", want: "ru"},
		{name: "q-values order", header: "en;q=0.3, zh;q=0.9, ru;q=0.5", want: "zh"},
		{name: "q=0 refuses", header: "ru;q=0, en", want: "en"},
		{name: "wildcard skipped", header: "*, ru;q=0.5", want: "ru"},
		{name: "invalid q dropped", header: "ru;q=abc, en;q=0.1", want: "en"},
		{name: "garbage header", header: "1234, @@, -x", want: ""},
		{name: "explicit wins", explicit: "zh", header: "ru", want: "zh"},
		{name: "explicit region", explicit: "en-GB", header: "ru", want: "en"},
		{name: "garbage explicit falls back", explicit: "<script>", header: "ru", want: "ru"},
		{name: "allowlist skips unsupported", header: "fr-FR, de;q=0.9, ru;q=0.8", allowed: supported, want: "ru"},
		{name: "allowlist rejects all", header: "fr, de", allowed: supported, want: ""},
		{name: "allowlist rejects explicit", explicit: "fr", header: "zh", allowed: supported, want: "zh"},
		{name: "allowlist case", header: "RU", allowed: []string{" Ru "}, want: "ru"},
		{name: "any tag without allowlist", header: "fr-CA", want: "fr"},
		{name: "too long tag", explicit: "ru-" + strings.Repeat("x", 40), want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := RequestLocale(tc.explicit, tc.header, tc.allowed); got != tc.want {
				t.Fatalf("RequestLocale(%q, %q, %v) = %q, want %q", tc.explicit, tc.header, tc.allowed, got, tc.want)
			}
		})
	}
}

func TestRequestLocaleBoundsHeader(t *testing.T) {
	header := strings.Repeat("xx-invalid1, ", maxAcceptLanguageEntries) + "ru"
	if got := RequestLocale("", header, []string{"ru"}); got != "" {
		t.Fatalf("entries past the limit must be ignored, got %q", got)
	}
}

func TestEventsCarryLocale(t *testing.T) {
	cfg := &config.Config{CodeDelivery: config.CodeDeliveryConfig{Email: config.CodeDeliveryEmailConfig{DefaultProvider: "email", AllowedProviders: []string{"email"}}}}
	for _, locale := range []string{"ru", ""} {
		code, err := NewCodeEvent(cfg, CodeRequest{RecipientType: RecipientTypeEmail, Recipient: "fixture@example.invalid", Locale: locale})
		if err != nil {
			t.Fatal(err)
		}
		notice, err := NewNoticeEvent(cfg, NoticeRequest{RecipientType: RecipientTypeEmail, Recipient: "fixture@example.invalid", Locale: locale})
		if err != nil {
			t.Fatal(err)
		}
		for name, event := range map[string]*RequestEvent{"code": code, "notice": notice} {
			got, present := event.Metadata["locale"]
			if got != locale || present != (locale != "") {
				t.Fatalf("%s event with locale %q has metadata %v", name, locale, event.Metadata)
			}
		}
	}
}
