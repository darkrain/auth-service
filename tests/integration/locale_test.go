package integration

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"testing"

	"github.com/darkrain/auth-service/internal/broker"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/delivery"
	"golang.org/x/crypto/bcrypt"
)

// eventRecorder keeps the delivery events the routes publish, built exactly as
// the broker publisher builds them.
type eventRecorder struct{ events []*delivery.RequestEvent }

func (r *eventRecorder) PublishCode(_ context.Context, request delivery.CodeRequest) error {
	event, err := delivery.NewCodeEvent(testCfg, request)
	if err == nil {
		r.events = append(r.events, event)
	}
	return err
}

func (r *eventRecorder) PublishNotice(_ context.Context, request delivery.NoticeRequest) error {
	event, err := delivery.NewNoticeEvent(testCfg, request)
	if err == nil {
		r.events = append(r.events, event)
	}
	return err
}

func recordDeliveryEvents(t *testing.T) *eventRecorder {
	t.Helper()
	recorder := new(eventRecorder)
	previous := delivery.NewEventPublisher
	delivery.NewEventPublisher = func(broker.ChannelProvider, *config.Config) delivery.Publisher { return recorder }
	t.Cleanup(func() { delivery.NewEventPublisher = previous })
	return recorder
}

// expectLocale checks metadata.locale of the newest event of template:
// want "" means the key must be absent, so message-delivery's default applies.
func (r *eventRecorder) expectLocale(t *testing.T, template, want string) {
	t.Helper()
	for i := len(r.events) - 1; i >= 0; i-- {
		if r.events[i].Template != template {
			continue
		}
		got, present := r.events[i].Metadata["locale"]
		if got != want || present != (want != "") {
			t.Fatalf("%s event: metadata %v, want locale %q", template, r.events[i].Metadata, want)
		}
		return
	}
	t.Fatalf("no %s event was published", template)
}

func lang(value string) map[string]string { return map[string]string{"Accept-Language": value} }

// langQuery is the "?lang=" query the webapp adds to every auth request, or ""
// without a language.
func langQuery(value string) string {
	if value == "" {
		return ""
	}
	return "?lang=" + url.QueryEscape(value)
}

func TestRegistrationCodeLocale(t *testing.T) {
	truncateTables(t)
	recorder := recordDeliveryEvents(t)
	previous := testCfg.CodeDelivery.Locales
	testCfg.CodeDelivery.Locales = []string{"en", "ru", "zh"}
	t.Cleanup(func() { testCfg.CodeDelivery.Locales = previous })

	for i, tc := range []struct {
		name    string
		headers map[string]string
		query   string
		body    string
		want    string
	}{
		{name: "browser header", headers: lang("ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7"), want: "ru"},
		{name: "query lang beats header", headers: lang("en-US,en;q=0.9"), query: "ru", want: "ru"},
		{name: "body beats query lang", headers: lang("en"), query: "ru", body: "zh", want: "zh"},
		{name: "query lang without header", query: "en", want: "en"},
		{name: "unsupported query lang falls back to header", headers: lang("ru-RU"), query: "fr", want: "ru"},
		{name: "invalid query lang falls back to header", headers: lang("zh"), query: "<b>", want: "zh"},
		{name: "q-values", headers: lang("en;q=0.2, zh-CN;q=0.9"), want: "zh"},
		{name: "body wins", headers: lang("ru"), body: "zh", want: "zh"},
		{name: "body without header", body: "en", want: "en"},
		{name: "unsupported language", headers: lang("fr-FR, de;q=0.5"), want: ""},
		{name: "no language", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder.events = nil
			request := map[string]interface{}{
				"login": "locale-" + strconv.Itoa(i) + "@example.com", "password": "Password1", "device_uid": "locale-device-" + strconv.Itoa(i),
			}
			if tc.body != "" {
				request["locale"] = tc.body
			}
			w := doRequestWithHeaders("POST", "/auth/register"+langQuery(tc.query), request, "", tc.headers)
			if w.Code != http.StatusCreated {
				t.Fatalf("register: expected 201, got %d: %s", w.Code, w.Body.String())
			}
			recorder.expectLocale(t, delivery.TemplateAuthVerificationCode, tc.want)
		})
	}
}

func TestRegistrationContactChangeCodeLocale(t *testing.T) {
	truncateTables(t)
	recorder := recordDeliveryEvents(t)

	registration := doRequestWithHeaders("POST", "/auth/register", map[string]interface{}{
		"login": "locale-typo@example.com", "password": "Password1", "device_uid": "locale-change",
	}, "", lang("en"))
	if registration.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", registration.Code, registration.Body.String())
	}
	registrationToken, _ := parseJSON(registration)["registration_token"].(string)

	changed := doRequestWithHeaders("PUT", "/auth/registration/contact", map[string]interface{}{
		"login": "locale-fixed@example.com", "device_uid": "locale-change", "allow_fallback": true,
	}, registrationToken, lang("zh-Hans-CN"))
	if changed.Code != http.StatusOK {
		t.Fatalf("change contact: expected 200, got %d: %s", changed.Code, changed.Body.String())
	}
	recorder.expectLocale(t, delivery.TemplateAuthVerificationCode, "zh")
	if last := recorder.events[len(recorder.events)-1]; last.Recipient != "locale-fixed@example.com" {
		t.Fatalf("code must go to the new contact, got %q", last.Recipient)
	}

	// The webapp's ?lang= wins over the browser's Accept-Language.
	recorder.events = nil
	changed = doRequestWithHeaders("PUT", "/auth/registration/contact"+langQuery("ru"), map[string]interface{}{
		"login": "locale-final@example.com", "device_uid": "locale-change", "allow_fallback": true,
	}, registrationToken, lang("en-US,en;q=0.9"))
	if changed.Code != http.StatusOK {
		t.Fatalf("change contact with lang: expected 200, got %d: %s", changed.Code, changed.Body.String())
	}
	recorder.expectLocale(t, delivery.TemplateAuthVerificationCode, "ru")
}

func TestContactVerificationAndNoticeLocale(t *testing.T) {
	truncateTables(t)
	recorder := recordDeliveryEvents(t)

	const login, password, device = "locale-owner@example.com", "Password1", "locale-contact"
	registrationToken := registerUser(t, login, password)
	verifyUser(t, login, device, registrationToken)
	token := loginUser(t, login, password)

	requested := doRequestWithHeaders("PUT", "/auth/contact_verifications"+langQuery("zh"), map[string]interface{}{
		"contact_type": "email", "recipient": "locale-new@example.com", "device_uid": device, "current_password": password,
	}, token, lang("en-US,en;q=0.9"))
	if requested.Code != http.StatusOK {
		t.Fatalf("request contact verification: expected 200, got %d: %s", requested.Code, requested.Body.String())
	}
	recorder.expectLocale(t, delivery.TemplateAuthVerificationCode, "zh")

	verificationID, _ := parseJSON(requested)["value"].(float64)
	hash, err := bcrypt.GenerateFromPassword([]byte("123456"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.ExecContext(context.Background(), `UPDATE contact_verifications SET code_hash=$1 WHERE id=$2`, string(hash), int64(verificationID)); err != nil {
		t.Fatal(err)
	}
	// The body's locale wins over both ?lang= and Accept-Language.
	confirmed := doRequestWithHeaders("POST", "/auth/contact_verifications/id/"+numberPath(verificationID)+langQuery("zh"), map[string]string{"code": "123456", "locale": "ru"}, token, lang("en"))
	if confirmed.Code != http.StatusOK {
		t.Fatalf("confirm contact: expected 200, got %d: %s", confirmed.Code, confirmed.Body.String())
	}
	recorder.expectLocale(t, delivery.TemplateAuthContactChanged, "ru")
}

func TestPasswordResetCodeLocale(t *testing.T) {
	truncateTables(t)
	recorder := recordDeliveryEvents(t)

	const login, password, device = "locale-reset@example.com", "Password1", "locale-reset"
	registrationToken := registerUser(t, login, password)
	verifyUser(t, login, device, registrationToken)

	for _, tc := range []struct {
		name    string
		headers map[string]string
		query   string
		body    map[string]string
		want    string
	}{
		{name: "header", headers: lang("ru-RU"), body: map[string]string{"login": login, "device_uid": device}, want: "ru"},
		{name: "query lang beats header", headers: lang("en-US,en;q=0.9"), query: "ru", body: map[string]string{"login": login, "device_uid": device}, want: "ru"},
		{name: "body beats query lang", headers: lang("en"), query: "ru", body: map[string]string{"login": login, "device_uid": device, "locale": "zh"}, want: "zh"},
		{name: "invalid query lang falls back to header", headers: lang("en"), query: "1x", body: map[string]string{"login": login, "device_uid": device}, want: "en"},
		{name: "body wins", headers: lang("ru"), body: map[string]string{"login": login, "device_uid": device, "locale": "zh"}, want: "zh"},
		{name: "no language", body: map[string]string{"login": login, "device_uid": device}, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder.events = nil
			w := doRequestWithHeaders("POST", "/auth/password/reset-request"+langQuery(tc.query), tc.body, "", tc.headers)
			if w.Code != http.StatusOK {
				t.Fatalf("reset request: expected 200, got %d: %s", w.Code, w.Body.String())
			}
			recorder.expectLocale(t, delivery.TemplateAuthPasswordReset, tc.want)
		})
	}
}

// The webapp resends a registration code through PUT /auth/contact_verifications
// with the registration token and its ?lang=.
func TestRegistrationCodeResendLocale(t *testing.T) {
	truncateTables(t)
	recorder := recordDeliveryEvents(t)

	const login = "locale-resend@example.com"
	registration := doRequestWithHeaders("POST", "/auth/register"+langQuery("ru"), map[string]interface{}{
		"login": login, "password": "Password1", "device_uid": "locale-resend",
	}, "", lang("en-US,en;q=0.9"))
	if registration.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", registration.Code, registration.Body.String())
	}
	recorder.expectLocale(t, delivery.TemplateAuthVerificationCode, "ru")
	registered := parseJSON(registration)
	registrationToken, _ := registered["registration_token"].(string)
	initialID, _ := registered["verification_id"].(float64)
	if _, err := testPool.ExecContext(context.Background(), `UPDATE contact_verifications SET sent_ts=NOW() - INTERVAL '61 seconds' WHERE id=$1`, int64(initialID)); err != nil {
		t.Fatal(err)
	}

	recorder.events = nil
	resent := doRequestWithHeaders("PUT", "/auth/contact_verifications"+langQuery("en"), map[string]interface{}{
		"contact_type": "email", "recipient": login, "device_uid": "locale-resend", "allow_fallback": true,
	}, registrationToken, lang("ru-RU,ru;q=0.9"))
	if resent.Code != http.StatusOK {
		t.Fatalf("resend: expected 200, got %d: %s", resent.Code, resent.Body.String())
	}
	recorder.expectLocale(t, delivery.TemplateAuthVerificationCode, "en")
}
