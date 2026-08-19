# auth-service

A lightweight authentication and authorization microservice built with Go and Gin. Supports opaque session tokens, email/phone verification, TOTP two-factor authentication, API key management, rate limiting, and RabbitMQ-based notification delivery.

## Features

- Registration and login via email or phone
- TOTP two-factor authentication with authenticator applications
- Opaque session tokens with configurable TTL
- API key management (admin/system roles)
- Redis-backed rate limiting and session cache
- PostgreSQL for persistent storage with auto-migrations
- Versioned `message.delivery.requested` events for the separate message-delivery service
- API-driven contact verification and account-security modules powered by request-generator
- Password change, active-session revocation, and account deactivation controls
- Swagger/OpenAPI documentation

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Service health check |
| POST | `/auth/register` | — | Register a new user |
| PUT | `/auth/registration/contact` | Registration Bearer | Change the contact of an unfinished registration and send a new code |
| POST | `/auth/login` | — | Login with email/phone + password |
| POST | `/auth/logout` | Bearer | Logout and invalidate token |
| PUT | `/auth/contact_verifications` | Bearer | Request verification for an additional email or phone |
| POST | `/auth/contact_verifications/id/{id}` | Bearer | Confirm a contact-verification code |
| GET | `/auth/account_security/view/id/{current_user_id}` | Bearer | API-driven Account & Security settings projection |
| POST | `/auth/login/verify-2fa` | — | Complete 2FA login |
| POST | `/auth/account_password/id/{current_user_id}` | Bearer | Change password and revoke other sessions |
| POST | `/auth/account_two_factor/id/{current_user_id}` | Bearer | Enable or disable TOTP two-factor authentication |
| GET | `/auth/account_sessions` | Bearer | List active sessions without exposing tokens |
| DELETE | `/auth/account_sessions/delete/id/{session_id}` | Bearer | Revoke one active session |
| POST | `/auth/account_deactivation/id/{current_user_id}` | Bearer | Deactivate the account and revoke all sessions |
| GET | `/auth/me` | Bearer | Get current user info |
| POST | `/auth/api-keys` | Bearer + admin/system | Create API key |
| GET | `/auth/api-keys` | Bearer + admin/system | List API keys |
| DELETE | `/auth/api-keys/:id` | Bearer + admin/system | Revoke API key |
| GET | `/swagger/*` | — | Swagger UI |

## Getting Started

### Prerequisites

- Go 1.22+
- PostgreSQL 15+
- Redis 7+
- RabbitMQ (optional, for email/SMS notifications)

### Configuration

Copy the example config and edit it:

```bash
cp auth-service.example.json auth-service.json
# Edit auth-service.json with your settings
```

`MessageBroker` defines the event transport. `PublishMode` is `required`,
`best_effort`, or `disabled`. The latter is appropriate for isolated tests.
`CodeDelivery` defines the permitted providers and default delivery chain:
email uses its default provider; a phone falls through `telegram`, `whatsapp`,
then `sms` unless the caller explicitly selects a permitted provider.

To enable TOTP two-factor authentication, set `TwoFactorEnabled` and supply a
stable base64-encoded 32-byte encryption key. The key encrypts TOTP secrets at
rest and must be backed up with the database: changing it makes existing 2FA
secrets unreadable.

```json
{
  "TwoFactorEnabled": true,
  "TwoFactorIssuer": "Example Application",
  "TwoFactorEncryptionKey": "<base64-encoded-32-byte-key>"
}
```

Generate a new key only for a new environment:

```bash
openssl rand -base64 32
```

The service does not deliver email, Telegram, WhatsApp, or SMS itself. It only
creates and validates the code, then publishes this stable payload to RabbitMQ:

```json
{
  "version": "v1",
  "type": "message.delivery.requested",
  "template": "auth_verification_code",
  "recipient_type": "phone",
  "recipient": "+79991234567",
  "variables": { "code": "123456", "ttl_sec": "300" },
  "delivery": { "provider_chain": ["telegram", "whatsapp", "sms"], "allow_fallback": true }
}
```

## Registration And Contact Verification

Registration always creates an unverified account and returns a short-lived
`registration_token` plus the ID of the verification record. The token is only
accepted by the confirmation action for that record; it cannot read account
data or use other protected endpoints.

```json
POST /auth/register

{
  "login": "model@example.com",
  "password": "Password1!",
  "role": "model",
  "device_uid": "web-device-123",
  "allow_fallback": true
}
```

```json
{
  "registration_token": "short-lived-registration-token",
  "verification_id": 42,
  "expires_in": 1800
}
```

Confirm that record through the standard generator update action:

```json
POST /auth/contact_verifications/id/42
Authorization: Bearer <registration_token>

{ "code": "123456" }
```

Before confirmation, a user may correct the contact without creating another
account. The operation keeps the same user, password, role and registration
session, replaces the login, expires every older registration code and sends a
new code:

```json
PUT /auth/registration/contact
Authorization: Bearer <registration_token>

{
  "login": "corrected@example.com",
  "device_uid": "web-device-123",
  "allow_fallback": true
}
```

The response contains the new `verification_id`. Expired unfinished
registrations are removed by the hourly auth cleanup after their registration
token TTL; this releases mistyped email addresses and phone numbers.

For an authenticated account, the same module adds a missing second sign-in
contact. The authenticated user ID comes from `GET /auth/me`; the account
security view exposes the localized modal action metadata used by a client.

```json
PUT /auth/contact_verifications
Authorization: Bearer <session-token>

{
  "contact_type": "phone",
  "recipient": "+79991234567",
  "device_uid": "web-device-123",
  "provider": "telegram",
  "allow_fallback": true
}
```

The response returns the new verification ID. Confirm it with the same `POST
/auth/contact_verifications/id/{id}` action. Only a bcrypt hash is stored in
PostgreSQL; the plaintext code exists only while the delivery event is being
published. `CodeDelivery` validates a user-selected provider and its fallback
chain before the request is created.

## Account Security

`GET /auth/account_security/view/id/{current_user_id}` returns the localized
settings projection and the action metadata. A client renders it with its
existing component kit; the service does not prescribe HTML or CSS. The
projection includes existing contacts, password information, TOTP state, and
the available sessions/deactivation actions.

### Password and sessions

Change a password through the generator-backed action. The current password is
always required; accounts with TOTP enabled also require a current TOTP code.
Every session except the caller's is revoked after a successful change.

```json
POST /auth/account_password/id/42
Authorization: Bearer <session-token>

{
  "current_password": "CurrentPassword1",
  "new_password": "NewPassword2",
  "confirmation": "NewPassword2",
  "two_factor_code": "123456"
}
```

`GET /auth/account_sessions` returns device ID, IP address, sign-in method,
last activity, and expiry. It never returns a token. A user may revoke an
individual non-current session with `DELETE
/auth/account_sessions/delete/id/{session_id}`.

### TOTP two-factor authentication

The client generates a random base32 secret with browser cryptography, shows
the user its standard `otpauth://` QR code, and submits the secret and first
six-digit code to the standard update action. The first code proves the secret
was scanned before it is encrypted and stored.

```json
POST /auth/account_two_factor/id/42
Authorization: Bearer <session-token>

{
  "two_factor_enabled": true,
  "two_factor_secret": "BASE32SECRET",
  "two_factor_code": "123456"
}
```

On sign-in, a valid password for an account with enabled TOTP returns `202`
with a single-use, five-minute `challenge_token`. It is bound to the requesting
device and IP address. The client must then submit the authenticator code:

```json
POST /auth/login/verify-2fa

{
  "challenge_token": "<challenge-token>",
  "device_uid": "web-device-123",
  "code": "123456"
}
```

A code by itself cannot create a session. Failed challenge attempts are rate
limited by `RateLimit.Code.MaxAttempts`.

### Deactivation

Account deactivation requires the current password, `DEACTIVATE` confirmation,
and a TOTP code when enabled. It marks the account as `deactivated`, blocks all
sessions immediately, and prevents subsequent sign-in. Restoring access is an
explicit support operation; there is no self-service reactivation endpoint.

### Run locally

```bash
make run
```

This uses `auth-service.example.json` as the config by default.

To use a custom config:

```bash
go run ./cmd/main.go --config /path/to/config.json
```

## Testing

### Integration Tests

Start test dependencies (PostgreSQL + Redis):

```bash
docker compose -f docker-compose.test.yml up -d
```

The test compose file intentionally exposes its Redis instance on `6381` so
it cannot flush or reuse a local development/staging Redis on the usual
`6380` port. `auth-service.test.json` already uses that isolated port.

Run integration tests:

```bash
go test -v -race -timeout 120s ./tests/integration/...
```

Or use the Makefile:

```bash
make test
```

## Building

### Binary

Build a Linux amd64 binary:

```bash
make build
```

Output: `bin/auth-service`

### Debian Package

Build a `.deb` package (requires `dpkg-deb`):

```bash
make deb
```

Output: `bin/auth-service_<version>_amd64.deb`

## Swagger UI

After starting the service, open:

```
http://localhost:8080/swagger/index.html
```

To regenerate the docs after making changes to handlers:

```bash
make swagger
```

## CI/CD

### GitHub Actions

- **CI** (`.github/workflows/ci.yml`): runs on every push/PR to `main`
  - `lint`: golangci-lint
  - `security`: gosec + govulncheck
  - `test`: integration tests with postgres:15 + redis:7

- **Release** (`.github/workflows/release.yml`): triggered by `v*` tags
  - Builds binary and `.deb` package
  - Creates a GitHub Release with artifacts

### Dependabot

Weekly Go module updates are configured via `.github/dependabot.yml`.

## Project Structure

```
.
├── cmd/                   # Entry point (main.go)
├── internal/
│   ├── broker/            # RabbitMQ connection
│   ├── cache/             # Redis cache client
│   ├── config/            # Config loading
│   ├── db/                # PostgreSQL connection + migrations + seed

│   ├── delivery/          # Message-delivery event contract and AMQP publisher
│   ├── handler/           # HTTP handlers (Gin)
│   ├── middleware/         # Auth, rate limit, role middleware
│   ├── modules/           # request-generator modules
│   └── service/           # Business logic
├── migrations/            # SQL migration files
├── tests/
│   └── integration/       # Integration tests
├── docs/                  # Generated Swagger docs
├── Makefile
├── docker-compose.test.yml
└── auth-service.example.json
```

## License

MIT
