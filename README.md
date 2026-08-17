# auth-service

A lightweight authentication and authorization microservice built with Go and Gin. Supports JWT session tokens, email/phone 2FA, API key management, rate limiting, and RabbitMQ-based notification delivery.

## Features

- Registration and login via email or phone
- Two-factor authentication (2FA) with verification codes
- JWT session tokens with configurable TTL
- API key management (admin/system roles)
- Redis-backed rate limiting and session cache
- PostgreSQL for persistent storage with auto-migrations
- Versioned `message.delivery.requested` events for the separate message-delivery service
- API-driven contact verification and account-security modules powered by request-generator
- Swagger/OpenAPI documentation

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Service health check |
| POST | `/auth/register` | — | Register a new user |
| POST | `/auth/login` | — | Login with email/phone + password |
| POST | `/auth/logout` | Bearer | Logout and invalidate token |
| PUT | `/auth/contact_verifications` | Bearer | Request verification for an additional email or phone |
| POST | `/auth/contact_verifications/id/{id}` | Bearer | Confirm a contact-verification code |
| GET | `/auth/account_security/view/id/{current_user_id}` | Bearer | API-driven Account & Security settings projection |
| POST | `/auth/login/verify-2fa` | — | Complete 2FA login |
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
