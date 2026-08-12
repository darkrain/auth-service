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
- API-driven `contact_verifications` module powered by request-generator
- Swagger/OpenAPI documentation

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Service health check |
| POST | `/auth/register` | — | Register a new user |
| POST | `/auth/login` | — | Login with email/phone + password |
| POST | `/auth/logout` | Bearer | Logout and invalidate token |
| POST | `/auth/send-code` | Bearer | Send verification code to an existing contact |
| POST | `/auth/verify/email` | — | Verify email address |
| POST | `/auth/verify/phone` | — | Verify phone number |
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

To request a code with a selected delivery method, call the protected endpoint:

```json
POST /auth/send-code
Authorization: Bearer <session-token>

{
  "recipient": "+79991234567",
  "device_uid": "device-123",
  "provider": "telegram",
  "allow_fallback": false
}
```

Authenticated clients can also use generator routes under
`/auth/contact_verifications` to add and confirm an additional email address or
phone number. The module's `defrec`, `add`, `list`, `view`, and `update` actions
return the UniversalRenderer metadata and localized labels needed by an API-driven UI.

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
