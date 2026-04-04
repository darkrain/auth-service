# auth-service

Authentication microservice with PostgreSQL, Redis, and RabbitMQ.

## Features

- User registration and login
- JWT session management
- Email/phone confirmation codes
- Rate limiting (IP, device, account)
- System user seed on startup
- DB migrations on startup

## Requirements

- Go 1.21+
- PostgreSQL 14+
- Redis 6+
- RabbitMQ 3.9+

## Configuration

Copy the example config and edit it:

```bash
cp auth-service.example.json config.json
```

Key fields:

| Field | Description |
|---|---|
| `Host` | HTTP listen address (empty = all interfaces) |
| `Port` | HTTP listen port (default: 8080) |
| `PasswordSalt` | Secret salt for password operations |
| `SystemUserEmail` | System user email (created on startup) |
| `SystemUserPassword` | System user password |
| `PostgreSql*` | PostgreSQL connection settings |
| `RedisDatabase*` | Redis connection settings |
| `Rmq*` | RabbitMQ connection settings |
| `RateLimit` | Rate limiting configuration |

## Running

```bash
# Development
make run

# Build Linux binary
make build

# Run binary
./bin/auth-service --config config.json
```

## Installation (Linux/systemd)

```bash
sudo make install
sudo systemctl enable --now auth-service
sudo nano /etc/auth-service/config.json
```

## Database Migrations

SQL files in `migrations/` are applied automatically on startup in alphabetical order. Applied migrations are tracked in the `schema_migrations` table.

## Build

```bash
make build
# Output: bin/auth-service
```

## Package (Debian/Ubuntu)

```bash
make deb
# Output: bin/auth-service_<version>_amd64.deb
```
