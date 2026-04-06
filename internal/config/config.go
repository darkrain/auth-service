package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type RateLimitIP struct {
	LoginMaxAttempts    int `json:"LoginMaxAttempts"`
	LoginWindowSec      int `json:"LoginWindowSec"`
	RegisterMaxAttempts int `json:"RegisterMaxAttempts"`
	RegisterWindowSec   int `json:"RegisterWindowSec"`
}

type RateLimitDevice struct {
	LoginMaxAttempts    int `json:"LoginMaxAttempts"`
	LoginWindowSec      int `json:"LoginWindowSec"`
	SendCodeMaxAttempts int `json:"SendCodeMaxAttempts"`
	SendCodeWindowSec   int `json:"SendCodeWindowSec"`
	RegisterMaxAttempts int `json:"RegisterMaxAttempts"`
	RegisterWindowSec   int `json:"RegisterWindowSec"`
}

type RateLimitAccount struct {
	MaxFailedLogins int `json:"MaxFailedLogins"`
	LockDurationSec int `json:"LockDurationSec"`
}

type RateLimitCode struct {
	MaxAttempts int `json:"MaxAttempts"`
	TTLSec      int `json:"TTLSec"`
}

type RateLimit struct {
	IP      RateLimitIP      `json:"IP"`
	Device  RateLimitDevice  `json:"Device"`
	Account RateLimitAccount `json:"Account"`
	Code    RateLimitCode    `json:"Code"`
}

type Config struct {
	Host                  string    `json:"Host"`
	Port                  string    `json:"Port"`
	PasswordSalt          string    `json:"PasswordSalt"`
	PasswordMinLength     int       `json:"PasswordMinLength"`
	PasswordRequireDigits bool      `json:"PasswordRequireDigits"`
	PasswordRequireSpecial bool     `json:"PasswordRequireSpecial"`
	SystemUserEmail       string    `json:"SystemUserEmail"`
	SystemUserPassword    string    `json:"SystemUserPassword"`
	PostgreSqlHost        string    `json:"PostgreSqlHost"`
	PostgreSqlPort        string    `json:"PostgreSqlPort"`
	PostgreSqlUserName    string    `json:"PostgreSqlUserName"`
	PostgreSqlPassword    string    `json:"PostgreSqlPassword"`
	PostgreSqlDatabase    string    `json:"PostgreSqlDatabase"`
	RedisDatabaseNetwork  string    `json:"RedisDatabaseNetwork"`
	RedisDatabaseHost     string    `json:"RedisDatabaseHost"`
	RedisDatabasePort     string    `json:"RedisDatabasePort"`
	RmqHost               string    `json:"RmqHost"`
	RmqUser               string    `json:"RmqUser"`
	RmqPassword           string    `json:"RmqPassword"`
	RmqQueueMailName      string    `json:"RmqQueueMailName"`
	RmqExchangeName       string    `json:"RmqExchangeName"`
	RmqExchangeKind       string    `json:"RmqExchangeKind"`
	RateLimit             RateLimit `json:"RateLimit"`
	SessionTTLDays           int       `json:"SessionTTLDays"`
	RegistrationTokenTTLMin  int       `json:"RegistrationTokenTTLMin"`
	TwoFactorEnabled      bool      `json:"TwoFactorEnabled"`
	TrustedProxies        []string  `json:"TrustedProxies"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %q: %w", path, err)
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("config: decode %q: %w", path, err)
	}
	return &cfg, nil
}
