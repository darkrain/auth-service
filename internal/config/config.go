package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
)

type RateLimitIP struct {
	LoginMaxAttempts    int `json:"LoginMaxAttempts"`
	LoginWindowSec      int `json:"LoginWindowSec"`
	RegisterMaxAttempts int `json:"RegisterMaxAttempts"`
	RegisterWindowSec   int `json:"RegisterWindowSec"`
	SendCodeMaxAttempts int `json:"SendCodeMaxAttempts"`
	SendCodeWindowSec   int `json:"SendCodeWindowSec"`
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

type TestAccount struct {
	Login string `json:"login"`
	Code  string `json:"code"`
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
	TwoFactorEnabled         bool      `json:"TwoFactorEnabled"`
	TrustedProxies           []string  `json:"TrustedProxies"`
	PostgreSQLSSLMode         string    `json:"PostgreSQLSSLMode"`
	SwaggerEnabled            bool      `json:"SwaggerEnabled"`
	TestAccounts              []TestAccount `json:"TestAccounts"`
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

	// Default PostgreSQLSSLMode to "disable" if not set (backward compatible)
	if cfg.PostgreSQLSSLMode == "" {
		cfg.PostgreSQLSSLMode = "disable"
	}

	return &cfg, nil
}

// Validate checks that critical config fields are present.
func (c *Config) Validate() error {
	if c.PasswordSalt == "" {
		return errors.New("config: PasswordSalt must not be empty")
	}
	if c.PostgreSqlHost == "" || c.PostgreSqlDatabase == "" {
		return errors.New("config: DB host and name must not be empty")
	}
	// Warn about zero rate limit values (don't fatal)
	if c.RateLimit.IP.LoginMaxAttempts == 0 {
		log.Printf("WARNING: config: RateLimit.IP.LoginMaxAttempts is 0 (rate limiting disabled)")
	}
	if c.RateLimit.IP.RegisterMaxAttempts == 0 {
		log.Printf("WARNING: config: RateLimit.IP.RegisterMaxAttempts is 0 (rate limiting disabled)")
	}
	if c.RateLimit.IP.SendCodeMaxAttempts == 0 {
		log.Printf("WARNING: config: RateLimit.IP.SendCodeMaxAttempts is 0 (rate limiting disabled)")
	}
	if c.RateLimit.Account.MaxFailedLogins == 0 {
		log.Printf("WARNING: config: RateLimit.Account.MaxFailedLogins is 0 (account lockout disabled)")
	}
	if len(c.TestAccounts) > 0 {
		log.Printf("WARNING: TestAccounts is non-empty (%d accounts configured) — ensure this is not a production deployment", len(c.TestAccounts))
	}
	for i, ta := range c.TestAccounts {
		if ta.Login == "" {
			return fmt.Errorf("config: TestAccounts[%d].login must not be empty", i)
		}
		if ta.Code == "" {
			return fmt.Errorf("config: TestAccounts[%d].code must not be empty", i)
		}
	}
	return nil
}
