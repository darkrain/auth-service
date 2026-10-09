package cache

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/darkrain/auth-service/internal/config"
)

// Run against an isolated Redis configured with requirepass. No application
// keys are read or flushed; this only exercises the startup handshake.
func TestConnectAuthenticatedRedis(t *testing.T) {
	address := os.Getenv("REDIS_TEST_ADDR")
	password := os.Getenv("REDIS_TEST_PASSWORD")
	if address == "" || password == "" {
		t.Skip("set REDIS_TEST_ADDR and REDIS_TEST_PASSWORD for an isolated password-protected Redis")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []bool{true, false} {
		name := "correct password"
		configuredPassword := password
		if !valid {
			name = "wrong password"
			configuredPassword += "-wrong"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			client, err := Connect(ctx, &config.Config{
				RedisDatabaseNetwork: "tcp", RedisDatabaseHost: host,
				RedisDatabasePort: port, RedisPassword: configuredPassword,
			})
			if valid {
				if err != nil {
					t.Fatalf("Redis handshake failed: %v", err)
				}
				defer client.Close()
				if err := client.Ping(ctx); err != nil {
					t.Fatal(err)
				}
			} else if err == nil || client != nil {
				t.Fatal("wrong Redis credentials must reject startup")
			} else if !strings.Contains(err.Error(), "WRONGPASS") {
				t.Fatalf("expected an authentication rejection, got %v", err)
			}
		})
	}
}
