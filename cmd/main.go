package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/darkrain/auth-service/internal/broker"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/db"
	"github.com/darkrain/auth-service/internal/handler"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var (
	// Injected via ldflags
	Version     = "dev"
	Build       = "unknown"
	ProjectName = "auth-service"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config JSON file")
	flag.Parse()

	log.Printf("%s version=%s build=%s", ProjectName, Version, Build)

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// PostgreSQL
	var pgPool *pgxpool.Pool
	rawPool, err := db.Connect(cfg)
	if err != nil {
		log.Printf("WARNING: PostgreSQL not available: %v", err)
	} else {
		pgPool = rawPool
		defer pgPool.Close()
		log.Println("PostgreSQL connected")

		// Migrations
		if err := db.Migrate(pgPool, "migrations"); err != nil {
			log.Printf("WARNING: migrations failed: %v", err)
		}

		// Seed
		if err := db.Seed(pgPool, cfg); err != nil {
			log.Printf("WARNING: seed failed: %v", err)
		}
	}

	// Redis
	rdb := redis.NewClient(&redis.Options{
		Network: cfg.RedisDatabaseNetwork,
		Addr:    fmt.Sprintf("%s:%s", cfg.RedisDatabaseHost, cfg.RedisDatabasePort),
	})
	defer rdb.Close()

	// Ping Redis in background — don't block startup
	go func() {
		if err := rdb.Ping(context.Background()).Err(); err != nil {
			log.Printf("WARNING: Redis not available: %v", err)
		} else {
			log.Println("Redis connected")
		}
	}()

	// RabbitMQ
	rmqConn, err := broker.Connect(cfg)
	if err != nil {
		log.Printf("WARNING: RabbitMQ not available: %v", err)
	} else {
		defer rmqConn.Close()
		log.Println("RabbitMQ connected")
	}

	// HTTP server
	r := gin.Default()

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": Version})
	})

	r.POST("/auth/register", handler.Register(pgPool, rmqConn, cfg))
	r.POST("/auth/login", handler.Login(pgPool, cfg))
	r.POST("/auth/logout", handler.Logout(pgPool))

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("starting server on %s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
