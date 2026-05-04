// Package main is the entry point for the Auth Service.
//
//	@title			Auth Service API
//	@version		1.0
//	@description	Authentication and authorization microservice with JWT sessions, 2FA, and API key management.
//	@termsOfService	http://swagger.io/terms/
//
//	@contact.name	darkrain
//	@contact.url	https://github.com/darkrain/auth-service
//
//	@license.name	MIT
//
//	@host		localhost:8080
//	@BasePath	/
//
//	@securityDefinitions.apikey	BearerAuth
//	@in							header
//	@name						Authorization
//	@description				Type "Bearer" followed by a space and the JWT token.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/darkrain/auth-service/docs"
	"github.com/darkrain/auth-service/internal/broker"
	"github.com/darkrain/auth-service/internal/cache"
	"github.com/darkrain/auth-service/internal/config"
	"github.com/darkrain/auth-service/internal/db"
	"github.com/darkrain/auth-service/internal/handler"
	"github.com/darkrain/auth-service/internal/middleware"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
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

	// MEDIUM-NEW-1: validate critical config fields
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid config: %v", err)
	}

	// Create a context that cancels on SIGTERM/SIGINT
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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

		// LOW: background goroutine to clean up expired sessions every 24h
		db.StartSessionCleanup(ctx, pgPool, log.Default())
	}

	cacheClient := cache.NewClient(cfg)

	// Ping Redis in background — don't block startup
	go func() {
		if err := cacheClient.Ping(context.Background()); err != nil {
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

	// HIGH-4: configure trusted proxies from config
	if len(cfg.TrustedProxies) > 0 {
		if err := r.SetTrustedProxies(cfg.TrustedProxies); err != nil {
			log.Printf("WARNING: SetTrustedProxies: %v", err)
		}
	} else {
		if err := r.SetTrustedProxies([]string{"127.0.0.1"}); err != nil {
			log.Printf("WARNING: SetTrustedProxies: %v", err)
		}
	}

	// CORS middleware
	if len(cfg.AllowedOrigins) > 0 {
		r.Use(func(c *gin.Context) {
			origin := c.Request.Header.Get("Origin")
			allowed := false
			for _, o := range cfg.AllowedOrigins {
				if o == "*" || o == origin {
					allowed = true
					break
				}
			}
			if allowed {
				c.Header("Access-Control-Allow-Origin", origin)
				c.Header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
				c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
				c.Header("Access-Control-Max-Age", "86400")
			}
			if c.Request.Method == http.MethodOptions {
				c.AbortWithStatus(http.StatusNoContent)
				return
			}
			c.Next()
		})
	}

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": Version})
	})

	// LOW: Swagger UI gated by config flag (disabled by default in production)
	if cfg.SwaggerEnabled {
		r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	}

	r.POST("/auth/register",
		middleware.RateLimit(cacheClient, rmqConn, "/auth/register",
			cfg.RateLimit.IP.RegisterMaxAttempts, cfg.RateLimit.IP.RegisterWindowSec,
			cfg.RateLimit.Device.RegisterMaxAttempts, cfg.RateLimit.Device.RegisterWindowSec),
		handler.Register(pgPool, rmqConn, cfg))
	r.POST("/auth/login",
		middleware.RateLimit(cacheClient, rmqConn, "/auth/login",
			cfg.RateLimit.IP.LoginMaxAttempts, cfg.RateLimit.IP.LoginWindowSec,
			cfg.RateLimit.Device.LoginMaxAttempts, cfg.RateLimit.Device.LoginWindowSec),
		handler.Login(pgPool, rmqConn, cfg, cacheClient))
	r.POST("/auth/logout", handler.Logout(pgPool, cacheClient))
	r.POST("/auth/login/verify-2fa",
		middleware.RateLimit(cacheClient, rmqConn, "/auth/login/verify-2fa",
			cfg.RateLimit.IP.LoginMaxAttempts, cfg.RateLimit.IP.LoginWindowSec,
			cfg.RateLimit.Device.SendCodeMaxAttempts, cfg.RateLimit.Device.SendCodeWindowSec),
		handler.VerifyLogin2FA(pgPool, cfg))

	// Password reset (public — no auth required)
	r.POST("/auth/password/reset-request",
		middleware.RateLimit(cacheClient, rmqConn, "/auth/password/reset-request",
			cfg.RateLimit.IP.SendCodeMaxAttempts, cfg.RateLimit.IP.SendCodeWindowSec,
			cfg.RateLimit.Device.SendCodeMaxAttempts, cfg.RateLimit.Device.SendCodeWindowSec),
		handler.ResetRequest(pgPool, rmqConn, cfg, cacheClient))
	r.POST("/auth/password/reset-confirm",
		middleware.RateLimit(cacheClient, rmqConn, "/auth/password/reset-confirm",
			cfg.RateLimit.IP.SendCodeMaxAttempts, cfg.RateLimit.IP.SendCodeWindowSec,
			cfg.RateLimit.Device.SendCodeMaxAttempts, cfg.RateLimit.Device.SendCodeWindowSec),
		handler.ResetConfirm(pgPool, cfg, cacheClient))

	// Protected routes (require valid session token)
	authRequired := r.Group("/")
	authRequired.Use(middleware.Auth(pgPool, cacheClient))

	authRequired.POST("/auth/send-code",
		middleware.RateLimit(cacheClient, rmqConn, "/auth/send-code",
			cfg.RateLimit.IP.SendCodeMaxAttempts, cfg.RateLimit.IP.SendCodeWindowSec,
			cfg.RateLimit.Device.SendCodeMaxAttempts, cfg.RateLimit.Device.SendCodeWindowSec),
		handler.SendCode(pgPool, rmqConn, cfg))

	// API key management (admin and system only)
	apiKeys := authRequired.Group("/auth/api-keys")
	apiKeys.Use(middleware.RequireRole("admin", "system"))
	apiKeys.POST("", handler.CreateAPIKey(pgPool))
	apiKeys.GET("", handler.ListAPIKeys(pgPool))
	apiKeys.DELETE("/:id", handler.RevokeAPIKey(pgPool, cacheClient))

	// CRIT-2 + HIGH-2: verify endpoints require auth and have rate limiting
	authRequired.POST("/auth/verify/email",
		middleware.RateLimit(cacheClient, rmqConn, "/auth/verify/email",
			cfg.RateLimit.IP.LoginMaxAttempts, cfg.RateLimit.IP.LoginWindowSec,
			cfg.RateLimit.Device.SendCodeMaxAttempts, cfg.RateLimit.Device.SendCodeWindowSec),
		handler.VerifyEmail(pgPool, cfg, cacheClient))
	authRequired.POST("/auth/verify/phone",
		middleware.RateLimit(cacheClient, rmqConn, "/auth/verify/phone",
			cfg.RateLimit.IP.LoginMaxAttempts, cfg.RateLimit.IP.LoginWindowSec,
			cfg.RateLimit.Device.SendCodeMaxAttempts, cfg.RateLimit.Device.SendCodeWindowSec),
		handler.VerifyPhone(pgPool, cfg, cacheClient))

	// Authenticated user info
	authRequired.GET("/auth/me", handler.Me())

	addr := fmt.Sprintf("%s:%s", cfg.Host, cfg.Port)
	log.Printf("starting server on %s", addr)

	srv := &http.Server{
		Addr:    addr,
		Handler: r,
	}

	// Start server in goroutine
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()
	log.Println("shutting down server...")

	// Graceful shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("server shutdown error: %v", err)
	}
}
