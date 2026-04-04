package db

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

func Migrate(pool *pgxpool.Pool, migrationsDir string) error {
	// Create migrations tracking table if not exists
	_, err := pool.Exec(context.Background(), `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			filename TEXT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)
	`)
	if err != nil {
		return fmt.Errorf("migrate: create schema_migrations: %w", err)
	}

	// Read applied migrations
	rows, err := pool.Query(context.Background(), `SELECT filename FROM schema_migrations`)
	if err != nil {
		return fmt.Errorf("migrate: query applied: %w", err)
	}
	applied := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return fmt.Errorf("migrate: scan: %w", err)
		}
		applied[name] = true
	}
	rows.Close()

	// List sql files
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return fmt.Errorf("migrate: read dir %q: %w", migrationsDir, err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, name := range files {
		if applied[name] {
			continue
		}

		path := filepath.Join(migrationsDir, name)
		content, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("migrate: read %q: %w", name, err)
		}

		if _, err := pool.Exec(context.Background(), string(content)); err != nil {
			return fmt.Errorf("migrate: exec %q: %w", name, err)
		}

		if _, err := pool.Exec(context.Background(),
			`INSERT INTO schema_migrations (filename) VALUES ($1)`, name); err != nil {
			return fmt.Errorf("migrate: record %q: %w", name, err)
		}

		fmt.Printf("migrate: applied %s\n", name)
	}

	return nil
}
