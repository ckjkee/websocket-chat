package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	_ "github.com/lib/pq"
)

// UserRecord представляет запись пользователя в БД
type UserRecord struct {
	Username     string
	PasswordHash string
	CreatedAt    time.Time
}

type UserRepository interface {
	CreateUser(ctx context.Context, username, passwordHash string) error
	GetUserByUsername(ctx context.Context, username string) (*UserRecord, error)
}

type PostgresUserRepository struct {
	db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
	return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) AutoMigrate(ctx context.Context) error {
	const query = `
	CREATE TABLE IF NOT EXISTS users (
		username TEXT PRIMARY KEY,
		password_hash TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	`
	_, err := r.db.ExecContext(ctx, query)
	return err
}

func (r *PostgresUserRepository) CreateUser(ctx context.Context, username, passwordHash string) error {
	const query = `INSERT INTO users (username, password_hash) VALUES ($1, $2)`
	_, err := r.db.ExecContext(ctx, query, username, passwordHash)
	return err
}

func (r *PostgresUserRepository) GetUserByUsername(ctx context.Context, username string) (*UserRecord, error) {
	const query = `SELECT username, password_hash, created_at FROM users WHERE username = $1`
	row := r.db.QueryRowContext(ctx, query, username)
	var rec UserRecord
	if err := row.Scan(&rec.Username, &rec.PasswordHash, &rec.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, err
	}
	return &rec, nil
}
