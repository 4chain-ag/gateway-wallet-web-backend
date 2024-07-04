package users

import (
	"context"
	"database/sql"

	"github.com/bitcoin-sv/spv-wallet-web-backend/domain/users"
)

const (
	postgresInsertUser = `
	INSERT INTO users(email, xpriv, paymail, created_at)
	VALUES($1, $2, $3, $4)
	`

	postgresGetUserByEmail = `
	SELECT id, email, xpriv, paymail, created_at
	FROM users
	WHERE email = $1
	`

	postgresGetUserByID = `
	SELECT id, email, xpriv, paymail, created_at
	FROM users
	WHERE id = $1
	`
)

// Repository is a repository for users.
type Repository struct {
	db *sql.DB
}

// NewUsersRepository creates a new users repository.
func NewUsersRepository(db *sql.DB) *Repository {
	return &Repository{
		db: db,
	}
}

// InsertUser inserts a user to db.
func (r *Repository) InsertUser(ctx context.Context, user *users.User) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() {
		_ = tx.Rollback()
	}()
	stmt, err := r.db.Prepare(postgresInsertUser)
	if err != nil {
		return err
	}
	defer stmt.Close() //nolint:all
	if _, err = stmt.Exec(user.Email, user.Xpriv, user.Paymail, user.CreatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

// GetUserByEmail returns user by email.
func (r *Repository) GetUserByEmail(ctx context.Context, email string) (*users.User, error) {
	var user UserDto
	row := r.db.QueryRowContext(ctx, postgresGetUserByEmail, email)
	if err := row.Scan(&user.ID, &user.Email, &user.Xpriv, &user.Paymail, &user.CreatedAt); err != nil {
		return nil, err
	}
	return user.toUser(), nil
}

// GetUserByID returns user by id.
func (r *Repository) GetUserByID(ctx context.Context, id int) (*users.User, error) {
	var user UserDto
	row := r.db.QueryRowContext(ctx, postgresGetUserByID, id)
	if err := row.Scan(&user.ID, &user.Email, &user.Xpriv, &user.Paymail, &user.CreatedAt); err != nil {
		return nil, err
	}
	return user.toUser(), nil
}
