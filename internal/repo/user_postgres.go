package repo

import (
	"context"
	"fmt"

	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
	"github.com/keshvan/go-common-forum/postgres"
)

type userRepository struct {
	pg *postgres.Postgres
}

func NewUserRepository(pg *postgres.Postgres) *userRepository {
	return &userRepository{pg}
}

func (r *userRepository) Create(ctx context.Context, user *entity.User) (int64, error) {
	row := r.pg.Pool.QueryRow(ctx,
		"INSERT INTO users (username, role, password_hash) VALUES($1, $2, $3) RETURNING id",
		user.Username, user.Role, user.PasswordHash)

	var id int64
	if err := row.Scan(&id); err != nil {
		return 0, fmt.Errorf("UserRepository - Create - row.Scan(): %w", err)
	}

	return id, nil
}

func (r *userRepository) Delete(ctx context.Context, id int64) error {
	if _, err := r.pg.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
		return fmt.Errorf("UserRepository- Delete - pg.Pool.Exec(): %w", err)
	}
	return nil
}

func (r *userRepository) GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	row := r.pg.Pool.QueryRow(ctx, "SELECT id, username, role, password_hash, created_at FROM users WHERE username = $1", username)

	var u entity.User
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.PasswordHash, &u.CreatedAt); err != nil {
		return nil, fmt.Errorf("UserRepository - GetByUsername - row.Scan(): %w", err)
	}

	return &u, nil
}

func (r *userRepository) GetRole(ctx context.Context, id int64) (string, error) {
	row := r.pg.Pool.QueryRow(ctx, "SELECT role FROM users WHERE id = $1", id)

	var role string
	if err := row.Scan(&role); err != nil {
		return "", fmt.Errorf("UserRepository - GetRole - row.Scan(): %w", err)
	}

	return role, nil
}
