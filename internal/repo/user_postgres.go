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
		"INSERT INTO users (username, is_admin, password_hash) VALUES($1, $2, $3) RETURNING id",
		user.Username, user.IsAdmin, user.PasswordHash)

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
	row := r.pg.Pool.QueryRow(ctx, "SELECT id, email, password, created_at FROM users WHERE username = $1", username)

	var u entity.User
	if err := row.Scan(&u.ID, &u.Username, &u.IsAdmin, &u.PasswordHash); err != nil {
		return nil, fmt.Errorf("UserRepository - GetByUsername - row.Scan(): %w", err)
	}

	return &u, nil
}

func (r *userRepository) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	row := r.pg.Pool.QueryRow(ctx, "SELECT id, email, password, created_at FROM users WHERE user_id = $1", userID)

	var b bool
	if err := row.Scan(&b); err != nil {
		return false, fmt.Errorf("UserRepository - IsAdmin - row.Scan(): %w", err)
	}

	return b, nil
}
