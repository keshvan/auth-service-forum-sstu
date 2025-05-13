package repo

import (
	"context"
	"fmt"

	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
	"github.com/keshvan/go-common-forum/postgres"
	"github.com/rs/zerolog"
)

const (
	createOp        = "UserRepository.Create"
	deleteOp        = "UserRepository.Delete"
	getByUsernameOp = "UserRepository.GetByUsername"
	getByIDOp       = "UserRepository.GetByID"
	getRoleOp       = "UserRepository.GetRole"
)

type userRepository struct {
	pg  *postgres.Postgres
	log *zerolog.Logger
}

func NewUserRepository(pg *postgres.Postgres, log *zerolog.Logger) UserRepository {
	return &userRepository{pg, log}
}

func (r *userRepository) Create(ctx context.Context, user *entity.User) (int64, error) {
	row := r.pg.Pool.QueryRow(ctx,
		"INSERT INTO users (username, password_hash) VALUES($1, $2) RETURNING id",
		user.Username, string(user.PasswordHash))

	var id int64
	if err := row.Scan(&id); err != nil {
		r.log.Error().Err(err).Str("op", createOp).Str("username", user.Username).Msg("Failed to scan user ID after insert")
		return 0, fmt.Errorf("UserRepository - Create - row.Scan(): %w", err)
	}

	return id, nil
}

func (r *userRepository) Delete(ctx context.Context, id int64) error {
	if _, err := r.pg.Pool.Exec(ctx, "DELETE FROM users WHERE id = $1", id); err != nil {
		r.log.Error().Err(err).Str("op", deleteOp).Int64("id", id).Msg("Failed to delete user")
		return fmt.Errorf("UserRepository - Delete - pg.Pool.Exec(): %w", err)
	}
	return nil
}

func (r *userRepository) GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	row := r.pg.Pool.QueryRow(ctx, "SELECT id, username, role, password_hash, created_at FROM users WHERE username = $1", username)

	var u entity.User
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.PasswordHash, &u.CreatedAt); err != nil {
		r.log.Error().Err(err).Str("op", getByUsernameOp).Str("username", username).Msg("Failed to scan user")
		return nil, fmt.Errorf("UserRepository - GetByUsername - row.Scan(): %w", err)
	}

	return &u, nil
}

func (r *userRepository) GetByID(ctx context.Context, id int64) (*entity.User, error) {
	row := r.pg.Pool.QueryRow(ctx, "SELECT id, username, role, created_at FROM users WHERE id = $1", id)

	var u entity.User
	if err := row.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt); err != nil {
		r.log.Error().Err(err).Str("op", getByIDOp).Int64("id", id).Msg("Failed to scan user")
		return nil, fmt.Errorf("UserRepository - GetByID - row.Scan(): %w", err)
	}

	return &u, nil
}

func (r *userRepository) GetRole(ctx context.Context, id int64) (string, error) {
	row := r.pg.Pool.QueryRow(ctx, "SELECT role FROM users WHERE id = $1", id)

	var role string
	if err := row.Scan(&role); err != nil {
		r.log.Error().Err(err).Str("op", getRoleOp).Int64("id", id).Msg("Failed to get role")
		return "", fmt.Errorf("UserRepository - GetRole - row.Scan(): %w", err)
	}

	return role, nil
}
