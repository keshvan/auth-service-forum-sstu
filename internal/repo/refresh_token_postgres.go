package repo

import (
	"context"
	"fmt"

	"github.com/keshvan/go-common-forum/postgres"
)

type refreshTokenRepository struct {
	pg *postgres.Postgres
}

func NewRefreshTokenRepository(pg *postgres.Postgres) RefreshTokenRepository {
	return &refreshTokenRepository{pg}
}

func (r *refreshTokenRepository) Save(ctx context.Context, token string, userID int64) error {
	if _, err := r.pg.Pool.Exec(ctx, "INSERT INTO refresh_tokens (token, user_id) VALUES($1, $2)", token, userID); err != nil {
		return fmt.Errorf("RefreshTokenRepository - Save - pg.Pool.Exec(): %w", err)
	}
	return nil
}

func (r *refreshTokenRepository) Delete(ctx context.Context, token string) error {
	if _, err := r.pg.Pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE token = $1`, token); err != nil {
		return fmt.Errorf("RefreshTokenRepository - Delete - pg.Pool.Exec(): %w", err)
	}
	return nil
}

func (r *refreshTokenRepository) GetUserID(ctx context.Context, token string) (int64, error) {
	row := r.pg.Pool.QueryRow(ctx, "SELECT user_id FROM refresh_tokens WHERE token = $1", token)

	var id int64
	if err := row.Scan(&id); err != nil {
		return 0, fmt.Errorf("UserRepository - GetByUsername - row.Scan(): %w", err)
	}

	return id, nil
}
