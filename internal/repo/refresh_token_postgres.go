package repo

import (
	"context"
	"fmt"

	"github.com/keshvan/go-common-forum/postgres"
	"github.com/rs/zerolog"
)

type refreshTokenRepository struct {
	pg  *postgres.Postgres
	log *zerolog.Logger
}

const (
	saveOp        = "RefreshTokenRepository.Save"
	deleteTokenOp = "RefreshTokenRepository.Delete"
	getUserIDOp   = "RefreshTokenRepository.GetUserID"
	isActiveOp    = "RefreshTokenRepository.IsActive"
)

func NewRefreshTokenRepository(pg *postgres.Postgres, log *zerolog.Logger) RefreshTokenRepository {
	return &refreshTokenRepository{pg, log}
}

func (r *refreshTokenRepository) Save(ctx context.Context, token string, userID int64) error {
	if _, err := r.pg.Pool.Exec(ctx, "INSERT INTO refresh_tokens (token, user_id) VALUES($1, $2)", token, userID); err != nil {
		r.log.Error().Err(err).Str("op", saveOp).Str("token", token).Int64("userID", userID).Msg("Failed to save refresh token")
		return fmt.Errorf("RefreshTokenRepository - Save - pg.Pool.Exec(): %w", err)
	}
	r.pg.Pool.Config()
	return nil
}

func (r *refreshTokenRepository) Delete(ctx context.Context, token string) error {
	if _, err := r.pg.Pool.Exec(ctx, `DELETE FROM refresh_tokens WHERE token = $1`, token); err != nil {
		r.log.Error().Err(err).Str("op", deleteTokenOp).Str("token", token).Msg("Failed to delete refresh token")
		return fmt.Errorf("RefreshTokenRepository - Delete - pg.Pool.Exec(): %w", err)
	}
	return nil
}

func (r *refreshTokenRepository) GetUserID(ctx context.Context, token string) (int64, error) {
	row := r.pg.Pool.QueryRow(ctx, "SELECT user_id FROM refresh_tokens WHERE token = $1", token)

	var id int64
	if err := row.Scan(&id); err != nil {
		r.log.Error().Err(err).Str("op", getUserIDOp).Str("token", token).Msg("Failed to get user ID")
		return 0, fmt.Errorf("RefreshTokenRepository - GetByUserID - row.Scan(): %w", err)
	}

	return id, nil
}
