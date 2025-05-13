package repo

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/pashagolub/pgxmock/v4"

	"github.com/keshvan/go-common-forum/postgres"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshTokenRepository_Save(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()

	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	pg := postgres.NewWithPool(mockPool)

	repo := NewRefreshTokenRepository(pg, &logger)

	token := "test-token"
	userID := int64(1)

	t.Run("Success", func(t *testing.T) {
		mockPool.ExpectExec("INSERT INTO refresh_tokens").WithArgs(token, userID).WillReturnResult(pgxmock.NewResult("INSERT", 1))

		err := repo.Save(ctx, token, userID)
		assert.NoError(t, err)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("DB Error", func(t *testing.T) {
		dbErr := errors.New("database insert error")
		mockPool.ExpectExec("INSERT INTO refresh_tokens").WithArgs(token, userID).WillReturnError(dbErr)

		err := repo.Save(ctx, token, userID)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "RefreshTokenRepository - Save - pg.Pool.Exec()")
		assert.ErrorIs(t, err, dbErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestRefreshTokenRepository_Delete(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()

	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	pg := postgres.NewWithPool(mockPool)

	repo := NewRefreshTokenRepository(pg, &logger)

	token := "test-token"

	t.Run("Success", func(t *testing.T) {
		mockPool.ExpectExec("DELETE FROM refresh_tokens WHERE token").WithArgs(token).WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(ctx, token)
		assert.NoError(t, err)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("DB Error", func(t *testing.T) {
		dbErr := errors.New("database delete error")
		mockPool.ExpectExec("DELETE FROM refresh_tokens WHERE token").WithArgs(token).WillReturnError(dbErr)

		err := repo.Delete(ctx, token)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "RefreshTokenRepository - Delete - pg.Pool.Exec()")
		assert.ErrorIs(t, err, dbErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestRefreshTokenRepository_GetUserID(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()

	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	pg := postgres.NewWithPool(mockPool)

	repo := NewRefreshTokenRepository(pg, &logger)

	token := "test-token"
	expectedUserID := int64(1)

	t.Run("Success", func(t *testing.T) {
		rows := pgxmock.NewRows([]string{"user_id"}).AddRow(expectedUserID)
		mockPool.ExpectQuery("SELECT user_id FROM refresh_tokens WHERE token").WithArgs(token).WillReturnRows(rows)

		userID, err := repo.GetUserID(ctx, token)
		assert.NoError(t, err)
		assert.Equal(t, expectedUserID, userID)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("pgx.ErrNoRows", func(t *testing.T) {
		mockPool.ExpectQuery("SELECT user_id FROM refresh_tokens WHERE token").WithArgs(token).WillReturnError(pgx.ErrNoRows)

		userID, err := repo.GetUserID(ctx, token)
		assert.Error(t, err)
		assert.Equal(t, int64(0), userID)
		assert.Contains(t, err.Error(), "RefreshTokenRepository - GetByUserID - row.Scan()")
		assert.ErrorIs(t, err, pgx.ErrNoRows)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("DB Error", func(t *testing.T) {
		dbErr := errors.New("some db error")
		mockPool.ExpectQuery("SELECT user_id FROM refresh_tokens WHERE token = \\$1").
			WithArgs(token).
			WillReturnError(dbErr)

		userID, err := repo.GetUserID(ctx, token)
		assert.Error(t, err)
		assert.Equal(t, int64(0), userID)
		assert.Contains(t, err.Error(), "RefreshTokenRepository - GetByUserID - row.Scan")
		assert.ErrorIs(t, err, dbErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

}
