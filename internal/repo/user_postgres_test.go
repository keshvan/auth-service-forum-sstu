package repo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
	"github.com/keshvan/go-common-forum/postgres"
	"github.com/pashagolub/pgxmock/v4"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserPostgres_Create(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()

	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	pg := postgres.NewWithPool(mockPool)
	repo := NewUserRepository(pg, &logger)

	testUser := &entity.User{Username: "test", PasswordHash: "testpasswordhash"}
	expectedId := int64(1)

	t.Run("Success", func(t *testing.T) {
		row := pgxmock.NewRows([]string{"id"}).AddRow(expectedId)
		mockPool.ExpectQuery("INSERT INTO users").WithArgs(testUser.Username, testUser.PasswordHash).WillReturnRows(row)

		id, err := repo.Create(ctx, testUser)
		assert.NoError(t, err)
		assert.Equal(t, expectedId, id)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("DB error", func(t *testing.T) {
		dbErr := errors.New("some db error")
		mockPool.ExpectQuery("INSERT INTO users").WithArgs(testUser.Username, testUser.PasswordHash).WillReturnError(dbErr)

		_, err := repo.Create(ctx, testUser)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "UserRepository - Create - row.Scan()")
		assert.ErrorIs(t, err, dbErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestUserPostgres_Delete(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()

	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	pg := postgres.NewWithPool(mockPool)
	repo := NewUserRepository(pg, &logger)

	testID := int64(1)

	t.Run("Success", func(t *testing.T) {
		mockPool.ExpectExec("DELETE FROM users WHERE id").WithArgs(testID).WillReturnResult(pgxmock.NewResult("DELETE", 1))

		err := repo.Delete(ctx, testID)
		assert.NoError(t, err)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("DB error", func(t *testing.T) {
		dbErr := errors.New("database delete error")
		mockPool.ExpectExec("DELETE FROM users WHERE id").WithArgs(testID).WillReturnError(dbErr)

		err := repo.Delete(ctx, testID)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "UserRepository - Delete - pg.Pool.Exec()")
		assert.ErrorIs(t, err, dbErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestUserPostgres_GetByUsername(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()

	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	pg := postgres.NewWithPool(mockPool)
	repo := NewUserRepository(pg, &logger)

	testUsername := "username"
	expectedUser := &entity.User{ID: 1, Username: "username", Role: "user", PasswordHash: "hash", CreatedAt: time.Now()}

	t.Run("Succes", func(t *testing.T) {
		row := pgxmock.NewRows([]string{"id", "username", "role", "password_hash", "created_at"}).AddRow(expectedUser.ID, expectedUser.Username, expectedUser.Role, expectedUser.PasswordHash, expectedUser.CreatedAt)
		mockPool.ExpectQuery("SELECT id, username, role, password_hash, created_at FROM users WHERE username").WithArgs(testUsername).WillReturnRows(row)

		user, err := repo.GetByUsername(ctx, testUsername)
		assert.NoError(t, err)
		assert.Equal(t, expectedUser, user)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("DB error", func(t *testing.T) {
		dbErr := errors.New("some database error")
		mockPool.ExpectQuery("SELECT id, username, role, password_hash, created_at FROM users WHERE username").WithArgs(testUsername).WillReturnError(dbErr)

		_, err := repo.GetByUsername(ctx, testUsername)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "UserRepository - GetByUsername - row.Scan()")
		assert.ErrorIs(t, err, dbErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestUserPostgres_GetByID(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()

	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	pg := postgres.NewWithPool(mockPool)
	repo := NewUserRepository(pg, &logger)

	testID := int64(1)
	expectedUser := &entity.User{ID: 1, Username: "username", Role: "user", CreatedAt: time.Now()}

	t.Run("Succes", func(t *testing.T) {
		row := pgxmock.NewRows([]string{"id", "username", "role", "created_at"}).AddRow(expectedUser.ID, expectedUser.Username, expectedUser.Role, expectedUser.CreatedAt)
		mockPool.ExpectQuery("SELECT id, username, role, created_at FROM users WHERE id").WithArgs(testID).WillReturnRows(row)

		user, err := repo.GetByID(ctx, testID)
		assert.NoError(t, err)
		assert.Equal(t, expectedUser, user)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("DB error", func(t *testing.T) {
		dbErr := errors.New("some database error")
		mockPool.ExpectQuery("SELECT id, username, role, created_at FROM users WHERE id").WithArgs(testID).WillReturnError(dbErr)

		_, err := repo.GetByID(ctx, testID)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "UserRepository - GetByID - row.Scan()")
		assert.ErrorIs(t, err, dbErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}

func TestUserPostgres_GetRole(t *testing.T) {
	ctx := context.Background()
	logger := zerolog.Nop()

	mockPool, err := pgxmock.NewPool()
	require.NoError(t, err)
	defer mockPool.Close()

	pg := postgres.NewWithPool(mockPool)
	repo := NewUserRepository(pg, &logger)

	testID := int64(1)
	expectedRole := "user"

	t.Run("Succes", func(t *testing.T) {
		row := pgxmock.NewRows([]string{"role"}).AddRow(expectedRole)
		mockPool.ExpectQuery("SELECT role FROM users WHERE id").WithArgs(testID).WillReturnRows(row)

		role, err := repo.GetRole(ctx, testID)
		assert.NoError(t, err)
		assert.Equal(t, expectedRole, role)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})

	t.Run("DB error", func(t *testing.T) {
		dbErr := errors.New("some database error")
		mockPool.ExpectQuery("SELECT role FROM users WHERE id").WithArgs(testID).WillReturnError(dbErr)

		_, err := repo.GetRole(ctx, testID)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "UserRepository - GetRole - row.Scan()")
		assert.ErrorIs(t, err, dbErr)
		assert.NoError(t, mockPool.ExpectationsWereMet())
	})
}
