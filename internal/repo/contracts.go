package repo

import (
	"context"

	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
)

type (
	UserRepository interface {
		Create(ctx context.Context, user *entity.User) (int64, error)
		Delete(ctx context.Context, id int64) error
		GetByUsername(ctx context.Context, username string) (*entity.User, error)
		IsAdmin(ctx context.Context, id int64) (bool, error)
	}

	RefreshTokenRepository interface {
		Save(ctx context.Context, token string, userID int64) error
		Delete(ctx context.Context, token string) error
		GetUserID(ctx context.Context, token string) (int64, error)
	}
)
