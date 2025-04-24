package usecase

import (
	"context"

	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
)

type AuthUsecase interface {
	Register(ctx context.Context, username string, isAdmin bool, password string) (int64, error)
	Login(ctx context.Context, username, password string) (*entity.Tokens, error)
	Refresh(ctx context.Context, refreshToken string) (*entity.Tokens, error)
}
