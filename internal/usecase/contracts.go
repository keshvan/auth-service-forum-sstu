package usecase

import (
	"context"

	authresponse "github.com/keshvan/auth-service-sstu-forum/internal/controller/response/auth_response.go"
)

type AuthUsecase interface {
	Register(ctx context.Context, username string, role string, password string) (int64, error)
	Login(ctx context.Context, username, password string) (*authresponse.Tokens, error)
	Refresh(ctx context.Context, refreshToken string) (*authresponse.Tokens, error)
	Logout(ctx context.Context, refreshToken string) error
}
