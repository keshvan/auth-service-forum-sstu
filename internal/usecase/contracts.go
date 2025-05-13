package usecase

import (
	"context"

	authresponse "github.com/keshvan/auth-service-sstu-forum/internal/controller/response/auth_response.go"
)

type AuthUsecase interface {
	Register(ctx context.Context, username string, role string, password string) (*authresponse.RegisterResponse, error)
	Login(ctx context.Context, username, password, refreshToken string) (*authresponse.LoginResponse, error)
	Refresh(ctx context.Context, refreshToken string) (*authresponse.RefreshResponse, error)
	Logout(ctx context.Context, refreshToken string) error
	IsSessionActive(ctx context.Context, refreshToken string) (*authresponse.IsSessionActiveResponse, error)
}
