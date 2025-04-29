package usecase

import (
	"context"
	"errors"
	"fmt"

	authresponse "github.com/keshvan/auth-service-sstu-forum/internal/controller/response/auth_response.go"
	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
	"github.com/keshvan/auth-service-sstu-forum/internal/repo"
	"github.com/keshvan/go-common-forum/jwt"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/bcrypt"
)

type authUsecase struct {
	userRepo  repo.UserRepository
	tokenRepo repo.RefreshTokenRepository
	jwt       *jwt.JWT
}

func NewAuthUsecase(userRepo repo.UserRepository, tokenRepo repo.RefreshTokenRepository, jwt *jwt.JWT) *authUsecase {
	return &authUsecase{userRepo: userRepo, tokenRepo: tokenRepo, jwt: jwt}
}

func (u *authUsecase) Register(ctx context.Context, username string, role string, password string) (int64, error) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user := &entity.User{Username: username, Role: role, PasswordHash: hashedPassword}
	id, err := u.userRepo.Create(ctx, user)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (u *authUsecase) Login(ctx context.Context, username, password string) (*authresponse.Tokens, error) {
	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("invalid username or password: %w", err)
	}
	if bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)) != nil {
		return nil, errors.New("invalid username or password")
	}

	access, err := u.jwt.GenerateAccessToken(user.ID, user.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refresh, err := u.jwt.GenerateRefreshToken(user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	err = u.tokenRepo.Save(ctx, refresh, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	return &authresponse.Tokens{AccessToken: access, RefreshToken: refresh}, nil
}

func (u *authUsecase) Refresh(ctx context.Context, refreshToken string) (*authresponse.Tokens, error) {
	claims, err := u.jwt.ParseToken(refreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	var refreshClaims entity.RefreshClaims
	if err := mapstructure.Decode(claims, &refreshClaims); err != nil {
		return nil, fmt.Errorf("failed to decode refresh token claims: %w", err)
	}

	userID, err := u.tokenRepo.GetUserID(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("refresh token not found or invalid: %w", err)
	}

	if refreshClaims.UserID != userID {
		return nil, errors.New("user_id mismatch in refresh token")
	}

	if err := u.tokenRepo.Delete(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("failed to delete used refresh token: %w", err)
	}

	role, err := u.userRepo.GetRole(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user role for refresh: %w", err)
	}

	newAccess, err := u.jwt.GenerateAccessToken(userID, role)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	newRefresh, err := u.jwt.GenerateRefreshToken(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	err = u.tokenRepo.Save(ctx, newRefresh, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to save new refresh token: %w", err)
	}

	return &authresponse.Tokens{AccessToken: newAccess, RefreshToken: newRefresh}, nil
}

func (u *authUsecase) Logout(ctx context.Context, refreshToken string) error {
	if err := u.tokenRepo.Delete(ctx, refreshToken); err != nil {
		return err
	}

	return nil
}
