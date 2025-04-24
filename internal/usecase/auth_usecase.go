package usecase

import (
	"context"

	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
	"github.com/keshvan/auth-service-sstu-forum/internal/repo"
	"github.com/keshvan/go-common-forum/jwt"
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

func (u *authUsecase) Register(ctx context.Context, username string, isAdmin bool, password string) (int64, error) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user := &entity.User{Username: username, IsAdmin: isAdmin, PasswordHash: hashedPassword}
	id, err := u.userRepo.Create(ctx, user)
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (u *authUsecase) Login(ctx context.Context, username, password string) (*entity.Tokens, error) {
	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil || bcrypt.CompareHashAndPassword(user.PasswordHash, []byte(password)) != nil {
		return nil, err
	}

	access, err := u.jwt.GenerateAccessToken(user.ID, user.IsAdmin)
	if err != nil {
		return nil, err
	}

	refresh, err := u.jwt.GenerateRefreshToken(user.ID, user.IsAdmin)
	if err != nil {
		return nil, err
	}

	err = u.tokenRepo.Save(ctx, refresh, user.ID)
	if err != nil {
		return nil, err
	}

	return &entity.Tokens{AccessToken: access, RefreshToken: refresh}, nil
}

func (u *authUsecase) Refresh(ctx context.Context, refreshToken string) (*entity.Tokens, error) {
	claims, err := u.jwt.ParseRefreshToken(refreshToken)
	if err != nil {
		return nil, err
	}

	isAdmin, err := u.userRepo.IsAdmin(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	access, err := u.jwt.GenerateAccessToken(claims.UserID, isAdmin)
	if err != nil {
		return nil, err
	}

	return &entity.Tokens{AccessToken: access, RefreshToken: refreshToken}, nil
}

func (u *authUsecase) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	return u.userRepo.IsAdmin(ctx, userID)
}
