package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	authresponse "github.com/keshvan/auth-service-sstu-forum/internal/controller/response/auth_response.go"
	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
	"github.com/keshvan/auth-service-sstu-forum/internal/repo"
	"github.com/keshvan/go-common-forum/jwt"
	"github.com/mitchellh/mapstructure"
	"github.com/rs/zerolog"
	"golang.org/x/crypto/bcrypt"
)

type authUsecase struct {
	userRepo  repo.UserRepository
	tokenRepo repo.RefreshTokenRepository
	jwt       *jwt.JWT
	log       *zerolog.Logger
}

const (
	registerOp        = "AuthUsecase.Register"
	loginOp           = "AuthUsecase.Login"
	refreshOp         = "AuthUsecase.Refresh"
	logoutOp          = "AuthUsecase.Logout"
	isSessionActiveOp = "AuthUsecase.IsSessionActive"
)

func NewAuthUsecase(userRepo repo.UserRepository, tokenRepo repo.RefreshTokenRepository, jwt *jwt.JWT, log *zerolog.Logger) AuthUsecase {
	return &authUsecase{userRepo: userRepo, tokenRepo: tokenRepo, jwt: jwt, log: log}
}

func (u *authUsecase) Register(ctx context.Context, username string, role string, password string) (*authresponse.RegisterResponse, error) {
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	user := &entity.User{Username: username, Role: role, PasswordHash: string(hashedPassword)}
	id, err := u.userRepo.Create(ctx, user)
	if err != nil {
		u.log.Error().Err(err).Str("op", registerOp).Str("username", username).Msg("Failed to create user in repository")
		return nil, err
	}
	u.log.Info().Str("op", registerOp).Str("username", username).Msg("User registered successfully")

	access, err := u.jwt.GenerateAccessToken(id, user.Role)
	if err != nil {
		u.log.Error().Err(err).Str("op", registerOp).Int64("user_id", user.ID).Msg("Failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refresh, err := u.jwt.GenerateRefreshToken(id)
	if err != nil {
		u.log.Error().Err(err).Str("op", registerOp).Int64("user_id", user.ID).Msg("Failed to generate refresh token")
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	err = u.tokenRepo.Save(ctx, refresh, id)
	if err != nil {
		u.log.Error().Err(err).Str("op", registerOp).Int64("user_id", user.ID).Msg("Failed to save refresh token")
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	createdUser, err := u.userRepo.GetByID(ctx, id)
	if err != nil {
		u.log.Error().Err(err).Str("op", registerOp).Int64("user_id", user.ID).Msg("Failed to get user in repository")
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return &authresponse.RegisterResponse{User: *createdUser, Tokens: authresponse.Tokens{AccessToken: access, RefreshToken: refresh}}, nil
}

func (u *authUsecase) Login(ctx context.Context, username, password, refreshToken string) (*authresponse.LoginResponse, error) {
	log := u.log.With().Str("op", loginOp).Str("username", username).Logger()
	user, err := u.userRepo.GetByUsername(ctx, username)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get user by username or user not found")
		return nil, fmt.Errorf("invalid username or password: %w", err)
	}

	if refreshToken != "" {
		if err := u.tokenRepo.Delete(ctx, refreshToken); err != nil {
			log.Error().Err(err).Int64("user_id", user.ID).Msg("Failed to delete used refresh token from repository")
			return nil, fmt.Errorf("failed to delete used refresh token: %w", err)
		}
	}

	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		log.Warn().Msg("Invalid password attempt")
		return nil, errors.New("invalid username or password")
	}

	access, err := u.jwt.GenerateAccessToken(user.ID, user.Role)
	if err != nil {
		log.Error().Err(err).Int64("user_id", user.ID).Msg("Failed to generate access token")
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refresh, err := u.jwt.GenerateRefreshToken(user.ID)
	if err != nil {
		log.Error().Err(err).Int64("user_id", user.ID).Msg("Failed to generate refresh token")
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	err = u.tokenRepo.Save(ctx, refresh, user.ID)
	if err != nil {
		log.Error().Err(err).Int64("user_id", user.ID).Msg("Failed to save refresh token")
		return nil, fmt.Errorf("failed to save refresh token: %w", err)
	}

	log.Info().Int64("user_id", user.ID).Msg("User logged in successfully")
	return &authresponse.LoginResponse{User: *user, Tokens: authresponse.Tokens{AccessToken: access, RefreshToken: refresh}}, nil
}

func (u *authUsecase) Refresh(ctx context.Context, refreshToken string) (*authresponse.RefreshResponse, error) {
	log := u.log.With().Str("op", refreshOp).Logger()

	claims, err := u.jwt.ParseToken(refreshToken)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to parse refresh token")
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}

	var refreshClaims entity.RefreshClaims
	if err := mapstructure.Decode(claims, &refreshClaims); err != nil {
		log.Error().Err(err).Msg("Failed to decode refresh token claims")
		return nil, fmt.Errorf("failed to decode refresh token claims: %w", err)
	}

	userID, err := u.tokenRepo.GetUserID(ctx, refreshToken)
	if err != nil {
		log.Warn().Err(err).Msg("Refresh token not found or DB error")
		return nil, fmt.Errorf("refresh token not found or invalid: %w", err)
	}

	if refreshClaims.UserID != userID {
		log.Warn().Int64("user_id_claims", refreshClaims.UserID).Int64("user_id_db", userID).Msg("User ID mismatch in refresh token")
		return nil, errors.New("user_id mismatch in refresh token")
	}

	user, err := u.userRepo.GetByID(ctx, userID)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("Failed to get user by ID")
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}

	if err := u.tokenRepo.Delete(ctx, refreshToken); err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("Failed to delete used refresh token from repository")
		return nil, fmt.Errorf("failed to delete used refresh token: %w", err)
	}

	role, err := u.userRepo.GetRole(ctx, userID)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("Failed to get user role for refresh")
		return nil, fmt.Errorf("failed to get user role for refresh: %w", err)
	}

	newAccess, err := u.jwt.GenerateAccessToken(userID, role)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("Failed to generate new access token")
		return nil, fmt.Errorf("failed to generate new access token: %w", err)
	}

	newRefresh, err := u.jwt.GenerateRefreshToken(userID)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("Failed to generate new refresh token")
		return nil, fmt.Errorf("failed to generate new refresh token: %w", err)
	}

	err = u.tokenRepo.Save(ctx, newRefresh, userID)
	if err != nil {
		log.Error().Err(err).Int64("user_id", userID).Msg("Failed to save new refresh token")
		return nil, fmt.Errorf("failed to save new refresh token: %w", err)
	}

	log.Info().Str("op", refreshOp).Int64("user_id", userID).Msg("User refreshed successfully")
	return &authresponse.RefreshResponse{User: *user, Tokens: authresponse.Tokens{AccessToken: newAccess, RefreshToken: newRefresh}}, nil
}

func (u *authUsecase) Logout(ctx context.Context, refreshToken string) error {
	if err := u.tokenRepo.Delete(ctx, refreshToken); err != nil {
		u.log.Warn().Err(err).Str("op", logoutOp).Msg("Failed to delete refresh token from repository")
		return err
	}

	u.log.Info().Str("op", logoutOp).Msg("User logged out successfully")
	return nil
}

func (u *authUsecase) IsSessionActive(ctx context.Context, refreshToken string) (*authresponse.IsSessionActiveResponse, error) {
	log := u.log.With().Str("op", isSessionActiveOp).Logger()

	if refreshToken == "" {
		return &authresponse.IsSessionActiveResponse{User: nil, IsActive: false}, nil
	}

	id, err := u.tokenRepo.GetUserID(ctx, refreshToken)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &authresponse.IsSessionActiveResponse{User: nil, IsActive: false}, nil
		}
		log.Error().Err(err).Msg("Failed to check if session is active")
		return nil, fmt.Errorf("failed to check if session is active: %w", err)
	}

	user, err := u.userRepo.GetByID(ctx, id)
	if err != nil {
		log.Error().Err(err).Int64("user_id", id).Msg("Failed to get user by ID")
		return nil, fmt.Errorf("failed to get user by ID: %w", err)
	}
	log.Info().Str("username", user.Username).Str("role", user.Role).Msg("succesfully checked session")
	return &authresponse.IsSessionActiveResponse{User: user, IsActive: true}, nil
}
