package usecase

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
	"github.com/keshvan/auth-service-sstu-forum/mocks"
	"github.com/keshvan/go-common-forum/jwt"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"
)

type AuthUsecaseSuite struct {
	suite.Suite
	usecase   AuthUsecase
	userRepo  *mocks.UserRepository
	tokenRepo *mocks.RefreshTokenRepository
	jwt       *jwt.JWT
	log       *zerolog.Logger
}

func (s *AuthUsecaseSuite) SetupTest() {
	s.userRepo = mocks.NewUserRepository(s.T())
	s.tokenRepo = mocks.NewRefreshTokenRepository(s.T())
	s.jwt = jwt.New("secret", 1*time.Minute, 10*time.Minute)
	logger := zerolog.Nop()
	s.log = &logger
	s.usecase = NewAuthUsecase(s.userRepo, s.tokenRepo, s.jwt, s.log)
}

func TestAuthUsecaseSuite(t *testing.T) {
	suite.Run(t, new(AuthUsecaseSuite))
}

// Register
func (s *AuthUsecaseSuite) TestRegister_Success() {
	ctx := context.Background()
	username := "user"
	role := "user"
	password := "password"
	userID := int64(1)
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	expectedUser := &entity.User{
		ID:           userID,
		Username:     username,
		Role:         role,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	s.userRepo.On("Create", ctx, mock.MatchedBy(func(user *entity.User) bool {
		return user.Username == username && user.Role == role && bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) == nil
	})).Return(userID, nil)

	s.tokenRepo.On("Save", ctx, mock.AnythingOfType("string"), userID).Return(nil).Once()

	s.userRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()

	resp, err := s.usecase.Register(ctx, username, role, password)

	s.NoError(err)
	s.NotNil(resp)
	s.Equal(expectedUser.ID, resp.User.ID)
	s.Equal(expectedUser.Username, resp.User.Username)
	s.NotEmpty(resp.Tokens.AccessToken)
	s.NotEmpty(resp.Tokens.RefreshToken)
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertExpectations(s.T())
}

func (s *AuthUsecaseSuite) TestRegister_CreateUserError() {
	ctx := context.Background()
	username := "user"
	role := "user"
	password := "password"
	expectedError := errors.New("db error on create")

	s.userRepo.On("Create", ctx, mock.AnythingOfType("*entity.User")).Return(int64(0), expectedError).Once()

	resp, err := s.usecase.Register(ctx, username, role, password)

	s.Error(err)
	s.Nil(resp)
	s.ErrorIs(err, expectedError)
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertNotCalled(s.T(), "Save")
	s.userRepo.AssertNotCalled(s.T(), "GetByID")
}

func (s *AuthUsecaseSuite) TestRegister_SaveTokenError() {
	ctx := context.Background()
	username := "user"
	role := "user"
	password := "password"
	userID := int64(1)
	expectedError := errors.New("db error on save token")

	s.userRepo.On("Create", ctx, mock.AnythingOfType("*entity.User")).Return(userID, nil).Once()
	s.tokenRepo.On("Save", ctx, mock.AnythingOfType("string"), userID).Return(expectedError).Once()

	resp, err := s.usecase.Register(ctx, username, role, password)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to save refresh token")
	s.userRepo.AssertNotCalled(s.T(), "GetByID")
	s.tokenRepo.AssertExpectations(s.T())
}

func (s *AuthUsecaseSuite) TestRegister_GetUserAfterCreateError() {
	ctx := context.Background()
	username := "user"
	role := "user"
	password := "password"
	userID := int64(1)
	expectedError := errors.New("db error on get user")

	s.userRepo.On("Create", ctx, mock.AnythingOfType("*entity.User")).Return(userID, nil).Once()
	s.tokenRepo.On("Save", ctx, mock.AnythingOfType("string"), userID).Return(nil).Once()
	s.userRepo.On("GetByID", ctx, userID).Return(nil, expectedError).Once()

	resp, err := s.usecase.Register(ctx, username, role, password)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to get user")
	s.userRepo.AssertExpectations(s.T())
}

