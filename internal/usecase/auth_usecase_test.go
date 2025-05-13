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
	username := "testuser"
	role := "user"
	password := "password123"
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
	username := "testuser"
	role := "user"
	password := "password123"
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

//Login

func (s *AuthUsecaseSuite) TestLogin_Success() {
	ctx := context.Background()
	username := "user"
	password := "password"
	userID := int64(1)
	role := "user"

	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	expectedUser := &entity.User{
		ID:           userID,
		Username:     username,
		Role:         role,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}
	oldRefreshToken := "old-refresh-token"

	s.userRepo.On("GetByUsername", ctx, username).Return(expectedUser, nil).Once()
	s.tokenRepo.On("Delete", ctx, oldRefreshToken).Return(nil).Once()
	s.tokenRepo.On("Save", ctx, mock.AnythingOfType("string"), userID).Return(nil).Once()

	resp, err := s.usecase.Login(ctx, username, password, oldRefreshToken)

	s.NoError(err)
	s.NotNil(resp)
	s.Equal(expectedUser.ID, resp.User.ID)
	s.Equal(expectedUser.Username, resp.User.Username)
	s.NotEmpty(resp.Tokens.AccessToken)
	s.NotEmpty(resp.Tokens.RefreshToken)
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertExpectations(s.T())
}

func (s *AuthUsecaseSuite) TestLogin_Success_NoOldToken() {
	ctx := context.Background()
	username := "testuser"
	password := "password123"
	userID := int64(1)
	role := "user"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	expectedUser := &entity.User{
		ID:           userID,
		Username:     username,
		Role:         role,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	s.userRepo.On("GetByUsername", ctx, username).Return(expectedUser, nil).Once()
	s.tokenRepo.On("Save", ctx, mock.AnythingOfType("string"), userID).Return(nil).Once()

	resp, err := s.usecase.Login(ctx, username, password, "")

	s.NoError(err)
	s.NotNil(resp)
	s.Equal(expectedUser.ID, resp.User.ID)
	s.NotEmpty(resp.Tokens.AccessToken)
	s.NotEmpty(resp.Tokens.RefreshToken)
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertNotCalled(s.T(), "Delete", mock.Anything, mock.Anything)
}

func (s *AuthUsecaseSuite) TestLogin_UserNotFound() {
	ctx := context.Background()
	username := "user"
	password := "password"
	expectedError := errors.New("db error on get user")

	s.userRepo.On("GetByUsername", ctx, username).Return(nil, expectedError).Once()

	resp, err := s.usecase.Login(ctx, username, password, "")

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "invalid username or password")
	s.ErrorIs(err, expectedError)
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertNotCalled(s.T(), "Save")
	s.tokenRepo.AssertNotCalled(s.T(), "Delete")
}

func (s *AuthUsecaseSuite) TestLogin_IncorrectPassword() {
	ctx := context.Background()
	username := "testuser"
	password := "wrongpassword"
	userID := int64(1)
	role := "user"

	correctPassword := "password"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(correctPassword), bcrypt.DefaultCost)
	expectedUser := &entity.User{
		ID:           userID,
		Username:     username,
		Role:         role,
		PasswordHash: string(hashedPassword),
		CreatedAt:    time.Now(),
	}

	s.userRepo.On("GetByUsername", ctx, username).Return(expectedUser, nil).Once()

	resp, err := s.usecase.Login(ctx, username, password, "")

	s.Error(err)
	s.Nil(resp)
	s.EqualError(err, "invalid username or password")
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertNotCalled(s.T(), "Save")
	s.tokenRepo.AssertNotCalled(s.T(), "Delete")
}

func (s *AuthUsecaseSuite) TestLogin_DeleteOldTokenError() {
	ctx := context.Background()
	username := "user"
	password := "password"
	userID := int64(1)
	role := "user"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	expectedUser := &entity.User{ID: userID, Username: username, Role: role, PasswordHash: string(hashedPassword)}
	oldRefreshToken := "old-refresh-token"
	expectedError := errors.New("db error on delete token")

	s.userRepo.On("GetByUsername", ctx, username).Return(expectedUser, nil).Once()
	s.tokenRepo.On("Delete", ctx, oldRefreshToken).Return(expectedError).Once()

	resp, err := s.usecase.Login(ctx, username, password, oldRefreshToken)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to delete used refresh token")
	s.ErrorIs(err, expectedError)
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertNotCalled(s.T(), "Save")
}

func (s *AuthUsecaseSuite) TestLogin_SaveTokenError() {
	ctx := context.Background()
	username := "testuser"
	password := "password"
	userID := int64(1)
	role := "user"
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	expectedUser := &entity.User{ID: userID, Username: username, Role: role, PasswordHash: string(hashedPassword)}
	expectedError := errors.New("db error on save token")

	s.userRepo.On("GetByUsername", ctx, username).Return(expectedUser, nil).Once()
	s.tokenRepo.On("Save", ctx, mock.AnythingOfType("string"), userID).Return(expectedError).Once()

	resp, err := s.usecase.Login(ctx, username, password, "")

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to save refresh token")
	s.ErrorIs(err, expectedError)
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertNotCalled(s.T(), "Delete", mock.Anything, mock.Anything) // Delete не вызывался, т.к. old token пуст
}

// Refresh
func (s *AuthUsecaseSuite) TestRefresh_Success() {
	ctx := context.Background()
	userID := int64(1)
	role := "admin"
	refreshToken, _ := s.jwt.GenerateRefreshToken(userID)
	<-time.After(time.Second * 1)
	expectedUser := &entity.User{ID: userID, Username: "refresher", Role: role, CreatedAt: time.Now()}

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(userID, nil).Once()
	s.userRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()
	s.tokenRepo.On("Delete", ctx, refreshToken).Return(nil).Once()
	s.userRepo.On("GetRole", ctx, userID).Return(role, nil).Once()
	s.tokenRepo.On("Save", ctx, mock.AnythingOfType("string"), userID).Return(nil).Once()

	resp, err := s.usecase.Refresh(ctx, refreshToken)
	fmt.Println(refreshToken, resp.Tokens.RefreshToken)
	s.NoError(err)
	s.NotNil(resp)
	s.Equal(expectedUser.ID, resp.User.ID)
	s.Equal(expectedUser.Username, resp.User.Username)
	s.NotEmpty(resp.Tokens.AccessToken)
	s.NotEmpty(resp.Tokens.RefreshToken)
	s.NotEqual(refreshToken, resp.Tokens.RefreshToken)
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertExpectations(s.T())
}

func (s *AuthUsecaseSuite) TestRefresh_InvalidTokenSignature() {
	ctx := context.Background()
	invalidToken := "this.is.invalid"

	resp, err := s.usecase.Refresh(ctx, invalidToken)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "invalid refresh token")
	s.userRepo.AssertNotCalled(s.T(), "GetByID", mock.Anything, mock.Anything)
	s.userRepo.AssertNotCalled(s.T(), "GetRole", mock.Anything, mock.Anything)
	s.tokenRepo.AssertNotCalled(s.T(), "GetUserID", mock.Anything, mock.Anything)
	s.tokenRepo.AssertNotCalled(s.T(), "Delete", mock.Anything, mock.Anything)
	s.tokenRepo.AssertNotCalled(s.T(), "Save", mock.Anything, mock.Anything, mock.Anything)
}

func (s *AuthUsecaseSuite) TestRefresh_TokenNotFoundInRepo() {
	ctx := context.Background()
	userID := int64(1)
	refreshToken, _ := s.jwt.GenerateRefreshToken(userID)
	expectedError := errors.New("token not found")

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(int64(0), expectedError).Once()

	resp, err := s.usecase.Refresh(ctx, refreshToken)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "refresh token not found or invalid")
	s.ErrorIs(err, expectedError)
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertNotCalled(s.T(), "GetByID")
	s.userRepo.AssertNotCalled(s.T(), "GetRole")
	s.tokenRepo.AssertNotCalled(s.T(), "Delete")
	s.tokenRepo.AssertNotCalled(s.T(), "Save")
}

func (s *AuthUsecaseSuite) TestRefresh_UserIDMismatch() {
	ctx := context.Background()
	userIDInToken := int64(1)
	userIDInDB := int64(2)
	refreshToken, _ := s.jwt.GenerateRefreshToken(userIDInToken)

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(userIDInDB, nil).Once()

	resp, err := s.usecase.Refresh(ctx, refreshToken)

	s.Error(err)
	s.Nil(resp)
	s.EqualError(err, "user_id mismatch in refresh token")
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertNotCalled(s.T(), "GetByID")
	s.userRepo.AssertNotCalled(s.T(), "GetRole")
	s.tokenRepo.AssertNotCalled(s.T(), "Delete")
	s.tokenRepo.AssertNotCalled(s.T(), "Save")
}

func (s *AuthUsecaseSuite) TestRefresh_GetUserError() {
	ctx := context.Background()
	userID := int64(1)
	refreshToken, _ := s.jwt.GenerateRefreshToken(userID)
	expectedError := errors.New("db error get user")

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(userID, nil).Once()
	s.userRepo.On("GetByID", ctx, userID).Return(nil, expectedError).Once()

	resp, err := s.usecase.Refresh(ctx, refreshToken)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to get user by ID")
	s.ErrorIs(err, expectedError)
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertNotCalled(s.T(), "Delete")
	s.tokenRepo.AssertNotCalled(s.T(), "Save")
}

func (s *AuthUsecaseSuite) TestRefresh_DeleteTokenError() {
	ctx := context.Background()
	userID := int64(1)
	role := "admin"
	refreshToken, _ := s.jwt.GenerateRefreshToken(userID)
	expectedUser := &entity.User{ID: userID, Username: "refresher", Role: role}
	expectedError := errors.New("db error delete token")

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(userID, nil).Once()
	s.userRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()
	s.tokenRepo.On("Delete", ctx, refreshToken).Return(expectedError).Once()

	resp, err := s.usecase.Refresh(ctx, refreshToken)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to delete used refresh token")
	s.ErrorIs(err, expectedError)
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertExpectations(s.T())
	s.userRepo.AssertNotCalled(s.T(), "GetRole")
	s.tokenRepo.AssertNotCalled(s.T(), "Save")
}

func (s *AuthUsecaseSuite) TestRefresh_GetRoleError() {
	ctx := context.Background()
	userID := int64(1)
	role := "admin"
	refreshToken, _ := s.jwt.GenerateRefreshToken(userID)
	expectedUser := &entity.User{ID: userID, Username: "refresher", Role: role}
	expectedError := errors.New("db error get role")

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(userID, nil).Once()
	s.userRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()
	s.tokenRepo.On("Delete", ctx, refreshToken).Return(nil).Once()
	s.userRepo.On("GetRole", ctx, userID).Return("", expectedError).Once()

	resp, err := s.usecase.Refresh(ctx, refreshToken)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to get user role for refresh")
	s.ErrorIs(err, expectedError)
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertExpectations(s.T())
	s.tokenRepo.AssertNotCalled(s.T(), "Save")
}

func (s *AuthUsecaseSuite) TestRefresh_SaveNewTokenError() {
	ctx := context.Background()
	userID := int64(1)
	role := "admin"
	refreshToken, _ := s.jwt.GenerateRefreshToken(userID)
	expectedUser := &entity.User{ID: userID, Username: "refresher", Role: role}
	expectedError := errors.New("db error save new token")

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(userID, nil).Once()
	s.userRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()
	s.tokenRepo.On("Delete", ctx, refreshToken).Return(nil).Once()
	s.userRepo.On("GetRole", ctx, userID).Return(role, nil).Once()
	s.tokenRepo.On("Save", ctx, mock.AnythingOfType("string"), userID).Return(expectedError).Once()

	resp, err := s.usecase.Refresh(ctx, refreshToken)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to save new refresh token")
	s.ErrorIs(err, expectedError)
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertExpectations(s.T())
}

// Logout
func (s *AuthUsecaseSuite) TestLogout_Success() {
	ctx := context.Background()
	refreshToken := "some-refresh-token"

	s.tokenRepo.On("Delete", ctx, refreshToken).Return(nil).Once()

	err := s.usecase.Logout(ctx, refreshToken)

	s.NoError(err)
	s.tokenRepo.AssertExpectations(s.T())
}

func (s *AuthUsecaseSuite) TestLogout_DeleteError() {
	ctx := context.Background()
	refreshToken := "some-refresh-token"
	expectedError := errors.New("db error on delete")

	s.tokenRepo.On("Delete", ctx, refreshToken).Return(expectedError).Once()

	err := s.usecase.Logout(ctx, refreshToken)

	s.Error(err)
	s.ErrorIs(err, expectedError) // Logout не оборачивает ошибку
	s.tokenRepo.AssertExpectations(s.T())
}

// IsSessionActive
func (s *AuthUsecaseSuite) TestIsSessionActive_Active() {
	ctx := context.Background()
	refreshToken := "active-token"
	userID := int64(1)
	expectedUser := &entity.User{ID: userID, Username: "activeuser", Role: "user"}

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(userID, nil).Once()
	s.userRepo.On("GetByID", ctx, userID).Return(expectedUser, nil).Once()

	resp, err := s.usecase.IsSessionActive(ctx, refreshToken)

	s.NoError(err)
	s.NotNil(resp)
	s.True(resp.IsActive)
	s.NotNil(resp.User)
	s.Equal(expectedUser.ID, resp.User.ID)
	s.Equal(expectedUser.Username, resp.User.Username)
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertExpectations(s.T())
}

func (s *AuthUsecaseSuite) TestIsSessionActive_Inactive_TokenNotFound() {
	ctx := context.Background()
	refreshToken := "non-existent-token"
	expectedError := pgx.ErrNoRows

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(int64(0), expectedError).Once()

	resp, err := s.usecase.IsSessionActive(ctx, refreshToken)

	s.NoError(err)
	s.NotNil(resp)
	s.False(resp.IsActive)
	s.Nil(resp.User)
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertNotCalled(s.T(), "GetByID")
}

func (s *AuthUsecaseSuite) TestIsSessionActive_Inactive_EmptyToken() {
	ctx := context.Background()
	refreshToken := ""

	resp, err := s.usecase.IsSessionActive(ctx, refreshToken)

	s.NoError(err)
	s.NotNil(resp)
	s.False(resp.IsActive)
	s.Nil(resp.User)
	s.tokenRepo.AssertNotCalled(s.T(), "GetUserID")
	s.userRepo.AssertNotCalled(s.T(), "GetByID")
}

func (s *AuthUsecaseSuite) TestIsSessionActive_GetUserIDError() {
	ctx := context.Background()
	refreshToken := "active-token"
	expectedError := errors.New("db error get user id") // Любая ошибка, кроме ErrNoRows

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(int64(0), expectedError).Once()

	resp, err := s.usecase.IsSessionActive(ctx, refreshToken)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to check if session is active")
	s.ErrorIs(err, expectedError)
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertNotCalled(s.T(), "GetByID")
}

func (s *AuthUsecaseSuite) TestIsSessionActive_GetUserError() {
	ctx := context.Background()
	refreshToken := "active-token"
	userID := int64(1)
	expectedError := errors.New("db error get user")

	s.tokenRepo.On("GetUserID", ctx, refreshToken).Return(userID, nil).Once()
	s.userRepo.On("GetByID", ctx, userID).Return(nil, expectedError).Once()

	resp, err := s.usecase.IsSessionActive(ctx, refreshToken)

	s.Error(err)
	s.Nil(resp)
	s.Contains(err.Error(), "failed to get user by ID")
	s.ErrorIs(err, expectedError)
	s.tokenRepo.AssertExpectations(s.T())
	s.userRepo.AssertExpectations(s.T())
}
