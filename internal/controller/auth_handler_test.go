package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	authrequest "github.com/keshvan/auth-service-sstu-forum/internal/controller/request/auth_request"
	authresponse "github.com/keshvan/auth-service-sstu-forum/internal/controller/response/auth_response.go"
	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
	"github.com/keshvan/auth-service-sstu-forum/mocks"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestAuthHandler_Register_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/register", handler.Register)

	reqBody := authrequest.RegisterRequest{
		Username: "user",
		Password: "password",
		Role:     "user",
	}
	expectedUser := entity.User{ID: 1, Username: "user", Role: "user"}
	expectedTokens := authresponse.Tokens{AccessToken: "new_access_token", RefreshToken: "new_refresh_token"}
	expectedResponse := &authresponse.RegisterResponse{
		User:   expectedUser,
		Tokens: expectedTokens,
	}

	mockUsecase.On("Register", mock.Anything, reqBody.Username, reqBody.Role, reqBody.Password).
		Return(expectedResponse, nil).Once()

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, expectedTokens.AccessToken, respBody["access_token"])

	userMap, ok := respBody["user"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, float64(expectedUser.ID), userMap["id"])
	assert.Equal(t, expectedUser.Username, userMap["username"])

	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, expectedTokens.RefreshToken, cookies[0].Value)

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_Register_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/register", handler.Register)

	req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("{invalid_json"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	mockUsecase.AssertNotCalled(t, "Register", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAuthHandler_Register_UsecaseError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/register", handler.Register)

	reqBody := authrequest.RegisterRequest{
		Username: "testuser",
		Password: "password123",
		Role:     "user",
	}
	usecaseError := errors.New("usecase failed to register")

	mockUsecase.On("Register", mock.Anything, reqBody.Username, reqBody.Role, reqBody.Password).
		Return(nil, usecaseError).Once()

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_Login_SuccessWithoutToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/login", handler.Login)

	reqBody := authrequest.LoginRequest{
		Username: "user",
		Password: "password",
	}
	expectedUser := entity.User{ID: 1, Username: "user", Role: "user"}
	expectedTokens := authresponse.Tokens{AccessToken: "new_access_token", RefreshToken: "new_refresh_token"}
	expectedResponse := &authresponse.LoginResponse{
		User:   expectedUser,
		Tokens: expectedTokens,
	}

	mockUsecase.On("Login", mock.Anything, reqBody.Username, reqBody.Password, "").
		Return(expectedResponse, nil).Once()

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, expectedTokens.AccessToken, respBody["access_token"])
	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, expectedTokens.RefreshToken, cookies[0].Value)

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_Login_SuccessWithToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/login", handler.Login)

	reqBody := authrequest.LoginRequest{
		Username: "user",
		Password: "password",
	}
	oldRefreshTokenValue := "old_refresh_token"
	expectedUser := entity.User{ID: 1, Username: "user", Role: "user"}
	expectedTokens := authresponse.Tokens{AccessToken: "new_access_token", RefreshToken: "new_refresh_token"}
	expectedResponse := &authresponse.LoginResponse{
		User:   expectedUser,
		Tokens: expectedTokens,
	}

	mockUsecase.On("Login", mock.Anything, reqBody.Username, reqBody.Password, oldRefreshTokenValue).
		Return(expectedResponse, nil).Once()

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: oldRefreshTokenValue})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, expectedTokens.AccessToken, respBody["access_token"])
	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, expectedTokens.RefreshToken, cookies[0].Value)

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_Login_InvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/login", handler.Login)

	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBufferString("{invalid_json"))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	mockUsecase.AssertNotCalled(t, "Login", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

func TestAuthHandler_Login_Unauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/login", handler.Login)

	reqBody := authrequest.LoginRequest{
		Username: "user",
		Password: "wrongpassword",
	}
	usecaseError := errors.New("invalid credentials from usecase")

	mockUsecase.On("Login", mock.Anything, reqBody.Username, reqBody.Password, "").
		Return(nil, usecaseError).Once()

	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/login", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_Refresh_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/refresh", handler.Refresh)

	refreshToken := "refresh_token"

	expectedNewTokens := authresponse.Tokens{AccessToken: "refreshed_access_token", RefreshToken: "refreshed_refresh_token"}
	usecaseResponse := &authresponse.RefreshResponse{
		Tokens: expectedNewTokens,
	}

	mockUsecase.On("Refresh", mock.Anything, refreshToken).Return(usecaseResponse, nil).Once()

	req, _ := http.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, expectedNewTokens.AccessToken, respBody["access_token"])
	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, expectedNewTokens.RefreshToken, cookies[0].Value)

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_Refresh_NoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/refresh", handler.Refresh)

	req, _ := http.NewRequest(http.MethodPost, "/refresh", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	mockUsecase.AssertNotCalled(t, "Refresh", mock.Anything, mock.Anything)
}

func TestAuthHandler_Refresh_InvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/refresh", handler.Refresh)

	refreshToken := "invalid_refresh_token"

	usecaseError := errors.New("token is invalid")
	mockUsecase.On("Refresh", mock.Anything, refreshToken).Return(nil, usecaseError).Once()

	req, _ := http.NewRequest(http.MethodPost, "/refresh", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)

	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.True(t, cookies[0].MaxAge < 0)

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_Logout_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/logout", handler.Logout)

	refreshToken := "refresh_token"

	mockUsecase.On("Logout", mock.Anything, refreshToken).Return(nil).Once()

	req, _ := http.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)

	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.True(t, cookies[0].MaxAge < 0)

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_Logout_SuccesWithoutToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/logout", handler.Logout)

	req, _ := http.NewRequest(http.MethodPost, "/logout", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.True(t, cookies[0].MaxAge < 0)

	mockUsecase.AssertNotCalled(t, "Logout", mock.Anything, mock.Anything)
}

func TestAuthHandler_Logout_UsecaseError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/logout", handler.Logout)

	refreshToken := "refresh_token"

	mockUsecase.On("Logout", mock.Anything, refreshToken).Return(errors.New("some usecase error")).Once()

	req, _ := http.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	cookies := rr.Result().Cookies()
	assert.Len(t, cookies, 1)
	assert.Equal(t, "refresh_token", cookies[0].Name)
	assert.Equal(t, "", cookies[0].Value)
	assert.True(t, cookies[0].MaxAge < 0)

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_CheckSession_SessionActive(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.GET("/check-session", handler.CheckSession)

	refreshToken := "refresh_token"

	expectedUser := &entity.User{ID: 1, Username: "user", Role: "user"}
	usecaseResponse := &authresponse.IsSessionActiveResponse{
		User:     expectedUser,
		IsActive: true,
	}
	mockUsecase.On("IsSessionActive", mock.Anything, refreshToken).Return(usecaseResponse, nil).Once()

	req, _ := http.NewRequest(http.MethodGet, "/check-session", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, true, respBody["is_active"])
	userMap, ok := respBody["user"].(map[string]interface{})
	assert.True(t, ok)
	assert.Equal(t, float64(expectedUser.ID), userMap["id"])

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_CheckSession_SessionInactive(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.GET("/check-session", handler.CheckSession)

	refreshToken := "refresh_token"

	usecaseResponse := &authresponse.IsSessionActiveResponse{
		User:     nil,
		IsActive: false,
	}
	mockUsecase.On("IsSessionActive", mock.Anything, refreshToken).Return(usecaseResponse, nil).Once()

	req, _ := http.NewRequest(http.MethodGet, "/check-session", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, false, respBody["is_active"])
	assert.Nil(t, respBody["user"])

	mockUsecase.AssertExpectations(t)
}

func TestAuthHandler_CheckSession_NoToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.GET("/check-session", handler.CheckSession)

	req, _ := http.NewRequest(http.MethodGet, "/check-session", nil)

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, false, respBody["is_active"])
	assert.Nil(t, respBody["user"])

	mockUsecase.AssertNotCalled(t, "IsSessionActive", mock.Anything, mock.Anything)
}

func TestAuthHandler_CheckSession_UsecaseError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.GET("/check-session", handler.CheckSession)

	refreshToken := "refresh_token"

	usecaseError := errors.New("usecase error checking session")
	mockUsecase.On("IsSessionActive", mock.Anything, refreshToken).
		Return(nil, usecaseError).Once()

	req, _ := http.NewRequest(http.MethodGet, "/check-session", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: refreshToken})

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	var respBody map[string]interface{}
	err := json.Unmarshal(rr.Body.Bytes(), &respBody)
	assert.NoError(t, err)
	assert.Equal(t, false, respBody["is_active"])
	assert.Nil(t, respBody["user"])

	mockUsecase.AssertExpectations(t)
}
