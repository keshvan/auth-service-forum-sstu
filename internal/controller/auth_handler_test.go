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

func TestAuthHandler_Register(t *testing.T) {
	router := gin.New()
	mockUsecase := mocks.NewAuthUsecase(t)
	log := zerolog.Nop()
	handler := &AuthHandler{
		usecase: mockUsecase,
		log:     &log,
	}
	router.POST("/register", handler.Register)

	t.Run("Success", func(t *testing.T) {
		reqBody := authrequest.RegisterRequest{
			Username: "testuser",
			Password: "password123",
			Role:     "user",
		}
		expectedUser := entity.User{ID: 1, Username: "testuser", Role: "user"}
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
		assert.Equal(t, float64(expectedUser.ID), userMap["id"]) // JSON числа это float64
		assert.Equal(t, expectedUser.Username, userMap["username"])

		cookies := rr.Result().Cookies()
		assert.Len(t, cookies, 1)
		assert.Equal(t, "refresh_token", cookies[0].Name)
		assert.Equal(t, expectedTokens.RefreshToken, cookies[0].Value)

		mockUsecase.AssertExpectations(t)
	})

	t.Run("Bad Request - Invalid JSON", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "/register", bytes.NewBufferString("{invalid_json"))
		req.Header.Set("Content-Type", "application/json")

		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		assert.Equal(t, http.StatusBadRequest, rr.Code)
		mockUsecase.AssertNotCalled(t, "Register", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
	})

	t.Run("Usecase Error", func(t *testing.T) {
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
	})
}
