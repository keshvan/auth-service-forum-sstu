package main_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"

	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/keshvan/auth-service-sstu-forum/config"
	"github.com/keshvan/auth-service-sstu-forum/internal/controller"
	authrequest "github.com/keshvan/auth-service-sstu-forum/internal/controller/request/auth_request"
	"github.com/keshvan/auth-service-sstu-forum/internal/entity"
	"github.com/keshvan/auth-service-sstu-forum/internal/repo"
	"github.com/keshvan/auth-service-sstu-forum/internal/usecase"
	"github.com/keshvan/go-common-forum/jwt"
	"github.com/keshvan/go-common-forum/logger"
	"github.com/keshvan/go-common-forum/postgres"
)

var (
	testConfig *config.Config
	testServer *httptest.Server
	testClient *http.Client
	testDB     *sql.DB
)

func cleanupTables(t *testing.T, db *sql.DB) {
	require.NotNil(t, db, "DB connection for cleanup should not be nil")
	_, err := db.ExecContext(context.Background(), "DELETE FROM refresh_tokens")
	require.NoError(t, err, "Failed to cleanup refresh_tokens table")
	_, err = db.ExecContext(context.Background(), "DELETE FROM users")
	require.NoError(t, err, "Failed to cleanup users table")
	t.Log("Test tables cleaned up.")
}

func TestMain(m *testing.M) {
	gin.SetMode(gin.TestMode)
	var err error

	testConfig, err = config.NewTestConfig()
	if err != nil {
		log.Fatalf("Failed to load test_config.yaml: %s", err)
	}

	testDB, err = sql.Open("pgx", testConfig.PG_URL)
	if err != nil {
		log.Fatalf("Failed to open database connection: %v", err)
	}

	err = testDB.PingContext(context.Background())
	if err != nil {
		log.Fatalf("Failed to ping database: %v. PG_URL: %s", err, testConfig.PG_URL)
	}
	log.Println("Successfully connected to the database for tests.")

	pgInstanceForMigration, err := postgres.New(testConfig.PG_URL)
	if err != nil {
		log.Fatalf("Postgres.New (for migration) failed: %v", err)
	}

	errRunMigrations := pgInstanceForMigration.RunMigrations(context.Background(), "migrations")
	pgInstanceForMigration.Close()
	if errRunMigrations != nil {
		log.Fatalf("RunMigrations failed: %v", errRunMigrations)
	}
	log.Println("Migrations applied successfully.")

	log.Println("Initial cleanup of tables before running tests...")
	_, errDelRT := testDB.ExecContext(context.Background(), "DELETE FROM refresh_tokens")
	_, errDelU := testDB.ExecContext(context.Background(), "DELETE FROM users")
	if errDelRT != nil || errDelU != nil {
		log.Printf("Warning: initial cleanup might have failed. RT err: %v, Users err: %v", errDelRT, errDelU)
	} else {
		log.Println("Initial tables cleanup successful.")
	}

	router := setupTestRouter(nil)
	testServer = httptest.NewServer(router)

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalf("Failed to create cookie jar: %s", err)
	}
	testClient = &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second, // Добавим таймаут для клиента
	}

	code := m.Run()

	testServer.Close()
	testDB.Close()
	os.Exit(code)
}

func doRequest(t *testing.T, method, path string, body io.Reader) *http.Response {
	req, err := http.NewRequest(method, testServer.URL+path, body)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := testClient.Do(req)
	require.NoError(t, err)
	return resp
}

func getRefreshTokenFromClientCookies(t *testing.T) string {
	serverURL, err := url.Parse(testServer.URL)
	require.NoError(t, err)
	cookies := testClient.Jar.Cookies(serverURL)
	for _, cookie := range cookies {
		if cookie.Name == "refresh_token" {
			return cookie.Value
		}
	}
	return ""
}

func TestAuthEndpoints(t *testing.T) {
	var currentAccessToken string
	var registeredUserID int64
	var initialRegisteredUsername = "testuser" + fmt.Sprintf("%d", time.Now().UnixNano())
	var registeredRole = "user"

	cleanupTables(t, testDB)

	t.Run("UserRegistration", func(t *testing.T) {
		username := initialRegisteredUsername
		regData := authrequest.RegisterRequest{
			Username: username,
			Role:     registeredRole,
			Password: "password123",
		}
		jsonData, err := json.Marshal(regData)
		require.NoError(t, err)

		resp := doRequest(t, http.MethodPost, "/register", bytes.NewBuffer(jsonData))
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode, "Registration status code should be 200 OK")

		var regResponse map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&regResponse)
		require.NoError(t, err)

		accessToken, ok := regResponse["access_token"].(string)
		require.True(t, ok, "access_token missing in registration response")
		currentAccessToken = accessToken

		userMap, ok := regResponse["user"].(map[string]interface{})
		require.True(t, ok, "user object missing in registration response")
		assert.Equal(t, username, userMap["username"])
		idFloat, idOk := userMap["id"].(float64)
		require.True(t, idOk, "user.id missing or not a number")
		registeredUserID = int64(idFloat)

		// DB Checks
		var dbUser entity.User
		err = testDB.QueryRowContext(context.Background(), "SELECT id, username, role, password_hash FROM users WHERE username = $1", username).Scan(&dbUser.ID, &dbUser.Username, &dbUser.Role, &dbUser.PasswordHash)
		require.NoError(t, err, "User not found in DB after registration")
		assert.Equal(t, username, dbUser.Username)
		assert.Equal(t, registeredRole, dbUser.Role)
		assert.NotEmpty(t, dbUser.PasswordHash)
		assert.Equal(t, registeredUserID, dbUser.ID)

		refreshTokenFromCookie := getRefreshTokenFromClientCookies(t)
		require.NotEmpty(t, refreshTokenFromCookie, "Refresh token cookie not set or empty after registration")

		var dbTokenUserID int64
		err = testDB.QueryRowContext(context.Background(), "SELECT user_id FROM refresh_tokens WHERE token = $1", refreshTokenFromCookie).Scan(&dbTokenUserID)
		require.NoError(t, err, "Refresh token not found in DB for the registered user")
		assert.Equal(t, registeredUserID, dbTokenUserID)
		t.Logf("User %s (ID: %d) registered. DB checks passed.", username, registeredUserID)
	})

	require.NotEmpty(t, currentAccessToken, "AccessToken is empty after registration")
	require.NotZero(t, registeredUserID, "RegisteredUserID is zero after registration")

	t.Run("CheckSession_ValidAfterRegistration", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, "/check-session", nil)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var sessionResponse map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&sessionResponse)
		require.NoError(t, err)
		isActive, _ := sessionResponse["is_active"].(bool)
		assert.True(t, isActive, "Session should be active")
		userMap, _ := sessionResponse["user"].(map[string]interface{})
		require.NotNil(t, userMap, "User map should not be nil for active session")
		assert.Equal(t, initialRegisteredUsername, userMap["username"])
	})

	var refreshTokenBeforeRefresh string
	t.Run("TokenRefresh", func(t *testing.T) {
		refreshTokenBeforeRefresh = getRefreshTokenFromClientCookies(t)
		require.NotEmpty(t, refreshTokenBeforeRefresh, "Refresh token cookie is empty before /refresh call")

		time.Sleep(1 * time.Second)
		resp := doRequest(t, http.MethodPost, "/refresh", nil)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var refreshApiResponse map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&refreshApiResponse)
		require.NoError(t, err)
		newAccessToken, ok := refreshApiResponse["access_token"].(string)
		require.True(t, ok, "access_token missing in /refresh response")
		assert.NotEqual(t, currentAccessToken, newAccessToken, "Access token should change after refresh")
		currentAccessToken = newAccessToken

		refreshedTokenFromCookie := getRefreshTokenFromClientCookies(t)
		require.NotEmpty(t, refreshedTokenFromCookie, "New refresh token cookie not set or empty after /refresh")
		assert.NotEqual(t, refreshTokenBeforeRefresh, refreshedTokenFromCookie, "Refresh token in cookie should change after /refresh")

		// DB Checks: old refresh token deleted, new one created
		var countOldToken int
		err = testDB.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM refresh_tokens WHERE token = $1", refreshTokenBeforeRefresh).Scan(&countOldToken)
		require.NoError(t, err)
		assert.Zero(t, countOldToken, "Old refresh token should be deleted from DB after successful /refresh")

		var newDbTokenUserID int64
		err = testDB.QueryRowContext(context.Background(), "SELECT user_id FROM refresh_tokens WHERE token = $1", refreshedTokenFromCookie).Scan(&newDbTokenUserID)
		require.NoError(t, err, "New refresh token not found in DB after /refresh")
		assert.Equal(t, registeredUserID, newDbTokenUserID)
		t.Log("Tokens refreshed. DB checks passed.")
	})

	var refreshTokenBeforeLogout string
	t.Run("UserLogout", func(t *testing.T) {
		refreshTokenBeforeLogout = getRefreshTokenFromClientCookies(t)
		require.NotEmpty(t, refreshTokenBeforeLogout, "Refresh token cookie is empty before /logout call")

		resp := doRequest(t, http.MethodPost, "/logout", nil)
		time.Sleep(1 * time.Second)
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var logoutResponse map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&logoutResponse)
		assert.Equal(t, "logged out successfully", logoutResponse["message"])

		currentRefreshTokenAfterLogout := getRefreshTokenFromClientCookies(t)
		if currentRefreshTokenAfterLogout != "" {
			t.Logf("Warning: Refresh token cookie value is '%s' after logout, expected empty or MaxAge<0 by server", currentRefreshTokenAfterLogout)
		}

		// DB Check: refresh token deleted
		var count int
		err := testDB.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM refresh_tokens WHERE token = $1", refreshTokenBeforeLogout).Scan(&count)
		require.NoError(t, err)
		assert.Zero(t, count, "Refresh token should be deleted from DB after logout")
		t.Log("User logged out. DB check passed.")
	})

	t.Run("CheckSession_InvalidAfterLogout", func(t *testing.T) {
		resp := doRequest(t, http.MethodGet, "/check-session", nil)
		defer resp.Body.Close()
		require.Equal(t, http.StatusUnauthorized, resp.StatusCode, "Expected Unauthorized for /check-session after logout")

		var sessionResponse map[string]interface{}
		err := json.NewDecoder(resp.Body).Decode(&sessionResponse)
		require.NoError(t, err)
		isActive, _ := sessionResponse["is_active"].(bool)
		assert.False(t, isActive, "Session should be inactive after logout")
		assert.Nil(t, sessionResponse["user"], "User should be nil after logout")
	})
	t.Run("UserLogin_ExistingUserAfterLogout", func(t *testing.T) {
		loginData := authrequest.LoginRequest{
			Username: initialRegisteredUsername, // Use the same user
			Password: "password123",
		}
		jsonData, err := json.Marshal(loginData)
		require.NoError(t, err)

		// Ensure cookie jar is clean or contains the (now invalid) logout cookie for this test part
		// The Login usecase should delete the old refresh token if passed.
		// Our testClient will send the cookie if it has one for the domain.

		resp := doRequest(t, http.MethodPost, "/login", bytes.NewBuffer(jsonData))
		defer resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)

		var loginResponse map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&loginResponse)
		require.NoError(t, err)
		newAccessToken, ok := loginResponse["access_token"].(string)
		require.True(t, ok)
		currentAccessToken = newAccessToken // Update current access token

		userMap, ok := loginResponse["user"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, initialRegisteredUsername, userMap["username"])
		idFloat, idOk := userMap["id"].(float64)
		require.True(t, idOk)
		assert.Equal(t, registeredUserID, int64(idFloat)) // Should be the same user ID

		// DB Check: a new refresh token should be created
		newRefreshTokenFromCookie := getRefreshTokenFromClientCookies(t)
		require.NotEmpty(t, newRefreshTokenFromCookie, "New refresh token cookie not set after login")
		// It must be different from the one that was presumably invalidated by logout
		assert.NotEqual(t, refreshTokenBeforeLogout, newRefreshTokenFromCookie, "New refresh token after login should be different from the one before logout")

		var dbTokenUserID int64
		err = testDB.QueryRowContext(context.Background(), "SELECT user_id FROM refresh_tokens WHERE token = $1", newRefreshTokenFromCookie).Scan(&dbTokenUserID)
		require.NoError(t, err, "New refresh token not found in DB after login")
		assert.Equal(t, registeredUserID, dbTokenUserID)

		// Also, ensure the token that might have been sent from cookie (refreshTokenBeforeLogout) is now deleted
		// if it wasn't already. Your Login usecase deletes the passed refresh_token.
		if refreshTokenBeforeLogout != "" { // Only check if there was one
			var countOldToken int
			err = testDB.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM refresh_tokens WHERE token = $1", refreshTokenBeforeLogout).Scan(&countOldToken)
			if err != nil && !strings.Contains(err.Error(), "no rows in result set") { // pgx.ErrNoRows is fine here
				require.NoError(t, err, "Error checking for old refresh token after login")
			}
			assert.Zero(t, countOldToken, "The refresh token active before logout (and sent by cookie jar during login) should be deleted by Login usecase")
		}
		t.Logf("User %s logged in again. DB checks passed.", initialRegisteredUsername)
	})
}

func setupTestRouter(t *testing.T) http.Handler {
	appLogger := logger.New("test-auth-integr", testConfig.LogLevel) // Используем testConfig

	// Важно: pgInstanceForApp должен использовать тот же testConfig.PG_URL, что и testDB
	pgInstanceForApp, err := postgres.New(testConfig.PG_URL)
	if t != nil { // Если вызывается из тестовой функции
		require.NoError(t, err, "setupTestRouter: Failed to create pgInstanceForApp")
	} else { // Если вызывается из TestMain
		if err != nil {
			log.Fatalf("setupTestRouter (from TestMain): Failed to create pgInstanceForApp: %v", err)
		}
	}
	// Замечание: pgInstanceForApp создается при каждом вызове setupTestRouter.
	// В идеале, для всего пакета тестов должен быть один экземпляр подключения для приложения.
	// Но для простоты оставим так. Этот экземпляр будет жить столько, сколько живет testEngine/testServer.
	// В TestMain мы не закрываем pgInstanceForApp, т.к. он используется активным testServer.
	// Он закроется косвенно, когда testServer будет остановлен, если GC его соберет.
	// Для явного управления лучше инициализировать в TestMain и передавать.

	userRepo := repo.NewUserRepository(pgInstanceForApp, appLogger)
	tokenRepo := repo.NewRefreshTokenRepository(pgInstanceForApp, appLogger)

	// Убедимся, что testConfig не nil и содержит значения для JWT
	if testConfig == nil {
		log.Fatalf("setupTestRouter: testConfig is nil before JWT initialization")
	}
	if testConfig.Secret == "" || testConfig.AccessTTL == 0 || testConfig.RefreshTTL == 0 {
		log.Fatalf("setupTestRouter: JWT config values in testConfig are zero/empty. Secret: '%s', AccessTTL: %v, RefreshTTL: %v",
			testConfig.Secret, testConfig.AccessTTL, testConfig.RefreshTTL)
	}

	appJwt := jwt.New(testConfig.Secret, testConfig.AccessTTL, testConfig.RefreshTTL)
	authUsecase := usecase.NewAuthUsecase(userRepo, tokenRepo, appJwt, appLogger)

	testEngine := gin.New()
	controller.NewRouter(testEngine, authUsecase, appJwt, appLogger)
	return testEngine
}
