package main

import (
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bosley/lighthouse/api"
	"github.com/bosley/lighthouse/ds"

	"crypto/rand"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupTestServer(db *gorm.DB) *httptest.Server {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	setupRoutes(router, db)
	return httptest.NewTLSServer(router)
}

func TestCreateUser(t *testing.T) {
	db, _ := setupTestDatabase()
	server := setupTestServer(db)
	defer server.Close()

	lighthouseAPI := api.NewLighthouseAPI(server.URL, api.WithSelfSignedCerts())

	t.Run("Valid user creation", func(t *testing.T) {
		magicLink, err := lighthouseAPI.CreateUser("test@example.com", "testuser", "password123")
		assert.NoError(t, err)
		assert.NotEmpty(t, magicLink)
	})

	t.Run("Duplicate user", func(t *testing.T) {
		_, err := lighthouseAPI.CreateUser("test@example.com", "testuser", "password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "User already exists")
	})

	t.Run("Invalid email", func(t *testing.T) {
		_, err := lighthouseAPI.CreateUser("invalid-email", "testuser2", "password123")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Field validation for 'Email' failed on the 'email' tag")
	})

	t.Run("Short password", func(t *testing.T) {
		_, err := lighthouseAPI.CreateUser("test2@example.com", "testuser2", "short")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Password")
	})
}

func TestVerifyUser(t *testing.T) {
	db, _ := setupTestDatabase()
	server := setupTestServer(db)
	defer server.Close()

	lighthouseAPI := api.NewLighthouseAPI(server.URL, api.WithSelfSignedCerts())

	t.Run("Valid verification", func(t *testing.T) {
		magicLink, _ := lighthouseAPI.CreateUser("verify@example.com", "verifyuser", "password123")
		err := lighthouseAPI.VerifyUser(magicLink)
		assert.NoError(t, err)
	})

	t.Run("Invalid magic link", func(t *testing.T) {
		err := lighthouseAPI.VerifyUser("invalid-magic-link")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid magic link")
	})

	t.Run("Expired magic link", func(t *testing.T) {
		// Create an expired token
		expiredToken := createExpiredToken(t, db)
		encodedToken := base64.StdEncoding.EncodeToString([]byte(expiredToken))
		err := lighthouseAPI.VerifyUser(encodedToken)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid or expired magic link")
	})
}

func TestLoginUser(t *testing.T) {
	db, _ := setupTestDatabase()
	server := setupTestServer(db)
	defer server.Close()

	lighthouseAPI := api.NewLighthouseAPI(server.URL, api.WithSelfSignedCerts())

	// Create a user for login tests
	lighthouseAPI.CreateUser("login@example.com", "loginuser", "password123")

	t.Run("Valid login", func(t *testing.T) {
		token, err := lighthouseAPI.LoginUser("login@example.com", "", "password123", "30m")
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("Invalid credentials", func(t *testing.T) {
		_, err := lighthouseAPI.LoginUser("login@example.com", "", "wrongpassword", "30m")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Invalid credentials")
	})

	t.Run("Invalid duration", func(t *testing.T) {
		token, err := lighthouseAPI.LoginUser("login@example.com", "", "password123", "invalid")
		assert.NoError(t, err) // Should not error, but use default duration
		assert.NotEmpty(t, token)
	})
}

func TestBlacklistToken(t *testing.T) {
	db, err := setupTestDatabase()
	assert.NoError(t, err)

	// Generate a random key for each test run using crypto/rand
	randomKey := make([]byte, 32)
	_, err = rand.Read(randomKey)
	assert.NoError(t, err)

	ServerConfig = ConfigInfo{
		DB:   db,
		SKey: randomKey,
	}

	server := setupTestServer(db)
	defer server.Close()

	lighthouseAPI := api.NewLighthouseAPI(server.URL, api.WithSelfSignedCerts())

	// Create a user and login to get a token
	_, err = lighthouseAPI.CreateUser("blacklist@example.com", "blacklistuser", "password123")
	assert.NoError(t, err)
	token, err := lighthouseAPI.LoginUser("blacklist@example.com", "", "password123", "30m")
	assert.NoError(t, err)

	t.Run("Valid token blacklisting", func(t *testing.T) {
		err := lighthouseAPI.Blacklist(token)
		assert.NoError(t, err)
	})

	t.Run("Using blacklisted token", func(t *testing.T) {
		err := lighthouseAPI.Blacklist(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Token is already blacklisted")
	})

	// Log back in to get a new token
	newToken, err := lighthouseAPI.LoginUser("blacklist@example.com", "", "password123", "30m")
	assert.NoError(t, err)

	t.Run("Blacklisting already blacklisted token", func(t *testing.T) {
		err := lighthouseAPI.Blacklist(token) // Use the old, blacklisted token
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Token is already blacklisted")
	})

	t.Run("Blacklisting non-existent token", func(t *testing.T) {
		err := lighthouseAPI.Blacklist("invalid.token.here")
		assert.Error(t, err)
	})

	// Test with the new, valid token
	t.Run("Blacklisting new valid token", func(t *testing.T) {
		err := lighthouseAPI.Blacklist(newToken)
		assert.NoError(t, err)
	})
}

func createExpiredToken(t *testing.T, db *gorm.DB) string {
	// Create a user
	user := ds.User{
		Email:              "expired@example.com",
		Username:           "expireduser",
		PasswordBcryptHash: []byte("hashedpassword"),
	}
	db.Create(&user)

	// Create an expired token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
	})

	tokenString, err := token.SignedString([]byte("super-secret-key"))
	assert.NoError(t, err)

	return tokenString
}

func setupTestDatabase() (*gorm.DB, error) {
	// Create a unique in-memory SQLite database for each test
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared&_fk=1"), &gorm.Config{})
	if err != nil {
		return nil, err
	}

	// Run migrations
	err = db.AutoMigrate(&ds.User{}, &ds.TokenData{}, &ds.UserMeta{})
	if err != nil {
		return nil, err
	}

	return db, nil
}

// Add this function to set up routes for testing
func setupRoutes(router *gin.Engine, db *gorm.DB) {
	v1 := router.Group("/api/v1")
	{
		v1.POST("/users/new", createUser(db))
		v1.GET("/verify", verifyUser(db))
		v1.POST("/auth", loginUser(db))

		vip := v1.Group("/vip")
		vip.Use(tokenAuthMiddleware(db))
		{
			vip.GET("/blacklist/:token", blacklistToken(db))
		}
	}
}

func TestLogoutUser(t *testing.T) {
	db, err := setupTestDatabase()
	assert.NoError(t, err)

	server := setupTestServer(db)
	defer server.Close()

	lighthouseAPI := api.NewLighthouseAPI(server.URL, api.WithSelfSignedCerts())

	// Create a user and login
	_, err = lighthouseAPI.CreateUser("logout@example.com", "logoutuser", "password123")
	assert.NoError(t, err)
	token, err := lighthouseAPI.LoginUser("logout@example.com", "", "password123", "30m")
	assert.NoError(t, err)
	assert.NotEmpty(t, token)

	t.Run("Successful logout", func(t *testing.T) {
		err := lighthouseAPI.Logout()
		assert.NoError(t, err)
	})

	t.Run("Logout when already logged out", func(t *testing.T) {
		err := lighthouseAPI.Logout()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "user is not currently logged in")
	})

	t.Run("Attempt to use token after logout", func(t *testing.T) {
		err := lighthouseAPI.Blacklist(token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Missing token")
	})
}
