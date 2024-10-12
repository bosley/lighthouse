package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bosley/lighthouse/api"
	"github.com/bosley/lighthouse/ds"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gorm.io/gorm"
)

type ConfigInfo struct {
	DB        *gorm.DB
	TLSConfig *tls.Config
	Port      string
	SKey      []byte
}

func Serve() error {
	router := gin.Default()

	// Set up rate limiters
	newUserLimiter := rate.NewLimiter(10, 1)
	verifyLimiter := rate.NewLimiter(10, 1)
	authLimiter := rate.NewLimiter(5, 1)
	blacklistLimiter := rate.NewLimiter(10, 1)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		v1.POST("/users/new", rateLimitMiddleware(newUserLimiter), createUser(ServerConfig.DB))
		v1.GET("/verify", rateLimitMiddleware(verifyLimiter), verifyUser(ServerConfig.DB))
		v1.POST("/auth", rateLimitMiddleware(authLimiter), loginUser(ServerConfig.DB))

		// Protected routes
		vip := v1.Group("/vip")
		vip.Use(tokenAuthMiddleware(ServerConfig.DB))
		{
			vip.GET("/blacklist/:token", rateLimitMiddleware(blacklistLimiter), blacklistToken(ServerConfig.DB))
		}
	}

	// Set up TLS
	server := &http.Server{
		Addr:      ServerConfig.Port, // You may want to make this configurable
		Handler:   router,
		TLSConfig: ServerConfig.TLSConfig,
	}

	// Start the server
	return server.ListenAndServeTLS("", "") // Certificates should be provided in TLSConfig
}

func rateLimitMiddleware(limiter *rate.Limiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, api.ApiResponse{Code: http.StatusTooManyRequests, Message: "Rate limit exceeded"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func tokenAuthMiddleware(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Lighthouse-Token")
		if token == "" {
			c.JSON(http.StatusUnauthorized, api.ApiResponse{Code: http.StatusUnauthorized, Message: "Missing token"})
			c.Abort()
			return
		}
		var tokenData ds.TokenData
		result := db.Where("token = ?", token).First(&tokenData)
		if result.Error != nil {
			if result.Error == gorm.ErrRecordNotFound {
				c.JSON(http.StatusUnauthorized, api.ApiResponse{Code: http.StatusUnauthorized, Message: "Token not found"})
			} else {
				c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Database error"})
			}
			c.Abort()
			return
		}

		if tokenData.Disabled {
			c.JSON(http.StatusUnauthorized, api.ApiResponse{Code: http.StatusUnauthorized, Message: "Token is already blacklisted"})
			c.Abort()
			return
		}

		// Verify token
		claims := jwt.MapClaims{}
		parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return ServerConfig.SKey, nil
		})

		if err != nil || !parsedToken.Valid {
			c.JSON(http.StatusUnauthorized, api.ApiResponse{Code: http.StatusUnauthorized, Message: "Invalid token"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func createUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var newUser api.NewUser
		if err := c.ShouldBindJSON(&newUser); err != nil {
			c.JSON(http.StatusBadRequest, api.ApiResponse{Code: http.StatusBadRequest, Message: "Invalid request body"})
			return
		}

		validate := validator.New()
		if err := validate.Struct(newUser); err != nil {
			validationErrors := err.(validator.ValidationErrors)
			errorMessages := make([]string, len(validationErrors))
			for i, e := range validationErrors {
				errorMessages[i] = fmt.Sprintf("Field validation for '%s' failed on the '%s' tag", e.Field(), e.Tag())
			}
			c.JSON(http.StatusBadRequest, api.ApiResponse{Code: http.StatusBadRequest, Message: strings.Join(errorMessages, "; ")})
			return
		}

		// Check if user already exists
		var existingUser ds.User
		result := db.Where("email = ? OR username = ?", newUser.Email, newUser.Username).First(&existingUser)
		if result.Error == nil {
			c.JSON(http.StatusConflict, api.ApiResponse{Code: http.StatusConflict, Message: "User already exists"})
			return
		} else if result.Error != gorm.ErrRecordNotFound {
			c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Database error"})
			return
		}

		// Hash the password
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newUser.Password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Error hashing password"})
			return
		}

		// Create new user
		user := ds.User{
			Email:              newUser.Email,
			Username:           newUser.Username,
			PasswordBcryptHash: hashedPassword,
		}

		if err := db.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Error creating user"})
			return
		}

		// Generate verification JWT
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": user.ID,
			"exp": time.Now().Add(24 * time.Hour).Unix(),
		})

		tokenString, err := token.SignedString(ServerConfig.SKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Error generating verification token"})
			return
		}

		// Base64 encode the token
		encodedToken := base64.StdEncoding.EncodeToString([]byte(tokenString))

		c.JSON(http.StatusOK, api.ApiResponse{Code: http.StatusOK, Message: encodedToken})
	}
}

func verifyUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		encodedToken := c.GetHeader("Lighthouse-Magic-Link")
		if encodedToken == "" {
			c.JSON(http.StatusBadRequest, api.ApiResponse{Code: http.StatusBadRequest, Message: "Missing magic link"})
			return
		}

		// Decode the token
		tokenBytes, err := base64.StdEncoding.DecodeString(encodedToken)
		if err != nil {
			c.JSON(http.StatusBadRequest, api.ApiResponse{Code: http.StatusBadRequest, Message: "Invalid magic link"})
			return
		}

		// Verify the token
		token, err := jwt.Parse(string(tokenBytes), func(token *jwt.Token) (interface{}, error) {
			return ServerConfig.SKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusBadRequest, api.ApiResponse{Code: http.StatusBadRequest, Message: "Invalid or expired magic link"})
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Error processing token"})
			return
		}

		userID := uint(claims["sub"].(float64))

		// Update user as verified
		if err := db.Model(&ds.User{}).Where("id = ?", userID).Update("is_verified", true).Error; err != nil {
			c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Error verifying user"})
			return
		}

		c.JSON(http.StatusOK, api.ApiResponse{Code: http.StatusOK, Message: "User verified successfully"})
	}
}

func loginUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var userLogin api.UserLogin
		if err := c.ShouldBindJSON(&userLogin); err != nil {
			c.JSON(http.StatusBadRequest, api.ApiResponse{Code: http.StatusBadRequest, Message: "Invalid request body"})
			return
		}

		var user ds.User
		result := db.Where("email = ? OR username = ?", userLogin.Email, userLogin.Username).First(&user)
		if result.Error != nil {
			c.JSON(http.StatusUnauthorized, api.ApiResponse{Code: http.StatusUnauthorized, Message: "Invalid credentials"})
			return
		}

		if err := bcrypt.CompareHashAndPassword(user.PasswordBcryptHash, []byte(userLogin.Password)); err != nil {
			c.JSON(http.StatusUnauthorized, api.ApiResponse{Code: http.StatusUnauthorized, Message: "Invalid credentials"})
			return
		}

		// Parse and validate requested duration
		duration, err := time.ParseDuration(userLogin.RequestedDuration)
		if err != nil || duration < 5*time.Minute || duration > 60*time.Minute {
			duration = 60 * time.Minute // Default to 60 minutes if invalid or out of range
		}

		// Create the JWT token with "iat" and "jti" claims
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"sub": user.ID,
			"exp": time.Now().Add(duration).Unix(),
			"iat": time.Now().Unix(),
			"jti": uuid.New().String(),
		})

		tokenString, err := token.SignedString(ServerConfig.SKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, api.ApiResponse{
				Code:    http.StatusInternalServerError,
				Message: "Error generating token",
			})
			return
		}

		// Store the token in the database
		tokenData := ds.TokenData{
			AssociatedUserID: user.ID,
			Generated:        time.Now(),
			Token:            tokenString,
		}

		if err := db.Create(&tokenData).Error; err != nil {
			errorMsg := fmt.Sprintf("Error storing token: %v", err)
			c.JSON(http.StatusInternalServerError, api.ApiResponse{
				Code:    http.StatusInternalServerError,
				Message: errorMsg,
			})
			return
		}

		c.JSON(http.StatusOK, api.ApiResponse{
			Code:    http.StatusOK,
			Message: tokenString,
		})
	}
}

func blacklistToken(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.Param("token")

		// Verify the token first
		claims := jwt.MapClaims{}
		_, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
			return ServerConfig.SKey, nil
		})

		if err != nil {
			c.JSON(http.StatusBadRequest, api.ApiResponse{Code: http.StatusBadRequest, Message: "Invalid Token"})
			return
		}

		var tokenData ds.TokenData
		result := db.Where("token = ?", token).First(&tokenData)

		if result.Error == gorm.ErrRecordNotFound {
			// Token not found in the database, create a new blacklisted entry
			tokenData = ds.TokenData{
				Token:    token,
				Disabled: true,
			}
			if err := db.Create(&tokenData).Error; err != nil {
				c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Failed to blacklist token"})
				return
			}
			c.JSON(http.StatusOK, api.ApiResponse{Code: http.StatusOK, Message: "Token blacklisted successfully"})
			return
		}

		if result.Error != nil {
			c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Database error"})
			return
		}

		if tokenData.Disabled {
			c.JSON(http.StatusBadRequest, api.ApiResponse{Code: http.StatusBadRequest, Message: "Token is already blacklisted"})
			return
		}

		// Update the token to be disabled
		if err := db.Model(&tokenData).Update("disabled", true).Error; err != nil {
			c.JSON(http.StatusInternalServerError, api.ApiResponse{Code: http.StatusInternalServerError, Message: "Failed to blacklist token"})
			return
		}

		c.JSON(http.StatusOK, api.ApiResponse{Code: http.StatusOK, Message: "Token blacklisted successfully"})
	}
}
