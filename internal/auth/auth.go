// -----------------------------------------------------------------------------
// internal/auth/auth.go
// -----------------------------------------------------------------------------
package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/OsGift/goshrinkit/internal/storage"
	"github.com/OsGift/goshrinkit/internal/utils"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// Service provides authentication related operations.
type Service struct {
	storage storage.Storage
	jwtKey  []byte
}

// NewService creates a new authentication service.
func NewService(s storage.Storage, jwtKey []byte) *Service {
	return &Service{
		storage: s,
		jwtKey:  jwtKey,
	}
}

// RegisterRequest represents the request body for user registration.
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginRequest represents the request body for user login.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims represents the JWT claims.
type Claims struct {
	UserID uint `json:"user_id"`
	jwt.RegisteredClaims
}

// RegisterHandler handles new user registration.
func (s *Service) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Input validation
	if req.Username == "" || req.Password == "" {
		utils.SendErrorResponse(w, "Username and password cannot be empty", http.StatusBadRequest)
		return
	}
	if len(req.Password) < 8 {
		utils.SendErrorResponse(w, "Password must be at least 8 characters long", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	user := &storage.User{
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
	}

	// Check if username already exists
	existingUser, err := s.storage.GetUserByUsername(r.Context(), req.Username)
	if err != nil && err != storage.ErrUserNotFound {
		log.Printf("Error checking existing user: %v", err)
		utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		utils.SendErrorResponse(w, "Username already exists", http.StatusConflict)
		return
	}

	// Save user to database
	if err := s.storage.CreateUser(r.Context(), user); err != nil {
		log.Printf("Error creating user: %v", err)
		utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	utils.SendSuccessResponse(w, nil, "User registered successfully", http.StatusCreated)
}

// LoginHandler handles user login and JWT token generation.
func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	user, err := s.storage.GetUserByUsername(r.Context(), req.Username)
	if err == storage.ErrUserNotFound {
		utils.SendErrorResponse(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("Error retrieving user: %v", err)
		utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Compare password with hashed password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		utils.SendErrorResponse(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	expirationTime := time.Now().Add(24 * time.Hour) // Token valid for 24 hours
	claims := &Claims{
		UserID: user.ID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(s.jwtKey)
	if err != nil {
		log.Printf("Error signing token: %v", err)
		utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	utils.SendSuccessWithTokenResponse(w, nil, tokenString, "Login successful", http.StatusOK)
}

// AuthMiddleware is a middleware to protect authenticated routes.
func (s *Service) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			utils.SendErrorResponse(w, "Unauthorized: Missing token", http.StatusUnauthorized)
			return
		}

		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.jwtKey, nil
		})

		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				utils.SendErrorResponse(w, "Unauthorized: Invalid token signature", http.StatusUnauthorized)
				return
			}
			log.Printf("Error parsing token: %v", err)
			utils.SendErrorResponse(w, "Unauthorized: Invalid token", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			utils.SendErrorResponse(w, "Unauthorized: Token expired or invalid", http.StatusUnauthorized)
			return
		}

		// Add user ID to request context
		ctx := context.WithValue(r.Context(), "userID", claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// GetUserIDFromContext retrieves the user ID from the request context.
func GetUserIDFromContext(ctx context.Context) (uint, error) {
	userID, ok := ctx.Value("userID").(uint)
	if !ok {
		return 0, fmt.Errorf("user ID not found in context")
	}
	return userID, nil
}
