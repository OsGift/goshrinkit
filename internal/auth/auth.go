// -----------------------------------------------------------------------------
// internal/auth/auth.go
// -----------------------------------------------------------------------------
package auth

import (
	"context"
	"encoding/json"
	"errors" // Explicitly import errors for errors.Is
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/OsGift/goshrinkit/internal/storage"
	"github.com/OsGift/goshrinkit/internal/utils" // Utility functions for sending HTTP responses
	"github.com/golang-jwt/jwt/v5"                // JWT package for token handling
	"golang.org/x/crypto/bcrypt"                  // For hashing and comparing passwords
)

// Define a custom context key type to avoid collisions when storing/retrieving
// values in the request context (e.g., UserID).
type contextKey string

const (
	userIDContextKey contextKey = "userID" // Key for storing authenticated user's ID in context
)

// Service provides authentication-related business logic and handlers.
type Service struct {
	storage storage.Storage // Dependency for database operations related to users
	jwtKey  []byte          // Secret key for JWT signing and verification
}

// NewService creates and returns a new authentication service instance.
// It takes a storage implementation and the JWT secret key as dependencies.
func NewService(s storage.Storage, jwtKey []byte) *Service {
	return &Service{
		storage: s,
		jwtKey:  jwtKey,
	}
}

// RegisterRequest defines the structure for the JSON request body
// when a user attempts to register.
type RegisterRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginRequest defines the structure for the JSON request body
// when a user attempts to log in.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Claims defines the structure of the JWT claims.
// It embeds jwt.RegisteredClaims for standard claims (e.g., expiry, issued at).
type Claims struct {
	UserID uint `json:"user_id"` // Custom claim: the ID of the authenticated user
	jwt.RegisteredClaims
}

// RegisterHandler handles new user registration requests (POST /api/v1/register).
// It parses the request, validates input, hashes the password, checks for username
// uniqueness, and creates a new user in the database.
func (s *Service) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	// Decode the JSON request body into the RegisterRequest struct.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendErrorResponse(w, "Invalid request payload. Please ensure JSON format is correct.", http.StatusBadRequest)
		return
	}

	// Input validation: ensure username and password are not empty.
	if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
		utils.SendErrorResponse(w, "Username and password cannot be empty.", http.StatusBadRequest)
		return
	}
	// Input validation: enforce a minimum password length for security.
	if len(req.Password) < 8 {
		utils.SendErrorResponse(w, "Password must be at least 8 characters long.", http.StatusBadRequest)
		return
	}

	// Hash the user's password using bcrypt.
	// bcrypt.DefaultCost provides a good balance between security and performance.
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password during registration for user '%s': %v", req.Username, err)
		utils.SendErrorResponse(w, "Internal server error during password processing.", http.StatusInternalServerError)
		return
	}

	// Create a new User struct with the hashed password.
	user := &storage.User{
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
	}

	// Check if a user with the given username already exists.
	existingUser, err := s.storage.GetUserByUsername(r.Context(), req.Username)
	if err != nil && err != storage.ErrUserNotFound {
		// Log any database errors other than "user not found".
		log.Printf("Error checking existing user '%s': %v", req.Username, err)
		utils.SendErrorResponse(w, "Internal server error checking username availability.", http.StatusInternalServerError)
		return
	}
	if existingUser != nil {
		// If a user with this username already exists, return a conflict error.
		utils.SendErrorResponse(w, "Username already exists. Please choose a different one.", http.StatusConflict)
		return
	}

	// Create the new user record in the database.
	if err := s.storage.CreateUser(r.Context(), user); err != nil {
		log.Printf("Error creating user '%s' in database: %v", req.Username, err)
		utils.SendErrorResponse(w, "Internal server error during user creation.", http.StatusInternalServerError)
		return
	}

	// Send a success response. No data payload is needed for registration.
	utils.SendSuccessResponse(w, nil, "User registered successfully.", http.StatusCreated)
}

// LoginHandler handles user login requests (POST /api/v1/login).
// It verifies the user's credentials and, if valid, generates and returns a JWT token.
func (s *Service) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	// Decode the JSON request body into the LoginRequest struct.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendErrorResponse(w, "Invalid request payload. Please ensure JSON format is correct.", http.StatusBadRequest)
		return
	}

	// Retrieve the user from the database by username.
	user, err := s.storage.GetUserByUsername(r.Context(), req.Username)
	if err == storage.ErrUserNotFound {
		// Use a generic "Invalid credentials" message to prevent username enumeration attacks.
		utils.SendErrorResponse(w, "Invalid credentials.", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("Error retrieving user '%s' for login: %v", req.Username, err)
		utils.SendErrorResponse(w, "Internal server error during login.", http.StatusInternalServerError)
		return
	}

	// Compare the provided plain-text password with the stored hashed password.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		// If passwords don't match, return "Invalid credentials".
		utils.SendErrorResponse(w, "Invalid credentials.", http.StatusUnauthorized)
		return
	}

	// Generate a JSON Web Token (JWT) upon successful authentication.
	// The token will expire after 24 hours.
	expirationTime := time.Now().Add(24 * time.Hour)
	claims := &Claims{
		UserID: user.ID, // Set the custom UserID claim
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime), // Token expiration time
			IssuedAt:  jwt.NewNumericDate(time.Now()),     // Token issuance time
			NotBefore: jwt.NewNumericDate(time.Now()),     // Token not valid before this time
		},
	}

	// Create a new JWT token using the HS256 signing method and the defined claims.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Sign the token string using the secret key.
	tokenString, err := token.SignedString(s.jwtKey)
	if err != nil {
		log.Printf("Error signing JWT token for user '%d': %v", user.ID, err)
		utils.SendErrorResponse(w, "Internal server error generating authentication token.", http.StatusInternalServerError)
		return
	}

	// Send a success response including the generated JWT token.
	utils.SendSuccessWithTokenResponse(w, nil, tokenString, "Login successful.", http.StatusOK)
}

// AuthMiddleware is an HTTP middleware that protects routes requiring authentication.
// It extracts and verifies the JWT token from the Authorization header.
// If the token is valid, it extracts the UserID and adds it to the request context
// before calling the next handler in the chain.
func (s *Service) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			utils.SendErrorResponse(w, "Unauthorized: Missing authentication token.", http.StatusUnauthorized)
			return
		}

		// Ensure the token string has the "Bearer " prefix and remove it.
		if !strings.HasPrefix(tokenString, "Bearer ") {
			utils.SendErrorResponse(w, "Unauthorized: Invalid token format. Token must be in 'Bearer <token>' format.", http.StatusUnauthorized)
			return
		}
		tokenString = strings.Replace(tokenString, "Bearer ", "", 1)

		claims := &Claims{}
		// Parse the token, validating its signature and structure against the Claims struct.
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method. Ensure it is HMAC (HS256 in this case) to prevent algorithm confusion attacks.
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return s.jwtKey, nil // Provide the secret key for signature verification
		})

		if err != nil {
			// Handle specific JWT parsing and validation errors.
			if errors.Is(err, jwt.ErrSignatureInvalid) {
				utils.SendErrorResponse(w, "Unauthorized: Invalid token signature.", http.StatusUnauthorized)
				return
			}
			if errors.Is(err, jwt.ErrTokenExpired) || errors.Is(err, jwt.ErrTokenNotValidYet) {
				utils.SendErrorResponse(w, "Unauthorized: Token expired or not yet valid.", http.StatusUnauthorized)
				return
			}
			// Catch any other general parsing errors.
			log.Printf("Error parsing token: %v", err)
			utils.SendErrorResponse(w, "Unauthorized: Invalid token.", http.StatusUnauthorized)
			return
		}

		// Check if the token is valid after parsing (e.g., checks all claims, including standard ones).
		if !token.Valid {
			utils.SendErrorResponse(w, "Unauthorized: Token validation failed.", http.StatusUnauthorized)
			return
		}

		// Add the authenticated UserID to the request context.
		// This makes the user's ID accessible to subsequent handlers in the chain.
		ctx := context.WithValue(r.Context(), userIDContextKey, claims.UserID)
		next.ServeHTTP(w, r.WithContext(ctx)) // Call the next handler with the updated context
	}
}

// GetUserIDFromContext is a helper function to retrieve the authenticated user's ID
// from the request context. This should be called by handlers that are protected by AuthMiddleware.
func GetUserIDFromContext(ctx context.Context) (uint, error) {
	// Retrieve the value from context using the custom context key.
	userID, ok := ctx.Value(userIDContextKey).(uint)
	if !ok {
		// Return an error if the UserID is not found or is not of the expected type (uint).
		return 0, fmt.Errorf("user ID not found in context or has wrong type")
	}
	return userID, nil
}
