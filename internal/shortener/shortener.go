// -----------------------------------------------------------------------------
// internal/shortener/shortener.go
// -----------------------------------------------------------------------------
package shortener

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/OsGift/goshrinkit/internal/auth"
	"github.com/OsGift/goshrinkit/internal/storage"
	"github.com/OsGift/goshrinkit/internal/utils"
	"github.com/gorilla/mux"
)

const (
	defaultSlugLength = 8
)

// Service provides URL shortening related operations.
type Service struct {
	storage storage.Storage
}

// NewService creates a new shortener service.
func NewService(s storage.Storage) *Service {
	return &Service{
		storage: s,
	}
}

// ShortenRequest represents the request body for URL shortening.
type ShortenRequest struct {
	OriginalURL string `json:"original_url"`
	CustomSlug  string `json:"custom_slug"` // Optional custom slug
	Expiration  string `json:"expiration"`  // Optional expiration date/TTL
}

// ShortenResponsePayload represents the data returned for a successful shorten operation.
type ShortenResponsePayload struct {
	ShortURL    string `json:"short_url"`
	OriginalURL string `json:"original_url"`
}

// UserURLResponse represents a shortened URL for a user's dashboard.
type UserURLResponse struct {
	ShortURL    string    `json:"short_url"`
	OriginalURL string    `json:"original_url"`
	Visits      uint      `json:"visits"`
	CreatedAt   time.Time `json:"created_at"`
}

// generateSlug generates a random alphanumeric string for the short URL.
func generateSlug(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Use URL-safe base64 encoding to avoid problematic characters
	return base64.URLEncoding.EncodeToString(bytes)[:length], nil
}

// ShortenURLHandler handles the URL shortening request.
func (s *Service) ShortenURLHandler(w http.ResponseWriter, r *http.Request) {
	var req ShortenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendErrorResponse(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Basic URL validation
	if req.OriginalURL == "" {
		utils.SendErrorResponse(w, "Original URL cannot be empty", http.StatusBadRequest)
		return
	}
	// TODO: More robust URL validation (e.g., using net/url.Parse)

	var slug string
	if req.CustomSlug != "" {
		// Validate custom slug characters (alphanumeric, hyphens allowed)
		// For simplicity, we'll allow it as is for now. In production, use regex.
		if len(req.CustomSlug) > 20 { // Limit custom slug length
			utils.SendErrorResponse(w, "Custom slug too long (max 20 characters)", http.StatusBadRequest)
			return
		}
		exists, err := s.storage.CheckSlugExists(r.Context(), req.CustomSlug)
		if err != nil {
			log.Printf("Error checking custom slug existence: %v", err)
			utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if exists {
			utils.SendErrorResponse(w, storage.ErrSlugAlreadyExists.Error(), http.StatusConflict)
			return
		}
		slug = req.CustomSlug
	} else {
		// Generate unique slug
		for {
			newSlug, err := generateSlug(defaultSlugLength)
			if err != nil {
				log.Printf("Error generating slug: %v", err)
				utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			exists, err := s.storage.CheckSlugExists(r.Context(), newSlug)
			if err != nil {
				log.Printf("Error checking slug existence: %v", err)
				utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
				return
			}
			if !exists {
				slug = newSlug
				break
			}
		}
	}

	// Handle expiration date
	var expirationTime *time.Time
	if req.Expiration != "" {
		parsedTime, err := time.Parse(time.RFC3339, req.Expiration) // Expect ISO 8601 format
		if err != nil {
			utils.SendErrorResponse(w, "Invalid expiration date format. Use ISO 8601 (e.g., 2006-01-02T15:04:05Z)", http.StatusBadRequest)
			return
		}
		expirationTime = &parsedTime
	}

	// Get UserID from context if authenticated
	userID, err := auth.GetUserIDFromContext(r.Context())
	var userIDPtr *uint
	if err == nil { // If user ID is found in context, means user is authenticated
		userIDPtr = &userID
	}

	url := &storage.URL{
		OriginalURL:    req.OriginalURL,
		ShortURL:       slug,
		UserID:         userIDPtr,
		ExpirationDate: expirationTime,
	}

	if err := s.storage.CreateURL(r.Context(), url); err != nil {
		log.Printf("Error saving URL to database: %v", err)
		utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	responsePayload := ShortenResponsePayload{
		ShortURL:    slug,
		OriginalURL: req.OriginalURL,
	}

	utils.SendSuccessResponse(w, responsePayload, "URL shortened successfully", http.StatusCreated)
}

// RedirectHandler handles redirection from short URL to original URL.
func (s *Service) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	slug := vars["slug"]

	url, err := s.storage.GetURLByShortURL(r.Context(), slug)
	if err == storage.ErrURLNotFound {
		utils.SendErrorResponse(w, "Short URL not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("Error retrieving URL from database: %v", err)
		utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check for expiration
	if url.ExpirationDate != nil && time.Now().After(*url.ExpirationDate) {
		utils.SendErrorResponse(w, "Short URL has expired", http.StatusGone)
		return
	}

	// Increment visit count (handled by analytics service externally, but could be here too)
	// For this implementation, we'll let the analytics service record and we'll just redirect.
	// In a high-traffic scenario, incrementing visits here might be better to ensure consistency,
	// or use a message queue for async analytics.
	if err := s.storage.IncrementURLVisits(r.Context(), url.ID); err != nil {
		log.Printf("Error incrementing URL visits: %v", err)
		// Do not block redirection for analytics error if it's not critical.
		// For this app, we'll let it pass but log the error.
	}

	http.Redirect(w, r, url.OriginalURL, http.StatusMovedPermanently)
}

// GetUserURLsHandler retrieves all shortened URLs for the authenticated user.
func (s *Service) GetUserURLsHandler(w http.ResponseWriter, r *http.Request) {
	userID, err := auth.GetUserIDFromContext(r.Context())
	if err != nil {
		utils.SendErrorResponse(w, "Unauthorized: User ID not found in context", http.StatusUnauthorized)
		return
	}

	urls, err := s.storage.GetURLsByUserID(r.Context(), userID)
	if err != nil {
		log.Printf("Error retrieving user URLs: %v", err)
		utils.SendErrorResponse(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// 'responsePayload' will be an empty slice if 'urls' is empty, which marshals to '[]'
	var responsePayload []UserURLResponse
	for _, u := range urls {
		responsePayload = append(responsePayload, UserURLResponse{
			ShortURL:    u.ShortURL,
			OriginalURL: u.OriginalURL,
			Visits:      u.Visits,
			CreatedAt:   u.CreatedAt,
		})
	}

	utils.SendSuccessResponse(w, responsePayload, "Successfully retrieved user URLs", http.StatusOK)
}
