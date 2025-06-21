// -----------------------------------------------------------------------------
// internal/shortener/shortener.go
// -----------------------------------------------------------------------------
package shortener

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url" // For robust URL parsing and validation
	"regexp"  // For custom slug validation
	"time"

	"github.com/OsGift/goshrinkit/internal/auth"    // To get UserID from context
	"github.com/OsGift/goshrinkit/internal/storage" // Database storage operations
	"github.com/OsGift/goshrinkit/internal/utils"   // Utility functions for HTTP responses
	"github.com/gorilla/mux"                        // For extracting path variables (slug)
)

const (
	defaultSlugLength   = 8  // Default length for randomly generated short URLs
	maxCustomSlugLength = 20 // Maximum allowed length for custom slugs
	// customSlugRegex defines allowed characters for custom slugs:
	// alphanumeric (a-z, A-Z, 0-9), hyphens (-), and underscores (_).
	// It ensures the slug is not empty and matches the pattern.
	customSlugRegex = "^[a-zA-Z0-9_-]+$"
)

// Service provides URL shortening and retrieval business logic.
type Service struct {
	storage storage.Storage // Dependency for database operations
}

// NewService creates and returns a new shortener service instance.
func NewService(s storage.Storage) *Service {
	return &Service{
		storage: s,
	}
}

// ShortenRequest defines the structure for the JSON request body
// when a client wants to shorten a URL.
type ShortenRequest struct {
	OriginalURL string `json:"original_url"` // The long URL to be shortened
	CustomSlug  string `json:"custom_slug"`  // Optional: A user-defined short slug
	Expiration  string `json:"expiration"`   // Optional: ISO 8601 string for expiration date/time
}

// ShortenResponsePayload defines the structure for the JSON data payload
// returned upon successful URL shortening.
type ShortenResponsePayload struct {
	ShortURL    string `json:"short_url"`    // The generated/custom short URL slug
	OriginalURL string `json:"original_url"` // The original long URL
}

// UserURLResponse defines the structure for a single shortened URL entry
// displayed on a user's dashboard.
type UserURLResponse struct {
	ShortURL    string    `json:"short_url"`    // The short URL slug
	OriginalURL string    `json:"original_url"` // The original long URL
	Visits      uint      `json:"visits"`       // Number of times this short URL has been visited
	CreatedAt   time.Time `json:"created_at"`   // Timestamp when the short URL was created
}

// generateSlug generates a random, URL-safe alphanumeric string of a specified length.
// It uses crypto/rand for cryptographically secure random bytes and base64.URLEncoding
// to ensure the resulting string contains only characters valid in URLs.
func generateSlug(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes for slug: %w", err)
	}
	// Encode to URL-safe base64 and then truncate to the desired length.
	// Base64 encoding expands bytes, so length is effectively the number of characters needed.
	encoded := base64.URLEncoding.EncodeToString(bytes)
	if len(encoded) < length {
		// This case is unlikely for typical lengths but good for robustness.
		return encoded, nil
	}
	return encoded[:length], nil
}

// ShortenURLHandler handles the HTTP POST request to shorten a URL (/api/v1/shorten).
// It validates the input URL, handles custom slugs or generates new ones,
// sets expiration dates, associates with a user (if authenticated), and saves to storage.
func (s *Service) ShortenURLHandler(w http.ResponseWriter, r *http.Request) {
	var req ShortenRequest
	// Decode the JSON request body into the ShortenRequest struct.
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		utils.SendErrorResponse(w, "Invalid request payload. Please ensure JSON format is correct.", http.StatusBadRequest)
		return
	}

	// --- Input Validation for OriginalURL ---
	// 1. Check if empty.
	if req.OriginalURL == "" {
		utils.SendErrorResponse(w, "Original URL cannot be empty.", http.StatusBadRequest)
		return
	}
	// 2. Robust URL parsing and validation using net/url.
	parsedURL, err := url.ParseRequestURI(req.OriginalURL)
	if err != nil || !parsedURL.IsAbs() || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") {
		utils.SendErrorResponse(w, "Invalid original URL format. Must be a valid absolute HTTP or HTTPS URL (e.g., https://example.com/path).", http.StatusBadRequest)
		return
	}
	// Use the normalized string from parsedURL for consistency and to remove potential redundancies.
	req.OriginalURL = parsedURL.String()

	var slug string
	if req.CustomSlug != "" {
		// --- Custom Slug Validation ---
		// 1. Validate characters using a regex.
		matched, _ := regexp.MatchString(customSlugRegex, req.CustomSlug)
		if !matched {
			utils.SendErrorResponse(w, "Custom slug contains invalid characters. Use alphanumeric characters, hyphens (-), or underscores (_).", http.StatusBadRequest)
			return
		}
		// 2. Enforce maximum length.
		if len(req.CustomSlug) > maxCustomSlugLength {
			utils.SendErrorResponse(w, fmt.Sprintf("Custom slug is too long. Max %d characters allowed.", maxCustomSlugLength), http.StatusBadRequest)
			return
		}
		// 3. Check if the custom slug already exists in the database.
		exists, err := s.storage.CheckSlugExists(r.Context(), req.CustomSlug)
		if err != nil {
			log.Printf("Error checking custom slug existence for '%s': %v", req.CustomSlug, err)
			utils.SendErrorResponse(w, "Internal server error checking custom slug availability.", http.StatusInternalServerError)
			return
		}
		if exists {
			utils.SendErrorResponse(w, storage.ErrSlugAlreadyExists.Error(), http.StatusConflict) // Use the specific error message
			return
		}
		slug = req.CustomSlug
	} else {
		// --- Generate Random Unique Slug ---
		// Loop to generate a unique slug, retrying a few times in case of collision.
		for i := 0; i < 5; i++ { // Try up to 5 times
			newSlug, err := generateSlug(defaultSlugLength)
			if err != nil {
				log.Printf("Error generating random slug: %v", err)
				utils.SendErrorResponse(w, "Internal server error generating short URL slug.", http.StatusInternalServerError)
				return
			}
			// Check if the newly generated slug already exists.
			exists, err := s.storage.CheckSlugExists(r.Context(), newSlug)
			if err != nil {
				log.Printf("Error checking generated slug existence: %v", err)
				utils.SendErrorResponse(w, "Internal server error during slug generation check.", http.StatusInternalServerError)
				return
			}
			if !exists {
				slug = newSlug // Found a unique slug
				break
			}
			if i == 4 { // If still no unique slug after all retries
				log.Printf("Failed to generate a unique slug after multiple attempts.")
				utils.SendErrorResponse(w, "Failed to generate a unique short URL. Please try again.", http.StatusInternalServerError)
				return
			}
		}
	}

	// --- Handle Expiration Date ---
	var expirationTime *time.Time // Pointer to time.Time, allowing nil for no expiration
	if req.Expiration != "" {
		// Parse the expiration string. Expecting ISO 8601 format (RFC3339).
		parsedTime, err := time.Parse(time.RFC3339, req.Expiration)
		if err != nil {
			utils.SendErrorResponse(w, "Invalid expiration date format. Please use ISO 8601 (e.g., 2006-01-02T15:04:05Z).", http.StatusBadRequest)
			return
		}
		// Ensure the expiration date is in the future.
		if parsedTime.Before(time.Now()) {
			utils.SendErrorResponse(w, "Expiration date cannot be in the past.", http.StatusBadRequest)
			return
		}
		expirationTime = &parsedTime
	}

	// --- Get UserID from Context (if authenticated) ---
	// auth.GetUserIDFromContext will return the UserID if it was set by the AuthMiddleware,
	// otherwise it returns 0 and an error.
	userID, err := auth.GetUserIDFromContext(r.Context())
	var userIDPtr *uint            // Pointer to uint, will be nil if user is unauthenticated
	if err == nil && userID != 0 { // Check both for no error AND non-zero ID (0 is invalid ID)
		userIDPtr = &userID
	}
	// If err is non-nil or userID is 0, userIDPtr remains nil, indicating an anonymous link.

	// Create the URL entry struct for database storage.
	urlEntry := &storage.URL{
		OriginalURL:    req.OriginalURL,
		ShortURL:       slug,
		UserID:         userIDPtr,      // Links to user if authenticated, else nil
		ExpirationDate: expirationTime, // Set expiration or nil
	}

	// Save the new URL entry to the database.
	if err := s.storage.CreateURL(r.Context(), urlEntry); err != nil {
		log.Printf("Error saving URL '%s' to database: %v", req.OriginalURL, err)
		utils.SendErrorResponse(w, "Internal server error saving shortened URL.", http.StatusInternalServerError)
		return
	}

	// Prepare the success response payload.
	responsePayload := ShortenResponsePayload{
		ShortURL:    slug,
		OriginalURL: req.OriginalURL,
	}

	// Send a successful JSON response to the client.
	utils.SendSuccessResponse(w, responsePayload, "URL shortened successfully.", http.StatusCreated)
}

// RedirectHandler handles HTTP GET requests for short URLs (e.g., /abc123de).
// It retrieves the original URL, increments visit count, records a click, and redirects the client.
func (s *Service) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	// Extract the short slug from the URL path using Gorilla Mux.
	vars := mux.Vars(r)
	slug := vars["slug"]

	// Retrieve the URL entry from storage using the slug.
	urlEntry, err := s.storage.GetURLByShortURL(r.Context(), slug)
	if err == storage.ErrURLNotFound {
		log.Printf("Redirect: Short URL '%s' not found.", slug)
		utils.SendErrorResponse(w, "Short URL not found or has been deleted.", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("Redirect: Error retrieving URL '%s' from database: %v", slug, err)
		utils.SendErrorResponse(w, "Internal server error during redirection.", http.StatusInternalServerError)
		return
	}

	// Check if the short URL has expired.
	if urlEntry.ExpirationDate != nil && time.Now().After(*urlEntry.ExpirationDate) {
		log.Printf("Redirect: Short URL '%s' has expired (original: %s).", slug, urlEntry.OriginalURL)
		utils.SendErrorResponse(w, "Short URL has expired.", http.StatusGone) // HTTP 410 Gone status
		return
	}

	// Increment the visit count for the URL.
	// This is done directly here as it's a critical part of the redirection.
	// Analytics service can still handle more detailed click tracking asynchronously.
	if err := s.storage.IncrementURLVisits(r.Context(), urlEntry.ID); err != nil {
		log.Printf("Redirect: Error incrementing URL visits for URLID %d ('%s'): %v", urlEntry.ID, slug, err)
		// Do not block redirection if visit increment fails; just log the error.
	}

	// Perform the HTTP redirect to the original URL.
	// http.StatusMovedPermanently (301) is typically used for permanent redirects,
	// which is good for SEO and browser caching. If the short URL might change,
	// use http.StatusFound (302) or http.StatusTemporaryRedirect (307).
	http.Redirect(w, r, urlEntry.OriginalURL, http.StatusMovedPermanently)
}

// GetUserURLsHandler retrieves all shortened URLs associated with the authenticated user.
// This route is protected by the authentication middleware.
func (s *Service) GetUserURLsHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the authenticated UserID from the request context.
	// This ID is guaranteed to be present if the AuthMiddleware successfully executed.
	userID, err := auth.GetUserIDFromContext(r.Context())
	if err != nil {
		// This should ideally not happen if middleware is correctly applied,
		// but acts as a safeguard.
		log.Printf("GetUserURLsHandler: Unauthorized access attempt, user ID not found in context: %v", err)
		utils.SendErrorResponse(w, "Unauthorized: User session invalid or missing. Please log in again.", http.StatusUnauthorized)
		return
	}

	// Fetch all URLs belonging to the retrieved UserID from storage.
	urls, err := s.storage.GetURLsByUserID(r.Context(), userID)
	if err != nil {
		log.Printf("Error retrieving user URLs for userID %d: %v", userID, err)
		utils.SendErrorResponse(w, "Internal server error retrieving your URLs.", http.StatusInternalServerError)
		return
	}

	// Prepare the response payload by transforming storage.URL structs into UserURLResponse structs.
	// IMPORTANT: Initialize responsePayload as an empty slice to ensure it marshals to `[]` in JSON
	// even if there are no URLs found, rather than `null`.
	responsePayload := make([]UserURLResponse, 0) // Changed from `var responsePayload []UserURLResponse`
	for _, u := range urls {
		responsePayload = append(responsePayload, UserURLResponse{
			ShortURL:    u.ShortURL,
			OriginalURL: u.OriginalURL,
			Visits:      u.Visits,
			CreatedAt:   u.CreatedAt, // GORM's Model automatically populates CreatedAt
		})
	}

	// Send a successful JSON response with the list of user's URLs.
	utils.SendSuccessResponse(w, responsePayload, "Successfully retrieved user URLs.", http.StatusOK)
}
