// -----------------------------------------------------------------------------
// internal/analytics/analytics.go
// -----------------------------------------------------------------------------
package analytics

import (
	"context"
	"log"
	"net/http"
	"strings" // Added for splitAndTrim and findLastIndex helpers
	"time"

	"github.com/OsGift/goshrinkit/internal/storage"
)

// Service provides click analytics operations.
type Service struct {
	storage storage.Storage
}

// NewService creates a new analytics service.
func NewService(s storage.Storage) *Service {
	return &Service{
		storage: s,
	}
}

// RecordClick records a click event for a given short URL slug.
func (s *Service) RecordClick(slug string, r *http.Request) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second) // Set a timeout for async operation
		defer cancel()

		url, err := s.storage.GetURLByShortURL(ctx, slug)
		if err == storage.ErrURLNotFound {
			log.Printf("Analytics: Short URL '%s' not found for click record", slug)
			return
		}
		if err != nil {
			log.Printf("Analytics: Error retrieving URL for click: %v", err)
			return
		}

		click := &storage.Click{
			URLID:     url.ID,
			Timestamp: time.Now(),
			IPAddress: getIPAddress(r),
			UserAgent: r.UserAgent(),
		}

		if err := s.storage.RecordClick(ctx, click); err != nil {
			log.Printf("Analytics: Error recording click for URLID %d: %v", url.ID, err)
		}
	}()
}

// getIPAddress extracts the client's IP address from the request.
func getIPAddress(r *http.Request) string {
	// Check X-Forwarded-For header for clients behind a proxy/load balancer
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := splitAndTrim(xff, ",")
		if len(ips) > 0 {
			return ips[0] // First IP is usually the client
		}
	}
	// Check X-Real-Ip header
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return xri
	}
	// Fallback to RemoteAddr
	addr := r.RemoteAddr
	// Remove port if present
	if colon := findLastIndex(addr, ":"); colon != -1 {
		addr = addr[:colon]
	}
	return addr
}

// Helper to split a string by separator and trim spaces.
func splitAndTrim(s, sep string) []string {
	parts := strings.Split(s, sep)
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	return parts
}

// Helper to find the last index of a substring.
func findLastIndex(s, sub string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
