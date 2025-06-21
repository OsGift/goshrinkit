// -----------------------------------------------------------------------------
// internal/analytics/analytics.go
// -----------------------------------------------------------------------------
package analytics

import (
	"context"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/OsGift/goshrinkit/internal/storage"
)

// Service provides click analytics operations.
// It depends on a storage implementation to record click events.
type Service struct {
	storage storage.Storage
}

// NewService creates and returns a new analytics service instance.
func NewService(s storage.Storage) *Service {
	return &Service{
		storage: s,
	}
}

// RecordClick records a click event for a given short URL slug.
// This operation is performed asynchronously in a goroutine to avoid blocking
// the main HTTP request flow (e.g., URL redirection).
func (s *Service) RecordClick(slug string, r *http.Request) {
	go func() {
		// Create a new context with a timeout for this asynchronous operation.
		// This prevents the goroutine from running indefinitely if storage operations hang.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel() // Ensure the context's cancel function is called to release resources.

		// Retrieve the URL entry from storage using the provided slug.
		urlEntry, err := s.storage.GetURLByShortURL(ctx, slug)
		if err == storage.ErrURLNotFound {
			// Log a warning if the short URL is not found. This might indicate
			// a request for an invalid/deleted URL, or a race condition.
			log.Printf("Analytics: Short URL '%s' not found for click record (might be invalid or deleted).", slug)
			return
		}
		if err != nil {
			// Log any other errors encountered while retrieving the URL.
			log.Printf("Analytics: Error retrieving URL '%s' for click record: %v", slug, err)
			return
		}

		// Construct a new Click record with relevant information from the request.
		click := &storage.Click{
			URLID:     urlEntry.ID,     // Foreign key to the URL that was clicked
			Timestamp: time.Now(),      // Current time of the click
			IPAddress: getIPAddress(r), // Client's IP address
			UserAgent: r.UserAgent(),   // Client's User-Agent string
		}

		// Record the click event in the database.
		if err := s.storage.RecordClick(ctx, click); err != nil {
			// Log an error if recording the click fails.
			// This error does not affect the main redirection flow due to the goroutine.
			log.Printf("Analytics: Error recording click for URLID %d ('%s'): %v", urlEntry.ID, slug, err)
		}
		// No explicit success logging is typically needed for background tasks unless
		// verbose debugging is enabled, to avoid excessive log spam.
	}()
}

// getIPAddress extracts the client's IP address from the HTTP request.
// It checks common headers used by proxies/load balancers (X-Forwarded-For, X-Real-Ip)
// before falling back to the direct remote address. This ensures the correct client IP
// is captured in various deployment scenarios.
func getIPAddress(r *http.Request) string {
	// Check the X-Forwarded-For header first. This header can contain a comma-separated list
	// of IP addresses, where the first one is typically the client's original IP.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			// Return the first IP address after trimming any whitespace.
			return strings.TrimSpace(ips[0])
		}
	}
	// If X-Forwarded-For is not present or empty, check X-Real-Ip.
	if xri := r.Header.Get("X-Real-Ip"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// As a fallback, use the request's RemoteAddr. This is the direct network address
	// of the client or the last proxy in the chain. It typically includes the port (e.g., "192.0.2.1:12345").
	addr := r.RemoteAddr
	// Remove the port part from the address string (e.g., ":12345") to get just the IP.
	if colon := strings.LastIndex(addr, ":"); colon != -1 {
		addr = addr[:colon]
	}
	return addr
}
