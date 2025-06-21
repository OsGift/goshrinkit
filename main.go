// main.go - Entry point for the GoShrink.it URL shortening application.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/OsGift/goshrinkit/internal/analytics"
	"github.com/OsGift/goshrinkit/internal/auth"
	"github.com/OsGift/goshrinkit/internal/config"
	"github.com/OsGift/goshrinkit/internal/shortener"
	"github.com/OsGift/goshrinkit/internal/storage"
	"github.com/gorilla/mux" // HTTP router for flexible routing
)

func main() {
	// Load application configuration from environment variables or .env file.
	// This includes port, database path, and JWT secret.
	cfg := config.LoadConfig()

	// Initialize the database storage. Currently configured for SQLite.
	db, err := storage.NewSQLiteStorage(cfg.DatabasePath)
	if err != nil {
		// If database connection fails, log a fatal error and exit.
		log.Fatalf("Failed to initialize database storage: %v", err)
	}

	// Defer the closing of the database connection. This ensures resources
	// are properly released when the main function exits.
	defer func() {
		// Type assertion is necessary here because the `db` variable is of
		// the `storage.Storage` interface type, which doesn't expose a `Close` method.
		// We need to access the underlying `*storage.SQLiteStorage` concrete type
		// to get its GORM DB instance, and then the native SQL DB connection to close it.
		sqliteDB, ok := db.(*storage.SQLiteStorage)
		if !ok {
			log.Println("Error: Underlying database is not SQLiteStorage, cannot safely close connection.")
			return
		}

		// Get the underlying *sql.DB connection from GORM.
		sqlDB, err := sqliteDB.DB.DB()
		if err != nil {
			log.Printf("Error getting underlying SQL DB instance for closing: %v", err)
			return
		}
		// Close the underlying SQL database connection.
		if err := sqlDB.Close(); err != nil {
			log.Printf("Error closing database connection: %v", err)
		} else {
			log.Println("Database connection closed gracefully.")
		}
	}()

	// Run database migrations to ensure all necessary tables are created
	// or updated according to the Go structs.
	if err := db.Migrate(); err != nil {
		log.Fatalf("Failed to run database migrations: %v", err)
	}

	// Initialize application services, injecting the database storage dependency.
	// These services encapsulate the business logic for each domain.
	authService := auth.NewService(db, []byte(cfg.JWTSecret))
	shortenerService := shortener.NewService(db)
	analyticsService := analytics.NewService(db) // Used for asynchronous click tracking

	// Create a new Gorilla Mux router.
	r := mux.NewRouter()

	// --- API Routes (prefixed with /api/v1) ---
	// These routes are typically used by the frontend via Fetch/XHR requests.
	api := r.PathPrefix("/api/v1").Subrouter()

	// Authentication API endpoints (publicly accessible for login/registration).
	api.HandleFunc("/register", authService.RegisterHandler).Methods("POST")
	api.HandleFunc("/login", authService.LoginHandler).Methods("POST")

	// Apply authentication middleware to protected API routes.
	// The `authMiddleware` verifies the JWT token before allowing access
	// to the underlying handler.
	authMiddleware := authService.AuthMiddleware // Get the middleware function

	api.HandleFunc("/shorten", authMiddleware(shortenerService.ShortenURLHandler)).Methods("POST")
	api.HandleFunc("/me/urls", authMiddleware(shortenerService.GetUserURLsHandler)).Methods("GET")

	// --- Frontend HTML File Routes ---
	// Explicitly handle GET requests for specific HTML pages.
	// This ensures that requests like `/login.html` are served directly
	// as files, rather than being interpreted as short URLs (slugs).
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/index.html")
	}).Methods("GET")
	r.HandleFunc("/login.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/login.html")
	}).Methods("GET")
	r.HandleFunc("/register.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/register.html")
	}).Methods("GET")
	r.HandleFunc("/dashboard.html", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "./web/dashboard.html")
	}).Methods("GET")

	// --- Short URL Redirection Route ---
	// This route handles incoming requests for shortened URLs (e.g., `yourdomain.com/abcde`).
	// It must be placed after specific HTML file routes but before the general static file server
	// to ensure it captures slugs without conflicting with static assets.
	r.HandleFunc("/{slug}", func(w http.ResponseWriter, req *http.Request) {
		vars := mux.Vars(req)
		slug := vars["slug"]
		// Asynchronously record click analytics for the accessed short URL.
		analyticsService.RecordClick(slug, req)
		// Perform the actual redirection to the original long URL.
		shortenerService.RedirectHandler(w, req)
	}).Methods("GET")

	// --- Static File Server ---
	// This acts as a catch-all for any other static frontend assets
	// (e.g., CSS, JavaScript files from `web/static/css`, images, etc.)
	// not explicitly handled by the routes above. It serves files from the `./web` directory.
	// The `PathPrefix("/")` ensures it matches any remaining request path.
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./web")))

	// Configure the HTTP server with addresses and timeouts for robustness and security.
	srv := &http.Server{
		Addr:         ":" + cfg.Port, // Listen on all available network interfaces on the configured port.
		Handler:      r,              // The main router handling all incoming requests.
		WriteTimeout: 15 * time.Second, // Maximum duration for writing a response.
		ReadTimeout:  15 * time.Second, // Maximum duration for reading the entire request, including the body.
		IdleTimeout:  60 * time.Second, // Maximum amount of time to wait for the next request when keep-alives are enabled.
	}

	// Start the HTTP server in a separate goroutine.
	// This allows the main goroutine to listen for OS signals.
	go func() {
		log.Printf("Server listening on http://localhost%s", srv.Addr)
		// ListenAndServe blocks until server shutdowns or an error occurs.
		// `http.ErrServerClosed` is a non-fatal error returned on graceful shutdown.
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// --- Graceful Shutdown ---
	// Set up a channel to listen for OS signals that indicate a request to terminate.
	quit := make(chan os.Signal, 1)
	// Notify the 'quit' channel upon receiving SIGINT (Ctrl+C) or SIGTERM (termination signal).
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit // Block the main goroutine until one of the specified signals is received.
	log.Println("Shutting down server...")

	// Create a context with a timeout for the server shutdown process.
	// This gives active requests a grace period to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel() // Ensure the context's cancel function is called.

	// Attempt a graceful shutdown of the HTTP server.
	if err := srv.Shutdown(ctx); err != nil {
		// If shutdown is not graceful (e.g., timeout), log a fatal error.
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited gracefully.")
}
