// main.go - Entry point for the application
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
	"github.com/gorilla/mux"
)


func main() {
	// Load configuration
	cfg := config.LoadConfig()

	// Initialize database storage
	db, err := storage.NewSQLiteStorage(cfg.DatabasePath)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer func() {
		// Type assert the storage.Storage interface back to *storage.SQLiteStorage
		// to access the underlying GORM DB instance for closing the connection.
		sqliteDB, ok := db.(*storage.SQLiteStorage)
		if !ok {
			log.Println("Error: Underlying database is not SQLiteStorage, cannot close connection.")
			return
		}

		sqlDB, err := sqliteDB.DB.DB() // Now access the GORM DB's underlying *sql.DB connection
		if err != nil {
			log.Printf("Error getting underlying SQL DB: %v", err)
			return
		}
		if err := sqlDB.Close(); err != nil {
			log.Printf("Error closing database: %v", err)
		}
	}()

	// Perform database migrations
	if err := db.Migrate(); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	// Initialize services
	authService := auth.NewService(db, []byte(cfg.JWTSecret))
	shortenerService := shortener.NewService(db)
	analyticsService := analytics.NewService(db)

	// Setup router
	r := mux.NewRouter()

	// 1. Define API routes on a subrouter first.
	// These have a distinct prefix (/api/v1) and should be matched before
	// the general slug handler or static file server.
	api := r.PathPrefix("/api/v1").Subrouter()

	// Authentication routes
	api.HandleFunc("/register", authService.RegisterHandler).Methods("POST")
	api.HandleFunc("/login", authService.LoginHandler).Methods("POST")

	// Declare and assign authMiddleware after authService is initialized
	authMiddleware := authService.AuthMiddleware

	// Authenticated routes
	api.HandleFunc("/shorten", authMiddleware(shortenerService.ShortenURLHandler)).Methods("POST")
	api.HandleFunc("/me/urls", authMiddleware(shortenerService.GetUserURLsHandler)).Methods("GET")

	// 2. Explicitly handle requests for root and specific HTML files.
	// This ensures they are served before the /{slug} route.
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

	// 3. Define the public short URL redirection route.
	// This will now catch paths that don't match the API or explicit HTML pages.
	r.HandleFunc("/{slug}", func(w http.ResponseWriter, req *http.Request) {
		vars := mux.Vars(req)
		slug := vars["slug"]
		// Log click analytics before redirection
		analyticsService.RecordClick(slug, req)
		shortenerService.RedirectHandler(w, req)
	}).Methods("GET")

	// 4. Serve other static frontend files (CSS, JS, images, etc.) as a fallback.
	// This handles anything else in the /web directory that wasn't explicitly matched.
	// For example, if you have /web/css/style.css, this will serve it.
	// The http.StripPrefix ensures that the file server looks for "css/style.css"
	// inside the "./web" directory when a request comes for "/css/style.css".
	// However, for generic "/" catch-all of all remaining files, we often just use http.FileServer.
	// Given the current HTML files are explicitly handled, this is a safe catch-all.
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./web")))


	// HTTP server setup
	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
		// Good practice: Set timeouts to avoid Slowloris attacks.
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server listening on http://localhost%s", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited gracefully.")
}
