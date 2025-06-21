// -----------------------------------------------------------------------------
// internal/storage/storage.go
// -----------------------------------------------------------------------------
package storage

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Define custom error types to provide specific information about storage operations.
var ErrURLNotFound = errors.New("url not found")
var ErrUserNotFound = errors.New("user not found")
var ErrSlugAlreadyExists = errors.New("custom slug already exists")

// User represents a user entity in the database.
// It includes GORM's Model for common fields like ID, CreatedAt, etc.
type User struct {
	gorm.Model          // Embeds common fields: ID, CreatedAt, UpdatedAt, DeletedAt (soft delete)
	Username     string `gorm:"uniqueIndex;not null"` // Username must be unique and not null
	PasswordHash string `gorm:"not null"`             // Stores the bcrypt hashed password
	URLs         []URL  `gorm:"foreignKey:UserID"`    // One-to-many relationship: a user can have many URLs
}

// URL represents a shortened URL entry in the database.
// It stores the original URL, its short slug, associated user, visit count, and expiration.
type URL struct {
	gorm.Model                // Embeds common fields
	OriginalURL    string     `gorm:"not null"`             // The original long URL
	ShortURL       string     `gorm:"uniqueIndex;not null"` // The short slug (e.g., "abc123de"), must be unique
	UserID         *uint      // Nullable foreign key to User.ID; nil if anonymous, pointer to ID if authenticated
	User           User       `gorm:"foreignKey:UserID"` // GORM association definition
	Visits         uint       `gorm:"default:0"`         // Counter for how many times the short URL has been accessed
	ExpirationDate *time.Time // Nullable; if set, the URL will expire at this time
	Clicks         []Click    `gorm:"foreignKey:URLID"` // One-to-many relationship: a URL can have many clicks
}

// Click represents a single click event for a shortened URL.
// Stores metadata about the click for analytics purposes.
type Click struct {
	gorm.Model           // Embeds common fields
	URLID      uint      `gorm:"not null"`         // Foreign key to URL.ID
	URL        URL       `gorm:"foreignKey:URLID"` // GORM association definition
	Timestamp  time.Time `gorm:"not null"`         // The exact time the click occurred
	IPAddress  string    // IP address of the client performing the click
	UserAgent  string    // User-Agent string from the client's request
}

// Storage is an interface that defines all data access operations for the application.
// This abstraction allows for easy swapping of database implementations (e.g., SQLite, PostgreSQL).
type Storage interface {
	// User operations
	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, userID uint) (*User, error)

	// URL operations
	CreateURL(ctx context.Context, url *URL) error
	GetURLByShortURL(ctx context.Context, shortURL string) (*URL, error)
	GetURLsByUserID(ctx context.Context, userID uint) ([]URL, error)
	IncrementURLVisits(ctx context.Context, urlID uint) error
	CheckSlugExists(ctx context.Context, slug string) (bool, error)

	// Click analytics operations
	RecordClick(ctx context.Context, click *Click) error

	// Database management operations
	Migrate() error  // Runs schema migrations (e.g., create tables)
	GetDB() *gorm.DB // Returns the underlying GORM DB instance (primarily for testing or advanced scenarios)
}

// SQLiteStorage is an implementation of the Storage interface for SQLite databases using GORM.
type SQLiteStorage struct {
	DB *gorm.DB // GORM database client instance
}

// NewSQLiteStorage initializes a new SQLite database connection.
// It takes the database file path and returns a Storage interface or an error.
func NewSQLiteStorage(dbPath string) (Storage, error) {
	// Open the SQLite database connection using GORM.
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database at %s: %w", dbPath, err)
	}
	log.Printf("Successfully connected to SQLite database: %s", dbPath)
	return &SQLiteStorage{DB: db}, nil
}

// Migrate runs GORM's AutoMigrate function to create or update database tables
// based on the defined Go structs (User, URL, Click).
func (s *SQLiteStorage) Migrate() error {
	log.Println("Running database migrations...")
	// AutoMigrate will create tables, add missing columns, and create indexes.
	// It will NOT delete unused columns or drop tables.
	err := s.DB.AutoMigrate(&User{}, &URL{}, &Click{})
	if err != nil {
		return fmt.Errorf("failed to auto migrate database: %w", err)
	}
	log.Println("Database migrations completed successfully.")
	return nil
}

// CreateUser creates a new user record in the database.
func (s *SQLiteStorage) CreateUser(ctx context.Context, user *User) error {
	if err := s.DB.WithContext(ctx).Create(user).Error; err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}
	return nil
}

// GetUserByUsername retrieves a user by their username.
// Returns ErrUserNotFound if no user with the given username is found.
func (s *SQLiteStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	// Find the first record where username matches.
	result := s.DB.WithContext(ctx).Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by username '%s': %w", username, result.Error)
	}
	return &user, nil
}

// GetUserByID retrieves a user by their ID.
// Returns ErrUserNotFound if no user with the given ID is found.
func (s *SQLiteStorage) GetUserByID(ctx context.Context, userID uint) (*User, error) {
	var user User
	// Find the record by primary key (ID).
	result := s.DB.WithContext(ctx).First(&user, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user by ID %d: %w", userID, result.Error)
	}
	return &user, nil
}

// CreateURL creates a new shortened URL entry in the database.
func (s *SQLiteStorage) CreateURL(ctx context.Context, url *URL) error {
	if err := s.DB.WithContext(ctx).Create(url).Error; err != nil {
		// In case of a unique constraint violation (e.g., duplicate ShortURL),
		// GORM might return a generic error. More specific error handling
		// for unique constraints can be added here if needed, but often
		// pre-checks (like CheckSlugExists) prevent most such errors.
		return fmt.Errorf("failed to create URL: %w", err)
	}
	return nil
}

// GetURLByShortURL retrieves a URL entry by its short slug.
// Returns ErrURLNotFound if no URL with the given slug is found.
func (s *SQLiteStorage) GetURLByShortURL(ctx context.Context, shortURL string) (*URL, error) {
	var url URL
	result := s.DB.WithContext(ctx).Where("short_url = ?", shortURL).First(&url)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrURLNotFound
		}
		return nil, fmt.Errorf("failed to get URL by short URL '%s': %w", shortURL, result.Error)
	}
	return &url, nil
}

// GetURLsByUserID retrieves all URLs associated with a specific user ID.
// It returns a slice of URL structs. If no URLs are found, an empty slice is returned (not nil),
// along with a nil error.
func (s *SQLiteStorage) GetURLsByUserID(ctx context.Context, userID uint) ([]URL, error) {
	var urls []URL
	// Use Find when expecting zero or more records. Where clause filters by UserID.
	result := s.DB.WithContext(ctx).Where("user_id = ?", userID).Find(&urls)
	if result.Error != nil {
		// Find does not return ErrRecordNotFound when no records are found; it returns an empty slice.
		// So, any error here indicates a genuine database issue.
		return nil, fmt.Errorf("failed to get URLs by user ID %d: %w", userID, result.Error)
	}
	return urls, nil // Returns an empty slice if no records, which is correct for JSON marshalling ([] vs null)
}

// IncrementURLVisits atomically increments the 'visits' counter for a given URL ID.
func (s *SQLiteStorage) IncrementURLVisits(ctx context.Context, urlID uint) error {
	// UpdateColumn is used for direct column updates, bypassing GORM's callbacks/hooks.
	// gorm.Expr allows using raw SQL expressions for the update value.
	if err := s.DB.WithContext(ctx).Model(&URL{}).Where("id = ?", urlID).UpdateColumn("visits", gorm.Expr("visits + ?", 1)).Error; err != nil {
		return fmt.Errorf("failed to increment visits for URL ID %d: %w", urlID, err)
	}
	return nil
}

// CheckSlugExists checks if a given short URL slug already exists in the database.
// Returns true if the slug exists, false otherwise, and an error if a database issue occurs.
func (s *SQLiteStorage) CheckSlugExists(ctx context.Context, slug string) (bool, error) {
	var count int64
	// Count returns the number of records matching the condition.
	err := s.DB.WithContext(ctx).Model(&URL{}).Where("short_url = ?", slug).Count(&count).Error
	if err != nil {
		return false, fmt.Errorf("failed to check slug existence for '%s': %w", slug, err)
	}
	return count > 0, nil
}

// RecordClick creates a new click event record in the database.
func (s *SQLiteStorage) RecordClick(ctx context.Context, click *Click) error {
	if err := s.DB.WithContext(ctx).Create(click).Error; err != nil {
		return fmt.Errorf("failed to record click: %w", err)
	}
	return nil
}

// GetDB returns the underlying GORM DB instance.
// This is typically used for advanced operations, transactions, or testing
// that go beyond the defined Storage interface methods.
func (s *SQLiteStorage) GetDB() *gorm.DB {
	return s.DB
}
