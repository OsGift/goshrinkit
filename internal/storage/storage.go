// -----------------------------------------------------------------------------
// internal/storage/storage.go
// -----------------------------------------------------------------------------
package storage

import (
	"context"
	"errors"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// ErrURLNotFound indicates that the requested URL was not found.
var ErrURLNotFound = errors.New("url not found")

// ErrUserNotFound indicates that the requested user was not found.
var ErrUserNotFound = errors.New("user not found")

// ErrSlugAlreadyExists indicates that the custom slug is already in use.
var ErrSlugAlreadyExists = errors.New("slug already exists")

// User represents a user in the system.
type User struct {
	gorm.Model
	Username     string `gorm:"uniqueIndex;not null"`
	PasswordHash string `gorm:"not null"`
	URLs         []URL  `gorm:"foreignKey:UserID"` // One-to-many relationship
}

// URL represents a shortened URL entry.
type URL struct {
	gorm.Model
	OriginalURL    string    `gorm:"not null"`
	ShortURL       string    `gorm:"uniqueIndex;not null"` // This is the slug
	UserID         *uint     // Nullable, for unauthenticated users or to link to user
	User           User      `gorm:"foreignKey:UserID"` // Belongs to relationship
	Visits         uint      `gorm:"default:0"`
	ExpirationDate *time.Time // Nullable, for optional expiration
	Clicks         []Click    `gorm:"foreignKey:URLID"` // One-to-many relationship
}

// Click represents a single click event for a shortened URL.
type Click struct {
	gorm.Model
	URLID     uint      `gorm:"not null"`
	URL       URL       `gorm:"foreignKey:URLID"`
	Timestamp time.Time `gorm:"not null"`
	IPAddress string
	UserAgent string
}

// Storage defines the interface for database operations.
type Storage interface {
	CreateUser(ctx context.Context, user *User) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByID(ctx context.Context, userID uint) (*User, error)

	CreateURL(ctx context.Context, url *URL) error
	GetURLByShortURL(ctx context.Context, shortURL string) (*URL, error)
	GetURLsByUserID(ctx context.Context, userID uint) ([]URL, error)
	IncrementURLVisits(ctx context.Context, urlID uint) error
	CheckSlugExists(ctx context.Context, slug string) (bool, error)

	RecordClick(ctx context.Context, click *Click) error

	// For database migration and other management functions
	Migrate() error
	GetDB() *gorm.DB // Expose GORM DB instance for advanced operations if needed
}

// SQLiteStorage implements the Storage interface for SQLite.
type SQLiteStorage struct {
	DB *gorm.DB
}

// NewSQLiteStorage initializes a new SQLite database connection.
func NewSQLiteStorage(dbPath string) (Storage, error) {
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		return nil, err
	}
	return &SQLiteStorage{DB: db}, nil
}

// Migrate runs database migrations.
func (s *SQLiteStorage) Migrate() error {
	return s.DB.AutoMigrate(&User{}, &URL{}, &Click{})
}

// CreateUser creates a new user in the database.
func (s *SQLiteStorage) CreateUser(ctx context.Context, user *User) error {
	return s.DB.WithContext(ctx).Create(user).Error
}

// GetUserByUsername retrieves a user by their username.
func (s *SQLiteStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	var user User
	result := s.DB.WithContext(ctx).Where("username = ?", username).First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

// GetUserByID retrieves a user by their ID.
func (s *SQLiteStorage) GetUserByID(ctx context.Context, userID uint) (*User, error) {
	var user User
	result := s.DB.WithContext(ctx).First(&user, userID)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, result.Error
	}
	return &user, nil
}

// CreateURL creates a new shortened URL entry.
func (s *SQLiteStorage) CreateURL(ctx context.Context, url *URL) error {
	return s.DB.WithContext(ctx).Create(url).Error
}

// GetURLByShortURL retrieves a URL by its short slug.
func (s *SQLiteStorage) GetURLByShortURL(ctx context.Context, shortURL string) (*URL, error) {
	var url URL
	result := s.DB.WithContext(ctx).Where("short_url = ?", shortURL).First(&url)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			return nil, ErrURLNotFound
		}
		return nil, result.Error
	}
	return &url, nil
}

// GetURLsByUserID retrieves all URLs associated with a specific user.
func (s *SQLiteStorage) GetURLsByUserID(ctx context.Context, userID uint) ([]URL, error) {
	var urls []URL
	result := s.DB.WithContext(ctx).Where("user_id = ?", userID).Find(&urls)
	if result.Error != nil {
		return nil, result.Error
	}
	return urls, nil
}

// IncrementURLVisits increments the visit counter for a URL.
func (s *SQLiteStorage) IncrementURLVisits(ctx context.Context, urlID uint) error {
	return s.DB.WithContext(ctx).Model(&URL{}).Where("id = ?", urlID).Update("visits", gorm.Expr("visits + ?", 1)).Error
}

// CheckSlugExists checks if a given slug already exists in the database.
func (s *SQLiteStorage) CheckSlugExists(ctx context.Context, slug string) (bool, error) {
	var count int64
	err := s.DB.WithContext(ctx).Model(&URL{}).Where("short_url = ?", slug).Count(&count).Error
	return count > 0, err
}

// RecordClick records a new click event.
func (s *SQLiteStorage) RecordClick(ctx context.Context, click *Click) error {
	return s.DB.WithContext(ctx).Create(click).Error
}

// GetDB returns the underlying GORM DB instance.
func (s *SQLiteStorage) GetDB() *gorm.DB {
	return s.DB
}
