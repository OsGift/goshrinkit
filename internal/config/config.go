// -----------------------------------------------------------------------------
// internal/config/config.go
// -----------------------------------------------------------------------------
package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds the application configuration.
type Config struct {
	Port         string
	DatabasePath string
	JWTSecret    string
	// Add other configurations as needed, e.g., link expiration settings
}

// LoadConfig loads configuration from environment variables or .env file.
func LoadConfig() *Config {
	// Load .env file if it exists
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, loading from environment variables directly.")
	}

	cfg := &Config{
		Port:         getEnv("PORT", "8080"),
		DatabasePath: getEnv("DATABASE_PATH", "./goshrinkit.db"),
		JWTSecret:    getEnv("JWT_SECRET", "123456789093245678909876543234657687"), // IMPORTANT: Change this in production!
	}

	if cfg.JWTSecret == "supersecretjwtkeythatshouldbeverylongandrandom" {
		log.Println("WARNING: Using default JWT secret. Please set JWT_SECRET environment variable in production!")
	}

	return cfg
}

// getEnv gets an environment variable or returns a default value.
func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// getEnvAsInt gets an environment variable as an integer or returns a default value.
func getEnvAsInt(key string, defaultValue int) int {
	strValue := getEnv(key, strconv.Itoa(defaultValue))
	if intValue, err := strconv.Atoi(strValue); err == nil {
		return intValue
	}
	return defaultValue
}
