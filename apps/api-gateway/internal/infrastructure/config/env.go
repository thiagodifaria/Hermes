package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment variable names - centralized for consistency
const (
	// Server
	EnvServerHost         = "HERMES_SERVER_HOST"
	EnvServerPort         = "HERMES_SERVER_PORT"
	EnvServerReadTimeout  = "HERMES_SERVER_READ_TIMEOUT"
	EnvServerWriteTimeout = "HERMES_SERVER_WRITE_TIMEOUT"
	EnvServerIdleTimeout  = "HERMES_SERVER_IDLE_TIMEOUT"
	
	// Database
	EnvDatabaseURL             = "HERMES_DATABASE_URL"
	EnvDatabaseMaxOpenConns    = "HERMES_DATABASE_MAX_OPEN_CONNS"
	EnvDatabaseMaxIdleConns    = "HERMES_DATABASE_MAX_IDLE_CONNS"
	EnvDatabaseConnMaxLifetime = "HERMES_DATABASE_CONN_MAX_LIFETIME"
	EnvDatabaseSSLMode         = "HERMES_DATABASE_SSL_MODE"
	
	// Redis
	EnvRedisURL         = "HERMES_REDIS_URL"
	EnvRedisMaxRetries  = "HERMES_REDIS_MAX_RETRIES"
	EnvRedisDialTimeout = "HERMES_REDIS_DIAL_TIMEOUT"
	EnvRedisPoolSize    = "HERMES_REDIS_POOL_SIZE"
	
	// Security
	EnvSecurityJWTSecret         = "HERMES_SECURITY_JWT_SECRET"
	EnvSecurityJWTExpiration     = "HERMES_SECURITY_JWT_EXPIRATION"
	EnvSecurityRefreshExpiration = "HERMES_SECURITY_REFRESH_EXPIRATION"
	EnvSecurityEncryptionKey     = "HERMES_SECURITY_ENCRYPTION_KEY"
	
	// Logging
	EnvLoggingLevel  = "HERMES_LOGGING_LEVEL"
	EnvLoggingFormat = "HERMES_LOGGING_FORMAT"
	EnvLoggingOutput = "HERMES_LOGGING_OUTPUT"
	
	// NATS
	EnvNATSURL           = "HERMES_NATS_URL"
	EnvNATSMaxReconnects = "HERMES_NATS_MAX_RECONNECTS"
	
	// OAuth
	EnvOAuthGoogleClientID     = "HERMES_OAUTH_GOOGLE_CLIENT_ID"
	EnvOAuthGoogleClientSecret = "HERMES_OAUTH_GOOGLE_CLIENT_SECRET"
	EnvOAuthGitHubClientID     = "HERMES_OAUTH_GITHUB_CLIENT_ID"
	EnvOAuthGitHubClientSecret = "HERMES_OAUTH_GITHUB_CLIENT_SECRET"
	EnvOAuthOktaDomain         = "HERMES_OAUTH_OKTA_DOMAIN"
	EnvOAuthOktaClientID       = "HERMES_OAUTH_OKTA_CLIENT_ID"
	EnvOAuthOktaClientSecret   = "HERMES_OAUTH_OKTA_CLIENT_SECRET"
	
	// CORS
	EnvCORSAllowedOrigins = "HERMES_CORS_ALLOWED_ORIGINS"
)

// GetStringEnv returns string environment variable or default
func GetStringEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetIntEnv returns integer environment variable or default
func GetIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// GetBoolEnv returns boolean environment variable or default
func GetBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// GetDurationEnv returns duration environment variable or default
func GetDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

// GetSliceEnv returns slice environment variable (comma-separated) or default
func GetSliceEnv(key string, defaultValue []string) []string {
	if value := os.Getenv(key); value != "" {
		return strings.Split(strings.TrimSpace(value), ",")
	}
	return defaultValue
}

// MustGetEnv returns environment variable or panics if not found
// Use only for critical configuration that must be present
func MustGetEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		panic(fmt.Sprintf("required environment variable %s is not set", key))
	}
	return value
}

// LoadFromEnv loads configuration directly from environment variables
// Useful for container deployments where config files are not preferred
func LoadFromEnv() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         GetStringEnv(EnvServerHost, "0.0.0.0"),
			Port:         GetIntEnv(EnvServerPort, 8080),
			ReadTimeout:  GetDurationEnv(EnvServerReadTimeout, 30*time.Second),
			WriteTimeout: GetDurationEnv(EnvServerWriteTimeout, 30*time.Second),
			IdleTimeout:  GetDurationEnv(EnvServerIdleTimeout, 60*time.Second),
			CORS: CORSConfig{
				AllowedOrigins: GetSliceEnv(EnvCORSAllowedOrigins, []string{"http://localhost:3000"}),
				AllowedMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
				AllowedHeaders: []string{"*"},
				AllowCredentials: true,
			},
			RateLimit: RateLimitConfig{
				Enabled: true,
				RPS:     100,
				Burst:   200,
			},
		},
		Database: DatabaseConfig{
			URL:             GetStringEnv(EnvDatabaseURL, ""),
			MaxOpenConns:    GetIntEnv(EnvDatabaseMaxOpenConns, 25),
			MaxIdleConns:    GetIntEnv(EnvDatabaseMaxIdleConns, 5),
			ConnMaxLifetime: GetDurationEnv(EnvDatabaseConnMaxLifetime, 5*time.Minute),
			ConnMaxIdleTime: GetDurationEnv(EnvDatabaseConnMaxLifetime, 5*time.Minute),
			SSLMode:         GetStringEnv(EnvDatabaseSSLMode, "require"),
		},
		Redis: RedisConfig{
			URL:         GetStringEnv(EnvRedisURL, ""),
			MaxRetries:  GetIntEnv(EnvRedisMaxRetries, 3),
			DialTimeout: GetDurationEnv(EnvRedisDialTimeout, 5*time.Second),
			ReadTimeout: GetDurationEnv(EnvRedisDialTimeout, 3*time.Second),
			WriteTimeout: GetDurationEnv(EnvRedisDialTimeout, 3*time.Second),
			PoolSize:    GetIntEnv(EnvRedisPoolSize, 10),
		},
		Security: SecurityConfig{
			JWTSecret:           GetStringEnv(EnvSecurityJWTSecret, ""),
			JWTExpiration:       GetDurationEnv(EnvSecurityJWTExpiration, 15*time.Minute),
			RefreshExpiration:   GetDurationEnv(EnvSecurityRefreshExpiration, 168*time.Hour), // 7 days
			PasswordMinLength:   8,
			PasswordRequireSpecial: true,
			EncryptionKey:       GetStringEnv(EnvSecurityEncryptionKey, ""),
		},
		Logging: LoggingConfig{
			Level:      GetStringEnv(EnvLoggingLevel, "info"),
			Format:     GetStringEnv(EnvLoggingFormat, "json"),
			Output:     GetStringEnv(EnvLoggingOutput, "stdout"),
			Structured: true,
			Caller:     true,
		},
		NATS: NATSConfig{
			URL:           GetStringEnv(EnvNATSURL, ""),
			MaxReconnects: GetIntEnv(EnvNATSMaxReconnects, 10),
			ReconnectWait: 2 * time.Second,
		},
		OAuth: OAuthConfig{
			Google: GoogleOAuthConfig{
				ClientID:     GetStringEnv(EnvOAuthGoogleClientID, ""),
				ClientSecret: GetStringEnv(EnvOAuthGoogleClientSecret, ""),
				RedirectURL:  GetStringEnv("HERMES_OAUTH_GOOGLE_REDIRECT_URL", "http://localhost:8080/auth/google/callback"),
			},
			GitHub: GitHubOAuthConfig{
				ClientID:     GetStringEnv(EnvOAuthGitHubClientID, ""),
				ClientSecret: GetStringEnv(EnvOAuthGitHubClientSecret, ""),
				RedirectURL:  GetStringEnv("HERMES_OAUTH_GITHUB_REDIRECT_URL", "http://localhost:8080/auth/github/callback"),
			},
			Okta: OktaOAuthConfig{
				Domain:       GetStringEnv(EnvOAuthOktaDomain, ""),
				ClientID:     GetStringEnv(EnvOAuthOktaClientID, ""),
				ClientSecret: GetStringEnv(EnvOAuthOktaClientSecret, ""),
				RedirectURL:  GetStringEnv("HERMES_OAUTH_OKTA_REDIRECT_URL", "http://localhost:8080/auth/okta/callback"),
			},
		},
	}
}

// IsDevelopment returns true if running in development mode
func IsDevelopment() bool {
	return GetStringEnv("HERMES_ENV", "development") == "development"
}

// IsProduction returns true if running in production mode
func IsProduction() bool {
	return GetStringEnv("HERMES_ENV", "development") == "production"
}

// GetEnvironment returns current environment (development, staging, production)
func GetEnvironment() string {
	return GetStringEnv("HERMES_ENV", "development")
}

// ValidateRequiredEnvVars checks that all required environment variables are set
// Returns error with missing variables for easier debugging
func ValidateRequiredEnvVars() error {
	var missing []string
	
	// Database URL is always required
	if GetStringEnv(EnvDatabaseURL, "") == "" {
		missing = append(missing, EnvDatabaseURL)
	}
	
	// JWT Secret is required for security
	if GetStringEnv(EnvSecurityJWTSecret, "") == "" {
		missing = append(missing, EnvSecurityJWTSecret)
	}
	
	// Encryption key is required for sensitive data
	if GetStringEnv(EnvSecurityEncryptionKey, "") == "" {
		missing = append(missing, EnvSecurityEncryptionKey)
	}
	
	// In production, require Redis for caching
	if IsProduction() && GetStringEnv(EnvRedisURL, "") == "" {
		missing = append(missing, EnvRedisURL)
	}
	
	// In production, require NATS for messaging
	if IsProduction() && GetStringEnv(EnvNATSURL, "") == "" {
		missing = append(missing, EnvNATSURL)
	}
	
	if len(missing) > 0 {
		return fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}
	
	return nil
}