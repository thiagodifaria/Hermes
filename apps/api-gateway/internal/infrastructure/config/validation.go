package config

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// ValidationError represents a configuration validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("validation error in field '%s': %s", e.Field, e.Message)
}

// ValidationErrors represents multiple validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	var messages []string
	for _, err := range e {
		messages = append(messages, err.Error())
	}
	return strings.Join(messages, "; ")
}

// Validate validates the entire configuration
func Validate(config *Config) error {
	var errors ValidationErrors
	
	// Validate server configuration
	if err := validateServer(&config.Server); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate database configuration
	if err := validateDatabase(&config.Database); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate Redis configuration
	if err := validateRedis(&config.Redis); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate security configuration
	if err := validateSecurity(&config.Security); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate logging configuration
	if err := validateLogging(&config.Logging); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate NATS configuration
	if err := validateNATS(&config.NATS); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate OAuth configuration
	if err := validateOAuth(&config.OAuth); err != nil {
		errors = append(errors, err...)
	}
	
	if len(errors) > 0 {
		return errors
	}
	
	return nil
}

func validateServer(config *ServerConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Validate port range
	if config.Port < 1 || config.Port > 65535 {
		errors = append(errors, ValidationError{
			Field:   "server.port",
			Message: "must be between 1 and 65535",
		})
	}
	
	// Validate timeouts
	if config.ReadTimeout <= 0 {
		errors = append(errors, ValidationError{
			Field:   "server.read_timeout",
			Message: "must be positive",
		})
	}
	
	if config.WriteTimeout <= 0 {
		errors = append(errors, ValidationError{
			Field:   "server.write_timeout",
			Message: "must be positive",
		})
	}
	
	if config.IdleTimeout <= 0 {
		errors = append(errors, ValidationError{
			Field:   "server.idle_timeout",
			Message: "must be positive",
		})
	}
	
	// Validate CORS
	if err := validateCORS(&config.CORS); err != nil {
		errors = append(errors, err...)
	}
	
	// Validate rate limiting
	if err := validateRateLimit(&config.RateLimit); err != nil {
		errors = append(errors, err...)
	}
	
	return errors
}

func validateDatabase(config *DatabaseConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Database URL is required
	if config.URL == "" {
		errors = append(errors, ValidationError{
			Field:   "database.url",
			Message: "is required",
		})
	} else {
		// Validate database URL format
		if _, err := url.Parse(config.URL); err != nil {
			errors = append(errors, ValidationError{
				Field:   "database.url",
				Message: "invalid URL format",
			})
		}
	}
	
	// Validate connection pool settings
	if config.MaxOpenConns <= 0 {
		errors = append(errors, ValidationError{
			Field:   "database.max_open_conns",
			Message: "must be positive",
		})
	}
	
	if config.MaxIdleConns < 0 {
		errors = append(errors, ValidationError{
			Field:   "database.max_idle_conns",
			Message: "must be non-negative",
		})
	}
	
	if config.MaxIdleConns > config.MaxOpenConns {
		errors = append(errors, ValidationError{
			Field:   "database.max_idle_conns",
			Message: "cannot be greater than max_open_conns",
		})
	}
	
	// Validate SSL mode
	validSSLModes := []string{"disable", "require", "verify-ca", "verify-full"}
	if !contains(validSSLModes, config.SSLMode) {
		errors = append(errors, ValidationError{
			Field:   "database.ssl_mode",
			Message: "must be one of: " + strings.Join(validSSLModes, ", "),
		})
	}
	
	return errors
}

func validateRedis(config *RedisConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Redis URL validation (optional for development)
	if config.URL != "" {
		if _, err := url.Parse(config.URL); err != nil {
			errors = append(errors, ValidationError{
				Field:   "redis.url",
				Message: "invalid URL format",
			})
		}
	}
	
	// Validate pool settings
	if config.PoolSize <= 0 {
		errors = append(errors, ValidationError{
			Field:   "redis.pool_size",
			Message: "must be positive",
		})
	}
	
	if config.MaxRetries < 0 {
		errors = append(errors, ValidationError{
			Field:   "redis.max_retries",
			Message: "must be non-negative",
		})
	}
	
	return errors
}

func validateSecurity(config *SecurityConfig) ValidationErrors {
	var errors ValidationErrors
	
	// JWT secret is critical for security
	if config.JWTSecret == "" {
		errors = append(errors, ValidationError{
			Field:   "security.jwt_secret",
			Message: "is required and must be a secure random string",
		})
	} else if len(config.JWTSecret) < 32 {
		errors = append(errors, ValidationError{
			Field:   "security.jwt_secret",
			Message: "must be at least 32 characters for security",
		})
	}
	
	// Encryption key validation
	if config.EncryptionKey == "" {
		errors = append(errors, ValidationError{
			Field:   "security.encryption_key",
			Message: "is required for encrypting sensitive data",
		})
	} else if len(config.EncryptionKey) != 32 {
		errors = append(errors, ValidationError{
			Field:   "security.encryption_key",
			Message: "must be exactly 32 characters (AES-256)",
		})
	}
	
	// JWT expiration validation
	if config.JWTExpiration <= 0 {
		errors = append(errors, ValidationError{
			Field:   "security.jwt_expiration",
			Message: "must be positive",
		})
	} else if config.JWTExpiration > time.Hour {
		errors = append(errors, ValidationError{
			Field:   "security.jwt_expiration",
			Message: "should not exceed 1 hour for security",
		})
	}
	
	// Refresh token validation
	if config.RefreshExpiration <= config.JWTExpiration {
		errors = append(errors, ValidationError{
			Field:   "security.refresh_expiration",
			Message: "must be greater than jwt_expiration",
		})
	}
	
	// Password policy validation
	if config.PasswordMinLength < 8 {
		errors = append(errors, ValidationError{
			Field:   "security.password_min_length",
			Message: "should be at least 8 characters",
		})
	}
	
	return errors
}

func validateLogging(config *LoggingConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Validate log level
	validLevels := []string{"trace", "debug", "info", "warn", "error", "fatal", "panic"}
	if !contains(validLevels, config.Level) {
		errors = append(errors, ValidationError{
			Field:   "logging.level",
			Message: "must be one of: " + strings.Join(validLevels, ", "),
		})
	}
	
	// Validate log format
	validFormats := []string{"json", "console"}
	if !contains(validFormats, config.Format) {
		errors = append(errors, ValidationError{
			Field:   "logging.format",
			Message: "must be one of: " + strings.Join(validFormats, ", "),
		})
	}
	
	return errors
}

func validateNATS(config *NATSConfig) ValidationErrors {
	var errors ValidationErrors
	
	// NATS URL validation (optional for development)
	if config.URL != "" {
		if _, err := url.Parse(config.URL); err != nil {
			errors = append(errors, ValidationError{
				Field:   "nats.url",
				Message: "invalid URL format",
			})
		}
	}
	
	if config.MaxReconnects < 0 {
		errors = append(errors, ValidationError{
			Field:   "nats.max_reconnects",
			Message: "must be non-negative",
		})
	}
	
	return errors
}

func validateOAuth(config *OAuthConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Validate Google OAuth (if configured)
	if config.Google.ClientID != "" || config.Google.ClientSecret != "" {
		if config.Google.ClientID == "" {
			errors = append(errors, ValidationError{
				Field:   "oauth.google.client_id",
				Message: "is required when Google OAuth is configured",
			})
		}
		if config.Google.ClientSecret == "" {
			errors = append(errors, ValidationError{
				Field:   "oauth.google.client_secret",
				Message: "is required when Google OAuth is configured",
			})
		}
		if config.Google.RedirectURL == "" {
			errors = append(errors, ValidationError{
				Field:   "oauth.google.redirect_url",
				Message: "is required when Google OAuth is configured",
			})
		} else if !isValidURL(config.Google.RedirectURL) {
			errors = append(errors, ValidationError{
				Field:   "oauth.google.redirect_url",
				Message: "must be a valid URL",
			})
		}
	}
	
	// Validate GitHub OAuth (if configured)
	if config.GitHub.ClientID != "" || config.GitHub.ClientSecret != "" {
		if config.GitHub.ClientID == "" {
			errors = append(errors, ValidationError{
				Field:   "oauth.github.client_id",
				Message: "is required when GitHub OAuth is configured",
			})
		}
		if config.GitHub.ClientSecret == "" {
			errors = append(errors, ValidationError{
				Field:   "oauth.github.client_secret",
				Message: "is required when GitHub OAuth is configured",
			})
		}
	}
	
	// Validate Okta OAuth (if configured)
	if config.Okta.Domain != "" || config.Okta.ClientID != "" || config.Okta.ClientSecret != "" {
		if config.Okta.Domain == "" {
			errors = append(errors, ValidationError{
				Field:   "oauth.okta.domain",
				Message: "is required when Okta OAuth is configured",
			})
		}
		if config.Okta.ClientID == "" {
			errors = append(errors, ValidationError{
				Field:   "oauth.okta.client_id",
				Message: "is required when Okta OAuth is configured",
			})
		}
		if config.Okta.ClientSecret == "" {
			errors = append(errors, ValidationError{
				Field:   "oauth.okta.client_secret",
				Message: "is required when Okta OAuth is configured",
			})
		}
	}
	
	return errors
}

func validateCORS(config *CORSConfig) ValidationErrors {
	var errors ValidationErrors
	
	// Validate allowed methods
	validMethods := []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"}
	for _, method := range config.AllowedMethods {
		if !contains(validMethods, method) {
			errors = append(errors, ValidationError{
				Field:   "server.cors.allowed_methods",
				Message: fmt.Sprintf("invalid method '%s', must be one of: %s", method, strings.Join(validMethods, ", ")),
			})
		}
	}
	
	return errors
}

func validateRateLimit(config *RateLimitConfig) ValidationErrors {
	var errors ValidationErrors
	
	if config.Enabled {
		if config.RPS <= 0 {
			errors = append(errors, ValidationError{
				Field:   "server.rate_limit.rps",
				Message: "must be positive when rate limiting is enabled",
			})
		}
		
		if config.Burst <= 0 {
			errors = append(errors, ValidationError{
				Field:   "server.rate_limit.burst",
				Message: "must be positive when rate limiting is enabled",
			})
		}
		
		if config.Burst < config.RPS {
			errors = append(errors, ValidationError{
				Field:   "server.rate_limit.burst",
				Message: "should be greater than or equal to RPS",
			})
		}
	}
	
	return errors
}

// Helper functions
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func isValidURL(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func isValidEmail(email string) bool {
	// Simple email regex for basic validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}