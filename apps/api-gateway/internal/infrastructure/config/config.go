package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the application
// Following hierarchical loading: defaults -> file -> env -> flags
type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	Redis    RedisConfig    `mapstructure:"redis"`
	Security SecurityConfig `mapstructure:"security"`
	Logging  LoggingConfig  `mapstructure:"logging"`
	NATS     NATSConfig     `mapstructure:"nats"`
	OAuth    OAuthConfig    `mapstructure:"oauth"`
}

type ServerConfig struct {
	Host         string        `mapstructure:"host"`
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
	CORS         CORSConfig    `mapstructure:"cors"`
	RateLimit    RateLimitConfig `mapstructure:"rate_limit"`
}

type DatabaseConfig struct {
	URL             string        `mapstructure:"url"`
	MaxOpenConns    int           `mapstructure:"max_open_conns"`
	MaxIdleConns    int           `mapstructure:"max_idle_conns"`
	ConnMaxLifetime time.Duration `mapstructure:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `mapstructure:"conn_max_idle_time"`
	SSLMode         string        `mapstructure:"ssl_mode"`
}

type RedisConfig struct {
	URL         string        `mapstructure:"url"`
	MaxRetries  int           `mapstructure:"max_retries"`
	DialTimeout time.Duration `mapstructure:"dial_timeout"`
	ReadTimeout time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	PoolSize    int           `mapstructure:"pool_size"`
}

type SecurityConfig struct {
	JWTSecret           string        `mapstructure:"jwt_secret"`
	JWTExpiration       time.Duration `mapstructure:"jwt_expiration"`
	RefreshExpiration   time.Duration `mapstructure:"refresh_expiration"`
	PasswordMinLength   int           `mapstructure:"password_min_length"`
	PasswordRequireSpecial bool       `mapstructure:"password_require_special"`
	EncryptionKey       string        `mapstructure:"encryption_key"`
}

type LoggingConfig struct {
	Level      string `mapstructure:"level"`
	Format     string `mapstructure:"format"` // json or console
	Output     string `mapstructure:"output"` // stdout, stderr, or file path
	Structured bool   `mapstructure:"structured"`
	Caller     bool   `mapstructure:"caller"`
}

type CORSConfig struct {
	AllowedOrigins   []string `mapstructure:"allowed_origins"`
	AllowedMethods   []string `mapstructure:"allowed_methods"`
	AllowedHeaders   []string `mapstructure:"allowed_headers"`
	AllowCredentials bool     `mapstructure:"allow_credentials"`
}

type RateLimitConfig struct {
	Enabled bool  `mapstructure:"enabled"`
	RPS     int   `mapstructure:"rps"`
	Burst   int   `mapstructure:"burst"`
}

type NATSConfig struct {
	URL           string        `mapstructure:"url"`
	MaxReconnects int           `mapstructure:"max_reconnects"`
	ReconnectWait time.Duration `mapstructure:"reconnect_wait"`
}

type OAuthConfig struct {
	Google GoogleOAuthConfig `mapstructure:"google"`
	GitHub GitHubOAuthConfig `mapstructure:"github"`
	Okta   OktaOAuthConfig   `mapstructure:"okta"`
}

type GoogleOAuthConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

type GitHubOAuthConfig struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

type OktaOAuthConfig struct {
	Domain       string `mapstructure:"domain"`
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURL  string `mapstructure:"redirect_url"`
}

// Load loads configuration from various sources with proper precedence
// Precedence: defaults < config file < environment variables < flags
func Load() (*Config, error) {
	v := viper.New()
	
	// Set defaults first
	setDefaults(v)
	
	// Configure viper
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./configs")
	v.AddConfigPath(".")
	
	// Enable environment variables
	v.SetEnvPrefix("HERMES")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	
	// Read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}
	
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	
	// Validate configuration
	if err := Validate(&config); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}
	
	return &config, nil
}

// setDefaults sets sensible default values
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.host", "0.0.0.0")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "60s")
	
	// CORS defaults
	v.SetDefault("server.cors.allowed_origins", []string{"http://localhost:3000"})
	v.SetDefault("server.cors.allowed_methods", []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"})
	v.SetDefault("server.cors.allowed_headers", []string{"*"})
	v.SetDefault("server.cors.allow_credentials", true)
	
	// Rate limiting defaults
	v.SetDefault("server.rate_limit.enabled", true)
	v.SetDefault("server.rate_limit.rps", 100)
	v.SetDefault("server.rate_limit.burst", 200)
	
	// Database defaults
	v.SetDefault("database.max_open_conns", 25)
	v.SetDefault("database.max_idle_conns", 5)
	v.SetDefault("database.conn_max_lifetime", "5m")
	v.SetDefault("database.conn_max_idle_time", "5m")
	v.SetDefault("database.ssl_mode", "require")
	
	// Redis defaults
	v.SetDefault("redis.max_retries", 3)
	v.SetDefault("redis.dial_timeout", "5s")
	v.SetDefault("redis.read_timeout", "3s")
	v.SetDefault("redis.write_timeout", "3s")
	v.SetDefault("redis.pool_size", 10)
	
	// Security defaults
	v.SetDefault("security.jwt_expiration", "15m")
	v.SetDefault("security.refresh_expiration", "168h") // 7 days
	v.SetDefault("security.password_min_length", 8)
	v.SetDefault("security.password_require_special", true)
	
	// Logging defaults
	v.SetDefault("logging.level", "info")
	v.SetDefault("logging.format", "json")
	v.SetDefault("logging.output", "stdout")
	v.SetDefault("logging.structured", true)
	v.SetDefault("logging.caller", true)
	
	// NATS defaults
	v.SetDefault("nats.max_reconnects", 10)
	v.SetDefault("nats.reconnect_wait", "2s")
}

// GetEnv returns environment variable or default value
func GetEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// MustLoad loads configuration and panics on error
// Use only in main function for fail-fast behavior
func MustLoad() *Config {
	config, err := Load()
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}
	return config
}