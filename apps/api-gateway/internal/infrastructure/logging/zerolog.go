package logging

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

// Logger wraps zerolog with additional functionality
type Logger struct {
	*zerolog.Logger
}

// Config defines logging configuration
type Config struct {
	Level      string `json:"level"`
	Format     string `json:"format"`     // json or console
	Output     string `json:"output"`     // stdout, stderr, or file path
	Structured bool   `json:"structured"`
	Caller     bool   `json:"caller"`
	TimeFormat string `json:"time_format"`
}

// Init initializes the global logger with the provided configuration
func Init(config Config) (*Logger, error) {
	// Set global time format
	if config.TimeFormat != "" {
		zerolog.TimeFieldFormat = config.TimeFormat
	} else {
		zerolog.TimeFieldFormat = time.RFC3339
	}
	
	// Enable stack trace support
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack
	
	// Set log level
	level, err := zerolog.ParseLevel(strings.ToLower(config.Level))
	if err != nil {
		level = zerolog.InfoLevel // default to info
	}
	zerolog.SetGlobalLevel(level)
	
	// Configure output writer
	var output io.Writer
	switch strings.ToLower(config.Output) {
	case "stdout", "":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		// File output
		if err := ensureDir(filepath.Dir(config.Output)); err != nil {
			return nil, err
		}
		file, err := os.OpenFile(config.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, err
		}
		output = file
	}
	
	// Configure format
	if strings.ToLower(config.Format) == "console" {
		output = zerolog.ConsoleWriter{
			Out:        output,
			TimeFormat: "15:04:05",
			NoColor:    false, // Enable colors for better readability
		}
	}
	
	// Create logger
	var logger zerolog.Logger
	if config.Caller {
		logger = zerolog.New(output).With().Timestamp().Caller().Logger()
	} else {
		logger = zerolog.New(output).With().Timestamp().Logger()
	}
	
	// Set as global logger
	log.Logger = logger
	
	return &Logger{Logger: &logger}, nil
}

// NewLogger creates a new logger instance with custom configuration
func NewLogger(config Config) (*Logger, error) {
	logger, err := Init(config)
	if err != nil {
		return nil, err
	}
	return logger, nil
}

// WithService adds service name to all log entries
func (l *Logger) WithService(service string) *Logger {
	newLogger := l.Logger.With().Str("service", service).Logger()
	return &Logger{Logger: &newLogger}
}

// WithComponent adds component name to all log entries
func (l *Logger) WithComponent(component string) *Logger {
	newLogger := l.Logger.With().Str("component", component).Logger()
	return &Logger{Logger: &newLogger}
}

// WithVersion adds version to all log entries
func (l *Logger) WithVersion(version string) *Logger {
	newLogger := l.Logger.With().Str("version", version).Logger()
	return &Logger{Logger: &newLogger}
}

// WithRequestID adds request ID for request tracing
func (l *Logger) WithRequestID(requestID string) *Logger {
	newLogger := l.Logger.With().Str("request_id", requestID).Logger()
	return &Logger{Logger: &newLogger}
}

// WithUserID adds user ID for user activity tracking
func (l *Logger) WithUserID(userID string) *Logger {
	newLogger := l.Logger.With().Str("user_id", userID).Logger()
	return &Logger{Logger: &newLogger}
}

// WithSessionID adds session ID for session tracking
func (l *Logger) WithSessionID(sessionID string) *Logger {
	newLogger := l.Logger.With().Str("session_id", sessionID).Logger()
	return &Logger{Logger: &newLogger}
}

// WithTraceID adds trace ID for distributed tracing
func (l *Logger) WithTraceID(traceID string) *Logger {
	newLogger := l.Logger.With().Str("trace_id", traceID).Logger()
	return &Logger{Logger: &newLogger}
}

// WithSpanID adds span ID for distributed tracing
func (l *Logger) WithSpanID(spanID string) *Logger {
	newLogger := l.Logger.With().Str("span_id", spanID).Logger()
	return &Logger{Logger: &newLogger}
}

// WithError adds error details to log context
func (l *Logger) WithError(err error) *zerolog.Event {
	return l.Logger.Error().Err(err)
}

// WithDuration adds duration for performance monitoring
func (l *Logger) WithDuration(duration time.Duration) *Logger {
	newLogger := l.Logger.With().Dur("duration", duration).Logger()
	return &Logger{Logger: &newLogger}
}

// GetDefaultConfig returns a sensible default configuration
func GetDefaultConfig() Config {
	return Config{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		Structured: true,
		Caller:     true,
		TimeFormat: time.RFC3339,
	}
}

// GetDevelopmentConfig returns configuration optimized for development
func GetDevelopmentConfig() Config {
	return Config{
		Level:      "debug",
		Format:     "console",
		Output:     "stdout",
		Structured: true,
		Caller:     true,
		TimeFormat: "15:04:05",
	}
}

// GetProductionConfig returns configuration optimized for production
func GetProductionConfig() Config {
	return Config{
		Level:      "info",
		Format:     "json",
		Output:     "stdout",
		Structured: true,
		Caller:     false, // Disable caller in production for performance
		TimeFormat: time.RFC3339,
	}
}

// HealthCheck provides a simple way to test if logging is working
func (l *Logger) HealthCheck() {
	l.Logger.Info().
		Str("status", "healthy").
		Str("check", "logging").
		Time("timestamp", time.Now()).
		Msg("logging health check")
}

// LogLevel represents available log levels
type LogLevel int

const (
	TraceLevel LogLevel = iota
	DebugLevel
	InfoLevel
	WarnLevel
	ErrorLevel
	FatalLevel
	PanicLevel
)

// String returns string representation of log level
func (l LogLevel) String() string {
	switch l {
	case TraceLevel:
		return "trace"
	case DebugLevel:
		return "debug"
	case InfoLevel:
		return "info"
	case WarnLevel:
		return "warn"
	case ErrorLevel:
		return "error"
	case FatalLevel:
		return "fatal"
	case PanicLevel:
		return "panic"
	default:
		return "unknown"
	}
}

// ParseLogLevel parses string to LogLevel
func ParseLogLevel(level string) LogLevel {
	switch strings.ToLower(level) {
	case "trace":
		return TraceLevel
	case "debug":
		return DebugLevel
	case "info":
		return InfoLevel
	case "warn", "warning":
		return WarnLevel
	case "error":
		return ErrorLevel
	case "fatal":
		return FatalLevel
	case "panic":
		return PanicLevel
	default:
		return InfoLevel
	}
}

// Performance logging helpers
func (l *Logger) LogPerformance(operation string, duration time.Duration, fields map[string]interface{}) {
	event := l.Logger.Info().
		Str("type", "performance").
		Str("operation", operation).
		Dur("duration_ms", duration)
	
	// Add additional fields
	for key, value := range fields {
		switch v := value.(type) {
		case string:
			event = event.Str(key, v)
		case int:
			event = event.Int(key, v)
		case int64:
			event = event.Int64(key, v)
		case float64:
			event = event.Float64(key, v)
		case bool:
			event = event.Bool(key, v)
		case time.Time:
			event = event.Time(key, v)
		default:
			event = event.Interface(key, v)
		}
	}
	
	event.Msg("performance metric")
}

// Security logging helpers
func (l *Logger) LogSecurityEvent(eventType, description string, fields map[string]interface{}) {
	event := l.Logger.Warn().
		Str("type", "security").
		Str("event_type", eventType).
		Str("description", description)
	
	// Add additional fields
	for key, value := range fields {
		switch v := value.(type) {
		case string:
			event = event.Str(key, v)
		case int:
			event = event.Int(key, v)
		default:
			event = event.Interface(key, v)
		}
	}
	
	event.Msg("security event")
}

// Business logic logging helpers
func (l *Logger) LogBusinessEvent(eventType, description string, fields map[string]interface{}) {
	event := l.Logger.Info().
		Str("type", "business").
		Str("event_type", eventType).
		Str("description", description)
	
	for key, value := range fields {
		event = event.Interface(key, value)
	}
	
	event.Msg("business event")
}

// ensureDir creates directory if it doesn't exist
func ensureDir(dir string) error {
	if dir == "" {
		return nil
	}
	return os.MkdirAll(dir, 0755)
}

// Global logger functions for convenience
func Info() *zerolog.Event {
	return log.Info()
}

func Debug() *zerolog.Event {
	return log.Debug()
}

func Warn() *zerolog.Event {
	return log.Warn()
}

func Error() *zerolog.Event {
	return log.Error()
}

func Fatal() *zerolog.Event {
	return log.Fatal()
}

func Panic() *zerolog.Event {
	return log.Panic()
}

// IsDebugEnabled checks if debug logging is enabled
func IsDebugEnabled() bool {
	return log.Logger.GetLevel() <= zerolog.DebugLevel
}

// IsTraceEnabled checks if trace logging is enabled
func IsTraceEnabled() bool {
	return log.Logger.GetLevel() <= zerolog.TraceLevel
}

// SetGlobalLogLevel sets the global log level
func SetGlobalLogLevel(level string) {
	if l, err := zerolog.ParseLevel(strings.ToLower(level)); err == nil {
		zerolog.SetGlobalLevel(l)
	}
}

// GetCurrentLogLevel returns current global log level
func GetCurrentLogLevel() string {
	return zerolog.GlobalLevel().String()
}