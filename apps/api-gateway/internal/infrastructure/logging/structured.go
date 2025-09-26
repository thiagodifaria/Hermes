package logging

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/rs/zerolog"
)

// Context keys for structured logging
type contextKey string

const (
	TraceIDKey   contextKey = "trace_id"
	SpanIDKey    contextKey = "span_id"
	RequestIDKey contextKey = "request_id"
	UserIDKey    contextKey = "user_id"
	SessionIDKey contextKey = "session_id"
	CorrelationIDKey contextKey = "correlation_id"
)

// ContextLogger provides structured logging with context
type ContextLogger struct {
	logger *Logger
	ctx    context.Context
}

// NewContextLogger creates a new context logger
func NewContextLogger(logger *Logger, ctx context.Context) *ContextLogger {
	return &ContextLogger{
		logger: logger,
		ctx:    ctx,
	}
}

// FromContext creates a context logger from context values
func FromContext(ctx context.Context, logger *Logger) *ContextLogger {
	contextLogger := &ContextLogger{
		logger: logger,
		ctx:    ctx,
	}
	
	// Automatically add context values to logger
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok && traceID != "" {
		contextLogger.logger = contextLogger.logger.WithTraceID(traceID)
	}
	
	if spanID, ok := ctx.Value(SpanIDKey).(string); ok && spanID != "" {
		contextLogger.logger = contextLogger.logger.WithSpanID(spanID)
	}
	
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
		contextLogger.logger = contextLogger.logger.WithRequestID(requestID)
	}
	
	if userID, ok := ctx.Value(UserIDKey).(string); ok && userID != "" {
		contextLogger.logger = contextLogger.logger.WithUserID(userID)
	}
	
	if sessionID, ok := ctx.Value(SessionIDKey).(string); ok && sessionID != "" {
		contextLogger.logger = contextLogger.logger.WithSessionID(sessionID)
	}
	
	return contextLogger
}

// Info returns an info level event with context
func (cl *ContextLogger) Info() *zerolog.Event {
	return cl.logger.Info()
}

// Debug returns a debug level event with context
func (cl *ContextLogger) Debug() *zerolog.Event {
	return cl.logger.Debug()
}

// Warn returns a warn level event with context
func (cl *ContextLogger) Warn() *zerolog.Event {
	return cl.logger.Warn()
}

// Error returns an error level event with context
func (cl *ContextLogger) Error() *zerolog.Event {
	return cl.logger.Error()
}

// Fatal returns a fatal level event with context
func (cl *ContextLogger) Fatal() *zerolog.Event {
	return cl.logger.Fatal()
}

// Panic returns a panic level event with context
func (cl *ContextLogger) Panic() *zerolog.Event {
	return cl.logger.Panic()
}

// Context manipulation functions

// WithTraceID adds trace ID to context
func WithTraceID(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey, traceID)
}

// WithSpanID adds span ID to context
func WithSpanID(ctx context.Context, spanID string) context.Context {
	return context.WithValue(ctx, SpanIDKey, spanID)
}

// WithRequestID adds request ID to context
func WithRequestID(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// WithUserID adds user ID to context
func WithUserID(ctx context.Context, userID string) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// WithSessionID adds session ID to context
func WithSessionID(ctx context.Context, sessionID string) context.Context {
	return context.WithValue(ctx, SessionIDKey, sessionID)
}

// WithCorrelationID adds correlation ID to context
func WithCorrelationID(ctx context.Context, correlationID string) context.Context {
	return context.WithValue(ctx, CorrelationIDKey, correlationID)
}

// Context retrieval functions

// GetTraceID retrieves trace ID from context
func GetTraceID(ctx context.Context) string {
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok {
		return traceID
	}
	return ""
}

// GetSpanID retrieves span ID from context
func GetSpanID(ctx context.Context) string {
	if spanID, ok := ctx.Value(SpanIDKey).(string); ok {
		return spanID
	}
	return ""
}

// GetRequestID retrieves request ID from context
func GetRequestID(ctx context.Context) string {
	if requestID, ok := ctx.Value(RequestIDKey).(string); ok {
		return requestID
	}
	return ""
}

// GetUserID retrieves user ID from context
func GetUserID(ctx context.Context) string {
	if userID, ok := ctx.Value(UserIDKey).(string); ok {
		return userID
	}
	return ""
}

// GetSessionID retrieves session ID from context
func GetSessionID(ctx context.Context) string {
	if sessionID, ok := ctx.Value(SessionIDKey).(string); ok {
		return sessionID
	}
	return ""
}

// ID generation functions

// GenerateTraceID generates a new trace ID
func GenerateTraceID() string {
	return generateID(16) // 128-bit trace ID
}

// GenerateSpanID generates a new span ID
func GenerateSpanID() string {
	return generateID(8) // 64-bit span ID
}

// GenerateRequestID generates a new request ID
func GenerateRequestID() string {
	return generateID(8) // 64-bit request ID
}

// GenerateCorrelationID generates a new correlation ID
func GenerateCorrelationID() string {
	return generateID(16) // 128-bit correlation ID
}

// generateID generates a random hex ID of specified byte length
func generateID(byteLength int) string {
	bytes := make([]byte, byteLength)
	if _, err := rand.Read(bytes); err != nil {
		// Fallback to timestamp-based ID if random generation fails
		return hex.EncodeToString([]byte(time.Now().Format("20060102150405")))
	}
	return hex.EncodeToString(bytes)
}

// HTTP middleware helpers

// RequestLoggingMiddleware creates HTTP middleware for request logging
func RequestLoggingMiddleware(logger *Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			
			// Generate request ID if not present
			requestID := r.Header.Get("X-Request-ID")
			if requestID == "" {
				requestID = GenerateRequestID()
				r.Header.Set("X-Request-ID", requestID)
			}
			
			// Add request ID to response header
			w.Header().Set("X-Request-ID", requestID)
			
			// Add request ID to context
			ctx := WithRequestID(r.Context(), requestID)
			r = r.WithContext(ctx)
			
			// Create wrapped response writer to capture status code
			wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}
			
			// Log request start
			contextLogger := FromContext(ctx, logger)
			contextLogger.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("remote_addr", r.RemoteAddr).
				Str("user_agent", r.UserAgent()).
				Str("referer", r.Referer()).
				Msg("request started")
			
			// Process request
			next.ServeHTTP(wrapped, r)
			
			// Log request completion
			duration := time.Since(start)
			event := contextLogger.Info().
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Int("status", wrapped.statusCode).
				Dur("duration", duration).
				Int64("response_size", wrapped.bytesWritten)
			
			// Add performance category based on response time
			if duration > 5*time.Second {
				event = event.Str("performance", "slow")
			} else if duration > 1*time.Second {
				event = event.Str("performance", "medium")
			} else {
				event = event.Str("performance", "fast")
			}
			
			// Add status category
			if wrapped.statusCode >= 500 {
				event = event.Str("category", "server_error")
			} else if wrapped.statusCode >= 400 {
				event = event.Str("category", "client_error")
			} else {
				event = event.Str("category", "success")
			}
			
			event.Msg("request completed")
		})
	}
}

// responseWriter wraps http.ResponseWriter to capture response metrics
type responseWriter struct {
	http.ResponseWriter
	statusCode   int
	bytesWritten int64
}

func (w *responseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

func (w *responseWriter) Write(data []byte) (int, error) {
	n, err := w.ResponseWriter.Write(data)
	w.bytesWritten += int64(n)
	return n, err
}

// Business event logging helpers

// LogUserAction logs user actions for audit purposes
func LogUserAction(ctx context.Context, logger *Logger, action, resource string, metadata map[string]interface{}) {
	contextLogger := FromContext(ctx, logger)
	
	event := contextLogger.Info().
		Str("type", "user_action").
		Str("action", action).
		Str("resource", resource)
	
	// Add metadata
	for key, value := range metadata {
		event = event.Interface(key, value)
	}
	
	event.Msg("user action performed")
}

// LogSecurityEvent logs security-related events
func LogSecurityEvent(ctx context.Context, logger *Logger, eventType, description string, severity string, metadata map[string]interface{}) {
	contextLogger := FromContext(ctx, logger)
	
	var event *zerolog.Event
	switch severity {
	case "high", "critical":
		event = contextLogger.Error()
	case "medium":
		event = contextLogger.Warn()
	default:
		event = contextLogger.Info()
	}
	
	event = event.
		Str("type", "security_event").
		Str("event_type", eventType).
		Str("description", description).
		Str("severity", severity)
	
	// Add metadata
	for key, value := range metadata {
		event = event.Interface(key, value)
	}
	
	event.Msg("security event detected")
}

// LogSystemEvent logs system-level events
func LogSystemEvent(ctx context.Context, logger *Logger, eventType, description string, metadata map[string]interface{}) {
	contextLogger := FromContext(ctx, logger)
	
	event := contextLogger.Info().
		Str("type", "system_event").
		Str("event_type", eventType).
		Str("description", description)
	
	// Add metadata
	for key, value := range metadata {
		event = event.Interface(key, value)
	}
	
	event.Msg("system event occurred")
}

// LogPerformanceEvent logs performance metrics
func LogPerformanceEvent(ctx context.Context, logger *Logger, operation string, duration time.Duration, metadata map[string]interface{}) {
	contextLogger := FromContext(ctx, logger)
	
	event := contextLogger.Info().
		Str("type", "performance").
		Str("operation", operation).
		Dur("duration", duration).
		Float64("duration_ms", float64(duration.Nanoseconds())/1000000)
	
	// Add performance classification
	if duration > 5*time.Second {
		event = event.Str("performance_class", "slow")
	} else if duration > 1*time.Second {
		event = event.Str("performance_class", "medium")
	} else {
		event = event.Str("performance_class", "fast")
	}
	
	// Add metadata
	for key, value := range metadata {
		event = event.Interface(key, value)
	}
	
	event.Msg("performance metric recorded")
}

// LogErrorEvent logs errors with full context
func LogErrorEvent(ctx context.Context, logger *Logger, err error, operation string, metadata map[string]interface{}) {
	contextLogger := FromContext(ctx, logger)
	
	event := contextLogger.Error().
		Err(err).
		Str("type", "error").
		Str("operation", operation)
	
	// Add metadata
	for key, value := range metadata {
		event = event.Interface(key, value)
	}
	
	event.Msg("error occurred")
}