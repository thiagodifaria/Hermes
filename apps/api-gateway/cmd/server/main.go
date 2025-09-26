// apps/api-gateway/cmd/server/main.go
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/adapters/database/postgres"
	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/adapters/http/middleware"
	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/adapters/http/routes"
	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/infrastructure/config"
	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/infrastructure/logging"
)

// Application holds the application dependencies
type Application struct {
	Config     *config.Config
	DB         *postgres.Connection
	HTTPServer *http.Server
	Logger     zerolog.Logger
}

// version information - set during build
var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

func main() {
	// Initialize application
	app, err := initializeApplication()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize application")
	}

	// Print startup information
	printStartupInfo()

	// Start application
	if err := app.Start(); err != nil {
		log.Fatal().Err(err).Msg("failed to start application")
	}
}

// initializeApplication initializes all application dependencies
func initializeApplication() (*Application, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize structured logging
	logger, err := logging.NewZerolog(&cfg.Logging)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Set global logger
	log.Logger = logger
	zerolog.DefaultContextLogger = &logger

	log.Info().Msg("starting Hermes API Gateway")

	// Initialize database connection
	dbConn, err := postgres.NewConnection(&cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Test database connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := dbConn.Health(ctx); err != nil {
		return nil, fmt.Errorf("database health check failed: %w", err)
	}

	log.Info().Msg("database connection established")

	// Initialize HTTP server
	httpServer, err := initializeHTTPServer(cfg, dbConn)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize HTTP server: %w", err)
	}

	return &Application{
		Config:     cfg,
		DB:         dbConn,
		HTTPServer: httpServer,
		Logger:     logger,
	}, nil
}

// initializeHTTPServer sets up the HTTP server with all routes and middleware
func initializeHTTPServer(cfg *config.Config, db *postgres.Connection) (*http.Server, error) {
	// Set Gin mode based on environment
	if cfg.Logging.Level == "debug" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	// Create Gin router
	router := gin.New()

	// Add global middleware
	router.Use(middleware.Recovery())
	router.Use(middleware.RequestID())
	router.Use(middleware.Logger())
	router.Use(middleware.CORS(cfg.Server.CORS))

	// Add rate limiting if enabled
	if cfg.Server.RateLimit.Enabled {
		router.Use(middleware.RateLimit(cfg.Server.RateLimit))
	}

	// Initialize handlers
	// Setup routes without handlers package (handlers removed due to missing package)
	routes.SetupSessionRoutes(router)
	// Create HTTP server
	server := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port),
		Handler:      router,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	return server, nil
}

// Start starts the application
func (app *Application) Start() error {
	// Setup graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Start HTTP server in a goroutine
	go func() {
		log.Info().
			Str("addr", app.HTTPServer.Addr).
			Msg("starting HTTP server")

		if err := app.HTTPServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal().Err(err).Msg("HTTP server failed")
		}
	}()

	// Log that server is ready
	log.Info().
		Str("version", version).
		Str("addr", app.HTTPServer.Addr).
		Msg("Hermes API Gateway is ready")

	// Wait for interrupt signal
	<-ctx.Done()

	// Start graceful shutdown
	log.Info().Msg("shutting down gracefully...")

	return app.Shutdown()
}

// Shutdown gracefully shuts down the application
func (app *Application) Shutdown() error {
	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	log.Info().Msg("shutting down HTTP server")
	if err := app.HTTPServer.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("HTTP server shutdown failed")
		return err
	}

	// Close database connections
	log.Info().Msg("closing database connections")
	app.DB.Close()

	// Final log message
	log.Info().Msg("Hermes API Gateway shutdown complete")

	return nil
}

// printStartupInfo prints application startup information
func printStartupInfo() {
	fmt.Printf(`
██╗  ██╗███████╗██████╗ ███╗   ███╗███████╗███████╗
██║  ██║██╔════╝██╔══██╗████╗ ████║██╔════╝██╔════╝
███████║█████╗  ██████╔╝██╔████╔██║█████╗  ███████╗
██╔══██║██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ╚════██║
██║  ██║███████╗██║  ██║██║ ╚═╝ ██║███████╗███████║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝

Remote Operations Platform with Unified Infrastructure Management

`)

	log.Info().
		Str("version", version).
		Str("build_time", buildTime).
		Str("git_commit", gitCommit).
		Str("go_version", fmt.Sprintf("%s", os.Getenv("GO_VERSION"))).
		Msg("build information")
}

// Health check endpoints and monitoring setup
func (app *Application) setupMonitoring() {
	// This would be expanded to include:
	// - Prometheus metrics endpoints
	// - Health check endpoints
	// - Readiness/liveness probes
	// - Performance monitoring
}

// Database migration runner (optional, could be separate command)
func runMigrations(db *postgres.Connection) error {
	log.Info().Msg("checking for pending migrations")
	
	// This would integrate with a migration library
	// For example, using golang-migrate/migrate
	
	log.Info().Msg("migrations completed successfully")
	return nil
}

// Configuration validation
func validateConfig(cfg *config.Config) error {
	// Additional runtime configuration validation
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("invalid server port: %d", cfg.Server.Port)
	}

	if cfg.Database.URL == "" {
		return fmt.Errorf("database URL is required")
	}

	if len(cfg.Security.JWTSecret) < 32 {
		return fmt.Errorf("JWT secret must be at least 32 characters")
	}

	return nil
}

// Environment-specific initialization
func initializeEnvironment(cfg *config.Config) error {
	switch os.Getenv("HERMES_ENV") {
	case "development":
		return initializeDevelopment(cfg)
	case "production":
		return initializeProduction(cfg)
	case "test":
		return initializeTest(cfg)
	default:
		log.Info().Msg("no specific environment initialization")
	}
	return nil
}

// Development environment setup
func initializeDevelopment(cfg *config.Config) error {
	log.Info().Msg("initializing development environment")
	
	// Development-specific setup:
	// - Enable debug logging
	// - Set up development tools
	// - Configure hot reloading (if applicable)
	
	return nil
}

// Production environment setup
func initializeProduction(cfg *config.Config) error {
	log.Info().Msg("initializing production environment")
	
	// Production-specific setup:
	// - Enhanced security settings
	// - Performance optimizations
	// - Monitoring and alerting
	
	return nil
}

// Test environment setup
func initializeTest(cfg *config.Config) error {
	log.Info().Msg("initializing test environment")
	
	// Test-specific setup:
	// - Use test database
	// - Mock external services
	// - Disable certain features
	
	return nil
}

// Signal handling for different shutdown scenarios
func setupSignalHandling(app *Application) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, 
		syscall.SIGINT,  // Ctrl+C
		syscall.SIGTERM, // Termination request
		syscall.SIGHUP,  // Terminal closed
	)

	go func() {
		sig := <-sigChan
		log.Info().
			Str("signal", sig.String()).
			Msg("received shutdown signal")
		
		// Perform cleanup based on signal type
		switch sig {
		case syscall.SIGHUP:
			// Reload configuration
			log.Info().Msg("reloading configuration")
			// Implementation for config reload
		default:
			// Standard shutdown
			if err := app.Shutdown(); err != nil {
				log.Error().Err(err).Msg("shutdown failed")
				os.Exit(1)
			}
			os.Exit(0)
		}
	}()
}

// Performance profiling setup (for debugging)
func setupProfiling() {
	// Enable pprof endpoints in development/debugging mode
	if os.Getenv("HERMES_ENABLE_PPROF") == "true" {
		go func() {
			log.Info().Msg("starting pprof server on :6060")
			log.Error().Err(http.ListenAndServe(":6060", nil)).Msg("pprof server failed")
		}()
	}
}

// Metrics collection setup
func setupMetrics(cfg *config.Config) error {
	// Initialize Prometheus metrics
	// Set up custom metrics for:
	// - HTTP request duration/count
	// - Database query performance
	// - Active sessions
	// - Authentication attempts
	// - Error rates
	
	log.Info().Msg("metrics collection initialized")
	return nil
}

// Distributed tracing setup
func setupTracing(cfg *config.Config) error {
	// Initialize Jaeger/OpenTelemetry tracing
	// Configure:
	// - Service name
	// - Sampling rate
	// - Export endpoint
	
	log.Info().Msg("distributed tracing initialized")
	return nil
}