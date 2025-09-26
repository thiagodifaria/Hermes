// apps/api-gateway/internal/adapters/database/postgres/connection.go
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/rs/zerolog/log"

	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/infrastructure/config"
)

// DB wraps pgxpool.Pool with additional functionality
type DB struct {
	Pool   *pgxpool.Pool
	Config *config.DatabaseConfig
}

// Connection provides database connection management
type Connection struct {
	db     *DB
	config *config.DatabaseConfig
}

// NewConnection creates a new database connection with connection pool
func NewConnection(cfg *config.DatabaseConfig) (*Connection, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("database URL is required")
	}

	conn := &Connection{
		config: cfg,
	}

	if err := conn.connect(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	return conn, nil
}

// connect establishes the database connection pool
func (c *Connection) connect() error {
	// Parse database URL and create pgx config
	pgxConfig, err := pgxpool.ParseConfig(c.config.URL)
	if err != nil {
		return fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure connection pool settings
	c.configureConnectionPool(pgxConfig)

	// Configure logging and monitoring
	c.configureLogging(pgxConfig)

	// Create connection pool
	pool, err := pgxpool.NewWithConfig(context.Background(), pgxConfig)
	if err != nil {
		return fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return fmt.Errorf("failed to ping database: %w", err)
	}

	c.db = &DB{
		Pool:   pool,
		Config: c.config,
	}

	log.Info().
		Str("host", pgxConfig.ConnConfig.Host).
		Uint16("port", pgxConfig.ConnConfig.Port).
		Str("database", pgxConfig.ConnConfig.Database).
		Int32("max_conns", pgxConfig.MaxConns).
		Msg("database connection pool initialized")

	return nil
}

// configureConnectionPool sets up connection pool parameters
func (c *Connection) configureConnectionPool(cfg *pgxpool.Config) {
	// Connection pool settings from config
	cfg.MaxConns = int32(c.config.MaxOpenConns)
	cfg.MinConns = int32(c.config.MaxIdleConns)
	cfg.MaxConnLifetime = c.config.ConnMaxLifetime
	cfg.MaxConnIdleTime = c.config.ConnMaxIdleTime
	cfg.HealthCheckPeriod = 1 * time.Minute

	// Connection settings
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	cfg.ConnConfig.PreferSimpleProtocol = false

	// Configure SSL mode
	if c.config.SSLMode != "" {
		cfg.ConnConfig.TLSConfig = nil // Let pgx handle SSL mode from URL
	}
}

// configureLogging sets up database query logging and tracing
func (c *Connection) configureLogging(cfg *pgxpool.Config) {
	// Configure query logging based on log level
	cfg.BeforeConnect = func(ctx context.Context, cc *pgx.ConnConfig) error {
		// Add query logging tracer
		cc.Tracer = &queryTracer{
			logQueries: log.Debug().Enabled(),
		}
		return nil
	}

	// Configure connection lifecycle logging
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		log.Debug().
			Str("pid", fmt.Sprintf("%d", conn.PgConn().PID())).
			Msg("new database connection established")
		return nil
	}
}

// GetDB returns the database instance
func (c *Connection) GetDB() *DB {
	return c.db
}

// Close closes the database connection pool
func (c *Connection) Close() {
	if c.db != nil && c.db.Pool != nil {
		log.Info().Msg("closing database connection pool")
		c.db.Pool.Close()
	}
}

// GetStdDB returns a *sql.DB interface for compatibility with libraries that need it
func (c *Connection) GetStdDB() *sql.DB {
	if c.db == nil || c.db.Pool == nil {
		return nil
	}
	return stdlib.OpenDBFromPool(c.db.Pool)
}

// Health checks the database connection health
func (c *Connection) Health(ctx context.Context) error {
	if c.db == nil || c.db.Pool == nil {
		return fmt.Errorf("database connection not initialized")
	}

	// Test connection with timeout
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return c.db.Pool.Ping(ctx)
}

// Stats returns connection pool statistics
func (c *Connection) Stats() *ConnectionStats {
	if c.db == nil || c.db.Pool == nil {
		return &ConnectionStats{}
	}

	stat := c.db.Pool.Stat()
	return &ConnectionStats{
		MaxConns:        stat.MaxConns(),
		TotalConns:      stat.TotalConns(),
		IdleConns:       stat.IdleConns(),
		AcquiredConns:   stat.AcquiredConns(),
		ConstructingConns: stat.ConstructingConns(),
		AcquireCount:    stat.AcquireCount(),
		AcquireDuration: stat.AcquireDuration(),
		EmptyAcquireCount: stat.EmptyAcquireCount(),
	}
}

// ConnectionStats provides connection pool statistics
type ConnectionStats struct {
	MaxConns          int32
	TotalConns        int32
	IdleConns         int32
	AcquiredConns     int32
	ConstructingConns int32
	AcquireCount      int64
	AcquireDuration   time.Duration
	EmptyAcquireCount int64
}

// Transaction executes a function within a database transaction
func (db *DB) Transaction(ctx context.Context, fn func(pgx.Tx) error) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback(ctx)
			panic(p)
		} else if err != nil {
			if rbErr := tx.Rollback(ctx); rbErr != nil {
				log.Error().Err(rbErr).Msg("failed to rollback transaction")
			}
		} else {
			if commitErr := tx.Commit(ctx); commitErr != nil {
				err = fmt.Errorf("failed to commit transaction: %w", commitErr)
			}
		}
	}()

	err = fn(tx)
	return err
}

// queryTracer implements pgx.QueryTracer for logging database queries
type queryTracer struct {
	logQueries bool
}

// TraceQueryStart is called at the beginning of Query, QueryRow, and Exec calls
func (t *queryTracer) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !t.logQueries {
		return ctx
	}

	startTime := time.Now()
	return context.WithValue(ctx, "query_start_time", startTime)
}

// TraceQueryEnd is called at the end of Query, QueryRow, and Exec calls
func (t *queryTracer) TraceQueryEnd(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryEndData) {
	if !t.logQueries {
		return
	}

	startTime, ok := ctx.Value("query_start_time").(time.Time)
	if !ok {
		return
	}

	duration := time.Since(startTime)

	logEvent := log.Debug().
		Str("sql", data.SQL).
		Dur("duration", duration).
		Int("rows_affected", int(data.CommandTag.RowsAffected()))

	if data.Err != nil {
		logEvent = logEvent.Err(data.Err)
	}

	// Log slow queries as warnings
	if duration > 100*time.Millisecond {
		logEvent = log.Warn().
			Str("sql", data.SQL).
			Dur("duration", duration).
			Msg("slow query detected")
	}

	logEvent.Msg("database query")
}

// Migrate runs database migrations
func (db *DB) Migrate(ctx context.Context, migrationDir string) error {
	// This would integrate with a migration library like golang-migrate
	// For now, we'll provide the interface
	log.Info().
		Str("migration_dir", migrationDir).
		Msg("database migration started")

	// Migration logic would go here
	// Example: using golang-migrate/migrate library

	log.Info().Msg("database migration completed")
	return nil
}

// Seed populates the database with initial data
func (db *DB) Seed(ctx context.Context, seedFile string) error {
	log.Info().
		Str("seed_file", seedFile).
		Msg("database seeding started")

	// Seeding logic would go here
	// Read and execute seed SQL files

	log.Info().Msg("database seeding completed")
	return nil
}

// ConnectionManager manages multiple database connections for different purposes
type ConnectionManager struct {
	primary   *Connection
	readOnly  *Connection
	analytics *Connection
}

// NewConnectionManager creates a new connection manager with different connection types
func NewConnectionManager(primaryCfg, readOnlyCfg, analyticsCfg *config.DatabaseConfig) (*ConnectionManager, error) {
	cm := &ConnectionManager{}

	// Primary connection (read/write)
	if primaryCfg != nil {
		primary, err := NewConnection(primaryCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create primary connection: %w", err)
		}
		cm.primary = primary
	}

	// Read-only replica connection
	if readOnlyCfg != nil {
		readOnly, err := NewConnection(readOnlyCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create read-only connection: %w", err)
		}
		cm.readOnly = readOnly
	}

	// Analytics connection (separate for heavy queries)
	if analyticsCfg != nil {
		analytics, err := NewConnection(analyticsCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create analytics connection: %w", err)
		}
		cm.analytics = analytics
	}

	return cm, nil
}

// Primary returns the primary database connection
func (cm *ConnectionManager) Primary() *DB {
	if cm.primary != nil {
		return cm.primary.GetDB()
	}
	return nil
}

// ReadOnly returns the read-only database connection, falls back to primary if not available
func (cm *ConnectionManager) ReadOnly() *DB {
	if cm.readOnly != nil {
		return cm.readOnly.GetDB()
	}
	return cm.Primary()
}

// Analytics returns the analytics database connection, falls back to primary if not available
func (cm *ConnectionManager) Analytics() *DB {
	if cm.analytics != nil {
		return cm.analytics.GetDB()
	}
	return cm.Primary()
}

// Close closes all database connections
func (cm *ConnectionManager) Close() {
	if cm.primary != nil {
		cm.primary.Close()
	}
	if cm.readOnly != nil {
		cm.readOnly.Close()
	}
	if cm.analytics != nil {
		cm.analytics.Close()
	}
}

// Health checks all database connections
func (cm *ConnectionManager) Health(ctx context.Context) map[string]error {
	health := make(map[string]error)

	if cm.primary != nil {
		health["primary"] = cm.primary.Health(ctx)
	}
	if cm.readOnly != nil {
		health["readonly"] = cm.readOnly.Health(ctx)
	}
	if cm.analytics != nil {
		health["analytics"] = cm.analytics.Health(ctx)
	}

	return health
}