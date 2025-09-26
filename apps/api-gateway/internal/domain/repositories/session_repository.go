// apps/api-gateway/internal/domain/repositories/session_repository.go
package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/entities"
	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/valueobjects"
)

// SessionRepository defines the interface for session persistence operations
// Following Interface Segregation Principle with focused methods
type SessionRepository interface {
	// Core CRUD operations
	Create(ctx context.Context, session *entities.Session) error
	GetByID(ctx context.Context, id uuid.UUID) (*entities.Session, error)
	Update(ctx context.Context, session *entities.Session) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Status management
	UpdateStatus(ctx context.Context, id uuid.UUID, status entities.SessionStatus) error
	GetActiveSessions(ctx context.Context) ([]*entities.Session, error)
	GetActiveSessionsByUser(ctx context.Context, userID uuid.UUID) ([]*entities.Session, error)
	GetActiveSessionsByHost(ctx context.Context, hostID uuid.UUID) ([]*entities.Session, error)

	// Session lifecycle management
	TerminateSession(ctx context.Context, id uuid.UUID, exitCode int) error
	FailSession(ctx context.Context, id uuid.UUID, reason string) error
	TimeoutSession(ctx context.Context, id uuid.UUID) error
	
	// Activity tracking
	UpdateLastActivity(ctx context.Context, id uuid.UUID) error
	UpdateBytesTransferred(ctx context.Context, id uuid.UUID, bytesSent, bytesReceived int64) error
	
	// Recording management
	SetRecordingPath(ctx context.Context, id uuid.UUID, recordingPath string) error
	EnableRecording(ctx context.Context, id uuid.UUID) error
	DisableRecording(ctx context.Context, id uuid.UUID) error
	GetSessionsWithRecordings(ctx context.Context, opts RecordingListOptions) ([]*entities.Session, error)

	// Command tracking
	AddCommand(ctx context.Context, sessionID uuid.UUID, command entities.Command) error
	CompleteCommand(ctx context.Context, sessionID, commandID uuid.UUID, exitCode int, output string) error
	GetSessionCommands(ctx context.Context, sessionID uuid.UUID) ([]entities.Command, error)

	// Terminal management
	UpdateTerminalSize(ctx context.Context, id uuid.UUID, width, height int) error
	UpdateEnvironment(ctx context.Context, id uuid.UUID, env map[string]string) error
	UpdateWorkingDirectory(ctx context.Context, id uuid.UUID, dir string) error

	// Connection info
	UpdateConnectionInfo(ctx context.Context, id uuid.UUID, info entities.ConnectionInfo) error

	// Query operations
	List(ctx context.Context, opts SessionListOptions) ([]*entities.Session, error)
	Count(ctx context.Context, opts SessionCountOptions) (int64, error)
	Search(ctx context.Context, query string, opts SessionSearchOptions) ([]*entities.Session, error)

	// Cleanup operations
	GetTimedOutSessions(ctx context.Context) ([]*entities.Session, error)
	GetExpiredSessions(ctx context.Context, maxAge time.Duration) ([]*entities.Session, error)
	CleanupOldSessions(ctx context.Context, maxAge time.Duration) (int64, error)

	// Analytics & reporting
	GetSessionStatistics(ctx context.Context, from, to time.Time) (*SessionStatistics, error)
	GetUserSessionHistory(ctx context.Context, userID uuid.UUID, opts SessionHistoryOptions) ([]*entities.Session, error)
	GetHostSessionHistory(ctx context.Context, hostID uuid.UUID, opts SessionHistoryOptions) ([]*entities.Session, error)
	GetMostActiveUsers(ctx context.Context, from, to time.Time, limit int) ([]*UserSessionStats, error)
	GetMostAccessedHosts(ctx context.Context, from, to time.Time, limit int) ([]*HostSessionStats, error)
}

// SessionListOptions provides filtering and pagination for session listing
type SessionListOptions struct {
	// Filtering
	UserID      *uuid.UUID
	HostID      *uuid.UUID
	Status      *entities.SessionStatus
	Type        *entities.SessionType
	StartedAfter *time.Time
	StartedBefore *time.Time
	EndedAfter   *time.Time
	EndedBefore  *time.Time
	HasRecording *bool
	MinDuration  *time.Duration
	MaxDuration  *time.Duration

	// Sorting
	SortBy    SessionSortField
	SortOrder SortOrder

	// Pagination
	Limit  int
	Offset int

	// Include related data
	IncludeCommands    bool
	IncludeConnectionInfo bool
}

// SessionCountOptions provides filtering options for counting sessions
type SessionCountOptions struct {
	UserID       *uuid.UUID
	HostID       *uuid.UUID
	Status       *entities.SessionStatus
	Type         *entities.SessionType
	StartedAfter *time.Time
	StartedBefore *time.Time
	HasRecording *bool
}

// SessionSearchOptions provides options for session search
type SessionSearchOptions struct {
	Fields    []SessionSearchField
	MatchType SearchMatchType
	Limit     int
	Offset    int
}

// RecordingListOptions provides filtering for sessions with recordings
type RecordingListOptions struct {
	UserID      *uuid.UUID
	HostID      *uuid.UUID
	StartedAfter *time.Time
	StartedBefore *time.Time
	MinSize     *int64
	MaxSize     *int64
	Limit       int
	Offset      int
}

// SessionHistoryOptions provides options for session history queries
type SessionHistoryOptions struct {
	From   *time.Time
	To     *time.Time
	Status *entities.SessionStatus
	Type   *entities.SessionType
	Limit  int
	Offset int
}

// SessionSortField represents fields that can be used for sorting
type SessionSortField string

const (
	SessionSortByID           SessionSortField = "id"
	SessionSortByStartTime    SessionSortField = "start_time"
	SessionSortByEndTime      SessionSortField = "end_time"
	SessionSortByLastActivity SessionSortField = "last_activity"
	SessionSortByDuration     SessionSortField = "duration"
	SessionSortByBytesTransferred SessionSortField = "bytes_transferred"
	SessionSortByCommandCount SessionSortField = "command_count"
	SessionSortByStatus       SessionSortField = "status"
	SessionSortByType         SessionSortField = "type"
)

// SessionSearchField represents fields that can be searched
type SessionSearchField string

const (
	SessionSearchFieldCommand     SessionSearchField = "command"
	SessionSearchFieldWorkingDir  SessionSearchField = "working_directory"
	SessionSearchFieldEnvironment SessionSearchField = "environment"
	SessionSearchFieldRemoteAddr  SessionSearchField = "remote_addr"
)

// SessionStatistics provides aggregate statistics about sessions
type SessionStatistics struct {
	TotalSessions    int64
	ActiveSessions   int64
	CompletedSessions int64
	FailedSessions   int64
	TimeoutSessions  int64
	TotalDuration    time.Duration
	AverageDuration  time.Duration
	TotalBytesTransferred int64
	TotalCommands    int64
	UniqueUsers      int64
	UniqueHosts      int64
	RecordedSessions int64
}

// UserSessionStats provides session statistics for a specific user
type UserSessionStats struct {
	UserID        uuid.UUID
	UserEmail     string
	SessionCount  int64
	TotalDuration time.Duration
	LastSession   *time.Time
	BytesTransferred int64
	CommandCount  int64
}

// HostSessionStats provides session statistics for a specific host
type HostSessionStats struct {
	HostID        uuid.UUID
	HostName      string
	SessionCount  int64
	TotalDuration time.Duration
	LastSession   *time.Time
	BytesTransferred int64
	CommandCount  int64
	UniqueUsers   int64
}

// SessionReadRepository defines read-only operations for performance optimization
// Useful for read replicas or CQRS pattern
type SessionReadRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entities.Session, error)
	List(ctx context.Context, opts SessionListOptions) ([]*entities.Session, error)
	Count(ctx context.Context, opts SessionCountOptions) (int64, error)
	Search(ctx context.Context, query string, opts SessionSearchOptions) ([]*entities.Session, error)
	GetActiveSessions(ctx context.Context) ([]*entities.Session, error)
	GetActiveSessionsByUser(ctx context.Context, userID uuid.UUID) ([]*entities.Session, error)
	GetActiveSessionsByHost(ctx context.Context, hostID uuid.UUID) ([]*entities.Session, error)
	GetSessionsWithRecordings(ctx context.Context, opts RecordingListOptions) ([]*entities.Session, error)
	GetSessionCommands(ctx context.Context, sessionID uuid.UUID) ([]entities.Command, error)
	GetSessionStatistics(ctx context.Context, from, to time.Time) (*SessionStatistics, error)
	GetUserSessionHistory(ctx context.Context, userID uuid.UUID, opts SessionHistoryOptions) ([]*entities.Session, error)
	GetHostSessionHistory(ctx context.Context, hostID uuid.UUID, opts SessionHistoryOptions) ([]*entities.Session, error)
}

// SessionWriteRepository defines write operations for performance optimization
// Useful for write optimization or CQRS pattern
type SessionWriteRepository interface {
	Create(ctx context.Context, session *entities.Session) error
	Update(ctx context.Context, session *entities.Session) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status entities.SessionStatus) error
	TerminateSession(ctx context.Context, id uuid.UUID, exitCode int) error
	FailSession(ctx context.Context, id uuid.UUID, reason string) error
	TimeoutSession(ctx context.Context, id uuid.UUID) error
	UpdateLastActivity(ctx context.Context, id uuid.UUID) error
	UpdateBytesTransferred(ctx context.Context, id uuid.UUID, bytesSent, bytesReceived int64) error
	AddCommand(ctx context.Context, sessionID uuid.UUID, command entities.Command) error
	CompleteCommand(ctx context.Context, sessionID, commandID uuid.UUID, exitCode int, output string) error
}

// SessionCacheRepository defines caching operations for sessions
// Useful for high-performance operations on active sessions
type SessionCacheRepository interface {
	Set(ctx context.Context, session *entities.Session, ttl time.Duration) error
	Get(ctx context.Context, id uuid.UUID) (*entities.Session, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Exists(ctx context.Context, id uuid.UUID) (bool, error)
	SetActiveSessions(ctx context.Context, sessions []*entities.Session, ttl time.Duration) error
	GetActiveSessions(ctx context.Context) ([]*entities.Session, error)
	GetActiveSessionsByUser(ctx context.Context, userID uuid.UUID) ([]*entities.Session, error)
}

// SessionArchiveRepository defines archival operations for old sessions
// Useful for data lifecycle management and compliance
type SessionArchiveRepository interface {
	ArchiveSession(ctx context.Context, session *entities.Session) error
	GetArchivedSession(ctx context.Context, id uuid.UUID) (*entities.Session, error)
	DeleteArchivedSession(ctx context.Context, id uuid.UUID) error
	SearchArchived(ctx context.Context, query string, opts SessionSearchOptions) ([]*entities.Session, error)
	GetArchivedSessionsOlderThan(ctx context.Context, age time.Duration) ([]*entities.Session, error)
}