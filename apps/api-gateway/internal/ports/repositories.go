// apps/api-gateway/internal/ports/repositories.go
package ports

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/entities"
	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/repositories"
	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/valueobjects"
)

// RepositoryManager consolidates all repository interfaces for dependency injection
// Following Hexagonal Architecture pattern - these are the ports
type RepositoryManager interface {
	// Core repositories
	Users() repositories.UserRepository
	Sessions() repositories.SessionRepository
	Hosts() HostRepository
	AuditEvents() AuditRepository

	// Specialized repositories (CQRS pattern support)
	UserReads() repositories.UserReadRepository
	UserWrites() repositories.UserWriteRepository
	SessionReads() repositories.SessionReadRepository
	SessionWrites() repositories.SessionWriteRepository

	// Caching repositories
	UserCache() repositories.UserCacheRepository
	SessionCache() repositories.SessionCacheRepository

	// Archive repositories
	SessionArchive() repositories.SessionArchiveRepository

	// Transaction management
	WithTransaction(ctx context.Context, fn func(RepositoryManager) error) error
}

// HostRepository defines the interface for host persistence operations
// Based on the host.go entity structure
type HostRepository interface {
	// Core CRUD operations
	Create(ctx context.Context, host *entities.Host) error
	GetByID(ctx context.Context, id uuid.UUID) (*entities.Host, error)
	GetByHostname(ctx context.Context, hostname string) (*entities.Host, error)
	GetByIPAddress(ctx context.Context, ipAddress valueobjects.IPAddress) ([]*entities.Host, error)
	Update(ctx context.Context, host *entities.Host) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Status management
	UpdateStatus(ctx context.Context, id uuid.UUID, status entities.HostStatus) error
	GetActiveHosts(ctx context.Context) ([]*entities.Host, error)
	GetHostsByStatus(ctx context.Context, status entities.HostStatus) ([]*entities.Host, error)

	// Health management
	UpdateHealthStatus(ctx context.Context, id uuid.UUID, health entities.HealthStatus) error
	GetUnhealthyHosts(ctx context.Context) ([]*entities.Host, error)
	GetHostsDueForHealthCheck(ctx context.Context) ([]*entities.Host, error)

	// Credential management
	UpdateCredentials(ctx context.Context, id uuid.UUID, credentials entities.HostCredentials) error
	UpdateSSHConfig(ctx context.Context, id uuid.UUID, config entities.SSHConfig) error

	// Metadata and tags
	SetMetadata(ctx context.Context, id uuid.UUID, key, value string) error
	GetMetadata(ctx context.Context, id uuid.UUID, key string) (string, error)
	AddTag(ctx context.Context, id uuid.UUID, tag string) error
	RemoveTag(ctx context.Context, id uuid.UUID, tag string) error
	GetHostsByTag(ctx context.Context, tag string) ([]*entities.Host, error)

	// Query operations
	List(ctx context.Context, opts HostListOptions) ([]*entities.Host, error)
	Count(ctx context.Context, opts HostCountOptions) (int64, error)
	Search(ctx context.Context, query string, opts HostSearchOptions) ([]*entities.Host, error)

	// Batch operations
	UpdateMultiple(ctx context.Context, hostIDs []uuid.UUID, updateFn func(*entities.Host) error) error
	DeleteMultiple(ctx context.Context, hostIDs []uuid.UUID) error
}

// AuditRepository defines the interface for audit event persistence
// Based on audit requirements from the planning document
type AuditRepository interface {
	// Core operations
	Create(ctx context.Context, event *AuditEvent) error
	GetByID(ctx context.Context, id uuid.UUID) (*AuditEvent, error)
	
	// Query operations
	List(ctx context.Context, opts AuditListOptions) ([]*AuditEvent, error)
	Count(ctx context.Context, opts AuditCountOptions) (int64, error)
	Search(ctx context.Context, opts AuditSearchOptions) ([]*AuditEvent, error)

	// User-specific events
	GetUserEvents(ctx context.Context, userID uuid.UUID, opts AuditListOptions) ([]*AuditEvent, error)
	GetUserLoginEvents(ctx context.Context, userID uuid.UUID, from, to time.Time) ([]*AuditEvent, error)

	// Session-specific events
	GetSessionEvents(ctx context.Context, sessionID uuid.UUID) ([]*AuditEvent, error)
	
	// Host-specific events
	GetHostEvents(ctx context.Context, hostID uuid.UUID, opts AuditListOptions) ([]*AuditEvent, error)

	// Security events
	GetSecurityEvents(ctx context.Context, from, to time.Time, severity AuditSeverity) ([]*AuditEvent, error)
	GetFailedLoginAttempts(ctx context.Context, from, to time.Time) ([]*AuditEvent, error)

	// Compliance queries
	GetEventsByCompliance(ctx context.Context, complianceType ComplianceType, from, to time.Time) ([]*AuditEvent, error)
	GetEventsForExport(ctx context.Context, format ExportFormat, opts AuditExportOptions) ([]byte, error)

	// Cleanup operations
	DeleteOldEvents(ctx context.Context, olderThan time.Time) (int64, error)
	ArchiveOldEvents(ctx context.Context, olderThan time.Time) (int64, error)
}

// Supporting types for Host operations
type HostListOptions struct {
	Status      *entities.HostStatus
	Type        *entities.HostType
	Tag         *string
	Healthy     *bool
	SortBy      HostSortField
	SortOrder   repositories.SortOrder
	Limit       int
	Offset      int
}

type HostCountOptions struct {
	Status  *entities.HostStatus
	Type    *entities.HostType
	Tag     *string
	Healthy *bool
}

type HostSearchOptions struct {
	Fields    []HostSearchField
	MatchType repositories.SearchMatchType
	Limit     int
	Offset    int
}

type HostSortField string

const (
	HostSortByID       HostSortField = "id"
	HostSortByName     HostSortField = "name"
	HostSortByHostname HostSortField = "hostname"
	HostSortByStatus   HostSortField = "status"
	HostSortByType     HostSortField = "type"
	HostSortByLastSeen HostSortField = "last_seen"
	HostSortByCreatedAt HostSortField = "created_at"
)

type HostSearchField string

const (
	HostSearchFieldName        HostSearchField = "name"
	HostSearchFieldHostname    HostSearchField = "hostname"
	HostSearchFieldDescription HostSearchField = "description"
	HostSearchFieldTags        HostSearchField = "tags"
)

// Audit Event types and supporting structures
type AuditEvent struct {
	ID          uuid.UUID
	UserID      *uuid.UUID
	SessionID   *uuid.UUID
	HostID      *uuid.UUID
	EventType   AuditEventType
	Action      string
	Resource    string
	Details     map[string]interface{}
	IPAddress   *valueobjects.IPAddress
	UserAgent   *string
	Severity    AuditSeverity
	Success     bool
	ErrorMessage *string
	Timestamp   time.Time
}

type AuditEventType string

const (
	AuditEventTypeAuthentication AuditEventType = "authentication"
	AuditEventTypeAuthorization  AuditEventType = "authorization"
	AuditEventTypeSession        AuditEventType = "session"
	AuditEventTypeCommand        AuditEventType = "command"
	AuditEventTypeFileTransfer   AuditEventType = "file_transfer"
	AuditEventTypeConfiguration  AuditEventType = "configuration"
	AuditEventTypeUserManagement AuditEventType = "user_management"
	AuditEventTypeHostManagement AuditEventType = "host_management"
	AuditEventTypeSystem         AuditEventType = "system"
	AuditEventTypeSecurity       AuditEventType = "security"
)

type AuditSeverity string

const (
	AuditSeverityLow      AuditSeverity = "low"
	AuditSeverityMedium   AuditSeverity = "medium"
	AuditSeverityHigh     AuditSeverity = "high"
	AuditSeverityCritical AuditSeverity = "critical"
)

type ComplianceType string

const (
	ComplianceTypeSOC2  ComplianceType = "soc2"
	ComplianceTypeGDPR  ComplianceType = "gdpr"
	ComplianceTypeHIPAA ComplianceType = "hipaa"
)

type ExportFormat string

const (
	ExportFormatJSON ExportFormat = "json"
	ExportFormatCSV  ExportFormat = "csv"
	ExportFormatXML  ExportFormat = "xml"
)

type AuditListOptions struct {
	EventType *AuditEventType
	UserID    *uuid.UUID
	SessionID *uuid.UUID
	HostID    *uuid.UUID
	Severity  *AuditSeverity
	Success   *bool
	From      *time.Time
	To        *time.Time
	SortBy    AuditSortField
	SortOrder repositories.SortOrder
	Limit     int
	Offset    int
}

type AuditCountOptions struct {
	EventType *AuditEventType
	UserID    *uuid.UUID
	Severity  *AuditSeverity
	Success   *bool
	From      *time.Time
	To        *time.Time
}

type AuditSearchOptions struct {
	Query     string
	Fields    []AuditSearchField
	EventType *AuditEventType
	Severity  *AuditSeverity
	From      *time.Time
	To        *time.Time
	Limit     int
	Offset    int
}

type AuditExportOptions struct {
	EventType *AuditEventType
	From      *time.Time
	To        *time.Time
	UserID    *uuid.UUID
	HostID    *uuid.UUID
	Severity  *AuditSeverity
}

type AuditSortField string

const (
	AuditSortByTimestamp AuditSortField = "timestamp"
	AuditSortByEventType AuditSortField = "event_type"
	AuditSortBySeverity  AuditSortField = "severity"
	AuditSortByUser      AuditSortField = "user_id"
	AuditSortByHost      AuditSortField = "host_id"
)

type AuditSearchField string

const (
	AuditSearchFieldAction   AuditSearchField = "action"
	AuditSearchFieldResource AuditSearchField = "resource"
	AuditSearchFieldDetails  AuditSearchField = "details"
	AuditSearchFieldError    AuditSearchField = "error_message"
)

// UnitOfWork provides transactional consistency across multiple repositories
// Implements the Unit of Work pattern for complex business operations
type UnitOfWork interface {
	Begin(ctx context.Context) error
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
	
	// Access to repositories within transaction
	Users() repositories.UserRepository
	Sessions() repositories.SessionRepository
	Hosts() HostRepository
	AuditEvents() AuditRepository
}

// ReadOnlyRepositoryManager provides read-only access to repositories
// Useful for read-only services and query optimization
type ReadOnlyRepositoryManager interface {
	UserReads() repositories.UserReadRepository
	SessionReads() repositories.SessionReadRepository
	HostReads() HostReadRepository
	AuditReads() AuditReadRepository
}

// HostReadRepository defines read-only operations for hosts
type HostReadRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entities.Host, error)
	GetByHostname(ctx context.Context, hostname string) (*entities.Host, error)
	GetByIPAddress(ctx context.Context, ipAddress valueobjects.IPAddress) ([]*entities.Host, error)
	List(ctx context.Context, opts HostListOptions) ([]*entities.Host, error)
	Count(ctx context.Context, opts HostCountOptions) (int64, error)
	Search(ctx context.Context, query string, opts HostSearchOptions) ([]*entities.Host, error)
	GetActiveHosts(ctx context.Context) ([]*entities.Host, error)
	GetHostsByStatus(ctx context.Context, status entities.HostStatus) ([]*entities.Host, error)
	GetHostsByTag(ctx context.Context, tag string) ([]*entities.Host, error)
}

// AuditReadRepository defines read-only operations for audit events
type AuditReadRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*AuditEvent, error)
	List(ctx context.Context, opts AuditListOptions) ([]*AuditEvent, error)
	Count(ctx context.Context, opts AuditCountOptions) (int64, error)
	Search(ctx context.Context, opts AuditSearchOptions) ([]*AuditEvent, error)
	GetUserEvents(ctx context.Context, userID uuid.UUID, opts AuditListOptions) ([]*AuditEvent, error)
	GetSessionEvents(ctx context.Context, sessionID uuid.UUID) ([]*AuditEvent, error)
	GetHostEvents(ctx context.Context, hostID uuid.UUID, opts AuditListOptions) ([]*AuditEvent, error)
	GetSecurityEvents(ctx context.Context, from, to time.Time, severity AuditSeverity) ([]*AuditEvent, error)
}