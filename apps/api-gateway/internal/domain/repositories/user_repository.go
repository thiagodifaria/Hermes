// apps/api-gateway/internal/domain/repositories/user_repository.go
package repositories

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/entities"
	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/valueobjects"
)

// UserRepository defines the interface for user persistence operations
// Following Interface Segregation Principle with focused methods
type UserRepository interface {
	// Core CRUD operations
	Create(ctx context.Context, user *entities.User) error
	GetByID(ctx context.Context, id uuid.UUID) (*entities.User, error)
	GetByEmail(ctx context.Context, email valueobjects.Email) (*entities.User, error)
	Update(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, id uuid.UUID) error

	// Status management
	UpdateStatus(ctx context.Context, id uuid.UUID, status entities.UserStatus) error
	GetActiveUsers(ctx context.Context) ([]*entities.User, error)
	GetPendingUsers(ctx context.Context) ([]*entities.User, error)

	// Authentication & security
	UpdatePasswordHash(ctx context.Context, id uuid.UUID, passwordHash string) error
	RecordFailedLogin(ctx context.Context, id uuid.UUID) error
	RecordSuccessfulLogin(ctx context.Context, id uuid.UUID) error
	LockAccount(ctx context.Context, id uuid.UUID, lockUntil time.Time) error
	UnlockAccount(ctx context.Context, id uuid.UUID) error

	// Email verification
	MarkEmailVerified(ctx context.Context, id uuid.UUID) error
	GetUnverifiedUsers(ctx context.Context, olderThan time.Duration) ([]*entities.User, error)

	// Role & permission management
	UpdateRoles(ctx context.Context, id uuid.UUID, roles []string) error
	UpdatePermissions(ctx context.Context, id uuid.UUID, permissions []string) error
	GetUsersByRole(ctx context.Context, role string) ([]*entities.User, error)
	GetUsersByPermission(ctx context.Context, permission string) ([]*entities.User, error)

	// SSH key management
	AddSSHKey(ctx context.Context, userID uuid.UUID, sshKey valueobjects.SSHKey) error
	RemoveSSHKey(ctx context.Context, userID uuid.UUID, fingerprint string) error
	GetUserSSHKeys(ctx context.Context, userID uuid.UUID) ([]valueobjects.SSHKey, error)
	GetUserBySSHKeyFingerprint(ctx context.Context, fingerprint string) (*entities.User, error)

	// Query operations
	List(ctx context.Context, opts UserListOptions) ([]*entities.User, error)
	Count(ctx context.Context, opts UserCountOptions) (int64, error)
	Search(ctx context.Context, query string, opts UserSearchOptions) ([]*entities.User, error)

	// Batch operations
	UpdateMultiple(ctx context.Context, userIDs []uuid.UUID, updateFn func(*entities.User) error) error
	DeleteMultiple(ctx context.Context, userIDs []uuid.UUID) error

	// Audit & compliance
	GetUserActivity(ctx context.Context, userID uuid.UUID, from, to time.Time) ([]*UserActivityRecord, error)
	GetInactiveUsers(ctx context.Context, inactiveFor time.Duration) ([]*entities.User, error)
}

// UserListOptions provides filtering and pagination for user listing
type UserListOptions struct {
	// Filtering
	Status      *entities.UserStatus
	Role        *string
	EmailDomain *string
	Verified    *bool

	// Sorting
	SortBy    UserSortField
	SortOrder SortOrder

	// Pagination
	Limit  int
	Offset int

	// Include related data
	IncludeSSHKeys bool
}

// UserCountOptions provides filtering options for counting users
type UserCountOptions struct {
	Status      *entities.UserStatus
	Role        *string
	EmailDomain *string
	Verified    *bool
	CreatedAfter *time.Time
	CreatedBefore *time.Time
}

// UserSearchOptions provides options for user search
type UserSearchOptions struct {
	Fields    []UserSearchField // Fields to search in
	MatchType SearchMatchType   // Exact, prefix, contains
	Limit     int
	Offset    int
}

// UserSortField represents fields that can be used for sorting
type UserSortField string

const (
	UserSortByID        UserSortField = "id"
	UserSortByEmail     UserSortField = "email"
	UserSortByFirstName UserSortField = "first_name"
	UserSortByLastName  UserSortField = "last_name"
	UserSortByStatus    UserSortField = "status"
	UserSortByCreatedAt UserSortField = "created_at"
	UserSortByUpdatedAt UserSortField = "updated_at"
	UserSortByLastLogin UserSortField = "last_login_at"
)

// UserSearchField represents fields that can be searched
type UserSearchField string

const (
	UserSearchFieldEmail     UserSearchField = "email"
	UserSearchFieldFirstName UserSearchField = "first_name"
	UserSearchFieldLastName  UserSearchField = "last_name"
	UserSearchFieldFullName  UserSearchField = "full_name"
)

// SortOrder represents sort direction
type SortOrder string

const (
	SortOrderASC  SortOrder = "ASC"
	SortOrderDESC SortOrder = "DESC"
)

// SearchMatchType represents how search matching should be performed
type SearchMatchType string

const (
	SearchMatchExact    SearchMatchType = "exact"
	SearchMatchPrefix   SearchMatchType = "prefix"
	SearchMatchContains SearchMatchType = "contains"
)

// UserActivityRecord represents user activity for audit purposes
type UserActivityRecord struct {
	ID        uuid.UUID
	UserID    uuid.UUID
	Action    string
	Details   map[string]interface{}
	IPAddress valueobjects.IPAddress
	UserAgent string
	Timestamp time.Time
}

// UserReadRepository defines read-only operations for performance optimization
// Useful for read replicas or CQRS pattern
type UserReadRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*entities.User, error)
	GetByEmail(ctx context.Context, email valueobjects.Email) (*entities.User, error)
	List(ctx context.Context, opts UserListOptions) ([]*entities.User, error)
	Count(ctx context.Context, opts UserCountOptions) (int64, error)
	Search(ctx context.Context, query string, opts UserSearchOptions) ([]*entities.User, error)
	GetActiveUsers(ctx context.Context) ([]*entities.User, error)
	GetUsersByRole(ctx context.Context, role string) ([]*entities.User, error)
	GetUsersByPermission(ctx context.Context, permission string) ([]*entities.User, error)
}

// UserWriteRepository defines write operations for performance optimization
// Useful for write optimization or CQRS pattern
type UserWriteRepository interface {
	Create(ctx context.Context, user *entities.User) error
	Update(ctx context.Context, user *entities.User) error
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateStatus(ctx context.Context, id uuid.UUID, status entities.UserStatus) error
	UpdatePasswordHash(ctx context.Context, id uuid.UUID, passwordHash string) error
	RecordFailedLogin(ctx context.Context, id uuid.UUID) error
	RecordSuccessfulLogin(ctx context.Context, id uuid.UUID) error
	LockAccount(ctx context.Context, id uuid.UUID, lockUntil time.Time) error
	UnlockAccount(ctx context.Context, id uuid.UUID) error
	MarkEmailVerified(ctx context.Context, id uuid.UUID) error
}

// UserCacheRepository defines caching operations for users
// Useful for high-performance read operations
type UserCacheRepository interface {
	Set(ctx context.Context, user *entities.User, ttl time.Duration) error
	Get(ctx context.Context, id uuid.UUID) (*entities.User, error)
	GetByEmail(ctx context.Context, email valueobjects.Email) (*entities.User, error)
	Delete(ctx context.Context, id uuid.UUID) error
	Exists(ctx context.Context, id uuid.UUID) (bool, error)
}