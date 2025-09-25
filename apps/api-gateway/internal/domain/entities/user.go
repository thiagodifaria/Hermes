package entities

import (
	"errors"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/valueobjects"
)

// UserStatus represents the current status of a user
type UserStatus string

const (
	UserStatusActive    UserStatus = "active"
	UserStatusInactive  UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusPending   UserStatus = "pending"
)

// User represents a user in the system with rich domain behavior
type User struct {
	id                uuid.UUID
	email             valueobjects.Email
	passwordHash      string
	firstName         string
	lastName          string
	status            UserStatus
	roles             []string
	permissions       []string
	sshKeys           []valueobjects.SSHKey
	lastLoginAt       *time.Time
	failedLoginCount  int
	lockedUntil       *time.Time
	emailVerifiedAt   *time.Time
	createdAt         time.Time
	updatedAt         time.Time
}

// Domain errors
var (
	ErrInvalidPassword      = errors.New("password does not meet requirements")
	ErrUserNotActive        = errors.New("user is not active")
	ErrUserLocked           = errors.New("user account is locked")
	ErrEmailNotVerified     = errors.New("email address is not verified")
	ErrTooManyFailedLogins  = errors.New("too many failed login attempts")
	ErrInsufficientPermissions = errors.New("insufficient permissions")
	ErrSSHKeyAlreadyExists  = errors.New("SSH key already exists")
	ErrSSHKeyNotFound       = errors.New("SSH key not found")
)

// Password policy constants
const (
	MinPasswordLength = 8
	MaxPasswordLength = 128
	MaxFailedLogins   = 5
	LockoutDuration   = 30 * time.Minute
)

// NewUser creates a new user with validated data
func NewUser(email, password, firstName, lastName string) (*User, error) {
	// Validate and create email value object
	emailVO, err := valueobjects.NewEmail(email)
	if err != nil {
		return nil, err
	}

	// Validate password
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create user
	user := &User{
		id:               uuid.New(),
		email:            emailVO,
		passwordHash:     hashedPassword,
		firstName:        firstName,
		lastName:         lastName,
		status:           UserStatusPending, // New users start as pending
		roles:            []string{"user"},  // Default role
		permissions:      []string{},
		sshKeys:          []valueobjects.SSHKey{},
		failedLoginCount: 0,
		createdAt:        time.Now(),
		updatedAt:        time.Now(),
	}

	return user, nil
}

// GetID returns the user ID
func (u *User) GetID() uuid.UUID {
	return u.id
}

// GetEmail returns the user email
func (u *User) GetEmail() valueobjects.Email {
	return u.email
}

// GetFullName returns the user's full name
func (u *User) GetFullName() string {
	return u.firstName + " " + u.lastName
}

// GetStatus returns the user status
func (u *User) GetStatus() UserStatus {
	return u.status
}

// GetRoles returns user roles
func (u *User) GetRoles() []string {
	rolesCopy := make([]string, len(u.roles))
	copy(rolesCopy, u.roles)
	return rolesCopy
}

// GetPermissions returns user permissions
func (u *User) GetPermissions() []string {
	permissionsCopy := make([]string, len(u.permissions))
	copy(permissionsCopy, u.permissions)
	return permissionsCopy
}

// GetSSHKeys returns user SSH keys
func (u *User) GetSSHKeys() []valueobjects.SSHKey {
	keysCopy := make([]valueobjects.SSHKey, len(u.sshKeys))
	copy(keysCopy, u.sshKeys)
	return keysCopy
}

// GetLastLoginAt returns last login time
func (u *User) GetLastLoginAt() *time.Time {
	return u.lastLoginAt
}

// IsActive checks if user is active and can perform actions
func (u *User) IsActive() bool {
	return u.status == UserStatusActive
}

// IsLocked checks if user account is locked due to failed logins
func (u *User) IsLocked() bool {
	if u.lockedUntil == nil {
		return false
	}
	return time.Now().Before(*u.lockedUntil)
}

// IsEmailVerified checks if user's email is verified
func (u *User) IsEmailVerified() bool {
	return u.emailVerifiedAt != nil
}

// CanLogin checks if user can login (active, not locked, email verified)
func (u *User) CanLogin() error {
	if !u.IsActive() {
		return ErrUserNotActive
	}
	if u.IsLocked() {
		return ErrUserLocked
	}
	if !u.IsEmailVerified() {
		return ErrEmailNotVerified
	}
	return nil
}

// VerifyPassword verifies the provided password against the stored hash
func (u *User) VerifyPassword(password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(u.passwordHash), []byte(password))
	if err != nil {
		u.recordFailedLogin()
		return err
	}
	u.recordSuccessfulLogin()
	return nil
}

// ChangePassword changes the user's password after validation
func (u *User) ChangePassword(oldPassword, newPassword string) error {
	// Verify current password
	if err := u.VerifyPassword(oldPassword); err != nil {
		return err
	}

	// Validate new password
	if err := validatePassword(newPassword); err != nil {
		return err
	}

	// Hash new password
	hashedPassword, err := hashPassword(newPassword)
	if err != nil {
		return err
	}

	u.passwordHash = hashedPassword
	u.updatedAt = time.Now()
	return nil
}

// Activate activates the user account
func (u *User) Activate() {
	u.status = UserStatusActive
	u.updatedAt = time.Now()
}

// Deactivate deactivates the user account
func (u *User) Deactivate() {
	u.status = UserStatusInactive
	u.updatedAt = time.Now()
}

// Suspend suspends the user account
func (u *User) Suspend() {
	u.status = UserStatusSuspended
	u.updatedAt = time.Now()
}

// VerifyEmail marks the user's email as verified
func (u *User) VerifyEmail() {
	now := time.Now()
	u.emailVerifiedAt = &now
	u.updatedAt = time.Now()
}

// HasRole checks if user has a specific role
func (u *User) HasRole(role string) bool {
	for _, r := range u.roles {
		if r == role {
			return true
		}
	}
	return false
}

// HasPermission checks if user has a specific permission
func (u *User) HasPermission(permission string) bool {
	for _, p := range u.permissions {
		if p == permission {
			return true
		}
	}
	return false
}

// AddRole adds a role to the user
func (u *User) AddRole(role string) {
	if !u.HasRole(role) {
		u.roles = append(u.roles, role)
		u.updatedAt = time.Now()
	}
}

// RemoveRole removes a role from the user
func (u *User) RemoveRole(role string) {
	for i, r := range u.roles {
		if r == role {
			u.roles = append(u.roles[:i], u.roles[i+1:]...)
			u.updatedAt = time.Now()
			break
		}
	}
}

// AddPermission adds a permission to the user
func (u *User) AddPermission(permission string) {
	if !u.HasPermission(permission) {
		u.permissions = append(u.permissions, permission)
		u.updatedAt = time.Now()
	}
}

// RemovePermission removes a permission from the user
func (u *User) RemovePermission(permission string) {
	for i, p := range u.permissions {
		if p == permission {
			u.permissions = append(u.permissions[:i], u.permissions[i+1:]...)
			u.updatedAt = time.Now()
			break
		}
	}
}

// AddSSHKey adds an SSH key to the user
func (u *User) AddSSHKey(sshKey valueobjects.SSHKey) error {
	// Check if key already exists
	for _, key := range u.sshKeys {
		if key.GetFingerprint() == sshKey.GetFingerprint() {
			return ErrSSHKeyAlreadyExists
		}
	}

	u.sshKeys = append(u.sshKeys, sshKey)
	u.updatedAt = time.Now()
	return nil
}

// RemoveSSHKey removes an SSH key by fingerprint
func (u *User) RemoveSSHKey(fingerprint string) error {
	for i, key := range u.sshKeys {
		if key.GetFingerprint() == fingerprint {
			u.sshKeys = append(u.sshKeys[:i], u.sshKeys[i+1:]...)
			u.updatedAt = time.Now()
			return nil
		}
	}
	return ErrSSHKeyNotFound
}

// GetSSHKeyByFingerprint finds an SSH key by fingerprint
func (u *User) GetSSHKeyByFingerprint(fingerprint string) (valueobjects.SSHKey, error) {
	for _, key := range u.sshKeys {
		if key.GetFingerprint() == fingerprint {
			return key, nil
		}
	}
	return valueobjects.SSHKey{}, ErrSSHKeyNotFound
}

// recordFailedLogin records a failed login attempt
func (u *User) recordFailedLogin() {
	u.failedLoginCount++
	if u.failedLoginCount >= MaxFailedLogins {
		lockUntil := time.Now().Add(LockoutDuration)
		u.lockedUntil = &lockUntil
	}
	u.updatedAt = time.Now()
}

// recordSuccessfulLogin records a successful login
func (u *User) recordSuccessfulLogin() {
	now := time.Now()
	u.lastLoginAt = &now
	u.failedLoginCount = 0
	u.lockedUntil = nil
	u.updatedAt = time.Now()
}

// UnlockAccount unlocks a locked user account
func (u *User) UnlockAccount() {
	u.failedLoginCount = 0
	u.lockedUntil = nil
	u.updatedAt = time.Now()
}

// UpdateProfile updates user profile information
func (u *User) UpdateProfile(firstName, lastName string) {
	u.firstName = firstName
	u.lastName = lastName
	u.updatedAt = time.Now()
}

// GetCreatedAt returns creation timestamp
func (u *User) GetCreatedAt() time.Time {
	return u.createdAt
}

// GetUpdatedAt returns last update timestamp
func (u *User) GetUpdatedAt() time.Time {
	return u.updatedAt
}

// validatePassword validates password against policy
func validatePassword(password string) error {
	if len(password) < MinPasswordLength {
		return ErrInvalidPassword
	}
	if len(password) > MaxPasswordLength {
		return ErrInvalidPassword
	}

	// Check for required character types
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsDigit(char):
			hasDigit = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return ErrInvalidPassword
	}

	return nil
}

// hashPassword creates a bcrypt hash of the password
func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}