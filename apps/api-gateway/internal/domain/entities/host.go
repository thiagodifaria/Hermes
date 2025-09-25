package entities

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/valueobjects"
)

// HostStatus represents the current status of a host
type HostStatus string

const (
	HostStatusActive      HostStatus = "active"
	HostStatusInactive    HostStatus = "inactive"
	HostStatusMaintenance HostStatus = "maintenance"
	HostStatusUnreachable HostStatus = "unreachable"
)

// HostType represents different types of hosts
type HostType string

const (
	HostTypeServer    HostType = "server"
	HostTypeWorkstation HostType = "workstation"
	HostTypeRouter    HostType = "router"
	HostTypeSwitch    HostType = "switch"
	HostTypeFirewall  HostType = "firewall"
	HostTypeContainer HostType = "container"
	HostTypeVirtual   HostType = "virtual"
)

// Host represents a remote host/server with connection details
type Host struct {
	id              uuid.UUID
	name            string
	description     string
	hostname        string
	ipAddress       valueobjects.IPAddress
	port            int
	hostType        HostType
	status          HostStatus
	operatingSystem string
	architecture    string
	tags            []string
	credentials     HostCredentials
	sshConfig       SSHConfig
	lastSeen        *time.Time
	lastHealthCheck *time.Time
	healthStatus    HealthStatus
	metadata        map[string]string
	createdAt       time.Time
	updatedAt       time.Time
}

// HostCredentials contains authentication information
type HostCredentials struct {
	Username       string
	AuthMethod     AuthMethod
	PrivateKeyPath string
	Password       string // Should be encrypted
	Certificate    string
}

// AuthMethod represents different authentication methods
type AuthMethod string

const (
	AuthMethodPassword    AuthMethod = "password"
	AuthMethodPrivateKey  AuthMethod = "private_key"
	AuthMethodCertificate AuthMethod = "certificate"
	AuthMethodAgent       AuthMethod = "agent"
)

// SSHConfig contains SSH-specific configuration
type SSHConfig struct {
	StrictHostKeyChecking bool
	UserKnownHostsFile    string
	ConnectTimeout        time.Duration
	ServerAliveInterval   time.Duration
	ServerAliveCountMax   int
	Compression           bool
	PreferredCiphers      []string
	PreferredKex          []string
	PreferredMACs         []string
}

// HealthStatus represents host health information
type HealthStatus struct {
	IsHealthy       bool
	ResponseTime    time.Duration
	LastError       string
	ConsecutiveFails int
	Uptime          time.Duration
	CPUUsage        float64
	MemoryUsage     float64
	DiskUsage       float64
}

// Host domain errors
var (
	ErrInvalidPort         = errors.New("invalid port number")
	ErrInvalidHostname     = errors.New("invalid hostname")
	ErrMissingCredentials  = errors.New("missing credentials")
	ErrHostNotReachable    = errors.New("host is not reachable")
	ErrHostInMaintenance   = errors.New("host is in maintenance mode")
	ErrUnsupportedAuthMethod = errors.New("unsupported authentication method")
	ErrHealthCheckFailed   = errors.New("health check failed")
)

// Host constants
const (
	DefaultSSHPort           = 22
	MinPort                  = 1
	MaxPort                  = 65535
	DefaultConnectTimeout    = 30 * time.Second
	DefaultServerAliveInterval = 60 * time.Second
	DefaultServerAliveCountMax = 3
	MaxConsecutiveFails      = 5
	HealthCheckInterval      = 5 * time.Minute
)

// NewHost creates a new host with validated data
func NewHost(name, hostname string, ipAddress valueobjects.IPAddress, port int) (*Host, error) {
	// Validate port
	if port < MinPort || port > MaxPort {
		return nil, ErrInvalidPort
	}

	// Validate hostname
	if hostname == "" {
		return nil, ErrInvalidHostname
	}

	host := &Host{
		id:        uuid.New(),
		name:      name,
		hostname:  hostname,
		ipAddress: ipAddress,
		port:      port,
		hostType:  HostTypeServer, // Default type
		status:    HostStatusActive,
		tags:      make([]string, 0),
		sshConfig: getDefaultSSHConfig(),
		metadata:  make(map[string]string),
		createdAt: time.Now(),
		updatedAt: time.Now(),
	}

	return host, nil
}

// GetID returns the host ID
func (h *Host) GetID() uuid.UUID {
	return h.id
}

// GetName returns the host name
func (h *Host) GetName() string {
	return h.name
}

// GetDescription returns the host description
func (h *Host) GetDescription() string {
	return h.description
}

// GetHostname returns the hostname
func (h *Host) GetHostname() string {
	return h.hostname
}

// GetIPAddress returns the IP address
func (h *Host) GetIPAddress() valueobjects.IPAddress {
	return h.ipAddress
}

// GetPort returns the connection port
func (h *Host) GetPort() int {
	return h.port
}

// GetHostType returns the host type
func (h *Host) GetHostType() HostType {
	return h.hostType
}

// GetStatus returns the host status
func (h *Host) GetStatus() HostStatus {
	return h.status
}

// GetOperatingSystem returns the OS information
func (h *Host) GetOperatingSystem() string {
	return h.operatingSystem
}

// GetArchitecture returns the architecture information
func (h *Host) GetArchitecture() string {
	return h.architecture
}

// GetTags returns host tags
func (h *Host) GetTags() []string {
	tags := make([]string, len(h.tags))
	copy(tags, h.tags)
	return tags
}

// IsActive checks if the host is active and available
func (h *Host) IsActive() bool {
	return h.status == HostStatusActive
}

// IsReachable checks if the host is reachable
func (h *Host) IsReachable() bool {
	return h.status != HostStatusUnreachable
}

// IsInMaintenance checks if the host is in maintenance mode
func (h *Host) IsInMaintenance() bool {
	return h.status == HostStatusMaintenance
}

// CanConnect checks if connections are allowed to this host
func (h *Host) CanConnect() error {
	if h.IsInMaintenance() {
		return ErrHostInMaintenance
	}
	if !h.IsReachable() {
		return ErrHostNotReachable
	}
	if !h.IsActive() {
		return errors.New("host is not active")
	}
	return nil
}

// UpdateDescription updates the host description
func (h *Host) UpdateDescription(description string) {
	h.description = description
	h.updatedAt = time.Now()
}

// UpdateHostname updates the hostname
func (h *Host) UpdateHostname(hostname string) error {
	if hostname == "" {
		return ErrInvalidHostname
	}
	h.hostname = hostname
	h.updatedAt = time.Now()
	return nil
}

// UpdateIPAddress updates the IP address
func (h *Host) UpdateIPAddress(ipAddress valueobjects.IPAddress) {
	h.ipAddress = ipAddress
	h.updatedAt = time.Now()
}

// UpdatePort updates the connection port
func (h *Host) UpdatePort(port int) error {
	if port < MinPort || port > MaxPort {
		return ErrInvalidPort
	}
	h.port = port
	h.updatedAt = time.Now()
	return nil
}

// SetHostType sets the host type
func (h *Host) SetHostType(hostType HostType) {
	h.hostType = hostType
	h.updatedAt = time.Now()
}

// SetStatus sets the host status
func (h *Host) SetStatus(status HostStatus) {
	h.status = status
	h.updatedAt = time.Now()
}

// Activate activates the host
func (h *Host) Activate() {
	h.status = HostStatusActive
	h.updatedAt = time.Now()
}

// Deactivate deactivates the host
func (h *Host) Deactivate() {
	h.status = HostStatusInactive
	h.updatedAt = time.Now()
}

// SetMaintenance puts the host in maintenance mode
func (h *Host) SetMaintenance() {
	h.status = HostStatusMaintenance
	h.updatedAt = time.Now()
}

// MarkUnreachable marks the host as unreachable
func (h *Host) MarkUnreachable() {
	h.status = HostStatusUnreachable
	h.updatedAt = time.Now()
}

// UpdateSystemInfo updates operating system and architecture information
func (h *Host) UpdateSystemInfo(os, arch string) {
	h.operatingSystem = os
	h.architecture = arch
	h.updatedAt = time.Now()
}

// AddTag adds a tag to the host
func (h *Host) AddTag(tag string) {
	// Check if tag already exists
	for _, t := range h.tags {
		if t == tag {
			return
		}
	}
	h.tags = append(h.tags, tag)
	h.updatedAt = time.Now()
}

// RemoveTag removes a tag from the host
func (h *Host) RemoveTag(tag string) {
	for i, t := range h.tags {
		if t == tag {
			h.tags = append(h.tags[:i], h.tags[i+1:]...)
			h.updatedAt = time.Now()
			break
		}
	}
}

// HasTag checks if the host has a specific tag
func (h *Host) HasTag(tag string) bool {
	for _, t := range h.tags {
		if t == tag {
			return true
		}
	}
	return false
}

// SetCredentials sets authentication credentials
func (h *Host) SetCredentials(credentials HostCredentials) error {
	// Validate credentials
	if credentials.Username == "" {
		return ErrMissingCredentials
	}

	switch credentials.AuthMethod {
	case AuthMethodPassword:
		if credentials.Password == "" {
			return ErrMissingCredentials
		}
	case AuthMethodPrivateKey:
		if credentials.PrivateKeyPath == "" {
			return ErrMissingCredentials
		}
	case AuthMethodCertificate:
		if credentials.Certificate == "" {
			return ErrMissingCredentials
		}
	case AuthMethodAgent:
		// Agent authentication doesn't require additional credentials
	default:
		return ErrUnsupportedAuthMethod
	}

	h.credentials = credentials
	h.updatedAt = time.Now()
	return nil
}

// GetCredentials returns host credentials
func (h *Host) GetCredentials() HostCredentials {
	return h.credentials
}

// UpdateSSHConfig updates SSH configuration
func (h *Host) UpdateSSHConfig(config SSHConfig) {
	h.sshConfig = config
	h.updatedAt = time.Now()
}

// GetSSHConfig returns SSH configuration
func (h *Host) GetSSHConfig() SSHConfig {
	return h.sshConfig
}

// RecordLastSeen updates the last seen timestamp
func (h *Host) RecordLastSeen() {
	now := time.Now()
	h.lastSeen = &now
	h.updatedAt = time.Now()
}

// GetLastSeen returns the last seen timestamp
func (h *Host) GetLastSeen() *time.Time {
	return h.lastSeen
}

// UpdateHealthStatus updates the health check information
func (h *Host) UpdateHealthStatus(healthStatus HealthStatus) {
	h.healthStatus = healthStatus
	now := time.Now()
	h.lastHealthCheck = &now
	
	// Update host status based on health
	if !healthStatus.IsHealthy {
		h.healthStatus.ConsecutiveFails++
		if h.healthStatus.ConsecutiveFails >= MaxConsecutiveFails {
			h.MarkUnreachable()
		}
	} else {
		h.healthStatus.ConsecutiveFails = 0
		if h.status == HostStatusUnreachable {
			h.Activate()
		}
	}
	
	h.updatedAt = time.Now()
}

// GetHealthStatus returns the current health status
func (h *Host) GetHealthStatus() HealthStatus {
	return h.healthStatus
}

// IsHealthy checks if the host is healthy
func (h *Host) IsHealthy() bool {
	return h.healthStatus.IsHealthy
}

// NeedsHealthCheck checks if a health check is due
func (h *Host) NeedsHealthCheck() bool {
	if h.lastHealthCheck == nil {
		return true
	}
	return time.Since(*h.lastHealthCheck) >= HealthCheckInterval
}

// SetMetadata sets a metadata key-value pair
func (h *Host) SetMetadata(key, value string) {
	h.metadata[key] = value
	h.updatedAt = time.Now()
}

// GetMetadata gets a metadata value by key
func (h *Host) GetMetadata(key string) (string, bool) {
	value, exists := h.metadata[key]
	return value, exists
}

// GetAllMetadata returns all metadata
func (h *Host) GetAllMetadata() map[string]string {
	metadata := make(map[string]string)
	for k, v := range h.metadata {
		metadata[k] = v
	}
	return metadata
}

// RemoveMetadata removes a metadata key
func (h *Host) RemoveMetadata(key string) {
	delete(h.metadata, key)
	h.updatedAt = time.Now()
}

// GetCreatedAt returns creation timestamp
func (h *Host) GetCreatedAt() time.Time {
	return h.createdAt
}

// GetUpdatedAt returns last update timestamp
func (h *Host) GetUpdatedAt() time.Time {
	return h.updatedAt
}

// GetConnectionString returns a connection string for SSH
func (h *Host) GetConnectionString() string {
	return h.credentials.Username + "@" + h.hostname + ":" + string(rune(h.port))
}

// Clone creates a deep copy of the host
func (h *Host) Clone() *Host {
	clone := *h
	
	// Deep copy slices and maps
	clone.tags = make([]string, len(h.tags))
	copy(clone.tags, h.tags)
	
	clone.metadata = make(map[string]string)
	for k, v := range h.metadata {
		clone.metadata[k] = v
	}
	
	return &clone
}

// getDefaultSSHConfig returns default SSH configuration
func getDefaultSSHConfig() SSHConfig {
	return SSHConfig{
		StrictHostKeyChecking: true,
		ConnectTimeout:        DefaultConnectTimeout,
		ServerAliveInterval:   DefaultServerAliveInterval,
		ServerAliveCountMax:   DefaultServerAliveCountMax,
		Compression:           false,
		PreferredCiphers:      []string{"aes128-ctr", "aes192-ctr", "aes256-ctr"},
		PreferredKex:          []string{"curve25519-sha256", "ecdh-sha2-nistp256"},
		PreferredMACs:         []string{"hmac-sha2-256", "hmac-sha2-512"},
	}
}

// HostSummary provides a lightweight view of host information
type HostSummary struct {
	ID          uuid.UUID
	Name        string
	Hostname    string
	IPAddress   valueobjects.IPAddress
	Port        int
	Type        HostType
	Status      HostStatus
	IsHealthy   bool
	LastSeen    *time.Time
	Tags        []string
}

// GetSummary returns a summary of the host
func (h *Host) GetSummary() HostSummary {
	return HostSummary{
		ID:        h.id,
		Name:      h.name,
		Hostname:  h.hostname,
		IPAddress: h.ipAddress,
		Port:      h.port,
		Type:      h.hostType,
		Status:    h.status,
		IsHealthy: h.healthStatus.IsHealthy,
		LastSeen:  h.lastSeen,
		Tags:      h.GetTags(),
	}
}