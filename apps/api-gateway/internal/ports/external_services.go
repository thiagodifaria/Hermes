// apps/api-gateway/internal/ports/external_services.go
package ports

import (
	"context"
	"io"
	"time"

	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/valueobjects"
)

// ExternalServiceManager consolidates all external service interfaces
// Following Hexagonal Architecture - these are outbound ports
type ExternalServiceManager interface {
	Email() EmailService
	OAuth() OAuthService
	Storage() StorageService
	Cache() CacheService
	MessageQueue() MessageQueueService
	Monitoring() MonitoringService
	Vault() VaultService
	Notification() NotificationService
}

// EmailService defines the interface for email operations
// Abstracts different email providers (Mailgun, SES, SMTP)
type EmailService interface {
	// Basic email operations
	SendEmail(ctx context.Context, email *Email) error
	SendBulkEmail(ctx context.Context, emails []*Email) error
	SendTemplateEmail(ctx context.Context, template *EmailTemplate) error
	
	// Email validation
	ValidateEmail(ctx context.Context, email string) (*EmailValidationResult, error)
	ValidateBulkEmails(ctx context.Context, emails []string) ([]*EmailValidationResult, error)
	
	// Bounce and complaint handling
	ProcessBounces(ctx context.Context) ([]*EmailBounce, error)
	ProcessComplaints(ctx context.Context) ([]*EmailComplaint, error)
	
	// Statistics and reporting
	GetEmailStats(ctx context.Context, from, to time.Time) (*EmailStats, error)
	GetDeliveryStatus(ctx context.Context, messageID string) (*DeliveryStatus, error)
	
	// Template management
	CreateTemplate(ctx context.Context, template *EmailTemplate) error
	UpdateTemplate(ctx context.Context, templateID string, template *EmailTemplate) error
	DeleteTemplate(ctx context.Context, templateID string) error
	ListTemplates(ctx context.Context) ([]*EmailTemplate, error)
}

// OAuthService defines the interface for OAuth2 operations
// Supports multiple providers (Google, GitHub, Okta)
type OAuthService interface {
	// Authorization flow
	GetAuthorizationURL(ctx context.Context, provider OAuthProvider, state string) (string, error)
	ExchangeCodeForToken(ctx context.Context, provider OAuthProvider, code, state string) (*OAuthToken, error)
	RefreshToken(ctx context.Context, provider OAuthProvider, refreshToken string) (*OAuthToken, error)
	
	// User information
	GetUserInfo(ctx context.Context, provider OAuthProvider, accessToken string) (*OAuthUserInfo, error)
	
	// Token validation
	ValidateToken(ctx context.Context, provider OAuthProvider, accessToken string) (*TokenValidation, error)
	RevokeToken(ctx context.Context, provider OAuthProvider, token string) error
	
	// Provider management
	GetProvider(provider OAuthProvider) (OAuthProviderConfig, error)
	ListProviders() []OAuthProvider
}

// StorageService defines the interface for file storage operations
// Supports multiple backends (S3, local file system)
type StorageService interface {
	// File operations
	Upload(ctx context.Context, bucket, key string, data io.Reader, metadata map[string]string) error
	Download(ctx context.Context, bucket, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, bucket, key string) error
	Exists(ctx context.Context, bucket, key string) (bool, error)
	
	// File metadata
	GetMetadata(ctx context.Context, bucket, key string) (map[string]string, error)
	SetMetadata(ctx context.Context, bucket, key string, metadata map[string]string) error
	GetFileInfo(ctx context.Context, bucket, key string) (*FileInfo, error)
	
	// Directory operations
	List(ctx context.Context, bucket, prefix string) ([]*FileInfo, error)
	ListWithPagination(ctx context.Context, bucket, prefix, marker string, maxKeys int) (*ListResult, error)
	
	// Bucket operations
	CreateBucket(ctx context.Context, bucket string) error
	DeleteBucket(ctx context.Context, bucket string) error
	BucketExists(ctx context.Context, bucket string) (bool, error)
	
	// URL generation
	GeneratePresignedURL(ctx context.Context, bucket, key string, expiration time.Duration, method string) (string, error)
	GenerateUploadURL(ctx context.Context, bucket, key string, expiration time.Duration) (string, map[string]string, error)
	
	// Batch operations
	UploadBatch(ctx context.Context, operations []*UploadOperation) ([]*UploadResult, error)
	DeleteBatch(ctx context.Context, operations []*DeleteOperation) ([]*DeleteResult, error)
}

// CacheService defines the interface for caching operations
// Abstracts Redis or other cache implementations
type CacheService interface {
	// Basic operations
	Set(ctx context.Context, key string, value interface{}, ttl time.Duration) error
	Get(ctx context.Context, key string) (interface{}, error)
	Delete(ctx context.Context, key string) error
	Exists(ctx context.Context, key string) (bool, error)
	
	// Batch operations
	SetMultiple(ctx context.Context, items map[string]interface{}, ttl time.Duration) error
	GetMultiple(ctx context.Context, keys []string) (map[string]interface{}, error)
	DeleteMultiple(ctx context.Context, keys []string) error
	
	// Hash operations
	SetHash(ctx context.Context, key, field string, value interface{}) error
	GetHash(ctx context.Context, key, field string) (interface{}, error)
	GetHashAll(ctx context.Context, key string) (map[string]interface{}, error)
	DeleteHash(ctx context.Context, key, field string) error
	
	// List operations
	PushList(ctx context.Context, key string, values ...interface{}) error
	PopList(ctx context.Context, key string) (interface{}, error)
	ListLength(ctx context.Context, key string) (int64, error)
	GetListRange(ctx context.Context, key string, start, stop int64) ([]interface{}, error)
	
	// Set operations
	AddToSet(ctx context.Context, key string, members ...interface{}) error
	RemoveFromSet(ctx context.Context, key string, members ...interface{}) error
	GetSetMembers(ctx context.Context, key string) ([]interface{}, error)
	IsSetMember(ctx context.Context, key string, member interface{}) (bool, error)
	
	// Expiration operations
	SetTTL(ctx context.Context, key string, ttl time.Duration) error
	GetTTL(ctx context.Context, key string) (time.Duration, error)
	RemoveTTL(ctx context.Context, key string) error
	
	// Pattern operations
	Keys(ctx context.Context, pattern string) ([]string, error)
	DeletePattern(ctx context.Context, pattern string) (int64, error)
	
	// Statistics
	GetStats(ctx context.Context) (*CacheStats, error)
}

// MessageQueueService defines the interface for message queue operations
// Abstracts NATS or other message queue implementations
type MessageQueueService interface {
	// Publishing
	Publish(ctx context.Context, subject string, data []byte) error
	PublishAsync(ctx context.Context, subject string, data []byte) error
	PublishRequest(ctx context.Context, subject string, data []byte, timeout time.Duration) ([]byte, error)
	
	// Subscribing
	Subscribe(ctx context.Context, subject string, handler MessageHandler) (*Subscription, error)
	SubscribeQueue(ctx context.Context, subject, queue string, handler MessageHandler) (*Subscription, error)
	SubscribeAsync(ctx context.Context, subject string, handler MessageHandler) (*Subscription, error)
	
	// Streaming
	CreateStream(ctx context.Context, config *StreamConfig) error
	DeleteStream(ctx context.Context, name string) error
	GetStream(ctx context.Context, name string) (*StreamInfo, error)
	ListStreams(ctx context.Context) ([]*StreamInfo, error)
	
	// Consumer management
	CreateConsumer(ctx context.Context, stream string, config *ConsumerConfig) error
	DeleteConsumer(ctx context.Context, stream, consumer string) error
	GetConsumer(ctx context.Context, stream, consumer string) (*ConsumerInfo, error)
	
	// Message acknowledgment
	AckMessage(ctx context.Context, msg *Message) error
	NakMessage(ctx context.Context, msg *Message) error
	
	// Connection management
	Connect(ctx context.Context) error
	Disconnect(ctx context.Context) error
	IsConnected() bool
	
	// Statistics
	GetConnectionStats(ctx context.Context) (*ConnectionStats, error)
}

// MonitoringService defines the interface for monitoring and metrics
// Abstracts Prometheus or other monitoring systems
type MonitoringService interface {
	// Metrics
	RecordCounter(name string, labels map[string]string, value float64)
	RecordGauge(name string, labels map[string]string, value float64)
	RecordHistogram(name string, labels map[string]string, value float64)
	RecordSummary(name string, labels map[string]string, value float64)
	
	// Health checks
	RegisterHealthCheck(name string, checker HealthChecker) error
	UnregisterHealthCheck(name string) error
	GetHealthStatus(ctx context.Context) (*HealthStatus, error)
	GetHealthCheck(ctx context.Context, name string) (*HealthCheckResult, error)
	
	// Alerting
	SendAlert(ctx context.Context, alert *Alert) error
	ResolveAlert(ctx context.Context, alertID string) error
	GetActiveAlerts(ctx context.Context) ([]*Alert, error)
	
	// Tracing
	StartTrace(ctx context.Context, operationName string) (TraceContext, error)
	FinishTrace(ctx context.Context, trace TraceContext) error
	AddTraceTag(ctx context.Context, trace TraceContext, key, value string) error
	AddTraceLog(ctx context.Context, trace TraceContext, level string, message string) error
}

// VaultService defines the interface for secret management
// Abstracts HashiCorp Vault or other secret management systems
type VaultService interface {
	// Secret operations
	WriteSecret(ctx context.Context, path string, data map[string]interface{}) error
	ReadSecret(ctx context.Context, path string) (map[string]interface{}, error)
	DeleteSecret(ctx context.Context, path string) error
	ListSecrets(ctx context.Context, path string) ([]string, error)
	
	// Encryption operations
	Encrypt(ctx context.Context, keyName string, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, keyName string, ciphertext []byte) ([]byte, error)
	GenerateDataKey(ctx context.Context, keyName string) (*DataKey, error)
	
	// Key management
	CreateKey(ctx context.Context, keyName string, keyType string) error
	DeleteKey(ctx context.Context, keyName string) error
	RotateKey(ctx context.Context, keyName string) error
	ListKeys(ctx context.Context) ([]string, error)
	
	// Certificate operations
	GenerateCertificate(ctx context.Context, config *CertificateConfig) (*Certificate, error)
	RevokeCertificate(ctx context.Context, serialNumber string) error
	
	// Authentication
	Login(ctx context.Context, method string, credentials map[string]interface{}) (*AuthResponse, error)
	RenewToken(ctx context.Context) (*AuthResponse, error)
	RevokeToken(ctx context.Context) error
}

// NotificationService defines the interface for notifications
// Supports multiple channels (email, Slack, Teams, webhooks)
type NotificationService interface {
	// Channel management
	RegisterChannel(channel NotificationChannel) error
	UnregisterChannel(channelID string) error
	ListChannels() []NotificationChannel
	
	// Notification sending
	Send(ctx context.Context, notification *Notification) error
	SendBulk(ctx context.Context, notifications []*Notification) error
	SendToChannel(ctx context.Context, channelID string, message *Message) error
	
	// Template-based notifications
	SendTemplate(ctx context.Context, templateID string, data map[string]interface{}, recipients []string) error
	
	// Webhook processing
	ProcessWebhook(ctx context.Context, payload []byte, signature string, provider string) error
	ValidateWebhook(ctx context.Context, payload []byte, signature string, secret string) error
	
	// Delivery tracking
	GetDeliveryStatus(ctx context.Context, notificationID string) (*DeliveryStatus, error)
	GetDeliveryHistory(ctx context.Context, from, to time.Time) ([]*DeliveryRecord, error)
	
	// Statistics
	GetNotificationStats(ctx context.Context, from, to time.Time) (*NotificationStats, error)
}

// Supporting types and structures

// Email types
type Email struct {
	From        string
	To          []string
	CC          []string
	BCC         []string
	Subject     string
	Body        string
	HTMLBody    string
	Attachments []*EmailAttachment
	Headers     map[string]string
	Priority    EmailPriority
}

type EmailTemplate struct {
	ID          string
	Name        string
	Subject     string
	Body        string
	HTMLBody    string
	Variables   []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type EmailValidationResult struct {
	Email       string
	IsValid     bool
	IsDisposable bool
	IsCatchAll  bool
	Reason      string
}

type EmailBounce struct {
	Email     string
	Type      BounceType
	Reason    string
	Timestamp time.Time
}

type EmailComplaint struct {
	Email     string
	Type      ComplaintType
	Reason    string
	Timestamp time.Time
}

type EmailStats struct {
	Sent        int64
	Delivered   int64
	Bounced     int64
	Complained  int64
	Opened      int64
	Clicked     int64
}

type EmailAttachment struct {
	Filename    string
	ContentType string
	Data        []byte
}

type EmailPriority string

const (
	EmailPriorityLow    EmailPriority = "low"
	EmailPriorityNormal EmailPriority = "normal"
	EmailPriorityHigh   EmailPriority = "high"
)

type BounceType string
type ComplaintType string

// OAuth types
type OAuthProvider string

const (
	OAuthProviderGoogle OAuthProvider = "google"
	OAuthProviderGitHub OAuthProvider = "github"
	OAuthProviderOkta   OAuthProvider = "okta"
)

type OAuthToken struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresIn    int64
	Scope        string
}

type OAuthUserInfo struct {
	ID       string
	Email    string
	Name     string
	Picture  string
	Verified bool
	Provider OAuthProvider
}

type TokenValidation struct {
	Valid     bool
	ExpiresAt time.Time
	Scope     string
}

type OAuthProviderConfig struct {
	Provider     OAuthProvider
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// Storage types
type FileInfo struct {
	Key          string
	Size         int64
	ETag         string
	LastModified time.Time
	ContentType  string
	Metadata     map[string]string
}

type ListResult struct {
	Files      []*FileInfo
	NextMarker string
	Truncated  bool
}

type UploadOperation struct {
	Bucket   string
	Key      string
	Data     io.Reader
	Metadata map[string]string
}

type UploadResult struct {
	Key   string
	ETag  string
	Error error
}

type DeleteOperation struct {
	Bucket string
	Key    string
}

type DeleteResult struct {
	Key   string
	Error error
}

// Cache types
type CacheStats struct {
	Hits           int64
	Misses         int64
	Keys           int64
	Memory         int64
	Connections    int64
	CommandsCount  int64
	ExpiredKeys    int64
}

// Message Queue types
type MessageHandler func(ctx context.Context, msg *Message) error

type Subscription struct {
	ID      string
	Subject string
	Queue   string
}

type Message struct {
	Subject string
	Data    []byte
	Headers map[string]string
}

type StreamConfig struct {
	Name        string
	Subjects    []string
	Retention   string
	MaxMessages int64
	MaxBytes    int64
	MaxAge      time.Duration
}

type StreamInfo struct {
	Config   StreamConfig
	Messages int64
	Bytes    int64
}

type ConsumerConfig struct {
	Name         string
	DeliverPolicy string
	AckPolicy    string
	AckWait      time.Duration
}

type ConsumerInfo struct {
	Config       ConsumerConfig
	Delivered    int64
	AckPending   int64
}

type ConnectionStats struct {
	Connected    bool
	Reconnects   int64
	LastError    string
	Servers      []string
}

// Monitoring types
type HealthChecker func(ctx context.Context) error

type HealthStatus struct {
	Status string
	Checks map[string]*HealthCheckResult
}

type HealthCheckResult struct {
	Status    string
	Duration  time.Duration
	Error     string
	Timestamp time.Time
}

type Alert struct {
	ID          string
	Name        string
	Description string
	Severity    AlertSeverity
	Status      AlertStatus
	Labels      map[string]string
	CreatedAt   time.Time
}

type AlertSeverity string
type AlertStatus string

type TraceContext interface {
	GetTraceID() string
	GetSpanID() string
}

// Vault types
type DataKey struct {
	Key       []byte
	Encrypted []byte
}

type CertificateConfig struct {
	CommonName string
	DNS        []string
	IPAddresses []valueobjects.IPAddress
	TTL        time.Duration
}

type Certificate struct {
	Certificate string
	PrivateKey  string
	CAChain     []string
	SerialNumber string
	ExpiresAt   time.Time
}

type AuthResponse struct {
	Token     string
	ExpiresAt time.Time
	Policies  []string
}

// Notification types
type NotificationChannel interface {
	GetID() string
	GetType() string
	Send(ctx context.Context, message *Message) error
}

type Notification struct {
	ID        string
	Type      NotificationType
	Recipients []string
	Subject   string
	Message   string
	Data      map[string]interface{}
	Priority  NotificationPriority
}

type NotificationType string
type NotificationPriority string

type DeliveryRecord struct {
	NotificationID string
	Recipient      string
	Status         string
	DeliveredAt    *time.Time
	Error          string
}

type NotificationStats struct {
	Sent      int64
	Delivered int64
	Failed    int64
	Pending   int64
}