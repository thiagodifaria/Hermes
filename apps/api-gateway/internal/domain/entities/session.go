package entities

import (
	"errors"
	"time"

	"github.com/google/uuid"

	"github.com/thiagodifaria/Hermes/apps/api-gateway/internal/domain/valueobjects"
)

// SessionStatus represents the current status of a session
type SessionStatus string

const (
	SessionStatusPending    SessionStatus = "pending"
	SessionStatusActive     SessionStatus = "active"
	SessionStatusTerminated SessionStatus = "terminated"
	SessionStatusFailed     SessionStatus = "failed"
	SessionStatusTimeout    SessionStatus = "timeout"
)

// SessionType represents different types of sessions
type SessionType string

const (
	SessionTypeSSH   SessionType = "ssh"
	SessionTypeSFTP  SessionType = "sftp"
	SessionTypeShell SessionType = "shell"
)

// Session represents an SSH/remote session with rich domain behavior
type Session struct {
	id              uuid.UUID
	userID          uuid.UUID
	hostID          uuid.UUID
	sessionType     SessionType
	status          SessionStatus
	connectionInfo  ConnectionInfo
	recordingPath   string
	recordingEnabled bool
	startTime       time.Time
	endTime         *time.Time
	lastActivity    time.Time
	bytesSent       int64
	bytesReceived   int64
	commandsExecuted []Command
	exitCode        *int
	terminalSize    TerminalSize
	environment     map[string]string
	workingDirectory string
	createdAt       time.Time
	updatedAt       time.Time
}

// ConnectionInfo holds connection details
type ConnectionInfo struct {
	RemoteAddr    valueobjects.IPAddress
	LocalAddr     valueobjects.IPAddress
	Protocol      string
	ClientVersion string
	ServerVersion string
	Cipher        string
	MAC           string
	Compression   string
}

// Command represents a command executed in the session
type Command struct {
	ID        uuid.UUID
	Command   string
	Arguments []string
	ExitCode  int
	StartTime time.Time
	EndTime   time.Time
	Output    string // Truncated for storage
}

// TerminalSize represents terminal dimensions
type TerminalSize struct {
	Width  int
	Height int
}

// Session domain errors
var (
	ErrSessionAlreadyActive    = errors.New("session is already active")
	ErrSessionNotActive        = errors.New("session is not active")
	ErrSessionAlreadyTerminated = errors.New("session is already terminated")
	ErrInvalidTerminalSize     = errors.New("invalid terminal size")
	ErrRecordingNotEnabled     = errors.New("recording is not enabled for this session")
	ErrSessionTimeout          = errors.New("session has timed out")
	ErrMaxCommandsExceeded     = errors.New("maximum commands per session exceeded")
)

// Session constants
const (
	DefaultSessionTimeout = 4 * time.Hour
	MaxSessionDuration    = 24 * time.Hour
	MaxCommandsPerSession = 10000
	DefaultTerminalWidth  = 80
	DefaultTerminalHeight = 24
	MaxTerminalWidth      = 500
	MaxTerminalHeight     = 200
)

// NewSession creates a new session
func NewSession(userID, hostID uuid.UUID, sessionType SessionType, remoteAddr valueobjects.IPAddress) (*Session, error) {
	session := &Session{
		id:              uuid.New(),
		userID:          userID,
		hostID:          hostID,
		sessionType:     sessionType,
		status:          SessionStatusPending,
		connectionInfo: ConnectionInfo{
			RemoteAddr: remoteAddr,
		},
		recordingEnabled: true, // Default to enabled
		startTime:       time.Now(),
		lastActivity:    time.Now(),
		commandsExecuted: make([]Command, 0),
		terminalSize: TerminalSize{
			Width:  DefaultTerminalWidth,
			Height: DefaultTerminalHeight,
		},
		environment:      make(map[string]string),
		workingDirectory: "/",
		createdAt:       time.Now(),
		updatedAt:       time.Now(),
	}

	return session, nil
}

// GetID returns the session ID
func (s *Session) GetID() uuid.UUID {
	return s.id
}

// GetUserID returns the user ID
func (s *Session) GetUserID() uuid.UUID {
	return s.userID
}

// GetHostID returns the host ID
func (s *Session) GetHostID() uuid.UUID {
	return s.hostID
}

// GetStatus returns the session status
func (s *Session) GetStatus() SessionStatus {
	return s.status
}

// GetSessionType returns the session type
func (s *Session) GetSessionType() SessionType {
	return s.sessionType
}

// GetDuration returns the session duration
func (s *Session) GetDuration() time.Duration {
	if s.endTime != nil {
		return s.endTime.Sub(s.startTime)
	}
	return time.Since(s.startTime)
}

// IsActive checks if the session is currently active
func (s *Session) IsActive() bool {
	return s.status == SessionStatusActive
}

// IsTerminated checks if the session has ended
func (s *Session) IsTerminated() bool {
	return s.status == SessionStatusTerminated || 
		   s.status == SessionStatusFailed || 
		   s.status == SessionStatusTimeout
}

// IsRecordingEnabled checks if recording is enabled
func (s *Session) IsRecordingEnabled() bool {
	return s.recordingEnabled
}

// HasTimedOut checks if the session has exceeded the timeout
func (s *Session) HasTimedOut() bool {
	return time.Since(s.lastActivity) > DefaultSessionTimeout
}

// Start activates the session
func (s *Session) Start() error {
	if s.status == SessionStatusActive {
		return ErrSessionAlreadyActive
	}
	if s.IsTerminated() {
		return ErrSessionAlreadyTerminated
	}

	s.status = SessionStatusActive
	s.lastActivity = time.Now()
	s.updatedAt = time.Now()
	return nil
}

// Terminate ends the session with an exit code
func (s *Session) Terminate(exitCode int) error {
	if s.IsTerminated() {
		return ErrSessionAlreadyTerminated
	}

	now := time.Now()
	s.status = SessionStatusTerminated
	s.endTime = &now
	s.exitCode = &exitCode
	s.updatedAt = time.Now()
	return nil
}

// Fail marks the session as failed
func (s *Session) Fail(reason string) error {
	if s.IsTerminated() {
		return ErrSessionAlreadyTerminated
	}

	now := time.Now()
	s.status = SessionStatusFailed
	s.endTime = &now
	s.updatedAt = time.Now()
	return nil
}

// Timeout marks the session as timed out
func (s *Session) Timeout() error {
	if s.IsTerminated() {
		return ErrSessionAlreadyTerminated
	}

	now := time.Now()
	s.status = SessionStatusTimeout
	s.endTime = &now
	s.updatedAt = time.Now()
	return nil
}

// UpdateActivity updates the last activity timestamp
func (s *Session) UpdateActivity() {
	s.lastActivity = time.Now()
	s.updatedAt = time.Now()
}

// AddBytesTransferred adds to the bytes transferred counters
func (s *Session) AddBytesTransferred(sent, received int64) {
	s.bytesSent += sent
	s.bytesReceived += received
	s.UpdateActivity()
}

// SetRecordingPath sets the path where session recording is stored
func (s *Session) SetRecordingPath(path string) {
	s.recordingPath = path
	s.updatedAt = time.Now()
}

// GetRecordingPath returns the recording path
func (s *Session) GetRecordingPath() string {
	return s.recordingPath
}

// EnableRecording enables session recording
func (s *Session) EnableRecording() {
	s.recordingEnabled = true
	s.updatedAt = time.Now()
}

// DisableRecording disables session recording
func (s *Session) DisableRecording() {
	s.recordingEnabled = false
	s.updatedAt = time.Now()
}

// SetTerminalSize updates the terminal dimensions
func (s *Session) SetTerminalSize(width, height int) error {
	if width <= 0 || height <= 0 {
		return ErrInvalidTerminalSize
	}
	if width > MaxTerminalWidth || height > MaxTerminalHeight {
		return ErrInvalidTerminalSize
	}

	s.terminalSize.Width = width
	s.terminalSize.Height = height
	s.updatedAt = time.Now()
	return nil
}

// GetTerminalSize returns the current terminal size
func (s *Session) GetTerminalSize() TerminalSize {
	return s.terminalSize
}

// SetEnvironmentVariable sets an environment variable for the session
func (s *Session) SetEnvironmentVariable(key, value string) {
	s.environment[key] = value
	s.updatedAt = time.Now()
}

// GetEnvironmentVariable gets an environment variable value
func (s *Session) GetEnvironmentVariable(key string) (string, bool) {
	value, exists := s.environment[key]
	return value, exists
}

// GetEnvironment returns all environment variables
func (s *Session) GetEnvironment() map[string]string {
	env := make(map[string]string)
	for k, v := range s.environment {
		env[k] = v
	}
	return env
}

// SetWorkingDirectory sets the current working directory
func (s *Session) SetWorkingDirectory(dir string) {
	s.workingDirectory = dir
	s.updatedAt = time.Now()
}

// GetWorkingDirectory returns the current working directory
func (s *Session) GetWorkingDirectory() string {
	return s.workingDirectory
}

// AddCommand records a command execution
func (s *Session) AddCommand(command string, args []string) (*Command, error) {
	if len(s.commandsExecuted) >= MaxCommandsPerSession {
		return nil, ErrMaxCommandsExceeded
	}

	cmd := Command{
		ID:        uuid.New(),
		Command:   command,
		Arguments: args,
		StartTime: time.Now(),
	}

	s.commandsExecuted = append(s.commandsExecuted, cmd)
	s.UpdateActivity()
	
	return &cmd, nil
}

// CompleteCommand marks a command as completed with exit code
func (s *Session) CompleteCommand(commandID uuid.UUID, exitCode int, output string) error {
	for i, cmd := range s.commandsExecuted {
		if cmd.ID == commandID {
			s.commandsExecuted[i].ExitCode = exitCode
			s.commandsExecuted[i].EndTime = time.Now()
			// Truncate output to prevent excessive memory usage
			if len(output) > 4096 {
				output = output[:4096] + "... [truncated]"
			}
			s.commandsExecuted[i].Output = output
			s.updatedAt = time.Now()
			return nil
		}
	}
	return errors.New("command not found")
}

// GetCommands returns all executed commands
func (s *Session) GetCommands() []Command {
	commands := make([]Command, len(s.commandsExecuted))
	copy(commands, s.commandsExecuted)
	return commands
}

// GetCommandCount returns the number of executed commands
func (s *Session) GetCommandCount() int {
	return len(s.commandsExecuted)
}

// GetLastCommand returns the most recently executed command
func (s *Session) GetLastCommand() *Command {
	if len(s.commandsExecuted) == 0 {
		return nil
	}
	return &s.commandsExecuted[len(s.commandsExecuted)-1]
}

// UpdateConnectionInfo updates connection information
func (s *Session) UpdateConnectionInfo(info ConnectionInfo) {
	s.connectionInfo = info
	s.updatedAt = time.Now()
}

// GetConnectionInfo returns connection information
func (s *Session) GetConnectionInfo() ConnectionInfo {
	return s.connectionInfo
}

// GetBytesTransferred returns bytes sent and received
func (s *Session) GetBytesTransferred() (int64, int64) {
	return s.bytesSent, s.bytesReceived
}

// GetStartTime returns when the session started
func (s *Session) GetStartTime() time.Time {
	return s.startTime
}

// GetEndTime returns when the session ended (if it has ended)
func (s *Session) GetEndTime() *time.Time {
	return s.endTime
}

// GetLastActivity returns the last activity timestamp
func (s *Session) GetLastActivity() time.Time {
	return s.lastActivity
}

// GetExitCode returns the exit code (if session has terminated)
func (s *Session) GetExitCode() *int {
	return s.exitCode
}

// GetCreatedAt returns creation timestamp
func (s *Session) GetCreatedAt() time.Time {
	return s.createdAt
}

// GetUpdatedAt returns last update timestamp
func (s *Session) GetUpdatedAt() time.Time {
	return s.updatedAt
}

// CheckTimeout checks if the session should be timed out
func (s *Session) CheckTimeout() error {
	if !s.IsActive() {
		return nil
	}

	if s.HasTimedOut() {
		return s.Timeout()
	}

	// Check for maximum session duration
	if s.GetDuration() > MaxSessionDuration {
		return s.Timeout()
	}

	return nil
}

// GetSessionSummary returns a summary of session statistics
func (s *Session) GetSessionSummary() SessionSummary {
	return SessionSummary{
		ID:               s.id,
		UserID:          s.userID,
		HostID:          s.hostID,
		Type:            s.sessionType,
		Status:          s.status,
		Duration:        s.GetDuration(),
		BytesSent:       s.bytesSent,
		BytesReceived:   s.bytesReceived,
		CommandCount:    len(s.commandsExecuted),
		RecordingPath:   s.recordingPath,
		StartTime:       s.startTime,
		EndTime:         s.endTime,
		ExitCode:        s.exitCode,
	}
}

// SessionSummary provides a lightweight view of session information
type SessionSummary struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	HostID        uuid.UUID
	Type          SessionType
	Status        SessionStatus
	Duration      time.Duration
	BytesSent     int64
	BytesReceived int64
	CommandCount  int
	RecordingPath string
	StartTime     time.Time
	EndTime       *time.Time
	ExitCode      *int
}