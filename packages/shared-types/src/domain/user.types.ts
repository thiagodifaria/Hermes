// Shared TypeScript types for User domain
// These types mirror the Go domain entities for frontend use

export type UserStatus = 'active' | 'inactive' | 'suspended' | 'pending';

export type UserRole = 'user' | 'admin' | 'operator' | 'auditor';

export type SSHKeyType = 'ssh-rsa' | 'ssh-ed25519' | 'ecdsa-sha2-nistp256' | 'ssh-dss';

export type IPAddressType = 'ipv4' | 'ipv6';

export type AuthMethod = 'password' | 'private_key' | 'certificate' | 'agent';

export type HostStatus = 'active' | 'inactive' | 'maintenance' | 'unreachable';

export type HostType = 'server' | 'workstation' | 'router' | 'switch' | 'firewall' | 'container' | 'virtual';

export type SessionStatus = 'pending' | 'active' | 'terminated' | 'failed' | 'timeout';

export type SessionType = 'ssh' | 'sftp' | 'shell';

// User domain types
export interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  status: UserStatus;
  roles: UserRole[];
  permissions: string[];
  sshKeys: SSHKey[];
  lastLoginAt?: string;
  failedLoginCount: number;
  lockedUntil?: string;
  emailVerifiedAt?: string;
  createdAt: string;
  updatedAt: string;
}

export interface CreateUserRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
}

export interface UpdateUserRequest {
  firstName?: string;
  lastName?: string;
  status?: UserStatus;
  roles?: UserRole[];
  permissions?: string[];
}

export interface ChangePasswordRequest {
  oldPassword: string;
  newPassword: string;
}

export interface UserSummary {
  id: string;
  email: string;
  fullName: string;
  status: UserStatus;
  roles: UserRole[];
  lastLoginAt?: string;
  createdAt: string;
}

// SSH Key domain types
export interface SSHKey {
  keyType: SSHKeyType;
  keyData: string;
  comment: string;
  fingerprint: string;
  bitLength: number;
  algorithm: string;
  createdAt: string;
}

export interface CreateSSHKeyRequest {
  keyString: string;
}

export interface SSHKeyInfo {
  type: string;
  algorithm: string;
  bitLength: number;
  fingerprint: string;
  md5Fingerprint: string;
  sha256Fingerprint: string;
  comment: string;
  securityLevel: 'weak' | 'good' | 'excellent';
  isSecure: boolean;
  createdAt: string;
}

// IP Address domain types
export interface IPAddress {
  value: string;
  type: IPAddressType;
  isPrivate: boolean;
  isLoopback: boolean;
  isMulticast: boolean;
}

export interface IPAddressInfo {
  address: string;
  type: string;
  isPrivate: boolean;
  isPublic: boolean;
  isLoopback: boolean;
  isMulticast: boolean;
  isReserved: boolean;
  reverseDns: string;
  class?: string; // For IPv4 only
}

// Host domain types
export interface Host {
  id: string;
  name: string;
  description: string;
  hostname: string;
  ipAddress: IPAddress;
  port: number;
  hostType: HostType;
  status: HostStatus;
  operatingSystem: string;
  architecture: string;
  tags: string[];
  credentials: HostCredentials;
  sshConfig: SSHConfig;
  lastSeen?: string;
  lastHealthCheck?: string;
  healthStatus: HealthStatus;
  metadata: Record<string, string>;
  createdAt: string;
  updatedAt: string;
}

export interface HostCredentials {
  username: string;
  authMethod: AuthMethod;
  privateKeyPath: string;
  password: string; // Should be encrypted
  certificate: string;
}

export interface SSHConfig {
  strictHostKeyChecking: boolean;
  userKnownHostsFile: string;
  connectTimeout: string; // Duration string
  serverAliveInterval: string; // Duration string
  serverAliveCountMax: number;
  compression: boolean;
  preferredCiphers: string[];
  preferredKex: string[];
  preferredMACs: string[];
}

export interface HealthStatus {
  isHealthy: boolean;
  responseTime: string; // Duration string
  lastError: string;
  consecutiveFails: number;
  uptime: string; // Duration string
  cpuUsage: number;
  memoryUsage: number;
  diskUsage: number;
}

export interface CreateHostRequest {
  name: string;
  description?: string;
  hostname: string;
  ipAddress: string;
  port: number;
  hostType?: HostType;
  tags?: string[];
}

export interface UpdateHostRequest {
  name?: string;
  description?: string;
  hostname?: string;
  ipAddress?: string;
  port?: number;
  hostType?: HostType;
  status?: HostStatus;
  operatingSystem?: string;
  architecture?: string;
  tags?: string[];
  metadata?: Record<string, string>;
}

export interface HostSummary {
  id: string;
  name: string;
  hostname: string;
  ipAddress: IPAddress;
  port: number;
  type: HostType;
  status: HostStatus;
  isHealthy: boolean;
  lastSeen?: string;
  tags: string[];
}

// Session domain types
export interface Session {
  id: string;
  userId: string;
  hostId: string;
  sessionType: SessionType;
  status: SessionStatus;
  connectionInfo: ConnectionInfo;
  recordingPath: string;
  recordingEnabled: boolean;
  startTime: string;
  endTime?: string;
  lastActivity: string;
  bytesSent: number;
  bytesReceived: number;
  commandsExecuted: Command[];
  exitCode?: number;
  terminalSize: TerminalSize;
  environment: Record<string, string>;
  workingDirectory: string;
  createdAt: string;
  updatedAt: string;
}

export interface ConnectionInfo {
  remoteAddr: IPAddress;
  localAddr: IPAddress;
  protocol: string;
  clientVersion: string;
  serverVersion: string;
  cipher: string;
  mac: string;
  compression: string;
}

export interface Command {
  id: string;
  command: string;
  arguments: string[];
  exitCode: number;
  startTime: string;
  endTime: string;
  output: string;
}

export interface TerminalSize {
  width: number;
  height: number;
}

export interface CreateSessionRequest {
  hostId: string;
  sessionType: SessionType;
  recordingEnabled?: boolean;
}

export interface UpdateSessionRequest {
  terminalSize?: TerminalSize;
  environment?: Record<string, string>;
  workingDirectory?: string;
}

export interface SessionSummary {
  id: string;
  userId: string;
  hostId: string;
  type: SessionType;
  status: SessionStatus;
  duration: string; // Duration string
  bytesSent: number;
  bytesReceived: number;
  commandCount: number;
  recordingPath: string;
  startTime: string;
  endTime?: string;
  exitCode?: number;
}

// Common validation types
export interface ValidationError {
  field: string;
  message: string;
}

export interface DomainError {
  code: string;
  message: string;
  field?: string;
}

// Pagination types
export interface PaginationParams {
  page: number;
  limit: number;
  sortBy?: string;
  sortOrder?: 'asc' | 'desc';
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
    hasNext: boolean;
    hasPrevious: boolean;
  };
}

// Filter types
export interface UserFilter {
  status?: UserStatus[];
  roles?: UserRole[];
  emailDomain?: string;
  createdAfter?: string;
  createdBefore?: string;
  lastLoginAfter?: string;
  lastLoginBefore?: string;
}

export interface HostFilter {
  status?: HostStatus[];
  hostType?: HostType[];
  tags?: string[];
  isHealthy?: boolean;
  createdAfter?: string;
  createdBefore?: string;
  lastSeenAfter?: string;
  lastSeenBefore?: string;
}

export interface SessionFilter {
  userId?: string;
  hostId?: string;
  status?: SessionStatus[];
  sessionType?: SessionType[];
  startTimeAfter?: string;
  startTimeBefore?: string;
  endTimeAfter?: string;
  endTimeBefore?: string;
  hasRecording?: boolean;
}

// Search types
export interface SearchParams {
  query: string;
  fields?: string[];
  exact?: boolean;
}

export interface SearchResult<T> {
  items: T[];
  total: number;
  query: string;
  searchTime: number;
}

// Event types for real-time updates
export interface UserEvent {
  type: 'user.created' | 'user.updated' | 'user.deleted' | 'user.login' | 'user.logout';
  userId: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

export interface HostEvent {
  type: 'host.created' | 'host.updated' | 'host.deleted' | 'host.health_changed';
  hostId: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

export interface SessionEvent {
  type: 'session.started' | 'session.ended' | 'session.command_executed';
  sessionId: string;
  userId: string;
  hostId: string;
  timestamp: string;
  metadata?: Record<string, any>;
}

// Audit types
export interface AuditLogEntry {
  id: string;
  userId?: string;
  sessionId?: string;
  action: string;
  resource: string;
  resourceId: string;
  timestamp: string;
  ipAddress: string;
  userAgent: string;
  metadata: Record<string, any>;
}

// Permission types
export interface Permission {
  resource: string; // e.g., 'sessions', 'hosts', 'users'
  action: string;   // e.g., 'read', 'write', 'delete'
  scope?: string;   // e.g., 'own', 'team', 'global'
}

export interface RoleDefinition {
  name: UserRole;
  description: string;
  permissions: Permission[];
}

// Configuration types
export interface SecuritySettings {
  passwordMinLength: number;
  passwordRequireSpecial: boolean;
  jwtExpiration: string;
  refreshExpiration: string;
  maxFailedLogins: number;
  lockoutDuration: string;
}

export interface SSHSettings {
  defaultPort: number;
  connectionTimeout: string;
  maxSessionsPerUser: number;
  sessionTTL: string;
  allowedKeyTypes: SSHKeyType[];
  minKeyLength: Record<SSHKeyType, number>;
}

// Statistics types
export interface UserStatistics {
  totalUsers: number;
  activeUsers: number;
  newUsersToday: number;
  loginAttempts24h: number;
  failedLogins24h: number;
}

export interface HostStatistics {
  totalHosts: number;
  activeHosts: number;
  healthyHosts: number;
  hostsDown: number;
  averageResponseTime: number;
}

export interface SessionStatistics {
  activeSessions: number;
  totalSessions24h: number;
  averageSessionDuration: string;
  totalBytesTransferred24h: number;
  topCommandsToday: Array<{ command: string; count: number }>;
}