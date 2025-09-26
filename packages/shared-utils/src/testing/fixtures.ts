// packages/shared-utils/src/testing/fixtures.ts
// Test fixtures for consistent test data across the application
// Based on domain entities and TypeScript types

import { v4 as uuidv4 } from 'uuid';
import type {
  User,
  Host,
  Session,
  UserStatus,
  UserRole,
  HostStatus,
  HostType,
  SessionStatus,
  SessionType,
  SSHKey,
  IPAddress,
  HostCredentials,
  SSHConfig,
  HealthStatus,
  ConnectionInfo,
  Command,
  TerminalSize,
} from '../types';

// User Fixtures
export const createUserFixture = (overrides: Partial<User> = {}): User => {
  const baseUser: User = {
    id: uuidv4(),
    email: 'test@example.com',
    firstName: 'John',
    lastName: 'Doe',
    status: 'active' as UserStatus,
    roles: ['user'] as UserRole[],
    permissions: ['sessions.create', 'hosts.read.assigned'],
    sshKeys: [],
    failedLoginCount: 0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  return { ...baseUser, ...overrides };
};

export const createAdminUserFixture = (overrides: Partial<User> = {}): User => {
  return createUserFixture({
    email: 'admin@example.com',
    firstName: 'Admin',
    lastName: 'User',
    roles: ['admin'],
    permissions: [
      'users.*',
      'hosts.*', 
      'sessions.*',
      'audit.*',
      'system.*',
    ],
    emailVerifiedAt: new Date().toISOString(),
    ...overrides,
  });
};

export const createLockedUserFixture = (overrides: Partial<User> = {}): User => {
  const futureTime = new Date();
  futureTime.setMinutes(futureTime.getMinutes() + 30);
  
  return createUserFixture({
    status: 'inactive' as UserStatus,
    failedLoginCount: 5,
    lockedUntil: futureTime.toISOString(),
    ...overrides,
  });
};

export const createPendingUserFixture = (overrides: Partial<User> = {}): User => {
  return createUserFixture({
    status: 'pending' as UserStatus,
    roles: ['user'],
    permissions: [],
    ...overrides,
  });
};

// SSH Key Fixtures
export const createSSHKeyFixture = (overrides: Partial<SSHKey> = {}): SSHKey => {
  const baseKey: SSHKey = {
    keyType: 'ssh-ed25519',
    keyData: 'AAAAC3NzaC1lZDI1NTE5AAAAIAbCdEfGhIjKlMnOpQrStUvWxYz0123456789',
    comment: 'test@example.com',
    fingerprint: 'SHA256:abcdefghijklmnopqrstuvwxyz0123456789',
    bitLength: 256,
    algorithm: 'Ed25519',
    createdAt: new Date().toISOString(),
  };

  return { ...baseKey, ...overrides };
};

export const createRSAKeyFixture = (overrides: Partial<SSHKey> = {}): SSHKey => {
  return createSSHKeyFixture({
    keyType: 'ssh-rsa',
    keyData: 'AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDjm...', // truncated
    bitLength: 2048,
    algorithm: 'RSA',
    ...overrides,
  });
};

// IP Address Fixtures
export const createIPAddressFixture = (overrides: Partial<IPAddress> = {}): IPAddress => {
  const baseIP: IPAddress = {
    value: '192.168.1.100',
    type: 'ipv4',
    isPrivate: true,
    isLoopback: false,
    isMulticast: false,
  };

  return { ...baseIP, ...overrides };
};

export const createPublicIPFixture = (overrides: Partial<IPAddress> = {}): IPAddress => {
  return createIPAddressFixture({
    value: '8.8.8.8',
    isPrivate: false,
    ...overrides,
  });
};

export const createIPv6AddressFixture = (overrides: Partial<IPAddress> = {}): IPAddress => {
  return createIPAddressFixture({
    value: '2001:db8::1',
    type: 'ipv6',
    isPrivate: false,
    ...overrides,
  });
};

// Host Fixtures
export const createHostCredentialsFixture = (overrides: Partial<HostCredentials> = {}): HostCredentials => {
  const baseCredentials: HostCredentials = {
    username: 'ubuntu',
    authMethod: 'private_key',
    privateKeyPath: '/home/user/.ssh/id_ed25519',
    password: '',
    certificate: '',
  };

  return { ...baseCredentials, ...overrides };
};

export const createSSHConfigFixture = (overrides: Partial<SSHConfig> = {}): SSHConfig => {
  const baseConfig: SSHConfig = {
    strictHostKeyChecking: true,
    userKnownHostsFile: '~/.ssh/known_hosts',
    connectTimeout: '30s',
    serverAliveInterval: '60s',
    serverAliveCountMax: 3,
    compression: false,
    preferredCiphers: ['aes128-ctr', 'aes192-ctr', 'aes256-ctr'],
    preferredKex: ['curve25519-sha256', 'ecdh-sha2-nistp256'],
    preferredMACs: ['hmac-sha2-256', 'hmac-sha2-512'],
  };

  return { ...baseConfig, ...overrides };
};

export const createHealthStatusFixture = (overrides: Partial<HealthStatus> = {}): HealthStatus => {
  const baseHealth: HealthStatus = {
    isHealthy: true,
    responseTime: '50ms',
    lastError: '',
    consecutiveFails: 0,
    uptime: '24h30m',
    cpuUsage: 25.5,
    memoryUsage: 45.2,
    diskUsage: 68.7,
  };

  return { ...baseHealth, ...overrides };
};

export const createUnhealthyStatusFixture = (overrides: Partial<HealthStatus> = {}): HealthStatus => {
  return createHealthStatusFixture({
    isHealthy: false,
    responseTime: '0ms',
    lastError: 'Connection timeout',
    consecutiveFails: 3,
    ...overrides,
  });
};

export const createHostFixture = (overrides: Partial<Host> = {}): Host => {
  const baseHost: Host = {
    id: uuidv4(),
    name: 'test-server-01',
    description: 'Test server for development',
    hostname: 'test-server-01.example.com',
    ipAddress: createIPAddressFixture(),
    port: 22,
    hostType: 'server' as HostType,
    status: 'active' as HostStatus,
    operatingSystem: 'Ubuntu 22.04 LTS',
    architecture: 'x86_64',
    tags: ['test', 'development'],
    credentials: createHostCredentialsFixture(),
    sshConfig: createSSHConfigFixture(),
    healthStatus: createHealthStatusFixture(),
    metadata: {
      environment: 'development',
      team: 'engineering',
      project: 'hermes-test',
    },
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  return { ...baseHost, ...overrides };
};

export const createProductionHostFixture = (overrides: Partial<Host> = {}): Host => {
  return createHostFixture({
    name: 'prod-web-01',
    description: 'Production web server',
    hostname: 'prod-web-01.company.com',
    ipAddress: createPublicIPFixture(),
    tags: ['production', 'web', 'critical'],
    metadata: {
      environment: 'production',
      team: 'platform',
      backup: 'daily',
    },
    ...overrides,
  });
};

export const createMaintenanceHostFixture = (overrides: Partial<Host> = {}): Host => {
  return createHostFixture({
    status: 'maintenance' as HostStatus,
    healthStatus: createUnhealthyStatusFixture({
      lastError: 'Host in maintenance mode',
    }),
    ...overrides,
  });
};

// Session Fixtures
export const createTerminalSizeFixture = (overrides: Partial<TerminalSize> = {}): TerminalSize => {
  const baseSize: TerminalSize = {
    width: 80,
    height: 24,
  };

  return { ...baseSize, ...overrides };
};

export const createConnectionInfoFixture = (overrides: Partial<ConnectionInfo> = {}): ConnectionInfo => {
  const baseInfo: ConnectionInfo = {
    remoteAddr: createIPAddressFixture(),
    localAddr: createIPAddressFixture({ value: '10.0.0.5' }),
    protocol: 'SSH-2.0',
    clientVersion: 'OpenSSH_8.9',
    serverVersion: 'OpenSSH_8.4',
    cipher: 'aes128-ctr',
    mac: 'hmac-sha2-256',
    compression: 'none',
  };

  return { ...baseInfo, ...overrides };
};

export const createCommandFixture = (overrides: Partial<Command> = {}): Command => {
  const now = new Date();
  const endTime = new Date(now.getTime() + 1000); // 1 second later

  const baseCommand: Command = {
    id: uuidv4(),
    command: 'ls',
    arguments: ['-la', '/home/ubuntu'],
    exitCode: 0,
    startTime: now.toISOString(),
    endTime: endTime.toISOString(),
    output: 'total 24\ndrwxr-xr-x 3 ubuntu ubuntu 4096 Oct 1 10:00 .',
  };

  return { ...baseCommand, ...overrides };
};

export const createFailedCommandFixture = (overrides: Partial<Command> = {}): Command => {
  return createCommandFixture({
    command: 'cat',
    arguments: ['/nonexistent/file.txt'],
    exitCode: 1,
    output: 'cat: /nonexistent/file.txt: No such file or directory',
    ...overrides,
  });
};

export const createSessionFixture = (overrides: Partial<Session> = {}): Session => {
  const baseSession: Session = {
    id: uuidv4(),
    userId: uuidv4(),
    hostId: uuidv4(),
    sessionType: 'ssh' as SessionType,
    status: 'active' as SessionStatus,
    connectionInfo: createConnectionInfoFixture(),
    recordingPath: `/recordings/${uuidv4()}.cast`,
    recordingEnabled: true,
    startTime: new Date().toISOString(),
    lastActivity: new Date().toISOString(),
    bytesSent: 1024,
    bytesReceived: 2048,
    commandsExecuted: [
      createCommandFixture(),
      createCommandFixture({ command: 'pwd', arguments: [], output: '/home/ubuntu' }),
    ],
    terminalSize: createTerminalSizeFixture(),
    environment: {
      HOME: '/home/ubuntu',
      PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
      SHELL: '/bin/bash',
      USER: 'ubuntu',
    },
    workingDirectory: '/home/ubuntu',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  return { ...baseSession, ...overrides };
};

export const createTerminatedSessionFixture = (overrides: Partial<Session> = {}): Session => {
  const endTime = new Date();
  endTime.setMinutes(endTime.getMinutes() - 30);

  return createSessionFixture({
    status: 'terminated' as SessionStatus,
    endTime: endTime.toISOString(),
    exitCode: 0,
    ...overrides,
  });
};

export const createFailedSessionFixture = (overrides: Partial<Session> = {}): Session => {
  return createSessionFixture({
    status: 'failed' as SessionStatus,
    endTime: new Date().toISOString(),
    exitCode: 1,
    ...overrides,
  });
};

// Collection Fixtures (for testing lists and pagination)
export const createUserListFixture = (count: number = 5): User[] => {
  return Array.from({ length: count }, (_, index) => 
    createUserFixture({
      email: `user${index + 1}@example.com`,
      firstName: `User${index + 1}`,
      lastName: 'Test',
    })
  );
};

export const createHostListFixture = (count: number = 3): Host[] => {
  return Array.from({ length: count }, (_, index) => 
    createHostFixture({
      name: `test-server-${String(index + 1).padStart(2, '0')}`,
      hostname: `test-server-${String(index + 1).padStart(2, '0')}.example.com`,
      ipAddress: createIPAddressFixture({
        value: `192.168.1.${100 + index}`,
      }),
    })
  );
};

export const createSessionListFixture = (count: number = 10): Session[] => {
  const statuses: SessionStatus[] = ['active', 'terminated', 'failed'];
  
  return Array.from({ length: count }, (_, index) => {
    const status = statuses[index % statuses.length];
    const baseSession = createSessionFixture({
      status,
    });

    if (status === 'terminated' || status === 'failed') {
      baseSession.endTime = new Date().toISOString();
      baseSession.exitCode = status === 'failed' ? 1 : 0;
    }

    return baseSession;
  });
};

// API Response Fixtures
export const createPaginatedResponseFixture = <T>(
  data: T[],
  page: number = 1,
  limit: number = 10
) => {
  const total = data.length;
  const totalPages = Math.ceil(total / limit);
  const startIndex = (page - 1) * limit;
  const endIndex = startIndex + limit;
  const paginatedData = data.slice(startIndex, endIndex);

  return {
    data: paginatedData,
    pagination: {
      page,
      limit,
      total,
      totalPages,
      hasNext: page < totalPages,
      hasPrevious: page > 1,
    },
  };
};

// Error Fixtures
export const createValidationErrorFixture = (field: string, message: string) => ({
  field,
  message,
});

export const createDomainErrorFixture = (code: string, message: string, field?: string) => ({
  code,
  message,
  field,
});

// Authentication Fixtures
export const createAuthTokenFixture = () => ({
  accessToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  refreshToken: 'refresh_token_example',
  tokenType: 'Bearer',
  expiresIn: 900, // 15 minutes
  refreshExpiresIn: 604800, // 7 days
});

export const createUserSessionFixture = () => ({
  sessionId: uuidv4(),
  userId: uuidv4(),
  deviceInfo: {
    browser: 'Chrome',
    os: 'macOS',
    device: 'Desktop',
  },
  ipAddress: '192.168.1.50',
  userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...',
  createdAt: new Date().toISOString(),
  lastActivity: new Date().toISOString(),
  expiresAt: new Date(Date.now() + 86400000).toISOString(), // 24 hours
});

// Test Utilities
export const createTestDatabase = async () => {
  // This would be used to set up a test database with fixtures
  // Implementation would depend on the testing framework and database setup
};

export const cleanupTestDatabase = async () => {
  // Clean up test data after tests
};

export const createTestUser = async (overrides: Partial<User> = {}) => {
  // Helper to create a user in the test database
  // Would integrate with the actual user creation logic
  return createUserFixture(overrides);
};

// Random Data Generators (for property-based testing)
export const generateRandomEmail = () => {
  const domains = ['example.com', 'test.org', 'demo.net'];
  const username = Math.random().toString(36).substring(2, 8);
  const domain = domains[Math.floor(Math.random() * domains.length)];
  return `${username}@${domain}`;
};

export const generateRandomIPv4 = () => {
  const octets = Array.from({ length: 4 }, () => 
    Math.floor(Math.random() * 256)
  );
  return octets.join('.');
};

export const generateRandomPort = () => {
  return Math.floor(Math.random() * 65535) + 1;
};

export const generateRandomString = (length: number = 10) => {
  return Math.random().toString(36).substring(2, length + 2);
};

// Export all fixtures as a collection for easy importing
export const fixtures = {
  user: {
    create: createUserFixture,
    admin: createAdminUserFixture,
    locked: createLockedUserFixture,
    pending: createPendingUserFixture,
    list: createUserListFixture,
  },
  host: {
    create: createHostFixture,
    production: createProductionHostFixture,
    maintenance: createMaintenanceHostFixture,
    list: createHostListFixture,
  },
  session: {
    create: createSessionFixture,
    terminated: createTerminatedSessionFixture,
    failed: createFailedSessionFixture,
    list: createSessionListFixture,
  },
  ssh: {
    key: createSSHKeyFixture,
    rsaKey: createRSAKeyFixture,
    config: createSSHConfigFixture,
  },
  network: {
    ip: createIPAddressFixture,
    publicIP: createPublicIPFixture,
    ipv6: createIPv6AddressFixture,
  },
  auth: {
    token: createAuthTokenFixture,
    session: createUserSessionFixture,
  },
  api: {
    paginated: createPaginatedResponseFixture,
    validationError: createValidationErrorFixture,
    domainError: createDomainErrorFixture,
  },
};