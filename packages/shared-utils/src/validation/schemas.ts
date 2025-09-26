// packages/shared-utils/src/validation/schemas.ts
// Zod validation schemas for type-safe validation across frontend and backend
// Based on domain types and business rules from entities

import { z } from 'zod';

// Common validation schemas
export const uuidSchema = z.string().uuid('Invalid UUID format');

export const emailSchema = z
  .string()
  .min(1, 'Email is required')
  .email('Invalid email format')
  .max(255, 'Email must be less than 255 characters')
  .toLowerCase()
  .trim();

export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters')
  .max(128, 'Password must be less than 128 characters')
  .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
  .regex(/[a-z]/, 'Password must contain at least one lowercase letter')
  .regex(/[0-9]/, 'Password must contain at least one number')
  .regex(/[^A-Za-z0-9]/, 'Password must contain at least one special character');

export const nameSchema = z
  .string()
  .min(1, 'Name is required')
  .max(100, 'Name must be less than 100 characters')
  .trim()
  .regex(/^[a-zA-Z\s-'\.]+$/, 'Name contains invalid characters');

export const hostnameSchema = z
  .string()
  .min(1, 'Hostname is required')
  .max(253, 'Hostname must be less than 253 characters')
  .regex(
    /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/,
    'Invalid hostname format'
  );

export const ipv4Schema = z
  .string()
  .regex(
    /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$/,
    'Invalid IPv4 address format'
  );

export const ipv6Schema = z
  .string()
  .regex(
    /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
    'Invalid IPv6 address format'
  );

export const ipAddressSchema = z.union([ipv4Schema, ipv6Schema], {
  errorMap: () => ({ message: 'Invalid IP address format' }),
});

export const portSchema = z
  .number()
  .int('Port must be an integer')
  .min(1, 'Port must be at least 1')
  .max(65535, 'Port must be at most 65535');

// Enum schemas
export const userStatusSchema = z.enum(['active', 'inactive', 'suspended', 'pending'], {
  errorMap: () => ({ message: 'Invalid user status' }),
});

export const userRoleSchema = z.enum(['user', 'admin', 'operator', 'auditor'], {
  errorMap: () => ({ message: 'Invalid user role' }),
});

export const hostStatusSchema = z.enum(['active', 'inactive', 'maintenance', 'unreachable'], {
  errorMap: () => ({ message: 'Invalid host status' }),
});

export const hostTypeSchema = z.enum(
  ['server', 'workstation', 'router', 'switch', 'firewall', 'container', 'virtual'],
  {
    errorMap: () => ({ message: 'Invalid host type' }),
  }
);

export const sessionStatusSchema = z.enum(['pending', 'active', 'terminated', 'failed', 'timeout'], {
  errorMap: () => ({ message: 'Invalid session status' }),
});

export const sessionTypeSchema = z.enum(['ssh', 'sftp', 'shell'], {
  errorMap: () => ({ message: 'Invalid session type' }),
});

export const authMethodSchema = z.enum(['password', 'private_key', 'certificate', 'agent'], {
  errorMap: () => ({ message: 'Invalid authentication method' }),
});

export const sshKeyTypeSchema = z.enum(['ssh-rsa', 'ssh-ed25519', 'ecdsa-sha2-nistp256', 'ssh-dss'], {
  errorMap: () => ({ message: 'Invalid SSH key type' }),
});

// SSH Key validation
export const sshKeySchema = z.object({
  keyType: sshKeyTypeSchema,
  keyData: z
    .string()
    .min(1, 'SSH key data is required')
    .regex(/^[A-Za-z0-9+/=]+$/, 'Invalid SSH key data format'),
  comment: z.string().max(255, 'Comment must be less than 255 characters').optional().default(''),
  fingerprint: z
    .string()
    .regex(/^(MD5:|SHA256:)?[A-Fa-f0-9:]+$/, 'Invalid fingerprint format'),
  bitLength: z.number().int().positive('Bit length must be positive'),
  algorithm: z.string().min(1, 'Algorithm is required'),
  createdAt: z.string().datetime(),
});

export const createSSHKeyRequestSchema = z.object({
  keyString: z
    .string()
    .min(1, 'SSH key string is required')
    .regex(/^ssh-\w+\s+[A-Za-z0-9+/=]+(\s+.+)?$/, 'Invalid SSH key format'),
});

// IP Address validation
export const ipAddressObjectSchema = z.object({
  value: ipAddressSchema,
  type: z.enum(['ipv4', 'ipv6']),
  isPrivate: z.boolean(),
  isLoopback: z.boolean(),
  isMulticast: z.boolean(),
});

// User validation schemas
export const userSchema = z.object({
  id: uuidSchema,
  email: emailSchema,
  firstName: nameSchema,
  lastName: nameSchema,
  status: userStatusSchema,
  roles: z.array(userRoleSchema).min(1, 'User must have at least one role'),
  permissions: z.array(z.string()),
  sshKeys: z.array(sshKeySchema).default([]),
  failedLoginCount: z.number().int().min(0).default(0),
  lastLoginAt: z.string().datetime().optional(),
  lockedUntil: z.string().datetime().optional(),
  emailVerifiedAt: z.string().datetime().optional(),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export const createUserRequestSchema = z
  .object({
    email: emailSchema,
    password: passwordSchema,
    confirmPassword: z.string(),
    firstName: nameSchema,
    lastName: nameSchema,
    roles: z.array(userRoleSchema).optional().default(['user']),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  });

export const updateUserRequestSchema = z.object({
  firstName: nameSchema.optional(),
  lastName: nameSchema.optional(),
  status: userStatusSchema.optional(),
  roles: z.array(userRoleSchema).min(1).optional(),
  permissions: z.array(z.string()).optional(),
});

export const changePasswordRequestSchema = z
  .object({
    oldPassword: z.string().min(1, 'Current password is required'),
    newPassword: passwordSchema,
    confirmPassword: z.string(),
  })
  .refine((data) => data.newPassword === data.confirmPassword, {
    message: "New passwords don't match",
    path: ['confirmPassword'],
  })
  .refine((data) => data.oldPassword !== data.newPassword, {
    message: 'New password must be different from current password',
    path: ['newPassword'],
  });

// Host validation schemas
export const hostCredentialsSchema = z.object({
  username: z
    .string()
    .min(1, 'Username is required')
    .max(32, 'Username must be less than 32 characters')
    .regex(/^[a-z_][a-z0-9_-]*$/i, 'Invalid username format'),
  authMethod: authMethodSchema,
  privateKeyPath: z.string().max(500).optional().default(''),
  password: z.string().optional().default(''), // Should be encrypted
  certificate: z.string().optional().default(''),
});

export const sshConfigSchema = z.object({
  strictHostKeyChecking: z.boolean().default(true),
  userKnownHostsFile: z.string().max(500).default('~/.ssh/known_hosts'),
  connectTimeout: z.string().regex(/^\d+[smh]$/, 'Invalid timeout format').default('30s'),
  serverAliveInterval: z.string().regex(/^\d+[smh]$/, 'Invalid interval format').default('60s'),
  serverAliveCountMax: z.number().int().min(1).max(10).default(3),
  compression: z.boolean().default(false),
  preferredCiphers: z.array(z.string()).default(['aes128-ctr', 'aes192-ctr', 'aes256-ctr']),
  preferredKex: z.array(z.string()).default(['curve25519-sha256', 'ecdh-sha2-nistp256']),
  preferredMACs: z.array(z.string()).default(['hmac-sha2-256', 'hmac-sha2-512']),
});

export const healthStatusSchema = z.object({
  isHealthy: z.boolean(),
  responseTime: z.string().regex(/^\d+(\.\d+)?(ms|s)$/, 'Invalid response time format'),
  lastError: z.string().default(''),
  consecutiveFails: z.number().int().min(0).default(0),
  uptime: z.string().regex(/^\d+[smhd]?(\d+[smhd]?)*$/, 'Invalid uptime format'),
  cpuUsage: z.number().min(0).max(100),
  memoryUsage: z.number().min(0).max(100),
  diskUsage: z.number().min(0).max(100),
});

export const hostSchema = z.object({
  id: uuidSchema,
  name: z
    .string()
    .min(1, 'Host name is required')
    .max(255, 'Host name must be less than 255 characters')
    .regex(/^[a-zA-Z0-9]([a-zA-Z0-9-_\s]{0,253}[a-zA-Z0-9])?$/, 'Invalid host name format')
    .trim(),
  description: z.string().max(1000, 'Description must be less than 1000 characters').default(''),
  hostname: hostnameSchema,
  ipAddress: ipAddressObjectSchema,
  port: portSchema.default(22),
  hostType: hostTypeSchema.default('server'),
  status: hostStatusSchema.default('active'),
  operatingSystem: z.string().max(100).default(''),
  architecture: z.string().max(50).default(''),
  tags: z.array(z.string().max(50)).default([]),
  credentials: hostCredentialsSchema,
  sshConfig: sshConfigSchema,
  lastSeen: z.string().datetime().optional(),
  lastHealthCheck: z.string().datetime().optional(),
  healthStatus: healthStatusSchema,
  metadata: z.record(z.string().max(1000)).default({}),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export const createHostRequestSchema = z.object({
  name: z
    .string()
    .min(1, 'Host name is required')
    .max(255, 'Host name must be less than 255 characters')
    .trim(),
  description: z.string().max(1000).optional().default(''),
  hostname: hostnameSchema,
  ipAddress: ipAddressSchema,
  port: portSchema.optional().default(22),
  hostType: hostTypeSchema.optional().default('server'),
  tags: z.array(z.string().max(50)).optional().default([]),
  credentials: hostCredentialsSchema,
  sshConfig: sshConfigSchema.optional().default({}),
});

export const updateHostRequestSchema = z.object({
  name: z.string().min(1).max(255).trim().optional(),
  description: z.string().max(1000).optional(),
  hostname: hostnameSchema.optional(),
  ipAddress: ipAddressSchema.optional(),
  port: portSchema.optional(),
  hostType: hostTypeSchema.optional(),
  status: hostStatusSchema.optional(),
  operatingSystem: z.string().max(100).optional(),
  architecture: z.string().max(50).optional(),
  tags: z.array(z.string().max(50)).optional(),
  credentials: hostCredentialsSchema.optional(),
  sshConfig: sshConfigSchema.optional(),
  metadata: z.record(z.string().max(1000)).optional(),
});

// Session validation schemas
export const terminalSizeSchema = z.object({
  width: z.number().int().min(10).max(500, 'Terminal width too large'),
  height: z.number().int().min(5).max(200, 'Terminal height too large'),
});

export const connectionInfoSchema = z.object({
  remoteAddr: ipAddressObjectSchema,
  localAddr: ipAddressObjectSchema,
  protocol: z.string().default('SSH-2.0'),
  clientVersion: z.string().default(''),
  serverVersion: z.string().default(''),
  cipher: z.string().default(''),
  mac: z.string().default(''),
  compression: z.string().default('none'),
});

export const commandSchema = z.object({
  id: uuidSchema,
  command: z.string().min(1, 'Command is required').max(1000),
  arguments: z.array(z.string().max(500)).default([]),
  exitCode: z.number().int().min(0).max(255),
  startTime: z.string().datetime(),
  endTime: z.string().datetime(),
  output: z.string().max(4096, 'Command output too large'), // Truncated for storage
});

export const sessionSchema = z.object({
  id: uuidSchema,
  userId: uuidSchema,
  hostId: uuidSchema,
  sessionType: sessionTypeSchema.default('ssh'),
  status: sessionStatusSchema.default('pending'),
  connectionInfo: connectionInfoSchema,
  recordingPath: z.string().max(1000).default(''),
  recordingEnabled: z.boolean().default(true),
  startTime: z.string().datetime(),
  endTime: z.string().datetime().optional(),
  lastActivity: z.string().datetime(),
  bytesSent: z.number().int().min(0).default(0),
  bytesReceived: z.number().int().min(0).default(0),
  commandsExecuted: z.array(commandSchema).default([]),
  exitCode: z.number().int().min(0).max(255).optional(),
  terminalSize: terminalSizeSchema.default({ width: 80, height: 24 }),
  environment: z.record(z.string().max(1000)).default({}),
  workingDirectory: z.string().max(1000).default('/'),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
});

export const createSessionRequestSchema = z.object({
  hostId: uuidSchema,
  sessionType: sessionTypeSchema.optional().default('ssh'),
  recordingEnabled: z.boolean().optional().default(true),
  terminalSize: terminalSizeSchema.optional().default({ width: 80, height: 24 }),
});

export const updateSessionRequestSchema = z.object({
  terminalSize: terminalSizeSchema.optional(),
  environment: z.record(z.string().max(1000)).optional(),
  workingDirectory: z.string().max(1000).optional(),
});

// Authentication schemas
export const loginRequestSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
  rememberMe: z.boolean().optional().default(false),
  deviceInfo: z
    .object({
      browser: z.string().optional(),
      os: z.string().optional(),
      device: z.string().optional(),
    })
    .optional(),
});

export const registerRequestSchema = createUserRequestSchema;

export const refreshTokenRequestSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

export const resetPasswordRequestSchema = z.object({
  email: emailSchema,
});

export const confirmResetPasswordSchema = z
  .object({
    token: z.string().min(1, 'Reset token is required'),
    password: passwordSchema,
    confirmPassword: z.string(),
  })
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords don't match",
    path: ['confirmPassword'],
  });

// Pagination and filtering schemas
export const paginationSchema = z.object({
  page: z.number().int().min(1, 'Page must be at least 1').default(1),
  limit: z.number().int().min(1, 'Limit must be at least 1').max(100, 'Limit cannot exceed 100').default(10),
  sortBy: z.string().optional(),
  sortOrder: z.enum(['asc', 'desc']).optional().default('asc'),
});

export const searchParamsSchema = z.object({
  query: z.string().min(1, 'Search query is required').max(255),
  fields: z.array(z.string()).optional(),
  exact: z.boolean().optional().default(false),
});

export const dateRangeSchema = z
  .object({
    from: z.string().datetime().optional(),
    to: z.string().datetime().optional(),
  })
  .refine((data) => {
    if (data.from && data.to) {
      return new Date(data.from) <= new Date(data.to);
    }
    return true;
  }, {
    message: 'From date must be before to date',
    path: ['from'],
  });

// Filter schemas
export const userFilterSchema = z.object({
  status: z.array(userStatusSchema).optional(),
  roles: z.array(userRoleSchema).optional(),
  emailDomain: z.string().optional(),
  createdAfter: z.string().datetime().optional(),
  createdBefore: z.string().datetime().optional(),
  lastLoginAfter: z.string().datetime().optional(),
  lastLoginBefore: z.string().datetime().optional(),
});

export const hostFilterSchema = z.object({
  status: z.array(hostStatusSchema).optional(),
  hostType: z.array(hostTypeSchema).optional(),
  tags: z.array(z.string()).optional(),
  isHealthy: z.boolean().optional(),
  createdAfter: z.string().datetime().optional(),
  createdBefore: z.string().datetime().optional(),
  lastSeenAfter: z.string().datetime().optional(),
  lastSeenBefore: z.string().datetime().optional(),
});

export const sessionFilterSchema = z.object({
  userId: uuidSchema.optional(),
  hostId: uuidSchema.optional(),
  status: z.array(sessionStatusSchema).optional(),
  sessionType: z.array(sessionTypeSchema).optional(),
  startTimeAfter: z.string().datetime().optional(),
  startTimeBefore: z.string().datetime().optional(),
  endTimeAfter: z.string().datetime().optional(),
  endTimeBefore: z.string().datetime().optional(),
  hasRecording: z.boolean().optional(),
});

// API Response schemas
export const apiErrorSchema = z.object({
  error: z.string(),
  message: z.string(),
  code: z.number().optional(),
  details: z.any().optional(),
});

export const validationErrorSchema = z.object({
  field: z.string(),
  message: z.string(),
});

export const paginatedResponseSchema = <T extends z.ZodTypeAny>(itemSchema: T) =>
  z.object({
    data: z.array(itemSchema),
    pagination: z.object({
      page: z.number().int().positive(),
      limit: z.number().int().positive(),
      total: z.number().int().min(0),
      totalPages: z.number().int().min(0),
      hasNext: z.boolean(),
      hasPrevious: z.boolean(),
    }),
  });

export const searchResponseSchema = <T extends z.ZodTypeAny>(itemSchema: T) =>
  z.object({
    items: z.array(itemSchema),
    total: z.number().int().min(0),
    query: z.string(),
    searchTime: z.number().positive(),
  });

// Utility functions for validation
export const validateSchema = <T>(schema: z.ZodSchema<T>, data: unknown): { success: true; data: T } | { success: false; errors: z.ZodIssue[] } => {
  const result = schema.safeParse(data);
  if (result.success) {
    return { success: true, data: result.data };
  }
  return { success: false, errors: result.error.issues };
};

export const createValidator = <T>(schema: z.ZodSchema<T>) => {
  return (data: unknown) => validateSchema(schema, data);
};

// Pre-built validators
export const validators = {
  user: {
    create: createValidator(createUserRequestSchema),
    update: createValidator(updateUserRequestSchema),
    changePassword: createValidator(changePasswordRequestSchema),
  },
  host: {
    create: createValidator(createHostRequestSchema),
    update: createValidator(updateHostRequestSchema),
  },
  session: {
    create: createValidator(createSessionRequestSchema),
    update: createValidator(updateSessionRequestSchema),
  },
  auth: {
    login: createValidator(loginRequestSchema),
    register: createValidator(registerRequestSchema),
    refreshToken: createValidator(refreshTokenRequestSchema),
    resetPassword: createValidator(resetPasswordRequestSchema),
    confirmResetPassword: createValidator(confirmResetPasswordSchema),
  },
  common: {
    pagination: createValidator(paginationSchema),
    search: createValidator(searchParamsSchema),
    dateRange: createValidator(dateRangeSchema),
    uuid: createValidator(uuidSchema),
    email: createValidator(emailSchema),
    password: createValidator(passwordSchema),
    ipAddress: createValidator(ipAddressSchema),
    hostname: createValidator(hostnameSchema),
  },
  filters: {
    user: createValidator(userFilterSchema),
    host: createValidator(hostFilterSchema),
    session: createValidator(sessionFilterSchema),
  },
};

// Export commonly used schemas
export {
  // Basic types
  uuidSchema,
  emailSchema,
  passwordSchema,
  nameSchema,
  hostnameSchema,
  ipAddressSchema,
  portSchema,
  
  // Entity schemas
  userSchema,
  hostSchema,
  sessionSchema,
  sshKeySchema,
  
  // Request schemas
  createUserRequestSchema,
  updateUserRequestSchema,
  createHostRequestSchema,
  updateHostRequestSchema,
  createSessionRequestSchema,
  updateSessionRequestSchema,
  
  // Auth schemas
  loginRequestSchema,
  registerRequestSchema,
  changePasswordRequestSchema,
  
  // Utility schemas
  paginationSchema,
  searchParamsSchema,
  dateRangeSchema,
  
  // Response schemas
  paginatedResponseSchema,
  searchResponseSchema,
  apiErrorSchema,
  validationErrorSchema,
};