-- packages/database/schemas/auth.sql
-- Authentication and authorization specific tables
-- Complements the main schema with OAuth, JWT, and RBAC functionality

-- OAuth providers and integrations
CREATE TABLE oauth_providers (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) NOT NULL UNIQUE, -- 'google', 'github', 'okta'
    display_name VARCHAR(100) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    client_secret_encrypted TEXT NOT NULL, -- Encrypted with app key
    redirect_url VARCHAR(500) NOT NULL,
    authorization_url VARCHAR(500) NOT NULL,
    token_url VARCHAR(500) NOT NULL,
    user_info_url VARCHAR(500) NOT NULL,
    scopes TEXT[] DEFAULT ARRAY['openid', 'profile', 'email'],
    enabled BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- OAuth user connections (links users to external providers)
CREATE TABLE oauth_connections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id UUID NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    provider_user_id VARCHAR(255) NOT NULL, -- External user ID
    provider_email VARCHAR(255),
    provider_name VARCHAR(255),
    provider_avatar_url VARCHAR(500),
    access_token_encrypted TEXT, -- Encrypted with app key
    refresh_token_encrypted TEXT, -- Encrypted with app key
    token_expires_at TIMESTAMPTZ,
    scopes TEXT[],
    raw_user_data JSONB, -- Store additional provider data
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(provider_id, provider_user_id)
);

-- JWT refresh tokens (for secure token management)
CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE, -- SHA-256 hash of token
    device_info JSONB, -- Browser, OS, IP, etc.
    ip_address INET,
    user_agent TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(255),
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User login sessions (separate from SSH sessions)
CREATE TABLE login_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_id UUID REFERENCES refresh_tokens(id) ON DELETE CASCADE,
    session_token_hash VARCHAR(255) NOT NULL UNIQUE,
    ip_address INET NOT NULL,
    user_agent TEXT,
    device_fingerprint VARCHAR(255),
    login_method VARCHAR(50) NOT NULL, -- 'password', 'oauth', '2fa'
    oauth_provider VARCHAR(50), -- Provider name if OAuth login
    is_active BOOLEAN NOT NULL DEFAULT true,
    expires_at TIMESTAMPTZ NOT NULL,
    last_activity_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Role definitions (RBAC system)
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(50) NOT NULL UNIQUE,
    display_name VARCHAR(100) NOT NULL,
    description TEXT,
    is_system_role BOOLEAN NOT NULL DEFAULT false, -- Built-in roles
    permissions TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Permission definitions
CREATE TABLE permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL UNIQUE, -- e.g., 'sessions.create', 'hosts.read'
    resource VARCHAR(50) NOT NULL, -- e.g., 'sessions', 'hosts', 'users'
    action VARCHAR(50) NOT NULL, -- e.g., 'create', 'read', 'update', 'delete'
    scope VARCHAR(50), -- e.g., 'own', 'team', 'all'
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- User role assignments
CREATE TABLE user_roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    assigned_by UUID REFERENCES users(id) ON DELETE SET NULL,
    assigned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ, -- Optional role expiration
    UNIQUE(user_id, role_id)
);

-- Direct user permission grants (for fine-grained control)
CREATE TABLE user_permissions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission_id UUID NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ, -- Optional permission expiration
    UNIQUE(user_id, permission_id)
);

-- API tokens for programmatic access
CREATE TABLE api_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(100) NOT NULL, -- User-defined name
    token_hash VARCHAR(255) NOT NULL UNIQUE, -- SHA-256 hash
    prefix VARCHAR(10) NOT NULL, -- First few chars for identification
    permissions TEXT[] DEFAULT ARRAY[]::TEXT[], -- Specific permissions for this token
    ip_whitelist INET[], -- Optional IP restrictions
    rate_limit INTEGER DEFAULT 1000, -- Requests per hour
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    revoked BOOLEAN NOT NULL DEFAULT false,
    revoked_at TIMESTAMPTZ,
    revoked_reason VARCHAR(255),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Two-factor authentication
CREATE TABLE user_2fa (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    method VARCHAR(20) NOT NULL, -- 'totp', 'sms', 'email'
    enabled BOOLEAN NOT NULL DEFAULT false,
    secret_encrypted TEXT, -- Encrypted TOTP secret or phone/email
    backup_codes_encrypted TEXT[], -- Encrypted backup codes
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(user_id, method)
);

-- Password reset tokens
CREATE TABLE password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL, -- Email where reset was sent
    ip_address INET NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Email verification tokens
CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL, -- Email to verify
    ip_address INET,
    expires_at TIMESTAMPTZ NOT NULL,
    used BOOLEAN NOT NULL DEFAULT false,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Login attempts tracking (security)
CREATE TABLE login_attempts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255), -- Attempted email (even if user doesn't exist)
    ip_address INET NOT NULL,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    failure_reason VARCHAR(100), -- 'invalid_credentials', 'account_locked', etc.
    user_id UUID REFERENCES users(id) ON DELETE SET NULL, -- If login succeeded
    oauth_provider VARCHAR(50), -- If OAuth attempt
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Security events (complement to audit_events)
CREATE TABLE security_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    event_type VARCHAR(50) NOT NULL, -- 'suspicious_login', 'brute_force', etc.
    severity audit_severity NOT NULL,
    source_ip INET,
    user_agent TEXT,
    details JSONB NOT NULL DEFAULT '{}',
    resolved BOOLEAN NOT NULL DEFAULT false,
    resolved_at TIMESTAMPTZ,
    resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for authentication tables

-- OAuth indexes
CREATE INDEX idx_oauth_providers_name ON oauth_providers(name);
CREATE INDEX idx_oauth_providers_enabled ON oauth_providers(enabled);
CREATE INDEX idx_oauth_connections_user_id ON oauth_connections(user_id);
CREATE INDEX idx_oauth_connections_provider_id ON oauth_connections(provider_id);
CREATE INDEX idx_oauth_connections_provider_user_id ON oauth_connections(provider_id, provider_user_id);

-- Token indexes
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
CREATE INDEX idx_refresh_tokens_revoked ON refresh_tokens(revoked);

-- Session indexes
CREATE INDEX idx_login_sessions_user_id ON login_sessions(user_id);
CREATE INDEX idx_login_sessions_token_hash ON login_sessions(session_token_hash);
CREATE INDEX idx_login_sessions_is_active ON login_sessions(is_active);
CREATE INDEX idx_login_sessions_expires_at ON login_sessions(expires_at);
CREATE INDEX idx_login_sessions_ip_address ON login_sessions(ip_address);

-- RBAC indexes
CREATE INDEX idx_roles_name ON roles(name);
CREATE INDEX idx_roles_is_system_role ON roles(is_system_role);
CREATE INDEX idx_permissions_name ON permissions(name);
CREATE INDEX idx_permissions_resource ON permissions(resource);
CREATE INDEX idx_permissions_resource_action ON permissions(resource, action);
CREATE INDEX idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX idx_user_roles_role_id ON user_roles(role_id);
CREATE INDEX idx_user_roles_expires_at ON user_roles(expires_at);
CREATE INDEX idx_user_permissions_user_id ON user_permissions(user_id);
CREATE INDEX idx_user_permissions_permission_id ON user_permissions(permission_id);

-- API token indexes
CREATE INDEX idx_api_tokens_user_id ON api_tokens(user_id);
CREATE INDEX idx_api_tokens_token_hash ON api_tokens(token_hash);
CREATE INDEX idx_api_tokens_prefix ON api_tokens(prefix);
CREATE INDEX idx_api_tokens_revoked ON api_tokens(revoked);
CREATE INDEX idx_api_tokens_expires_at ON api_tokens(expires_at);

-- 2FA indexes
CREATE INDEX idx_user_2fa_user_id ON user_2fa(user_id);
CREATE INDEX idx_user_2fa_method ON user_2fa(method);
CREATE INDEX idx_user_2fa_enabled ON user_2fa(enabled);

-- Reset token indexes
CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
CREATE INDEX idx_email_verification_tokens_token_hash ON email_verification_tokens(token_hash);
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);

-- Security indexes
CREATE INDEX idx_login_attempts_email ON login_attempts(email);
CREATE INDEX idx_login_attempts_ip_address ON login_attempts(ip_address);
CREATE INDEX idx_login_attempts_timestamp ON login_attempts(timestamp);
CREATE INDEX idx_login_attempts_success ON login_attempts(success);
CREATE INDEX idx_security_events_user_id ON security_events(user_id);
CREATE INDEX idx_security_events_event_type ON security_events(event_type);
CREATE INDEX idx_security_events_severity ON security_events(severity);
CREATE INDEX idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX idx_security_events_resolved ON security_events(resolved);

-- Triggers for updated_at columns
CREATE TRIGGER update_oauth_providers_updated_at BEFORE UPDATE ON oauth_providers FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_oauth_connections_updated_at BEFORE UPDATE ON oauth_connections FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_roles_updated_at BEFORE UPDATE ON roles FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_user_2fa_updated_at BEFORE UPDATE ON user_2fa FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Insert default roles and permissions

-- Default roles
INSERT INTO roles (name, display_name, description, is_system_role, permissions) VALUES
('admin', 'Administrator', 'Full system access with all permissions', true, ARRAY[
    'users.*', 'hosts.*', 'sessions.*', 'audit.*', 'system.*', 'roles.*'
]),
('operator', 'Operator', 'Can manage hosts and sessions but not users', true, ARRAY[
    'hosts.*', 'sessions.*', 'audit.read'
]),
('auditor', 'Auditor', 'Read-only access for compliance and security review', true, ARRAY[
    'users.read', 'hosts.read', 'sessions.read', 'audit.*'
]),
('user', 'User', 'Basic user with session access to assigned hosts', true, ARRAY[
    'sessions.create', 'sessions.read.own', 'hosts.read.assigned'
]);

-- Default permissions
INSERT INTO permissions (name, resource, action, scope, description) VALUES
-- User permissions
('users.create', 'users', 'create', 'all', 'Create new users'),
('users.read', 'users', 'read', 'all', 'Read all user information'),
('users.read.own', 'users', 'read', 'own', 'Read own user information'),
('users.update', 'users', 'update', 'all', 'Update user information'),
('users.update.own', 'users', 'update', 'own', 'Update own user information'),
('users.delete', 'users', 'delete', 'all', 'Delete users'),
('users.manage_roles', 'users', 'manage_roles', 'all', 'Assign/revoke user roles'),

-- Host permissions
('hosts.create', 'hosts', 'create', 'all', 'Add new hosts'),
('hosts.read', 'hosts', 'read', 'all', 'View all hosts'),
('hosts.read.assigned', 'hosts', 'read', 'assigned', 'View assigned hosts only'),
('hosts.update', 'hosts', 'update', 'all', 'Modify host configuration'),
('hosts.delete', 'hosts', 'delete', 'all', 'Remove hosts'),
('hosts.manage_credentials', 'hosts', 'manage_credentials', 'all', 'Manage host authentication'),

-- Session permissions
('sessions.create', 'sessions', 'create', 'all', 'Start new sessions'),
('sessions.read', 'sessions', 'read', 'all', 'View all session information'),
('sessions.read.own', 'sessions', 'read', 'own', 'View own sessions only'),
('sessions.terminate', 'sessions', 'terminate', 'all', 'Terminate active sessions'),
('sessions.terminate.own', 'sessions', 'terminate', 'own', 'Terminate own sessions'),
('sessions.recording.access', 'sessions', 'recording', 'all', 'Access session recordings'),

-- Audit permissions
('audit.read', 'audit', 'read', 'all', 'Read audit logs'),
('audit.export', 'audit', 'export', 'all', 'Export audit data'),
('audit.delete', 'audit', 'delete', 'all', 'Delete audit records'),

-- System permissions
('system.settings', 'system', 'settings', 'all', 'Manage system settings'),
('system.monitoring', 'system', 'monitoring', 'all', 'Access monitoring data'),

-- Role management permissions
('roles.create', 'roles', 'create', 'all', 'Create new roles'),
('roles.read', 'roles', 'read', 'all', 'View roles and permissions'),
('roles.update', 'roles', 'update', 'all', 'Modify roles and permissions'),
('roles.delete', 'roles', 'delete', 'all', 'Delete custom roles');

-- Views for authentication and authorization

-- User permissions view (combines roles and direct permissions)
CREATE VIEW user_effective_permissions AS
WITH role_permissions AS (
    SELECT ur.user_id, unnest(r.permissions) as permission
    FROM user_roles ur
    JOIN roles r ON ur.role_id = r.id
    WHERE (ur.expires_at IS NULL OR ur.expires_at > NOW())
),
direct_permissions AS (
    SELECT up.user_id, p.name as permission
    FROM user_permissions up
    JOIN permissions p ON up.permission_id = p.id
    WHERE (up.expires_at IS NULL OR up.expires_at > NOW())
)
SELECT user_id, permission
FROM role_permissions
UNION
SELECT user_id, permission
FROM direct_permissions;

-- Active login sessions view
CREATE VIEW active_login_sessions AS
SELECT 
    ls.*,
    u.email,
    u.first_name || ' ' || u.last_name as user_name,
    EXTRACT(EPOCH FROM (NOW() - ls.last_activity_at)) as inactive_seconds
FROM login_sessions ls
JOIN users u ON ls.user_id = u.id
WHERE ls.is_active = true 
AND ls.expires_at > NOW();

-- Security dashboard view
CREATE VIEW security_dashboard AS
SELECT 
    'failed_logins_24h' as metric,
    COUNT(*) as value
FROM login_attempts 
WHERE success = false 
AND timestamp > NOW() - INTERVAL '24 hours'
UNION ALL
SELECT 
    'active_sessions' as metric,
    COUNT(*) as value
FROM login_sessions 
WHERE is_active = true 
AND expires_at > NOW()
UNION ALL
SELECT 
    'unresolved_security_events' as metric,
    COUNT(*) as value
FROM security_events 
WHERE resolved = false
UNION ALL
SELECT 
    'users_locked' as metric,
    COUNT(*) as value
FROM users 
WHERE locked_until > NOW();

-- Functions for authentication

-- Function to clean up expired tokens and sessions
CREATE OR REPLACE FUNCTION cleanup_auth_tokens()
RETURNS TABLE(
    expired_refresh_tokens INTEGER,
    expired_login_sessions INTEGER,
    expired_reset_tokens INTEGER,
    expired_verification_tokens INTEGER
) AS $$
DECLARE
    refresh_count INTEGER;
    session_count INTEGER;
    reset_count INTEGER;
    verify_count INTEGER;
BEGIN
    -- Clean up expired refresh tokens
    DELETE FROM refresh_tokens WHERE expires_at < NOW();
    GET DIAGNOSTICS refresh_count = ROW_COUNT;
    
    -- Clean up expired login sessions
    UPDATE login_sessions SET is_active = false WHERE expires_at < NOW();
    GET DIAGNOSTICS session_count = ROW_COUNT;
    
    -- Clean up expired password reset tokens
    DELETE FROM password_reset_tokens WHERE expires_at < NOW();
    GET DIAGNOSTICS reset_count = ROW_COUNT;
    
    -- Clean up expired email verification tokens
    DELETE FROM email_verification_tokens WHERE expires_at < NOW();
    GET DIAGNOSTICS verify_count = ROW_COUNT;
    
    RETURN QUERY SELECT refresh_count, session_count, reset_count, verify_count;
END;
$$ LANGUAGE plpgsql;

-- Function to check user permissions
CREATE OR REPLACE FUNCTION user_has_permission(check_user_id UUID, permission_name TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM user_effective_permissions 
        WHERE user_id = check_user_id 
        AND (permission = permission_name OR permission LIKE SPLIT_PART(permission_name, '.', 1) || '.*')
    );
END;
$$ LANGUAGE plpgsql;

-- Comments
COMMENT ON TABLE oauth_providers IS 'OAuth2/OIDC provider configurations';
COMMENT ON TABLE oauth_connections IS 'User connections to external OAuth providers';
COMMENT ON TABLE refresh_tokens IS 'JWT refresh tokens for secure session management';
COMMENT ON TABLE login_sessions IS 'Web/API login sessions (separate from SSH sessions)';
COMMENT ON TABLE roles IS 'Role definitions for RBAC system';
COMMENT ON TABLE permissions IS 'Permission definitions for fine-grained access control';
COMMENT ON TABLE user_roles IS 'User-to-role assignments';
COMMENT ON TABLE user_permissions IS 'Direct permission grants to users';
COMMENT ON TABLE api_tokens IS 'API tokens for programmatic access';
COMMENT ON TABLE user_2fa IS 'Two-factor authentication settings per user';
COMMENT ON TABLE password_reset_tokens IS 'Secure password reset tokens';
COMMENT ON TABLE email_verification_tokens IS 'Email address verification tokens';
COMMENT ON TABLE login_attempts IS 'Login attempt tracking for security monitoring';
COMMENT ON TABLE security_events IS 'Security-specific events and alerts';