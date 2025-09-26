-- packages/database/migrations/001_initial_schema.sql
-- Initial schema for Hermes platform
-- Based on domain entities: User, Session, Host, AuditEvent

-- Enable UUID generation
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Enable pgcrypto for encryption functions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create custom types for enums
DO $$ BEGIN
    -- User related types
    CREATE TYPE user_status AS ENUM ('active', 'inactive', 'suspended', 'pending');
    
    -- Host related types  
    CREATE TYPE host_status AS ENUM ('active', 'inactive', 'maintenance', 'unreachable');
    CREATE TYPE host_type AS ENUM ('server', 'workstation', 'router', 'switch', 'firewall', 'container', 'virtual');
    CREATE TYPE auth_method AS ENUM ('password', 'private_key', 'certificate', 'agent');
    
    -- Session related types
    CREATE TYPE session_status AS ENUM ('pending', 'active', 'terminated', 'failed', 'timeout');
    CREATE TYPE session_type AS ENUM ('ssh', 'sftp', 'shell');
    
    -- Audit related types
    CREATE TYPE audit_event_type AS ENUM (
        'authentication', 'authorization', 'session', 'command', 
        'file_transfer', 'configuration', 'user_management', 
        'host_management', 'system', 'security'
    );
    CREATE TYPE audit_severity AS ENUM ('low', 'medium', 'high', 'critical');
    
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    status user_status NOT NULL DEFAULT 'pending',
    roles TEXT[] NOT NULL DEFAULT ARRAY['user'],
    permissions TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_login_at TIMESTAMPTZ,
    email_verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- SSH Keys table (separate from users for normalization)
CREATE TABLE ssh_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_type VARCHAR(50) NOT NULL,
    key_data TEXT NOT NULL,
    comment TEXT,
    fingerprint VARCHAR(255) NOT NULL UNIQUE,
    bit_length INTEGER NOT NULL,
    algorithm VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Hosts table
CREATE TABLE hosts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    port INTEGER NOT NULL DEFAULT 22 CHECK (port BETWEEN 1 AND 65535),
    host_type host_type NOT NULL DEFAULT 'server',
    status host_status NOT NULL DEFAULT 'active',
    operating_system VARCHAR(100),
    architecture VARCHAR(50),
    tags TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[],
    
    -- Credentials (encrypted)
    credentials_username VARCHAR(100),
    credentials_auth_method auth_method,
    credentials_private_key_path VARCHAR(500),
    credentials_password_encrypted TEXT, -- Encrypted with app encryption key
    credentials_certificate TEXT,
    
    -- SSH Configuration
    ssh_strict_host_key_checking BOOLEAN DEFAULT true,
    ssh_user_known_hosts_file VARCHAR(500),
    ssh_connect_timeout INTERVAL DEFAULT INTERVAL '30 seconds',
    ssh_server_alive_interval INTERVAL DEFAULT INTERVAL '60 seconds',
    ssh_server_alive_count_max INTEGER DEFAULT 3,
    ssh_compression BOOLEAN DEFAULT false,
    ssh_preferred_ciphers TEXT[],
    ssh_preferred_kex TEXT[],
    ssh_preferred_macs TEXT[],
    
    -- Health status
    last_seen TIMESTAMPTZ,
    last_health_check TIMESTAMPTZ,
    is_healthy BOOLEAN DEFAULT true,
    health_response_time INTERVAL,
    health_last_error TEXT,
    health_consecutive_fails INTEGER DEFAULT 0,
    health_uptime INTERVAL,
    health_cpu_usage DECIMAL(5,2),
    health_memory_usage DECIMAL(5,2),
    health_disk_usage DECIMAL(5,2),
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Host metadata table (for flexible key-value storage)
CREATE TABLE host_metadata (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    key VARCHAR(100) NOT NULL,
    value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(host_id, key)
);

-- Sessions table
CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    host_id UUID NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    session_type session_type NOT NULL DEFAULT 'ssh',
    status session_status NOT NULL DEFAULT 'pending',
    
    -- Connection info
    remote_addr INET,
    local_addr INET,
    protocol VARCHAR(50),
    client_version VARCHAR(100),
    server_version VARCHAR(100),
    cipher VARCHAR(100),
    mac VARCHAR(100),
    compression VARCHAR(50),
    
    -- Recording
    recording_path VARCHAR(1000),
    recording_enabled BOOLEAN NOT NULL DEFAULT true,
    
    -- Timing
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    last_activity TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Transfer stats
    bytes_sent BIGINT NOT NULL DEFAULT 0,
    bytes_received BIGINT NOT NULL DEFAULT 0,
    
    -- Exit info
    exit_code INTEGER,
    
    -- Terminal info
    terminal_width INTEGER DEFAULT 80,
    terminal_height INTEGER DEFAULT 24,
    working_directory VARCHAR(1000) DEFAULT '/',
    
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Session environment variables
CREATE TABLE session_environment (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    key VARCHAR(100) NOT NULL,
    value TEXT NOT NULL,
    UNIQUE(session_id, key)
);

-- Commands executed in sessions
CREATE TABLE session_commands (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    command VARCHAR(1000) NOT NULL,
    arguments TEXT[],
    exit_code INTEGER DEFAULT 0,
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    output TEXT, -- Truncated output for storage efficiency
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Audit events table
CREATE TABLE audit_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
    host_id UUID REFERENCES hosts(id) ON DELETE SET NULL,
    event_type audit_event_type NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100) NOT NULL,
    resource_id UUID,
    details JSONB NOT NULL DEFAULT '{}',
    ip_address INET,
    user_agent TEXT,
    severity audit_severity NOT NULL DEFAULT 'low',
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for performance

-- Users indexes
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_users_last_login_at ON users(last_login_at);
CREATE INDEX idx_users_roles ON users USING GIN(roles);

-- SSH Keys indexes
CREATE INDEX idx_ssh_keys_user_id ON ssh_keys(user_id);
CREATE INDEX idx_ssh_keys_fingerprint ON ssh_keys(fingerprint);

-- Hosts indexes
CREATE INDEX idx_hosts_name ON hosts(name);
CREATE INDEX idx_hosts_hostname ON hosts(hostname);
CREATE INDEX idx_hosts_ip_address ON hosts(ip_address);
CREATE INDEX idx_hosts_status ON hosts(status);
CREATE INDEX idx_hosts_host_type ON hosts(host_type);
CREATE INDEX idx_hosts_tags ON hosts USING GIN(tags);
CREATE INDEX idx_hosts_last_seen ON hosts(last_seen);
CREATE INDEX idx_hosts_is_healthy ON hosts(is_healthy);

-- Host metadata indexes
CREATE INDEX idx_host_metadata_host_id ON host_metadata(host_id);
CREATE INDEX idx_host_metadata_key ON host_metadata(key);

-- Sessions indexes
CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_host_id ON sessions(host_id);
CREATE INDEX idx_sessions_status ON sessions(status);
CREATE INDEX idx_sessions_session_type ON sessions(session_type);
CREATE INDEX idx_sessions_start_time ON sessions(start_time);
CREATE INDEX idx_sessions_end_time ON sessions(end_time);
CREATE INDEX idx_sessions_last_activity ON sessions(last_activity);
CREATE INDEX idx_sessions_recording_enabled ON sessions(recording_enabled);

-- Composite indexes for common queries
CREATE INDEX idx_sessions_user_status ON sessions(user_id, status);
CREATE INDEX idx_sessions_host_status ON sessions(host_id, status);
CREATE INDEX idx_sessions_active ON sessions(status) WHERE status = 'active';

-- Session environment indexes
CREATE INDEX idx_session_environment_session_id ON session_environment(session_id);

-- Session commands indexes
CREATE INDEX idx_session_commands_session_id ON session_commands(session_id);
CREATE INDEX idx_session_commands_start_time ON session_commands(start_time);
CREATE INDEX idx_session_commands_command ON session_commands(command);

-- Audit events indexes
CREATE INDEX idx_audit_events_timestamp ON audit_events(timestamp);
CREATE INDEX idx_audit_events_user_id ON audit_events(user_id);
CREATE INDEX idx_audit_events_session_id ON audit_events(session_id);
CREATE INDEX idx_audit_events_host_id ON audit_events(host_id);
CREATE INDEX idx_audit_events_event_type ON audit_events(event_type);
CREATE INDEX idx_audit_events_action ON audit_events(action);
CREATE INDEX idx_audit_events_severity ON audit_events(severity);
CREATE INDEX idx_audit_events_success ON audit_events(success);
CREATE INDEX idx_audit_events_ip_address ON audit_events(ip_address);

-- JSONB indexes for audit event details
CREATE INDEX idx_audit_events_details ON audit_events USING GIN(details);

-- Composite indexes for audit queries
CREATE INDEX idx_audit_events_user_timestamp ON audit_events(user_id, timestamp);
CREATE INDEX idx_audit_events_type_timestamp ON audit_events(event_type, timestamp);
CREATE INDEX idx_audit_events_security_events ON audit_events(event_type, severity) WHERE event_type = 'security';

-- Triggers for updated_at timestamps

-- Function to update updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers to all tables with updated_at column
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_hosts_updated_at BEFORE UPDATE ON hosts FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_host_metadata_updated_at BEFORE UPDATE ON host_metadata FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_sessions_updated_at BEFORE UPDATE ON sessions FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Views for common queries

-- Active sessions view
CREATE VIEW active_sessions AS
SELECT 
    s.*,
    u.email as user_email,
    u.first_name || ' ' || u.last_name as user_name,
    h.name as host_name,
    h.hostname as host_hostname
FROM sessions s
JOIN users u ON s.user_id = u.id
JOIN hosts h ON s.host_id = h.id
WHERE s.status = 'active';

-- User session statistics view
CREATE VIEW user_session_stats AS
SELECT 
    u.id as user_id,
    u.email,
    u.first_name || ' ' || u.last_name as full_name,
    COUNT(s.id) as total_sessions,
    COUNT(CASE WHEN s.status = 'active' THEN 1 END) as active_sessions,
    COUNT(CASE WHEN s.recording_enabled = true THEN 1 END) as recorded_sessions,
    SUM(s.bytes_sent + s.bytes_received) as total_bytes,
    MAX(s.start_time) as last_session_time
FROM users u
LEFT JOIN sessions s ON u.id = s.user_id
GROUP BY u.id, u.email, u.first_name, u.last_name;

-- Host connection statistics view
CREATE VIEW host_connection_stats AS
SELECT 
    h.id as host_id,
    h.name,
    h.hostname,
    h.ip_address,
    h.status,
    h.is_healthy,
    COUNT(s.id) as total_sessions,
    COUNT(CASE WHEN s.status = 'active' THEN 1 END) as active_sessions,
    COUNT(DISTINCT s.user_id) as unique_users,
    MAX(s.start_time) as last_connection_time
FROM hosts h
LEFT JOIN sessions s ON h.id = s.host_id
GROUP BY h.id, h.name, h.hostname, h.ip_address, h.status, h.is_healthy;

-- Audit summary view for security events
CREATE VIEW security_audit_summary AS
SELECT 
    DATE(timestamp) as audit_date,
    event_type,
    action,
    severity,
    COUNT(*) as event_count,
    COUNT(CASE WHEN success = false THEN 1 END) as failed_count,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(DISTINCT ip_address) as unique_ips
FROM audit_events
WHERE event_type IN ('authentication', 'authorization', 'security')
GROUP BY DATE(timestamp), event_type, action, severity
ORDER BY audit_date DESC, event_count DESC;

-- Row Level Security (RLS) policies

-- Enable RLS on sensitive tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssh_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE session_commands ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

-- RLS policies will be defined based on application roles
-- These are examples - actual policies depend on authentication implementation

-- Example: Users can only see their own data
-- CREATE POLICY users_self_access ON users FOR ALL USING (id = current_user_id());

-- Example: Users can only see their own sessions
-- CREATE POLICY sessions_user_access ON sessions FOR ALL USING (user_id = current_user_id());

-- Cleanup functions

-- Function to cleanup old sessions
CREATE OR REPLACE FUNCTION cleanup_old_sessions(older_than INTERVAL DEFAULT INTERVAL '30 days')
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM sessions 
    WHERE status IN ('terminated', 'failed', 'timeout') 
    AND end_time < NOW() - older_than;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Function to cleanup old audit events
CREATE OR REPLACE FUNCTION cleanup_old_audit_events(older_than INTERVAL DEFAULT INTERVAL '2555 days') -- 7 years for compliance
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM audit_events 
    WHERE timestamp < NOW() - older_than
    AND severity NOT IN ('high', 'critical'); -- Keep critical events longer
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Performance monitoring views

-- Slow queries view (requires pg_stat_statements extension)
-- CREATE VIEW slow_queries AS
-- SELECT query, calls, total_time, mean_time, rows
-- FROM pg_stat_statements 
-- ORDER BY mean_time DESC;

-- Database statistics view
CREATE VIEW db_stats AS
SELECT 
    schemaname,
    tablename,
    n_tup_ins as inserts,
    n_tup_upd as updates,
    n_tup_del as deletes,
    n_live_tup as live_tuples,
    n_dead_tup as dead_tuples,
    last_vacuum,
    last_autovacuum,
    last_analyze,
    last_autoanalyze
FROM pg_stat_user_tables
ORDER BY n_live_tup DESC;

-- Comments for documentation
COMMENT ON TABLE users IS 'User accounts with authentication and authorization data';
COMMENT ON TABLE ssh_keys IS 'SSH public keys associated with user accounts';
COMMENT ON TABLE hosts IS 'Remote hosts/servers that can be accessed via SSH';
COMMENT ON TABLE host_metadata IS 'Flexible key-value metadata for hosts';
COMMENT ON TABLE sessions IS 'SSH/remote sessions with connection tracking';
COMMENT ON TABLE session_environment IS 'Environment variables for sessions';
COMMENT ON TABLE session_commands IS 'Commands executed during sessions';
COMMENT ON TABLE audit_events IS 'Comprehensive audit log for compliance and security';

-- Grant permissions (these would be customized based on application roles)
-- GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO hermes_app_user;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO hermes_app_user;