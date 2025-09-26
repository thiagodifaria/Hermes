#!/bin/bash
# infrastructure/scripts/setup-dev.sh
# Development environment setup script for Hermes platform
# Automates the setup of databases, services, and development tools

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKER_DIR="$PROJECT_ROOT/infrastructure/docker"
MONITORING_DIR="$PROJECT_ROOT/infrastructure/monitoring"

# Default settings
DEFAULT_PROFILE="base"
WAIT_TIMEOUT=60
LOG_FILE="$PROJECT_ROOT/setup-dev.log"

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_header() {
    echo -e "${PURPLE}========================================${NC}"
    echo -e "${PURPLE} $1${NC}"
    echo -e "${PURPLE}========================================${NC}"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check system requirements
check_requirements() {
    print_header "Checking System Requirements"
    
    local required_commands=("docker" "docker-compose" "pnpm" "go" "node")
    local missing_commands=()
    
    for cmd in "${required_commands[@]}"; do
        if command_exists "$cmd"; then
            print_status "✓ $cmd is installed"
        else
            missing_commands+=("$cmd")
            print_error "✗ $cmd is not installed"
        fi
    done
    
    if [ ${#missing_commands[@]} -ne 0 ]; then
        print_error "Missing required commands: ${missing_commands[*]}"
        print_status "Please install the missing commands and run this script again"
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker daemon is not running"
        print_status "Please start Docker and run this script again"
        exit 1
    fi
    
    print_success "All requirements are satisfied"
}

# Function to check available disk space
check_disk_space() {
    print_status "Checking disk space..."
    
    local required_space_gb=5
    local available_space_gb=$(df -BG "$PROJECT_ROOT" | awk 'NR==2 {gsub(/G/, "", $4); print $4}')
    
    if [ "$available_space_gb" -lt "$required_space_gb" ]; then
        print_warning "Available disk space: ${available_space_gb}GB"
        print_warning "Recommended: At least ${required_space_gb}GB"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_success "Sufficient disk space available: ${available_space_gb}GB"
    fi
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    
    local directories=(
        "$PROJECT_ROOT/data/postgres"
        "$PROJECT_ROOT/data/redis" 
        "$PROJECT_ROOT/data/minio"
        "$PROJECT_ROOT/logs"
        "$PROJECT_ROOT/keys"
        "$PROJECT_ROOT/recordings"
        "$PROJECT_ROOT/backups"
    )
    
    for dir in "${directories[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_status "Created directory: $dir"
        fi
    done
    
    # Set appropriate permissions
    chmod 700 "$PROJECT_ROOT/keys" 2>/dev/null || true
    chmod 755 "$PROJECT_ROOT/recordings" 2>/dev/null || true
    
    print_success "Directory structure created"
}

# Function to generate environment files
generate_env_files() {
    print_status "Generating environment files..."
    
    local env_file="$PROJECT_ROOT/.env"
    local env_example="$PROJECT_ROOT/configs/.env.example"
    
    if [ ! -f "$env_file" ]; then
        if [ -f "$env_example" ]; then
            cp "$env_example" "$env_file"
            print_status "Created .env from .env.example"
            
            # Generate secure random values for development
            generate_secure_secrets "$env_file"
        else
            print_error ".env.example not found"
            exit 1
        fi
    else
        print_status ".env file already exists"
    fi
}

# Function to generate secure secrets for development
generate_secure_secrets() {
    local env_file="$1"
    
    print_status "Generating secure secrets..."
    
    # Generate JWT secret (32 characters)
    local jwt_secret=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    sed -i.bak "s|your-super-secure-jwt-secret-here-at-least-32-chars|$jwt_secret|g" "$env_file"
    
    # Generate encryption key (32 characters)
    local encryption_key=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    sed -i.bak "s|your-32-char-encryption-key-here!|$encryption_key|g" "$env_file"
    
    # Generate webhook secret
    local webhook_secret=$(openssl rand -hex 32)
    sed -i.bak "s|your-webhook-secret-for-verification|$webhook_secret|g" "$env_file"
    
    # Generate backup encryption key
    local backup_key=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)
    sed -i.bak "s|your-backup-encryption-key|$backup_key|g" "$env_file"
    
    # Clean up backup file
    rm -f "$env_file.bak"
    
    print_success "Secure secrets generated"
}

# Function to setup Docker configuration files
setup_docker_configs() {
    print_status "Setting up Docker configuration files..."
    
    # Create PostgreSQL configuration
    local postgres_conf_dir="$DOCKER_DIR/postgres-conf"
    mkdir -p "$postgres_conf_dir"
    
    cat > "$postgres_conf_dir/postgresql.conf" << 'EOF'
# PostgreSQL configuration for development
# Performance settings
shared_buffers = 256MB
effective_cache_size = 1GB
work_mem = 4MB
maintenance_work_mem = 64MB

# Logging settings
log_statement = 'all'
log_min_duration_statement = 100ms
log_line_prefix = '%t [%p]: [%l-1] user=%u,db=%d,app=%a,client=%h '

# Connection settings
max_connections = 100
listen_addresses = '*'

# Extensions
shared_preload_libraries = 'pg_stat_statements'
EOF
    
    # Create Redis configuration
    local redis_conf_dir="$DOCKER_DIR/redis-conf"
    mkdir -p "$redis_conf_dir"
    
    cat > "$redis_conf_dir/redis.conf" << 'EOF'
# Redis configuration for development
appendonly yes
appendfsync everysec
save 900 1
save 300 10
save 60 10000

# Memory settings
maxmemory 512mb
maxmemory-policy allkeys-lru

# Network settings
bind 0.0.0.0
protected-mode no
port 6379

# Logging
loglevel notice
logfile ""
EOF
    
    # Create NATS configuration
    local nats_conf_dir="$DOCKER_DIR/nats-conf"
    mkdir -p "$nats_conf_dir"
    
    cat > "$nats_conf_dir/nats.conf" << 'EOF'
# NATS Server configuration for development
port: 4222
http_port: 8222

# Logging
log_file: "/tmp/nats.log"
logtime: true
debug: false
trace: false

# Limits
max_connections: 64K
max_payload: 1MB
max_pending: 64MB

# Clustering (for future use)
cluster {
    port: 6222
}
EOF
    
    cat > "$nats_conf_dir/jetstream.conf" << 'EOF'
# NATS JetStream configuration
port: 4222
http_port: 8222

jetstream {
    store_dir: "/data"
    max_memory_store: 256MB
    max_file_store: 2GB
}
EOF
    
    # Create Nginx configuration
    local nginx_conf_dir="$DOCKER_DIR/nginx-conf"
    mkdir -p "$nginx_conf_dir"
    
    cat > "$nginx_conf_dir/nginx.conf" << 'EOF'
events {
    worker_connections 1024;
}

http {
    upstream api_gateway {
        server host.docker.internal:8080;
    }
    
    upstream web_ui {
        server host.docker.internal:3000;
    }
    
    server {
        listen 80;
        server_name localhost;
        
        location /api/ {
            proxy_pass http://api_gateway;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }
        
        location / {
            proxy_pass http://web_ui;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            
            # WebSocket support
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
        }
    }
}
EOF
    
    print_success "Docker configuration files created"
}

# Function to start Docker services
start_docker_services() {
    local profile="$1"
    print_status "Starting Docker services with profile: $profile"
    
    cd "$DOCKER_DIR"
    
    # Pull latest images
    print_status "Pulling Docker images..."
    docker-compose pull
    
    # Start services
    case "$profile" in
        "base")
            docker-compose up -d postgres redis nats minio
            ;;
        "monitoring")
            docker-compose --profile monitoring up -d postgres redis nats minio prometheus grafana loki tempo
            ;;
        "development")
            docker-compose --profile development up -d postgres redis nats minio mailhog pgadmin redis-commander
            ;;
        "full")
            docker-compose --profile monitoring --profile development --profile vault up -d
            ;;
        *)
            print_error "Unknown profile: $profile"
            exit 1
            ;;
    esac
    
    print_success "Docker services started"
}

# Function to wait for services to be ready
wait_for_services() {
    print_status "Waiting for services to be ready..."
    
    local services=("postgres:5432" "redis:6379" "nats:4222")
    local timeout=$WAIT_TIMEOUT
    
    for service in "${services[@]}"; do
        local host=${service%:*}
        local port=${service#*:}
        
        print_status "Waiting for $host:$port..."
        
        local count=0
        while ! nc -z localhost "$port" 2>/dev/null; do
            if [ $count -ge $timeout ]; then
                print_error "Timeout waiting for $host:$port"
                exit 1
            fi
            sleep 1
            count=$((count + 1))
        done
        
        print_success "$host:$port is ready"
    done
}

# Function to run database migrations
run_migrations() {
    print_status "Running database migrations..."
    
    # Wait a bit more for PostgreSQL to be fully ready
    sleep 5
    
    local migration_dir="$PROJECT_ROOT/packages/database/migrations"
    local schema_dir="$PROJECT_ROOT/packages/database/schemas"
    
    # Run main schema
    if [ -f "$migration_dir/001_initial_schema.sql" ]; then
        print_status "Running initial schema migration..."
        PGPASSWORD=hermes_password psql -h localhost -p 5432 -U hermes_user -d hermes_db -f "$migration_dir/001_initial_schema.sql" >> "$LOG_FILE" 2>&1
        print_success "Initial schema migration completed"
    fi
    
    # Run auth schema
    if [ -f "$schema_dir/auth.sql" ]; then
        print_status "Running auth schema migration..."
        PGPASSWORD=hermes_password psql -h localhost -p 5432 -U hermes_user -d hermes_db -f "$schema_dir/auth.sql" >> "$LOG_FILE" 2>&1
        print_success "Auth schema migration completed"
    fi
}

# Function to seed database with initial data
seed_database() {
    print_status "Seeding database with initial data..."
    
    local seed_dir="$PROJECT_ROOT/packages/database/seeds"
    
    if [ -d "$seed_dir" ]; then
        for seed_file in "$seed_dir"/*.sql; do
            if [ -f "$seed_file" ]; then
                print_status "Running seed file: $(basename "$seed_file")"
                PGPASSWORD=hermes_password psql -h localhost -p 5432 -U hermes_user -d hermes_db -f "$seed_file" >> "$LOG_FILE" 2>&1
            fi
        done
        print_success "Database seeding completed"
    else
        print_warning "No seed directory found, skipping seeding"
    fi
}

# Function to setup MinIO buckets
setup_minio_buckets() {
    print_status "Setting up MinIO buckets..."
    
    # Wait for MinIO to be ready
    local count=0
    while ! curl -f http://localhost:9000/minio/health/live >/dev/null 2>&1; do
        if [ $count -ge 30 ]; then
            print_warning "MinIO health check timeout, continuing..."
            return
        fi
        sleep 1
        count=$((count + 1))
    done
    
    # Install MinIO client if not present
    if ! command_exists mc; then
        print_status "Installing MinIO client..."
        curl -o /tmp/mc https://dl.min.io/client/mc/release/linux-amd64/mc
        chmod +x /tmp/mc
        MC_CMD="/tmp/mc"
    else
        MC_CMD="mc"
    fi
    
    # Configure MinIO client
    $MC_CMD alias set local http://localhost:9000 hermes_minio hermes_minio_password >/dev/null 2>&1
    
    # Create buckets
    local buckets=("hermes-recordings" "hermes-backups" "hermes-uploads")
    
    for bucket in "${buckets[@]}"; do
        if ! $MC_CMD ls "local/$bucket" >/dev/null 2>&1; then
            $MC_CMD mb "local/$bucket"
            print_status "Created bucket: $bucket"
        else
            print_status "Bucket already exists: $bucket"
        fi
    done
    
    print_success "MinIO buckets configured"
}

# Function to install project dependencies
install_dependencies() {
    print_status "Installing project dependencies..."
    
    cd "$PROJECT_ROOT"
    
    # Install Node.js dependencies
    print_status "Installing Node.js dependencies..."
    pnpm install
    
    # Install Go dependencies
    print_status "Installing Go dependencies..."
    cd "$PROJECT_ROOT/apps/api-gateway"
    go mod download
    
    cd "$PROJECT_ROOT"
    print_success "Dependencies installed"
}

# Function to build project
build_project() {
    print_status "Building project..."
    
    cd "$PROJECT_ROOT"
    
    # Build TypeScript packages
    print_status "Building TypeScript packages..."
    pnpm build
    
    # Build Go services
    print_status "Building Go services..."
    cd "$PROJECT_ROOT/apps/api-gateway"
    go build -o bin/api-gateway ./cmd/server
    
    cd "$PROJECT_ROOT"
    print_success "Project built successfully"
}

# Function to run tests
run_tests() {
    print_status "Running tests..."
    
    cd "$PROJECT_ROOT"
    
    # Run TypeScript tests
    if [ -f "package.json" ] && grep -q '"test"' package.json; then
        print_status "Running TypeScript tests..."
        pnpm test || print_warning "Some TypeScript tests failed"
    fi
    
    # Run Go tests
    print_status "Running Go tests..."
    cd "$PROJECT_ROOT/apps/api-gateway"
    go test ./... || print_warning "Some Go tests failed"
    
    cd "$PROJECT_ROOT"
    print_success "Tests completed"
}

# Function to show service status
show_service_status() {
    print_header "Service Status"
    
    local services=(
        "PostgreSQL|localhost:5432"
        "Redis|localhost:6379"
        "NATS|localhost:4222"
        "MinIO API|localhost:9000"
        "MinIO Console|localhost:9001"
    )
    
    for service in "${services[@]}"; do
        local name=${service%|*}
        local endpoint=${service#*|}
        local host=${endpoint%:*}
        local port=${endpoint#*:}
        
        if nc -z "$host" "$port" 2>/dev/null; then
            print_success "$name: ✓ Running on $endpoint"
        else
            print_error "$name: ✗ Not accessible on $endpoint"
        fi
    done
    
    print_status ""
    print_status "Docker containers:"
    docker-compose -f "$DOCKER_DIR/docker-compose.yml" ps
}

# Function to show usage information
show_usage() {
    cat << 'EOF'
Usage: setup-dev.sh [OPTIONS] [COMMAND]

Setup development environment for Hermes platform

OPTIONS:
  -p, --profile PROFILE    Docker compose profile (base|monitoring|development|full) [default: base]
  -s, --skip-build         Skip building the project
  -t, --skip-tests         Skip running tests
  -w, --wait-timeout SEC   Timeout for waiting services (default: 60)
  -h, --help              Show this help message

COMMANDS:
  setup                   Full setup (default)
  start                   Start services only
  stop                    Stop all services
  restart                 Restart all services
  clean                   Clean up containers and volumes
  status                  Show service status
  logs                    Show logs for all services
  migrate                 Run database migrations only
  seed                    Seed database only

EXAMPLES:
  ./setup-dev.sh                          # Basic setup
  ./setup-dev.sh -p monitoring           # Setup with monitoring stack
  ./setup-dev.sh -p full                 # Setup with all services
  ./setup-dev.sh --skip-build start      # Start services without building
  ./setup-dev.sh clean                   # Clean up everything

EOF
}

# Function to clean up everything
cleanup() {
    print_header "Cleaning Up"
    
    cd "$DOCKER_DIR"
    
    print_status "Stopping all containers..."
    docker-compose --profile monitoring --profile development --profile vault down
    
    print_status "Removing volumes..."
    docker-compose --profile monitoring --profile development --profile vault down -v
    
    print_status "Removing networks..."
    docker network prune -f
    
    print_status "Cleaning up temporary files..."
    rm -rf "$PROJECT_ROOT/tmp/*" 2>/dev/null || true
    
    print_success "Cleanup completed"
}

# Function to show logs
show_logs() {
    cd "$DOCKER_DIR"
    docker-compose logs -f "$@"
}

# Main setup function
main_setup() {
    local profile="$1"
    local skip_build="$2"
    local skip_tests="$3"
    
    print_header "Hermes Development Environment Setup"
    print_status "Profile: $profile"
    print_status "Log file: $LOG_FILE"
    
    # Create log file
    touch "$LOG_FILE"
    
    check_requirements
    check_disk_space
    create_directories
    generate_env_files
    setup_docker_configs
    start_docker_services "$profile"
    wait_for_services
    
    if [ "$skip_build" != "true" ]; then
        install_dependencies
        build_project
    fi
    
    run_migrations
    seed_database
    setup_minio_buckets
    
    if [ "$skip_tests" != "true" ]; then
        run_tests
    fi
    
    show_service_status
    
    print_success "Development environment setup completed!"
    print_status "Check the log file for details: $LOG_FILE"
    
    echo ""
    print_status "Next steps:"
    print_status "1. Start the API Gateway: cd apps/api-gateway && go run cmd/server/main.go"
    print_status "2. Start the Web UI: cd apps/web-ui && pnpm dev"
    print_status "3. Access the application at http://localhost:3000"
    echo ""
    print_status "Useful URLs:"
    print_status "- pgAdmin: http://localhost:8080 (admin@hermes.local / admin)"
    print_status "- Redis Commander: http://localhost:8081 (admin / admin)"
    print_status "- MinIO Console: http://localhost:9001 (hermes_minio / hermes_minio_password)"
    print_status "- MailHog: http://localhost:8025"
}

# Parse command line arguments
PROFILE="$DEFAULT_PROFILE"
SKIP_BUILD="false"
SKIP_TESTS="false"
COMMAND="setup"

while [[ $# -gt 0 ]]; do
    case $1 in
        -p|--profile)
            PROFILE="$2"
            shift 2
            ;;
        -s|--skip-build)
            SKIP_BUILD="true"
            shift
            ;;
        -t|--skip-tests)
            SKIP_TESTS="true"
            shift
            ;;
        -w|--wait-timeout)
            WAIT_TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        setup|start|stop|restart|clean|status|logs|migrate|seed)
            COMMAND="$1"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Execute command
case "$COMMAND" in
    "setup")
        main_setup "$PROFILE" "$SKIP_BUILD" "$SKIP_TESTS"
        ;;
    "start")
        start_docker_services "$PROFILE"
        wait_for_services
        show_service_status
        ;;
    "stop")
        cd "$DOCKER_DIR"
        docker-compose --profile monitoring --profile development --profile vault down
        print_success "Services stopped"
        ;;
    "restart")
        cd "$DOCKER_DIR"
        docker-compose --profile monitoring --profile development --profile vault restart
        print_success "Services restarted"
        ;;
    "clean")
        cleanup
        ;;
    "status")
        show_service_status
        ;;
    "logs")
        show_logs "$@"
        ;;
    "migrate")
        run_migrations
        ;;
    "seed")
        seed_database
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_usage
        exit 1
        ;;
esac