#!/bin/bash
# scripts/dev.sh
# Development helper script for Hermes platform
# Provides quick commands for common development tasks

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
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
API_GATEWAY_DIR="$PROJECT_ROOT/apps/api-gateway"
WEB_UI_DIR="$PROJECT_ROOT/apps/web-ui"
DOCKER_DIR="$PROJECT_ROOT/infrastructure/docker"

# Default settings
DEFAULT_API_PORT=8080
DEFAULT_WEB_PORT=3000
LOG_LEVEL=${HERMES_LOG_LEVEL:-info}
ENVIRONMENT=${HERMES_ENV:-development}

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

# Function to check if port is available
is_port_available() {
    local port=$1
    ! nc -z localhost "$port" 2>/dev/null
}

# Function to wait for service to be available
wait_for_service() {
    local host=$1
    local port=$2
    local timeout=${3:-30}
    local count=0

    print_status "Waiting for $host:$port..."
    
    while ! nc -z "$host" "$port" 2>/dev/null; do
        if [ $count -ge $timeout ]; then
            print_error "Timeout waiting for $host:$port"
            return 1
        fi
        sleep 1
        count=$((count + 1))
    done
    
    print_success "$host:$port is ready"
}

# Function to kill process on port
kill_port() {
    local port=$1
    local pid=$(lsof -ti:$port 2>/dev/null || echo "")
    
    if [ -n "$pid" ]; then
        print_status "Killing process on port $port (PID: $pid)"
        kill -9 $pid 2>/dev/null || true
        sleep 1
    fi
}

# Function to start Docker services
start_docker() {
    print_header "Starting Docker Services"
    
    cd "$DOCKER_DIR"
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    
    # Start basic services
    print_status "Starting PostgreSQL, Redis, and NATS..."
    docker-compose up -d postgres redis nats minio
    
    # Wait for services
    wait_for_service localhost 5432 30  # PostgreSQL
    wait_for_service localhost 6379 30  # Redis
    wait_for_service localhost 4222 30  # NATS
    
    print_success "Docker services started successfully"
}

# Function to stop Docker services
stop_docker() {
    print_header "Stopping Docker Services"
    
    cd "$DOCKER_DIR"
    docker-compose down
    
    print_success "Docker services stopped"
}

# Function to install dependencies
install_deps() {
    print_header "Installing Dependencies"
    
    cd "$PROJECT_ROOT"
    
    # Install Node.js dependencies
    if [ -f "package.json" ]; then
        print_status "Installing Node.js dependencies..."
        pnpm install
    fi
    
    # Install Go dependencies
    cd "$API_GATEWAY_DIR"
    if [ -f "go.mod" ]; then
        print_status "Installing Go dependencies..."
        go mod download
        go mod tidy
    fi
    
    cd "$PROJECT_ROOT"
    print_success "Dependencies installed successfully"
}

# Function to build the project
build() {
    print_header "Building Project"
    
    cd "$PROJECT_ROOT"
    
    # Build TypeScript packages
    print_status "Building TypeScript packages..."
    pnpm build
    
    # Build Go API Gateway
    cd "$API_GATEWAY_DIR"
    print_status "Building Go API Gateway..."
    go build -o bin/api-gateway ./cmd/server
    
    cd "$PROJECT_ROOT"
    print_success "Project built successfully"
}

# Function to run tests
test() {
    local component=${1:-all}
    
    print_header "Running Tests"
    
    case $component in
        "go"|"api")
            cd "$API_GATEWAY_DIR"
            print_status "Running Go tests..."
            go test -v ./... -cover
            ;;
        "js"|"ts"|"web")
            cd "$PROJECT_ROOT"
            print_status "Running TypeScript/JavaScript tests..."
            pnpm test
            ;;
        "e2e")
            cd "$PROJECT_ROOT"
            print_status "Running E2E tests..."
            pnpm test:e2e
            ;;
        "all"|*)
            cd "$API_GATEWAY_DIR"
            print_status "Running Go tests..."
            go test -v ./... -cover
            
            cd "$PROJECT_ROOT"
            print_status "Running TypeScript/JavaScript tests..."
            pnpm test
            ;;
    esac
    
    print_success "Tests completed"
}

# Function to lint code
lint() {
    local fix=${1:-false}
    
    print_header "Linting Code"
    
    cd "$PROJECT_ROOT"
    
    if [ "$fix" = "fix" ] || [ "$fix" = "--fix" ]; then
        print_status "Running linter with --fix..."
        pnpm lint:fix
        
        cd "$API_GATEWAY_DIR"
        print_status "Running Go formatter..."
        go fmt ./...
        goimports -w .
    else
        print_status "Running linter..."
        pnpm lint
        
        cd "$API_GATEWAY_DIR"
        print_status "Checking Go formatting..."
        if ! gofmt -l . | grep -q .; then
            print_success "Go code is properly formatted"
        else
            print_warning "Go code needs formatting. Run 'gofmt -w .'"
        fi
    fi
    
    print_success "Linting completed"
}

# Function to start API Gateway
start_api() {
    local port=${1:-$DEFAULT_API_PORT}
    
    print_header "Starting API Gateway"
    
    # Check if port is available
    if ! is_port_available $port; then
        print_warning "Port $port is already in use. Attempting to kill existing process..."
        kill_port $port
    fi
    
    cd "$API_GATEWAY_DIR"
    
    # Set environment variables
    export HERMES_ENV=$ENVIRONMENT
    export HERMES_SERVER_PORT=$port
    export HERMES_LOGGING_LEVEL=$LOG_LEVEL
    
    # Check if binary exists
    if [ ! -f "bin/api-gateway" ]; then
        print_status "Binary not found. Building first..."
        go build -o bin/api-gateway ./cmd/server
    fi
    
    print_status "Starting API Gateway on port $port..."
    print_status "Environment: $ENVIRONMENT"
    print_status "Log Level: $LOG_LEVEL"
    
    # Run with live reload using air (if available)
    if command_exists air; then
        print_status "Using air for live reload..."
        air
    else
        print_status "Running binary directly..."
        ./bin/api-gateway
    fi
}

# Function to start Web UI
start_web() {
    local port=${1:-$DEFAULT_WEB_PORT}
    
    print_header "Starting Web UI"
    
    cd "$WEB_UI_DIR"
    
    # Check if port is available
    if ! is_port_available $port; then
        print_warning "Port $port is already in use. Attempting to kill existing process..."
        kill_port $port
    fi
    
    # Set environment variables
    export PORT=$port
    export VITE_API_URL="http://localhost:$DEFAULT_API_PORT"
    export VITE_NODE_ENV=$ENVIRONMENT
    
    print_status "Starting Web UI on port $port..."
    print_status "API URL: $VITE_API_URL"
    
    # Start development server
    pnpm dev --port $port --host 0.0.0.0
}

# Function to start both API and Web UI
start_all() {
    print_header "Starting Full Development Environment"
    
    # Start Docker services first
    start_docker
    
    # Wait a moment for services to be fully ready
    sleep 3
    
    # Start API Gateway in background
    print_status "Starting API Gateway in background..."
    cd "$API_GATEWAY_DIR"
    
    # Set environment variables
    export HERMES_ENV=$ENVIRONMENT
    export HERMES_SERVER_PORT=$DEFAULT_API_PORT
    export HERMES_LOGGING_LEVEL=$LOG_LEVEL
    
    # Build if needed
    if [ ! -f "bin/api-gateway" ]; then
        go build -o bin/api-gateway ./cmd/server
    fi
    
    # Start API in background
    nohup ./bin/api-gateway > "../logs/api-gateway.log" 2>&1 &
    API_PID=$!
    
    # Wait for API to be ready
    wait_for_service localhost $DEFAULT_API_PORT 30
    
    # Start Web UI
    cd "$WEB_UI_DIR"
    export PORT=$DEFAULT_WEB_PORT
    export VITE_API_URL="http://localhost:$DEFAULT_API_PORT"
    
    print_status "API Gateway running on port $DEFAULT_API_PORT (PID: $API_PID)"
    print_status "Starting Web UI on port $DEFAULT_WEB_PORT..."
    
    # This will run in foreground
    pnpm dev --port $DEFAULT_WEB_PORT --host 0.0.0.0
}

# Function to create migration
create_migration() {
    local name=${1:-"new_migration"}
    local timestamp=$(date +"%Y%m%d%H%M%S")
    local filename="${timestamp}_${name}.sql"
    local migration_file="$PROJECT_ROOT/packages/database/migrations/$filename"
    
    print_header "Creating Migration"
    
    mkdir -p "$(dirname "$migration_file")"
    
    cat > "$migration_file" << EOF
-- Migration: $name
-- Created: $(date)

-- Up migration
BEGIN;

-- Add your migration SQL here


COMMIT;

-- Down migration (comment out the up migration and uncomment this for rollback)
-- BEGIN;

-- Add your rollback SQL here

-- COMMIT;
EOF

    print_success "Migration created: $filename"
    print_status "Edit the file: $migration_file"
}

# Function to run database migrations
migrate() {
    print_header "Running Database Migrations"
    
    cd "$PROJECT_ROOT"
    
    # Ensure database is running
    if ! nc -z localhost 5432 2>/dev/null; then
        print_status "Database not running. Starting Docker services..."
        start_docker
        wait_for_service localhost 5432 30
    fi
    
    # Run migrations
    local migration_dir="$PROJECT_ROOT/packages/database/migrations"
    if [ -d "$migration_dir" ]; then
        for migration in "$migration_dir"/*.sql; do
            if [ -f "$migration" ]; then
                print_status "Running migration: $(basename "$migration")"
                PGPASSWORD=hermes_password psql -h localhost -p 5432 -U hermes_user -d hermes_db -f "$migration"
            fi
        done
    fi
    
    print_success "Migrations completed"
}

# Function to seed database
seed() {
    print_header "Seeding Database"
    
    cd "$PROJECT_ROOT"
    
    # Ensure database is running
    if ! nc -z localhost 5432 2>/dev/null; then
        print_status "Database not running. Starting Docker services..."
        start_docker
        wait_for_service localhost 5432 30
    fi
    
    # Run seeds
    local seed_dir="$PROJECT_ROOT/packages/database/seeds"
    if [ -d "$seed_dir" ]; then
        for seed in "$seed_dir"/*.sql; do
            if [ -f "$seed" ]; then
                print_status "Running seed: $(basename "$seed")"
                PGPASSWORD=hermes_password psql -h localhost -p 5432 -U hermes_user -d hermes_db -f "$seed"
            fi
        done
    fi
    
    print_success "Database seeding completed"
}

# Function to reset database
reset_db() {
    print_header "Resetting Database"
    
    print_warning "This will delete all data in the database!"
    read -p "Are you sure? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cd "$DOCKER_DIR"
        
        # Stop and remove database container
        docker-compose stop postgres
        docker-compose rm -f postgres
        
        # Remove volume
        docker volume rm hermes-postgres-data 2>/dev/null || true
        
        # Start fresh database
        docker-compose up -d postgres
        wait_for_service localhost 5432 30
        
        # Run migrations and seeds
        migrate
        seed
        
        print_success "Database reset completed"
    else
        print_status "Database reset cancelled"
    fi
}

# Function to clean up everything
clean() {
    print_header "Cleaning Up"
    
    # Kill running processes
    kill_port $DEFAULT_API_PORT
    kill_port $DEFAULT_WEB_PORT
    
    # Stop Docker services
    stop_docker
    
    # Clean build artifacts
    cd "$PROJECT_ROOT"
    rm -rf node_modules/.cache
    rm -rf apps/*/dist
    rm -rf apps/*/build
    rm -rf apps/api-gateway/bin
    
    # Clean Go cache
    cd "$API_GATEWAY_DIR"
    go clean -cache -modcache -testcache
    
    print_success "Cleanup completed"
}

# Function to show logs
logs() {
    local service=${1:-all}
    local lines=${2:-50}
    
    case $service in
        "api"|"gateway")
            if [ -f "$PROJECT_ROOT/logs/api-gateway.log" ]; then
                tail -n $lines -f "$PROJECT_ROOT/logs/api-gateway.log"
            else
                print_error "API Gateway log file not found"
            fi
            ;;
        "docker")
            cd "$DOCKER_DIR"
            docker-compose logs -f --tail=$lines
            ;;
        "postgres"|"db")
            cd "$DOCKER_DIR"
            docker-compose logs -f --tail=$lines postgres
            ;;
        "redis")
            cd "$DOCKER_DIR"
            docker-compose logs -f --tail=$lines redis
            ;;
        "all"|*)
            print_status "Showing all available logs..."
            
            # Show API logs if available
            if [ -f "$PROJECT_ROOT/logs/api-gateway.log" ]; then
                print_status "=== API Gateway Logs ==="
                tail -n 20 "$PROJECT_ROOT/logs/api-gateway.log"
            fi
            
            # Show Docker logs
            print_status "=== Docker Logs ==="
            cd "$DOCKER_DIR"
            docker-compose logs --tail=20
            ;;
    esac
}

# Function to show service status
status() {
    print_header "Service Status"
    
    local services=(
        "PostgreSQL|localhost:5432"
        "Redis|localhost:6379"
        "NATS|localhost:4222"
        "API Gateway|localhost:$DEFAULT_API_PORT"
        "Web UI|localhost:$DEFAULT_WEB_PORT"
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
    
    # Docker container status
    print_status ""
    print_status "Docker containers:"
    cd "$DOCKER_DIR"
    docker-compose ps 2>/dev/null || print_warning "Docker Compose not available"
}

# Function to show usage
usage() {
    cat << 'EOF'
Development script for Hermes platform

Usage: ./scripts/dev.sh [COMMAND] [OPTIONS]

COMMANDS:
    setup               Initial project setup (install deps, build, start docker)
    deps                Install dependencies
    build               Build the project
    test [component]    Run tests (go|api, js|ts|web, e2e, or all)
    lint [fix]          Lint code (optionally with --fix)
    
    # Services
    start-docker        Start Docker services (PostgreSQL, Redis, NATS)
    stop-docker         Stop Docker services
    start-api [port]    Start API Gateway (default: 8080)
    start-web [port]    Start Web UI (default: 3000)
    start-all          Start full development environment
    
    # Database
    migrate             Run database migrations
    seed                Seed database with initial data
    migration <name>    Create new migration file
    reset-db            Reset database (WARNING: deletes all data)
    
    # Utilities
    status              Show service status
    logs [service]      Show logs (api, docker, postgres, redis, all)
    clean               Clean up build artifacts and stop services
    help                Show this help message

EXAMPLES:
    ./scripts/dev.sh setup                    # Initial setup
    ./scripts/dev.sh start-all                # Start everything
    ./scripts/dev.sh test go                  # Run Go tests only
    ./scripts/dev.sh lint fix                 # Lint and fix issues
    ./scripts/dev.sh migration add_user_roles # Create migration
    ./scripts/dev.sh logs api                 # Show API logs

ENVIRONMENT VARIABLES:
    HERMES_ENV           Environment (development, staging, production)
    HERMES_LOG_LEVEL     Log level (trace, debug, info, warn, error)

EOF
}

# Main command dispatcher
case "${1:-help}" in
    "setup")
        install_deps
        build
        start_docker
        migrate
        seed
        status
        ;;
    "deps")
        install_deps
        ;;
    "build")
        build
        ;;
    "test")
        test "${2:-all}"
        ;;
    "lint")
        lint "${2:-}"
        ;;
    "start-docker")
        start_docker
        ;;
    "stop-docker")
        stop_docker
        ;;
    "start-api")
        start_api "${2:-$DEFAULT_API_PORT}"
        ;;
    "start-web")
        start_web "${2:-$DEFAULT_WEB_PORT}"
        ;;
    "start-all")
        start_all
        ;;
    "migrate")
        migrate
        ;;
    "seed")
        seed
        ;;
    "migration")
        create_migration "${2:-new_migration}"
        ;;
    "reset-db")
        reset_db
        ;;
    "status")
        status
        ;;
    "logs")
        logs "${2:-all}" "${3:-50}"
        ;;
    "clean")
        clean
        ;;
    "help"|*)
        usage
        ;;
esac