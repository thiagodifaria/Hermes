# Hermes Development Makefile
.PHONY: help setup-dev clean build test lint format docker-up docker-down

# Default target
help:
	@echo "Hermes Development Commands:"
	@echo "  setup-dev    - Setup development environment"
	@echo "  build        - Build all applications"
	@echo "  dev          - Start development servers"
	@echo "  test         - Run all tests"
	@echo "  lint         - Run linting"
	@echo "  format       - Format code"
	@echo "  clean        - Clean build artifacts"
	@echo "  docker-up    - Start development infrastructure"
	@echo "  docker-down  - Stop development infrastructure"

# Development setup
setup-dev:
	@echo "🚀 Setting up development environment..."
	@command -v pnpm >/dev/null 2>&1 || { echo "❌ pnpm is required but not installed. Install with: npm install -g pnpm"; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required but not installed."; exit 1; }
	@command -v go >/dev/null 2>&1 || { echo "❌ Go 1.21+ is required but not installed."; exit 1; }
	pnpm install
	@echo "🐳 Starting development infrastructure..."
	$(MAKE) docker-up
	@echo "✅ Development environment ready!"

# Build
build:
	@echo "🔨 Building all applications..."
	pnpm build

# Development
dev:
	@echo "🚀 Starting development servers..."
	pnpm dev

# Testing
test:
	@echo "🧪 Running tests..."
	pnpm test

test-e2e:
	@echo "🎭 Running E2E tests..."
	pnpm test:e2e

# Code quality
lint:
	@echo "🔍 Running linting..."
	pnpm lint

lint-fix:
	@echo "🔧 Fixing linting issues..."
	pnpm lint:fix

format:
	@echo "✨ Formatting code..."
	pnpm format

format-check:
	@echo "📋 Checking code format..."
	pnpm format:check

# Infrastructure
docker-up:
	@echo "🐳 Starting Docker containers..."
	docker-compose -f infrastructure/docker/docker-compose.yml up -d
	@echo "⏳ Waiting for services to be ready..."
	sleep 5

docker-down:
	@echo "🛑 Stopping Docker containers..."
	docker-compose -f infrastructure/docker/docker-compose.yml down

docker-logs:
	docker-compose -f infrastructure/docker/docker-compose.yml logs -f

# Database
db-migrate:
	@echo "🗄️ Running database migrations..."
	cd packages/database && pnpm migrate

db-seed:
	@echo "🌱 Seeding database..."
	cd packages/database && pnpm seed

db-reset:
	@echo "🔄 Resetting database..."
	cd packages/database && pnpm reset

# Cleanup
clean:
	@echo "🧹 Cleaning build artifacts..."
	pnpm clean
	rm -rf .turbo
	@echo "✅ Cleanup complete!"

# Security
security-scan:
	@echo "🔒 Running security scan..."
	pnpm audit
	@command -v gosec >/dev/null 2>&1 && find . -name "*.go" -path "./apps/*" | xargs gosec || echo "⚠️ gosec not installed"

# Go specific commands
go-mod-tidy:
	@echo "📦 Tidying Go modules..."
	find . -name "go.mod" -execdir go mod tidy \;

go-test:
	@echo "🐹 Running Go tests..."
	find . -name "*.go" -path "./apps/*" -execdir go test -v ./... \;

# Install tools
install-tools:
	@echo "🔧 Installing development tools..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest
	npm install -g @changesets/cli