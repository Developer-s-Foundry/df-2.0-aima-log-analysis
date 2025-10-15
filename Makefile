# Log Analysis Service - Makefile

.PHONY: help start stop restart test clean logs status

# Default target
help:
	@echo "Log Analysis Service - Available Commands:"
	@echo ""
	@echo "🚀 Service Management:"
	@echo "  start     - Start all services with Docker Compose"
	@echo "  stop      - Stop all services"
	@echo "  restart   - Restart all services"
	@echo "  logs      - View application logs"
	@echo "  status    - Check service status"
	@echo "  clean     - Clean up containers and volumes"
	@echo ""
	@echo "🔑 Authentication:"
	@echo "  get-token      - Generate admin authentication token"
	@echo "  get-token-user - Generate user authentication token"
	@echo "  get-token-admin- Generate admin authentication token"
	@echo ""
	@echo "⚙️  Configuration:"
	@echo "  get-config     - Show application configuration"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test-logs      - Run comprehensive log processing tests"
	@echo "  test-critical   - Test critical error scenarios"
	@echo "  test-pattern    - Test pattern detection"
	@echo "  test-anomaly    - Test anomaly detection"
	@echo "  test-api-status - Test AI status endpoint"
	@echo "  test-api-logs   - Test logs endpoint"
	@echo "  test-api-stats  - Test stats endpoint"
	@echo ""
	@echo "📊 Monitoring:"
	@echo "  check-logs-db   - View recent logs in database"
	@echo "  check-patterns  - View detected patterns"
	@echo "  check-queues    - View RabbitMQ queue status"
	@echo "  metrics         - View Prometheus metrics"
	@echo ""

# Start all services
start:
	@echo "🚀 Starting Log Analysis Service..."
	docker compose up -d
	@echo "⏳ Waiting for services to be ready..."
	@sleep 10
	@echo "✅ Services started! Check status with 'make status'"

# Stop all services
stop:
	@echo "🛑 Stopping services..."
	docker compose down

# Restart services
restart:
	@echo "🔄 Restarting services..."
	docker compose restart

restart-build:
	@echo "🔄 Restarting services..."
	docker compose up -d --build
	

# View logs
logs:
	@echo "📋 Viewing application logs..."
	docker compose logs -f log_analysis_service

# Check service status
status:
	@echo "📊 Service Status:"
	@echo ""
	@echo "Docker Services:"
	@docker compose ps
	@echo ""
	@echo "Health Check:"
	@curl -s http://localhost:8000/health | jq . || echo "❌ Health check failed"
	@echo ""
	@echo "Readiness Check:"
	@curl -s http://localhost:8000/health/ready | jq . || echo "❌ Readiness check failed"

# Clean up
clean:
	@echo "🧹 Cleaning up..."
	docker compose down -v
	docker system prune -f

# Local development
dev:
	@echo "🔧 Starting for local development..."
	python start_app.py

# Initial setup
setup:
	@echo "⚙️  Setting up Log Analysis Service..."
	@echo "1. Creating .env file..."
	@if [ ! -f .env ]; then cp .env.example .env; echo "✅ .env file created"; else echo "✅ .env file already exists"; fi
	@echo "2. Starting services..."
	docker compose up -d
	@echo "3. Waiting for services to be ready..."
	@sleep 15
	@echo "4. Running initial tests..."
	python test_all_endpoints.py
	@echo "✅ Setup complete! Service is ready to use."

# Quick test
quick-test:
	@echo "⚡ Quick API test..."
	@curl -s http://localhost:8000/health | jq . && echo "✅ Health check passed" || echo "❌ Health check failed"
	@curl -s http://localhost:8000/health/ready | jq . && echo "✅ Readiness check passed" || echo "❌ Readiness check failed"

# AI toggle commands
ai-on:
	@echo "🤖 Enabling AI processing..."
	@curl -s -X POST -H "Authorization: Bearer test-token" "http://localhost:8000/api/v1/ai/toggle?enable_ai=true" | jq .

ai-off:
	@echo "🔄 Disabling AI processing..."
	@curl -s -X POST -H "Authorization: Bearer test-token" "http://localhost:8000/api/v1/ai/toggle?enable_ai=false" | jq .

ai-status:
	@echo "📊 AI Status:"
	@curl -s -H "Authorization: Bearer test-token" "http://localhost:8000/api/v1/ai/status" | jq .

# Test AI with custom message
test-ai:
	@echo "🧪 Testing AI with custom message..."
	@curl -s -X POST -H "Authorization: Bearer test-token" "http://localhost:8000/api/v1/ai/test?test_message=Database connection timeout&service_name=test-service" | jq .

# View all logs
logs-all:
	@echo "📋 Viewing all service logs..."
	docker compose logs -f

# Database commands
db-shell:
	@echo "🗄️  Opening database shell..."
	docker compose exec postgres psql -U postgres -d log_analysis_db

db-tables:
	@echo "📊 Database tables:"
	docker compose exec postgres psql -U postgres -d log_analysis_db -c "\dt"

# Metrics
metrics:
	@echo "📈 Prometheus metrics:"
	@curl -s http://localhost:8000/metrics | head -20

# Authentication
get-token:
	@echo "🔑 Generating authentication token..."
	@docker compose exec -T log_analysis_service python -c "from app.core.auth_external import create_test_token; print('Token:', create_test_token('test-user', ['admin']))"

get-token-user:
	@echo "🔑 Generating user token..."
	@docker compose exec -T log_analysis_service python -c "from app.core.auth_external import create_test_token; print('Token:', create_test_token('user-123', ['user']))"

get-token-admin:
	@echo "🔑 Generating admin token..."
	@docker compose exec -T log_analysis_service python -c "from app.core.auth_external import create_test_token; print('Token:', create_test_token('admin-456', ['admin', 'user']))"

# Configuration
get-config:
	@echo "⚙️  Application Configuration:"
	@docker compose exec -T log_analysis_service python -c "from app.core.config import get_settings; s = get_settings(); print(f'Database URL: {s.database_url}'); print(f'RabbitMQ URL: {s.rabbitmq_url}'); print(f'Server: {s.host}:{s.port}')"

# Testing
test-logs:
	@echo "🧪 Running comprehensive log tests..."
	docker compose exec -T log_analysis_service python /app/test_send_log.py --scenario all

test-critical:
	@echo "🚨 Testing critical errors..."
	docker compose exec -T log_analysis_service python /app/test_send_log.py --scenario critical

test-pattern:
	@echo "💡 Testing pattern detection..."
	docker compose exec -T log_analysis_service python /app/test_send_log.py --scenario pattern

test-anomaly:
	@echo "⚠️  Testing anomaly detection..."
	docker compose exec -T log_analysis_service python /app/test_send_log.py --scenario anomaly

test-normal:
	@echo "✅ Testing normal logs..."
	docker compose exec -T log_analysis_service python /app/test_send_log.py --scenario normal

test-mixed:
	@echo "🎯 Testing mixed scenario..."
	docker compose exec -T log_analysis_service python /app/test_send_log.py --scenario mixed

# API Testing (requires token)
test-api-status:
	@echo "🌐 Testing AI status endpoint..."
	@TOKEN=$$(docker compose exec -T log_analysis_service python -c "from app.core.auth_external import create_test_token; print(create_test_token('test-user', ['admin']))"); \
	curl -H "Authorization: Bearer $$TOKEN" http://localhost:8000/api/v1/ai/status

test-api-logs:
	@echo "📋 Testing logs endpoint..."
	@TOKEN=$$(docker compose exec -T log_analysis_service python -c "from app.core.auth_external import create_test_token; print(create_test_token('test-user', ['admin']))"); \
	curl -H "Authorization: Bearer $$TOKEN" http://localhost:8000/api/v1/logs

test-api-stats:
	@echo "📊 Testing stats endpoint..."
	@TOKEN=$$(docker compose exec -T log_analysis_service python -c "from app.core.auth_external import create_test_token; print(create_test_token('test-user', ['admin']))"); \
	curl -H "Authorization: Bearer $$TOKEN" http://localhost:8000/api/v1/stats

# View results
check-logs-db:
	@echo "📊 Recent logs in database:"
	docker compose exec postgres psql -U postgres -d log_analysis_db -c "SELECT id, service_name, log_level, LEFT(message, 50) as message, timestamp FROM log_entries ORDER BY timestamp DESC LIMIT 10;"

check-patterns:
	@echo "🔍 Detected patterns:"
	docker compose exec postgres psql -U postgres -d log_analysis_db -c "SELECT pattern_id, LEFT(template, 40) as template, occurrence_count, service_name FROM patterns WHERE is_active = true ORDER BY occurrence_count DESC LIMIT 10;"

check-queues:
	@echo "📬 RabbitMQ queues:"
	docker compose exec rabbitmq rabbitmqctl list_queues name messages