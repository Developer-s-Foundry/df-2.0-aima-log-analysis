# Log Analysis System Microservice

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.109.0-green.svg)](https://fastapi.tiangolo.com)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A production-ready Python microservice for intelligent log analysis, pattern detection, and anomaly identification. Part of the Developer Foundry 2.0 (AIMA) ecosystem.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Configuration](#configuration)
- [Running the Application](#running-the-application)
  - [Using Docker (Recommended)](#using-docker-recommended)
  - [Local Development](#local-development)
- [Testing](#testing)
- [API Documentation](#api-documentation)
- [Monitoring](#monitoring)
- [Contributing](#contributing)
- [Team](#team)

## Overview

The Log Analysis System is a microservice designed to analyze, interpret, and summarize logs from all services within the Developer Foundry 2.0 (AIMA) ecosystem. It provides:

- **Real-time log ingestion** from RabbitMQ queues
- **Intelligent pattern detection** using template-based clustering
- **ML-based anomaly detection** using Isolation Forest algorithm
- **Automated error analysis** and summarization
- **Integration with Recommendation and Alert systems**
- **Prometheus metrics** for observability

**Tech Stack:**
- Python 3.11+
- FastAPI (async web framework)
- PostgreSQL (database)
- RabbitMQ (message broker)
- SQLAlchemy (async ORM)
- Prometheus (metrics)
- Docker & Docker Compose

## Features

### Core Capabilities

✅ **Log Ingestion**
- Consumes structured JSON messages from RabbitMQ
- Validates and normalizes log entries
- Stores logs in PostgreSQL with full metadata

✅ **Pattern Detection**
- Identifies recurring log patterns
- Template-based message normalization
- Frequency-based pattern clustering

✅ **Anomaly Detection**
- ML-based anomaly identification (Isolation Forest)
- Configurable anomaly thresholds
- Real-time anomaly scoring

✅ **Error Analysis**
- Common error extraction
- Error rate calculation
- Severity scoring

✅ **Insights & Recommendations**
- Automated summary generation
- Publishes insights to Recommendation System (Team E)
- Sends high-severity alerts to Alert System (Team A)

✅ **Security**
- JWT-based authentication
- API Gateway integration (Team G)
- Secure password hashing

✅ **Observability**
- Prometheus metrics endpoint
- Structured logging (JSON in production)
- Health check endpoints

## Architecture

```
┌─────────────────┐
│   Log Mgmt (B)  │ ──── log_analysis_queue ────┐
└─────────────────┘                              │
                                                 ▼
                                    ┌────────────────────────┐
                                    │  Log Analysis Service  │
                                    │  • Ingestion           │
                                    │  • Pattern Detection   │
                                    │  • Anomaly Detection   │
                                    │  • Analysis Engine     │
                                    └────────┬───────────────┘
                                             │
                    ┌────────────────────────┴─────────────────┐
                    │                                           │
          recommendation_queue                         alerts_queue
                    │                                           │
                    ▼                                           ▼
        ┌───────────────────┐                    ┌──────────────────┐
        │  Recommendations  │                    │   Alerts (A)     │
        │       (E)         │                    └──────────────────┘
        └───────────────────┘
```

**Processing Pipeline:**
1. Consume logs from `log_analysis_queue` (RabbitMQ)
2. Parse and validate message structure
3. Store in PostgreSQL database
4. Analyze for patterns and anomalies
5. Generate insights and summaries
6. Publish results to downstream services
7. Expose metrics for monitoring

## Getting Started

### Prerequisites

Ensure you have the following installed:

- **Python 3.11+** - [Download](https://www.python.org/downloads/)
- **Docker** - [Download](https://www.docker.com/get-started)
- **Docker Compose** - Included with Docker Desktop
- **Git** - [Download](https://git-scm.com/downloads)

Optional for local development:
- PostgreSQL 15+
- RabbitMQ 3.12+

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/Developer-s-Foundry/df-2.0-aima-log-analysis
cd df-2.0-aima-log-analysis
```

2. **Create environment file:**

```bash
cp .env.example .env
```

3. **Install Python dependencies:**

```bash
pip install -r requirements.txt
```

### Configuration

Edit the `.env` file to configure the service:

See `.env.example` for all available configuration options.

## Running the Application

### Using Docker (Recommended)

This is the easiest way to get started. Docker Compose will start all required services:

1. **Start all services:**

```bash
docker compose up -d
```

This starts:
- PostgreSQL database (port 5432)
- RabbitMQ with management UI (ports 5672, 15672)
- Log Analysis Service (port 8000)
- Prometheus (port 9091)

2. **Check service health:**

```bash
# View logs
docker compose logs -f log_analysis_service

# Check health endpoint
curl http://localhost:8000/health/
```

3. **Run database migrations:**

```bash
docker compose exec log_analysis_service alembic upgrade head
```

4. **Stop services:**

```bash
docker compose down
```

**Quick commands using Makefile:**

```bash
make docker-build    # Build Docker image
make docker-up       # Start all services
make docker-down     # Stop all services
```

### Local Development

For development with hot-reload:

1. **Start PostgreSQL and RabbitMQ:**

```bash
docker compose up -d postgres rabbitmq
```

2. **Run database migrations:**

```bash
alembic upgrade head
```

3. **Start the development server:**

```bash
# Using uvicorn directly
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# Or using Make
make dev
```

The API will be available at `http://localhost:8000` with auto-reload enabled.

## Testing

### Running Tests

```bash
# Run all tests with coverage
pytest tests/ -v --cov=app --cov-report=html --cov-report=term

# Or using Make
make test
```

### Run Linting

```bash
# Run flake8
flake8 app/ tests/

# Run mypy type checking
mypy app/

# Or using Make
make lint
```

### Format Code

```bash
# Format with black
black app/ tests/

# Sort imports with isort
isort app/ tests/

# Or using Make
make format
```

### Pre-commit Hooks

Install pre-commit hooks to automatically format and lint code:

```bash
pre-commit install
```

## API Documentation

Once the service is running, access the interactive API documentation:

### Swagger UI
**URL:** `http://localhost:8000/docs`

Interactive API documentation with "Try it out" functionality.

### ReDoc
**URL:** `http://localhost:8000/redoc`

Alternative API documentation with a clean, readable interface.

### Key Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/health/` | Health check | No |
| GET | `/health/ready` | Readiness check (DB connectivity) | No |
| GET | `/` | Root endpoint | No |
| GET | `/api/v1/logs` | List logs with filtering | Yes (JWT) |
| GET | `/api/v1/logs/{id}` | Get specific log entry | Yes (JWT) |
| GET | `/api/v1/logs/summary` | Get aggregated analysis summary | Yes (JWT) |
| GET | `/metrics` | Prometheus metrics | No |

### Authentication

API endpoints require JWT authentication. Include the token in the Authorization header:

```bash
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
     http://localhost:8000/api/v1/logs
```

### Example Requests

**Get logs for a specific service:**

```bash
curl -X GET "http://localhost:8000/api/v1/logs?service_name=auth_service&log_level=ERROR&page=1&page_size=50" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Get analysis summary:**

```bash
curl -X GET "http://localhost:8000/api/v1/logs/summary?service_name=auth_service" \
     -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

**Response Example:**

```json
{
  "data": {
    "service": "auth_service",
    "total_logs": 230,
    "error_rate": 12.3,
    "common_errors": ["Database timeout", "JWT expired"],
    "anomalies_detected": 3,
    "recommendations": ["Increase connection pool", "Review JWT expiration"]
  },
  "status_code": 200,
  "message": "Log summary retrieved successfully"
}
```

## Monitoring

### Accessing Services

| Service | URL | Credentials |
|---------|-----|-------------|
| API Docs | http://localhost:8000/docs | N/A |
| Health Check | http://localhost:8000/health/ | N/A |
| Prometheus Metrics | http://localhost:8000/metrics | N/A |
| RabbitMQ Management | http://localhost:15672 | guest/guest |
| Prometheus UI | http://localhost:9091 | N/A |

### Prometheus Metrics

The service exposes the following metrics at `/metrics`:

- `logs_ingested_total` - Total logs ingested (by service, level)
- `logs_processed_total` - Successfully processed logs
- `logs_failed_total` - Failed log processing attempts
- `anomalies_detected_total` - Anomalies detected
- `patterns_detected_total` - Patterns detected
- `messages_consumed_total` - RabbitMQ messages consumed
- `messages_published_total` - RabbitMQ messages published
- `api_requests_total` - API requests (by method, endpoint, status)
- `api_request_duration_seconds` - API request latency
- `active_consumers` - Active RabbitMQ consumers
- `unprocessed_logs` - Unprocessed logs in queue

### Logs

**View application logs:**

```bash
# Docker
docker compose logs -f log_analysis_service

## Database Migrations

### Create a New Migration

```bash
alembic revision --autogenerate -m "Description of changes"

# Or using Make
make migrate-create
```

### Apply Migrations

```bash
alembic upgrade head

# Or using Make
make migrate
```

### Rollback Migration

```bash
alembic downgrade -1
```

## Development Workflow

1. **Create a feature branch:**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes and test:**
   ```bash
   make test
   make lint
   ```

3. **Format code:**
   ```bash
   make format
   ```

4. **Commit changes:**
   ```bash
   git add .
   git commit -m "feat: your feature description"
   ```

5. **Push and create PR:**
   ```bash
   git push origin feature/your-feature-name
   ```

## Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Check what's using the port
lsof -i :8000

# Kill the process or change the port in .env
PORT=8001
```

**Database connection errors:**
```bash
# Ensure PostgreSQL is running
docker compose ps postgres

# Check connection string in .env
DATABASE_URL=postgresql+asyncpg://postgres:password@localhost:5432/log_analysis_db
```

**RabbitMQ connection errors:**
```bash
# Ensure RabbitMQ is running
docker compose ps rabbitmq

# Check RabbitMQ logs
docker compose logs rabbitmq
```

**Migration errors:**
```bash
# Reset database (development only!)
docker compose down -v
docker compose up -d postgres
alembic upgrade head
```

## Performance

**Design Targets:**
- Throughput: ≥ 10,000 logs/minute
- Latency: ≤ 2 seconds per batch
- Uptime: ≥ 99.9%
- Pattern Detection Precision: ≥ 90%
- Anomaly Alert Reliability: ≥ 95%

**Optimizations:**
- Async I/O throughout
- Database connection pooling
- Batch processing
- Efficient indexing
- Caching where appropriate

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Ensure all tests pass
6. Submit a pull request

### Code Style

- Follow PEP 8 guidelines
- Use type hints
- Write docstrings for all functions
- Format with Black (line length 100)
- Sort imports with isort

## Team

**Developer Foundry 2.0 (AIMA) - Team F**

- Samuel Ogboye
- Nasiff Bello
- Daniel Kiyiki

## License

This project is part of the Developer Foundry 2.0 (AIMA) ecosystem.

## Support

For issues, questions, or contributions, please:
- Open an issue on GitHub
- Contact the development team
- Check the documentation in `/docs`

---

**Built with ❤️ by Team F**
