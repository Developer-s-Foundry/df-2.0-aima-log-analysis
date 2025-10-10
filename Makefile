.PHONY: help install dev test lint format clean docker-build docker-up docker-down migrate

help:
	@echo "Log Analysis Service - Available commands:"
	@echo "  install       - Install dependencies"
	@echo "  dev           - Run development server"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linters"
	@echo "  format        - Format code"
	@echo "  clean         - Clean generated files"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-up     - Start Docker services"
	@echo "  docker-down   - Stop Docker services"
	@echo "  migrate       - Run database migrations"

install:
	pip install -r requirements.txt

dev:
	uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

test:
	pytest tests/ -v --cov=app --cov-report=html --cov-report=term

lint:
	flake8 app/ tests/
	mypy app/

format:
	black app/ tests/
	isort app/ tests/

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} +
	rm -rf .pytest_cache .mypy_cache .coverage htmlcov/

docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-down:
	docker-compose down

migrate:
	alembic upgrade head

migrate-create:
	@read -p "Enter migration message: " msg; \
	alembic revision --autogenerate -m "$$msg"
