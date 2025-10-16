"""API routes and endpoints."""

from fastapi import APIRouter

from app.api import health, logs

api_router = APIRouter()

api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(logs.router, prefix="/api/v1", tags=["logs"])
