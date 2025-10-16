"""Database session management."""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool, QueuePool

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.base import Base

logger = get_logger(__name__)

# Global engine and session factory
engine = None
async_session_factory = None


def init_db() -> None:
    """
    Initialize database engine and session factory.

    Creates async engine with connection pooling and configures session factory.
    """
    global engine, async_session_factory

    settings = get_settings()

    # Configure connection pool based on environment
    if settings.is_production:
        # Production: Use connection pooling
        engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            poolclass=QueuePool,
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            pool_timeout=settings.database_pool_timeout,
            pool_recycle=settings.database_pool_recycle,
            pool_pre_ping=True,  # Enable connection health checks
            connect_args={
                "server_settings": {"application_name": settings.app_name},
                "timeout": 30,
            },
        )
        logger.info(
            "database_initialized",
            pool_size=settings.database_pool_size,
            max_overflow=settings.database_max_overflow,
            environment=settings.environment,
        )
    else:
        # Development: No pooling for easier debugging
        engine = create_async_engine(
            settings.database_url,
            echo=settings.debug,
            poolclass=NullPool,  # NullPool doesn't accept pool_size, max_overflow, etc.
            pool_pre_ping=True,
            connect_args={
                "server_settings": {"application_name": settings.app_name},
                "timeout": 30,
            },
        )
        logger.info(
            "database_initialized",
            pool_class="NullPool",
            environment=settings.environment,
        )

    # Create session factory
    async_session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency to get database session.

    Yields:
        AsyncSession instance

    Usage:
        @app.get("/endpoint")
        async def endpoint(db: AsyncSession = Depends(get_db)):
            ...
    """
    if async_session_factory is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def close_db() -> None:
    """Close database connections and dispose of engine."""
    if engine is not None:
        await engine.dispose()
        logger.info("database_connections_closed")


async def create_tables() -> None:
    """Create all database tables. Use only in development or for testing."""
    if engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        logger.info("database_tables_created")


async def drop_tables() -> None:
    """Drop all database tables. Use only in development or for testing."""
    if engine is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        logger.warning("database_tables_dropped")
