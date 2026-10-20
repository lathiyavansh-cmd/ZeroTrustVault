"""SQLAlchemy 2 async engine/session; tables are created at startup (no migrations in this dev stack)."""
from __future__ import annotations

from typing import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import settings
from .models import Base

engine = create_async_engine(settings.DATABASE_URL, pool_pre_ping=True, pool_size=settings.DB_POOL_SIZE, max_overflow=settings.DB_MAX_OVERFLOW)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def init_db() -> None:
    from sqlalchemy import text

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.execute(text("INSERT INTO audit_chain_head (id, seq, head_hash, last_checkpoint_seq, last_checkpoint_at) VALUES (1, 0, NULL, 0, NULL) ON CONFLICT (id) DO NOTHING"))


async def get_db() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session
