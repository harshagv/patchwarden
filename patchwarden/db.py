"""Database engine and session handling. SQLite in dev, PostgreSQL in production."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import create_engine, event, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(database_url: str) -> Engine:
    if database_url.startswith("sqlite"):
        kwargs: dict = {"connect_args": {"check_same_thread": False}}
        if database_url in {"sqlite://", "sqlite:///:memory:"}:
            kwargs["poolclass"] = StaticPool
        else:
            Path(database_url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(database_url, **kwargs)

        @event.listens_for(engine, "connect")
        def _sqlite_fk_on(dbapi_conn, _record):  # pragma: no cover - driver hook
            dbapi_conn.execute("PRAGMA foreign_keys=ON")

        return engine
    return create_engine(database_url, pool_pre_ping=True)


def create_schema(engine: Engine) -> None:
    """Create missing tables, and add new nullable columns to existing tables.

    This keeps a dev database from an earlier phase working. It never drops or
    changes a column; real schema migrations are listed under README "Future ideas".
    """
    Base.metadata.create_all(engine)
    inspector = inspect(engine)
    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            existing = {c["name"] for c in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name not in existing and column.nullable:
                    ddl = column.type.compile(dialect=engine.dialect)
                    conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {column.name} {ddl}'))


def make_sessionmaker(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def session_scope(factory: sessionmaker[Session]) -> Iterator[Session]:
    session = factory()
    try:
        yield session
    finally:
        session.close()
