"""SQLite engine + session helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import inspect as _sa_inspect
from sqlalchemy import text as _sa_text
from sqlmodel import Session, SQLModel, create_engine

from owlforge.config import db_path, owlforge_home
from owlforge.store import models  # noqa: F401  (import registers tables)

_engine = None


def get_engine():
    global _engine
    if _engine is None:
        owlforge_home().mkdir(parents=True, exist_ok=True)
        _engine = create_engine(f"sqlite:///{db_path()}", echo=False)
    return _engine


def init_db() -> None:
    engine = get_engine()
    SQLModel.metadata.create_all(engine)  # create any missing tables
    _migrate_add_columns(engine)  # additive migration: add new columns to existing tables


def _migrate_add_columns(engine) -> None:
    """Lightweight forward migration: add columns a newer model defines but an existing
    table lacks (prevents the "no such column" crash when upgrading owlforge over an
    older DB). Additive only — existing rows get NULL for the new column."""
    insp = _sa_inspect(engine)
    tables = set(insp.get_table_names())
    for table in SQLModel.metadata.sorted_tables:
        if table.name not in tables:
            continue
        have = {c['name'] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name not in have:
                try:
                    with engine.begin() as conn:
                        conn.execute(_sa_text(f'ALTER TABLE "{table.name}" ADD COLUMN "{col.name}"'))
                except Exception:
                    pass  # best-effort; never block startup on migration



@contextmanager
def session() -> Iterator[Session]:
    with Session(get_engine()) as s:
        yield s
