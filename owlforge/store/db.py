"""SQLite engine + session helpers."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

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
    SQLModel.metadata.create_all(get_engine())


@contextmanager
def session() -> Iterator[Session]:
    with Session(get_engine()) as s:
        yield s
