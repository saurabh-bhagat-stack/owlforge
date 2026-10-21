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
        # check_same_thread=False: the live TUI reads findings on the UI thread while the
        # scan writes from a worker thread; SQLite still serialises access internally.
        _engine = create_engine(f"sqlite:///{db_path()}", echo=False,
                                connect_args={"check_same_thread": False})
    return _engine


def init_db() -> None:
    engine = get_engine()
    SQLModel.metadata.create_all(engine)  # create any missing tables
    _migrate_add_columns(engine)  # additive migration: add new columns to existing tables
    _migrate_drop_breaking_orphans(engine)  # drop legacy NOT-NULL columns the model dropped


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


def _breaking_orphans(insp, table) -> list[dict]:
    """Columns in the DB table but not in the model that are NOT NULL without a default —
    these make every INSERT fail."""
    model_cols = {c.name for c in table.columns}
    return [c for c in insp.get_columns(table.name)
            if c["name"] not in model_cols
            and not c.get("nullable", True) and c.get("default") is None]


def _migrate_drop_breaking_orphans(engine) -> None:
    """Reconcile an older DB whose tables carry NOT-NULL columns the current model dropped
    (e.g. the legacy `engagement_id` left over from the engagement->assessment rename) —
    otherwise every INSERT fails. First try DROP COLUMN (after removing any dependent index);
    if a breaking orphan survives because it is the primary key (SQLite cannot drop a PK
    column), rebuild the table from the model schema. Best-effort; never blocks startup."""
    insp = _sa_inspect(engine)
    tables = set(insp.get_table_names())
    for table in SQLModel.metadata.sorted_tables:
        if table.name not in tables:
            continue
        for col in _breaking_orphans(insp, table):
            dep_indexes = [ix["name"] for ix in insp.get_indexes(table.name)
                           if col["name"] in (ix.get("column_names") or [])]
            try:
                with engine.begin() as conn:
                    for ix_name in dep_indexes:
                        if ix_name:
                            conn.execute(_sa_text(f'DROP INDEX IF EXISTS "{ix_name}"'))
                    conn.execute(_sa_text(
                        f'ALTER TABLE "{table.name}" DROP COLUMN "{col["name"]}"'))
            except Exception:
                pass  # e.g. a PK column — handled by the rebuild below
        # if a breaking orphan remains (PK column), rebuild the table to the model schema
        insp2 = _sa_inspect(engine)
        if _breaking_orphans(insp2, table):
            _rebuild_table_to_model(engine, insp2, table)


def _rebuild_table_to_model(engine, insp, table) -> None:
    """Rebuild a stale table to the model schema: rename old -> recreate from the model ->
    copy rows that satisfy the new primary key -> drop the old. Rows incompatible with the
    new schema (e.g. a NULL new-PK) are dropped; report/derived data regenerates."""
    name = table.name
    tmp = f"{name}__owl_migrate_old"
    old_cols = {c["name"] for c in insp.get_columns(name)}
    model_col_names = [c.name for c in table.columns]
    shared = [c for c in model_col_names if c in old_cols]
    pk_cols = [c.name for c in table.primary_key.columns if c.name in old_cols]
    try:
        with engine.begin() as conn:
            for ix in insp.get_indexes(name):
                if ix.get("name"):
                    conn.execute(_sa_text(f'DROP INDEX IF EXISTS "{ix["name"]}"'))
            conn.execute(_sa_text(f'ALTER TABLE "{name}" RENAME TO "{tmp}"'))
        table.create(engine)  # recreate with the correct (model) schema
        with engine.begin() as conn:
            if shared:
                cols_sql = ", ".join(f'"{c}"' for c in shared)
                where = " AND ".join(f'"{c}" IS NOT NULL' for c in pk_cols) or "1=1"
                conn.execute(_sa_text(
                    f'INSERT OR IGNORE INTO "{name}" ({cols_sql}) '
                    f'SELECT {cols_sql} FROM "{tmp}" WHERE {where}'))
            conn.execute(_sa_text(f'DROP TABLE "{tmp}"'))
    except Exception:
        pass  # never block startup; worst case the stale table is left as-is


@contextmanager
def session() -> Iterator[Session]:
    with Session(get_engine()) as s:
        yield s
