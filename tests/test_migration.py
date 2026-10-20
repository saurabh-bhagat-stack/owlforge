"""Upgrade migration: reconcile a stale DB with legacy NOT-NULL columns the model dropped
(the engagement->assessment rename left `engagement_id` behind and broke every INSERT)."""

from __future__ import annotations

import sqlite3


def _make_stale_db(path):
    """A minimal pre-rename schema: `finding` with a NOT NULL `engagement_id` + an index on
    it, and `report` with `engagement_id` as the PRIMARY KEY (cannot be DROP COLUMN'd)."""
    c = sqlite3.connect(path)
    c.executescript(
        """
        CREATE TABLE finding (
            id VARCHAR NOT NULL PRIMARY KEY,
            engagement_id VARCHAR NOT NULL,
            title VARCHAR NOT NULL,
            severity VARCHAR, status VARCHAR, confidence VARCHAR
        );
        CREATE INDEX ix_finding_engagement_id ON finding (engagement_id);
        CREATE TABLE report (
            engagement_id VARCHAR NOT NULL PRIMARY KEY,
            status VARCHAR NOT NULL
        );
        INSERT INTO finding (id, engagement_id, title) VALUES ('old1', 'eng1', 'old finding');
        INSERT INTO report (engagement_id, status) VALUES ('eng1', 'ready');
        """
    )
    c.commit()
    c.close()


def test_migration_reconciles_stale_schema(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None

    dbfile = tmp_path / "owlforge.db"
    _make_stale_db(str(dbfile))

    db.init_db()  # should drop finding.engagement_id and rebuild report

    c = sqlite3.connect(str(dbfile))
    fcols = [r[1] for r in c.execute("PRAGMA table_info(finding)")]
    rcols = [r[1] for r in c.execute("PRAGMA table_info(report)")]
    assert "engagement_id" not in fcols and "assessment_id" in fcols
    assert "engagement_id" not in rcols and "assessment_id" in rcols
    c.close()

    # the inserts that used to fail now succeed
    from owlforge.store.models import Assessment, Finding, Report
    with db.session() as s:
        s.add(Assessment(id="a1", project_name="p", target="t", instructions="x", scan_mode="m"))
        s.commit()
        s.add(Finding(id="f1", assessment_id="a1", title="Missing CSP",
                      severity="low", status="candidate"))
        s.add(Report(assessment_id="a1", status="ready", executive_summary="s",
                     risk_rating="Low", body_markdown="#"))
        s.commit()
