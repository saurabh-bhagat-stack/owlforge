"""HTML + SARIF report export."""

from __future__ import annotations


def _seed(tmp_path, monkeypatch):
    import owlforge.config as config
    import owlforge.store.db as db
    monkeypatch.setenv("OWLFORGE_HOME", str(tmp_path))
    config.load_config.cache_clear()
    db._engine = None
    db.init_db()
    from owlforge.store.models import Assessment, Finding
    with db.session() as s:
        s.add(Assessment(id="asmt_x", project_name="p", target="https://t.example", instructions="assess", scan_mode="orchestrate"))
        s.add(Finding(id="f1", assessment_id="asmt_x",
                      title="SQL injection (error-based) in 'category'",
                      severity="high", status="validated", confidence="high",
                      endpoint="/catalog?category=x", method="GET",
                      validation_note="reproduced (500)", impact="DB read",
                      remediation="parameterize", proof_of_concept="category=x'"))
        s.add(Finding(id="f2", assessment_id="asmt_x", title="Missing CSP header",
                      severity="low", status="candidate", endpoint="/",
                      validation_note="no Content-Security-Policy"))
        s.add(Finding(id="f3", assessment_id="asmt_x", title="Reflected XSS",
                      severity="medium", status="false_positive", endpoint="/search"))
        s.commit()
    return db


def test_sarif_shape_and_cwe_mapping(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    from owlforge.report.export import to_sarif
    sarif, path = to_sarif("asmt_x")
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "owlforge"
    # only the validated finding becomes a result (not candidate/false-positive)
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["level"] == "error"            # high -> error
    assert res["ruleId"] == "sql-injection"
    rule = {r["id"]: r for r in run["tool"]["driver"]["rules"]}["sql-injection"]
    assert rule["properties"]["cwe"] == "CWE-89"
    assert "A03:2021-Injection" in rule["properties"]["owasp"]
    assert path and path.endswith("report.sarif.json")


def test_html_renders_and_escapes(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    from owlforge.report.export import to_html
    page, path = to_html("asmt_x")
    assert "<!doctype html>" in page.lower()
    assert "SQL injection (error-based)" in page
    assert "CWE-89" in page                     # derived tag shown
    assert "Missing CSP header" in page         # candidate listed
    assert "Validated: 1" in page and "Candidates: 1" in page and "Rejected: 1" in page
    assert path and path.endswith("report.html")


def test_builder_emits_all_three(tmp_path, monkeypatch):
    _seed(tmp_path, monkeypatch)
    from owlforge.config import assessments_dir
    from owlforge.report.builder import build_and_save_report
    build_and_save_report("asmt_x")
    d = assessments_dir() / "asmt_x"
    assert (d / "report.md").exists()
    assert (d / "report.html").exists()
    assert (d / "report.sarif.json").exists()
