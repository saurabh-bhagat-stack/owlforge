"""Benchmark harness: drive the same assessment with several models, score each,
and emit a compatibility matrix.

Metrics per model: did it drive the loop (turns, tool calls, clean finish), did it
produce findings (filed / validated / rejected), did it hit the known-vuln oracle
(recall), and how long it took. Offloading other models between runs lives HERE (a
test harness), never in the product `run` path.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass

from sqlmodel import select

from owlforge.config import assessments_dir, load_config
from owlforge.engine.agent import run_single_agent
from owlforge.engine.events import Emitter
from owlforge.engine.validate import validate_findings
from owlforge.llm.client import make_client
from owlforge.sandbox import manager
from owlforge.store.db import init_db, session
from owlforge.store.models import Assessment, Event, Finding
from owlforge.tools.builtin import build_registry


@dataclass
class BenchResult:
    model: str
    status: str = "ok"  # ok | error
    turns: int = 0
    tool_calls: int = 0
    llm_errors: int = 0
    filed: int = 0
    validated: int = 0
    rejected: int = 0
    found_oracle: bool | None = None
    finished: bool = False  # agent called finish (vs ran out of turns)
    duration_s: float = 0.0
    error: str = ""
    assessment_id: str = ""


def _free_other_models(base_url: str, keep: str, log) -> None:
    """Offload other loaded Ollama models (bench-only memory discipline)."""
    import httpx

    root = base_url.rstrip("/")
    if root.endswith("/v1"):
        root = root[:-3]
    try:
        loaded = [m.get("name", "") for m in httpx.get(f"{root}/api/ps", timeout=5.0).json().get("models", [])]
    except Exception:
        return
    for name in loaded:
        if name and name != keep:
            try:
                httpx.post(f"{root}/api/generate", json={"model": name, "keep_alive": 0}, timeout=10.0)
                log(f"offloaded {name}")
            except Exception:
                pass


def run_model(
    model: str,
    *,
    mission: str,
    target: str,
    scan_mode: str,
    max_turns: int,
    oracle: str | None,
    offload: bool,
    log,
) -> BenchResult:
    cfg = load_config().model_copy(deep=True)
    cfg.llm.model = model
    target = target or cfg.testing.default_target
    init_db()

    if offload:
        _free_other_models(cfg.llm.base_url, model, log)

    try:
        client = make_client(cfg)
    except Exception as e:
        return BenchResult(model, status="error", error=f"{type(e).__name__}: {e}")

    aid = f"bench_{secrets.token_hex(5)}"
    with session() as s:
        s.add(Assessment(id=aid, project_name="bench", target=target, instructions=mission,
                         scan_mode=scan_mode, status="executing"))
        s.commit()

    emit = Emitter(aid, persist=True, quiet=True)
    sandbox_session = None
    sandbox_client = None
    if cfg.sandbox.enabled and manager.docker_available() and manager.image_exists(cfg.sandbox.image):
        try:
            sandbox_session = manager.start(cfg.sandbox.image, workspace=str(assessments_dir() / aid),
                                             log=lambda m: None)
            sandbox_client = sandbox_session.client
        except Exception as e:
            log(f"sandbox start failed: {e}")

    t0 = time.monotonic()
    err = ""
    try:
        asyncio.run(run_single_agent(
            client=client, registry=build_registry(with_sandbox=sandbox_client is not None),
            emit=emit, assessment_id=aid, target=target, instructions=mission,
            scan_mode=scan_mode, max_turns=max_turns, sandbox=sandbox_client))
        asyncio.run(validate_findings(assessment_id=aid, sandbox=sandbox_client, emit=emit))
    except Exception as e:
        err = f"{type(e).__name__}: {e}"
    finally:
        if sandbox_session:
            manager.stop(sandbox_session, log=lambda m: None)
    dur = round(time.monotonic() - t0, 1)

    with session() as s:
        evs = s.exec(select(Event).where(Event.assessment_id == aid)).all()
        finds = s.exec(select(Finding).where(Finding.assessment_id == aid)).all()

    turns = sum(1 for e in evs if e.type == "status" and e.message.startswith("turn "))
    tool_calls = sum(1 for e in evs if e.type == "tool_call")
    llm_errors = sum(1 for e in evs if e.type == "error")
    finished = any(e.type == "status" and "finished by agent" in e.message for e in evs)
    validated = sum(1 for f in finds if f.status == "validated")
    rejected = sum(1 for f in finds if f.status == "false_positive")
    found_oracle = None
    if oracle:
        found_oracle = any(
            oracle.lower() in (f.title or "").lower() and f.status == "validated" for f in finds
        )

    return BenchResult(
        model=model, status=("error" if err else "ok"), turns=turns, tool_calls=tool_calls,
        llm_errors=llm_errors, filed=len(finds), validated=validated, rejected=rejected,
        found_oracle=found_oracle, finished=finished, duration_s=dur, error=err, assessment_id=aid,
    )


def render_matrix(results: list[BenchResult], oracle: str | None) -> str:
    cols = ["model", "status", "turns", "tools", "finish", "filed", "valid", "rej", "errs", "time(s)"]
    if oracle:
        cols.insert(6, "oracle")
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join(["---"] * len(cols)) + "|"]
    for r in results:
        row = [r.model, r.status, str(r.turns), str(r.tool_calls), "yes" if r.finished else "no",
               str(r.filed), str(r.validated), str(r.rejected), str(r.llm_errors), str(r.duration_s)]
        if oracle:
            row.insert(6, ("HIT" if r.found_oracle else "miss"))
        lines.append("| " + " | ".join(row) + " |")
    return "\n".join(lines)


def run_bench(
    models: list[str],
    *,
    mission: str,
    target: str,
    scan_mode: str = "standard",
    max_turns: int = 16,
    oracle: str | None = None,
    offload: bool = True,
    log=print,
) -> tuple[list[BenchResult], str]:
    results: list[BenchResult] = []
    for i, model in enumerate(models, 1):
        log(f"[bench {i}/{len(models)}] {model} …")
        r = run_model(model, mission=mission, target=target, scan_mode=scan_mode,
                      max_turns=max_turns, oracle=oracle, offload=offload, log=log)
        log(f"[bench {i}/{len(models)}] {model}: status={r.status} turns={r.turns} "
            f"filed={r.filed} validated={r.validated} time={r.duration_s}s"
            + (f" oracle={'HIT' if r.found_oracle else 'miss'}" if oracle else ""))
        results.append(r)
    return results, render_matrix(results, oracle)
