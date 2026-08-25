"""Test suite for InterruptGPT.

Run with:  INTERRUPTGPT_DISABLE_LLM=1 pytest -q
The env var keeps the LLM backend deterministic so assertions are stable.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("INTERRUPTGPT_DISABLE_LLM", "1")
os.environ.setdefault("INTERRUPTGPT_SEMANTIC_EMBEDDINGS", "0")

from app.analyzer.rules import analyze  # noqa: E402
from app.core.models import AnalysisRequest, EventKind, Severity  # noqa: E402
from app.core.pipeline import run_analysis  # noqa: E402
from app.llm.providers import TemplateProvider  # noqa: E402
from app.parsers.dmesg_parser import parse_dmesg  # noqa: E402
from app.parsers.proc_interrupts_parser import parse_proc_interrupts  # noqa: E402
from app.rag.retriever import KnowledgeBase, load_documents  # noqa: E402

DATASETS = Path(__file__).resolve().parents[1] / "datasets" / "sample_logs"


def read(name: str) -> str:
    return (DATASETS / name).read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def kb() -> KnowledgeBase:
    return KnowledgeBase(load_documents(), prefer_semantic=False)


# ---------------------------------------------------------------- parsers
class TestDmesgParser:
    def test_detects_nobody_cared_with_irq(self):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        nobody = [e for e in events if e.kind is EventKind.NOBODY_CARED]
        assert len(nobody) == 1
        assert nobody[0].irq == 16
        assert nobody[0].severity is Severity.CRITICAL

    def test_detects_disabling_irq(self):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        disabled = [e for e in events if e.kind is EventKind.IRQ_DISABLED]
        assert len(disabled) == 1
        assert disabled[0].irq == 16

    def test_attaches_handlers_to_preceding_event(self):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        handlers = {e.handler for e in events if e.handler}
        assert "ahci_interrupt" in handlers
        assert "usb_hcd_irq" in handlers

    def test_derives_driver_from_handler_symbol(self):
        events = parse_dmesg("[<ffffffff810f0f70>] ahci_interrupt")
        assert events[0].driver == "ahci"

    def test_parses_boot_timestamp(self):
        events = parse_dmesg("[  312.774519] irq 16: nobody cared")
        assert events[0].timestamp == pytest.approx(312.774519)

    def test_handles_syslog_prefix(self):
        line = "Mar 14 09:12:01 host kernel: irq 16: nobody cared"
        events = parse_dmesg(line)
        assert events[0].kind is EventKind.NOBODY_CARED
        assert events[0].irq == 16

    def test_detects_msi_failure(self):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        assert any(e.kind is EventKind.MSI_FAILURE for e in events)

    def test_detects_storm(self):
        events = parse_dmesg(read("dmesg_storm.log"))
        assert any(e.kind is EventKind.IRQ_STORM and e.irq == 19 for e in events)

    def test_ignores_irrelevant_lines(self):
        events = parse_dmesg("[    0.000000] Linux version 6.1.0\n[ 0.1 ] Booting")
        assert events == []

    def test_empty_input(self):
        assert parse_dmesg("") == []


class TestProcInterruptsParser:
    def test_parses_cpu_columns(self):
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        irq16 = next(c for c in counters if c.irq == "16")
        assert irq16.per_cpu_counts == [418922, 112, 98, 104]
        assert irq16.total == 419236

    def test_detects_shared_actions(self):
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        irq16 = next(c for c in counters if c.irq == "16")
        assert irq16.is_shared
        assert "ahci" in irq16.actions
        assert "eth0" in irq16.actions

    def test_non_shared_line(self):
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        irq18 = next(c for c in counters if c.irq == "18")
        assert not irq18.is_shared

    def test_symbolic_rows_preserved(self):
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        err = next(c for c in counters if c.irq == "ERR")
        assert err.total == 1847
        assert err.irq_number is None

    def test_chip_and_kind(self):
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        nvme = next(c for c in counters if c.irq == "24")
        assert nvme.chip == "PCI-MSI"

    def test_empty_input(self):
        assert parse_proc_interrupts("") == []

    def test_handles_missing_header(self):
        text = " 16:   100   200  IO-APIC  16-fasteoi  ahci"
        counters = parse_proc_interrupts(text)
        assert counters[0].irq == "16"
        assert counters[0].per_cpu_counts == [100, 200]


# ---------------------------------------------------------------- analyzer
class TestAnalyzer:
    def test_flags_nobody_cared_as_critical(self):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        findings = analyze(events, counters)
        top = findings[0]
        assert top.rule_id == "IRQ_NOBODY_CARED"
        assert top.severity is Severity.CRITICAL
        assert top.irq == 16

    def test_confidence_boosted_by_corroborating_evidence(self):
        """Sharing + disabling should score higher than the bare message alone."""
        bare = analyze(parse_dmesg("[ 1.0 ] irq 16: nobody cared"), [])
        rich = analyze(
            parse_dmesg(read("dmesg_shared_irq.log")),
            parse_proc_interrupts(read("interrupts_shared.txt")),
        )
        bare_conf = next(f for f in bare if f.rule_id == "IRQ_NOBODY_CARED").confidence
        rich_conf = next(f for f in rich if f.rule_id == "IRQ_NOBODY_CARED").confidence
        assert rich_conf > bare_conf

    def test_confidence_never_exceeds_one(self):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        for f in analyze(events, counters):
            assert 0.0 <= f.confidence <= 1.0

    def test_never_claims_absolute_certainty(self):
        """A triage tool working from partial evidence must not report 100%."""
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        for f in analyze(events, counters):
            assert f.confidence <= 0.95

    def test_storm_confirmed_only_by_explicit_log_message(self):
        """Cumulative counters alone must not produce a CRITICAL storm verdict."""
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        findings = analyze([], counters)
        confirmed = [f for f in findings if f.rule_id == "IRQ_STORM"]
        assert not confirmed, "counter dominance alone should not confirm a storm"

    def test_storm_candidate_states_its_limitation(self):
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        findings = analyze([], counters)
        candidates = [f for f in findings if f.rule_id == "IRQ_STORM_CANDIDATE"]
        assert candidates
        assert candidates[0].severity is Severity.WARNING
        assert any("cumulative" in ev.lower() for ev in candidates[0].evidence)

    def test_logged_storm_is_critical(self):
        events = parse_dmesg(read("dmesg_storm.log"))
        findings = analyze(events, [])
        storm = next(f for f in findings if f.rule_id == "IRQ_STORM")
        assert storm.severity is Severity.CRITICAL
        assert storm.irq == 19

    def test_detects_shared_conflict(self):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        findings = analyze(events, counters)
        assert any(f.rule_id == "IRQ_SHARED_CONFLICT" for f in findings)

    def test_detects_msi_failure(self):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        findings = analyze(events, [])
        assert any(f.rule_id == "MSI_ALLOCATION_FAILURE" for f in findings)

    def test_detects_affinity_imbalance(self):
        counters = parse_proc_interrupts(read("interrupts_affinity.txt"))
        findings = analyze([], counters)
        imbalance = [f for f in findings if f.rule_id == "IRQ_AFFINITY_IMBALANCE"]
        assert imbalance and imbalance[0].irq == 19

    def test_balanced_irq_not_flagged(self):
        counters = parse_proc_interrupts(read("interrupts_affinity.txt"))
        findings = analyze([], counters)
        flagged = {f.irq for f in findings if f.rule_id == "IRQ_AFFINITY_IMBALANCE"}
        assert 24 not in flagged

    def test_err_counter_flagged(self):
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        findings = analyze([], counters)
        assert any(f.rule_id == "APIC_ERROR_COUNTER" for f in findings)

    def test_zero_err_not_flagged(self):
        counters = parse_proc_interrupts(read("interrupts_affinity.txt"))
        findings = analyze([], counters)
        assert not any(f.rule_id == "APIC_ERROR_COUNTER" for f in findings)

    def test_clean_system_yields_no_findings(self):
        text = "           CPU0       CPU1\n  1:   9   0   IO-APIC  1-edge  i8042\nERR:  0\n"
        assert analyze([], parse_proc_interrupts(text)) == []

    def test_findings_sorted_critical_first(self):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        findings = analyze(events, counters)
        severities = [f.severity for f in findings]
        assert severities[0] is Severity.CRITICAL
        # No critical may appear after a warning.
        first_warning = next(
            (i for i, s in enumerate(severities) if s is Severity.WARNING), len(severities)
        )
        assert all(s is not Severity.CRITICAL for s in severities[first_warning:])


# ---------------------------------------------------------------- RAG
class TestKnowledgeBase:
    def test_indexes_all_documents(self, kb):
        assert len(kb.docs) >= 8

    def test_search_returns_relevant_doc(self, kb):
        results = kb.search("shared interrupt line IRQF_SHARED conflict", k=3)
        assert results
        assert any("shared" in r.title.lower() for r in results)

    def test_search_respects_k(self, kb):
        assert len(kb.search("interrupt", k=2)) <= 2

    def test_empty_query_returns_nothing(self, kb):
        assert kb.search("   ") == []

    def test_finding_driven_retrieval_deduplicates(self, kb):
        events = parse_dmesg(read("dmesg_shared_irq.log"))
        counters = parse_proc_interrupts(read("interrupts_shared.txt"))
        findings = analyze(events, counters)
        refs = kb.search_for_findings(findings)
        assert refs
        assert len({r.doc_id for r in refs}) == len(refs)


# ---------------------------------------------------------------- pipeline
class TestPipeline:
    def test_end_to_end_produces_report(self, kb):
        req = AnalysisRequest(
            dmesg=read("dmesg_shared_irq.log"),
            proc_interrupts=read("interrupts_shared.txt"),
        )
        result = run_analysis(req, kb, TemplateProvider())
        assert result.findings
        assert result.references
        assert "Interrupt Incident Report" in result.report_markdown
        assert "Root Cause Analysis" in result.report_markdown
        assert result.findings[0].title in result.report_markdown

    def test_clean_input_reports_no_anomalies(self, kb):
        req = AnalysisRequest(proc_interrupts="ERR:  0\n")
        result = run_analysis(req, kb, TemplateProvider())
        assert result.findings == []
        assert "No interrupt anomalies" in result.narrative

    def test_narrative_is_grounded_in_top_finding(self, kb):
        req = AnalysisRequest(dmesg=read("dmesg_shared_irq.log"))
        result = run_analysis(req, kb, TemplateProvider())
        assert str(result.findings[0].confidence_pct) in result.narrative


# ---------------------------------------------------------------- API
class TestAPI:
    @pytest.fixture(scope="class")
    @classmethod
    def client(cls):
        from app.main import app
        from fastapi.testclient import TestClient

        return TestClient(app)

    def test_health(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_analyze(self, client):
        r = client.post(
            "/api/analyze",
            json={
                "dmesg": read("dmesg_shared_irq.log"),
                "proc_interrupts": read("interrupts_shared.txt"),
            },
        )
        assert r.status_code == 200
        body = r.json()
        assert body["findings"][0]["rule_id"] == "IRQ_NOBODY_CARED"
        assert body["findings"][0]["irq"] == 16

    def test_analyze_requires_input(self, client):
        r = client.post("/api/analyze", json={"dmesg": "", "proc_interrupts": ""})
        assert r.status_code == 422

    def test_upload(self, client):
        r = client.post(
            "/api/analyze/upload",
            files={
                "dmesg_file": ("dmesg.log", read("dmesg_shared_irq.log"), "text/plain"),
                "interrupts_file": (
                    "interrupts.txt",
                    read("interrupts_shared.txt"),
                    "text/plain",
                ),
            },
        )
        assert r.status_code == 200
        assert r.json()["findings"]

    def test_upload_requires_a_file(self, client):
        assert client.post("/api/analyze/upload").status_code == 422

    def test_chat(self, client):
        r = client.post(
            "/api/chat", json={"question": "Why was IRQ 16 disabled?"}
        )
        assert r.status_code == 200
        assert r.json()["answer"]
        assert r.json()["references"]

    def test_chat_rejects_empty_question(self, client):
        assert client.post("/api/chat", json={"question": "  "}).status_code == 422

    def test_search(self, client):
        r = client.get("/api/search", params={"q": "MSI vectors", "k": 3})
        assert r.status_code == 200
        assert 1 <= len(r.json()) <= 3

    def test_search_rejects_empty_query(self, client):
        assert client.get("/api/search", params={"q": " "}).status_code == 422
