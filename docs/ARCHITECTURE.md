# Architecture

This document covers how the pieces fit together and how to extend them.

## Request lifecycle

```
POST /api/analyze
  │
  ├─ parse_dmesg(text)                → list[InterruptEvent]
  ├─ parse_proc_interrupts(text)      → list[IrqCounter]
  │
  ├─ analyze(events, counters)        → list[Finding]      (deterministic)
  │
  ├─ kb.search_for_findings(findings) → list[RetrievedDoc] (finding-steered)
  │
  ├─ provider.generate(prompt)        → narrative          (or grounded fallback)
  │
  └─ build_report(...)                → markdown report
```

Each layer depends only on the domain models in `core/models.py`, so any stage can be
swapped or tested in isolation.

## Layer responsibilities

| Layer | Responsibility | Never does |
|---|---|---|
| `parsers/` | Text → structured events | Interpretation or judgement |
| `analyzer/` | Events → scored findings | I/O, network, model calls |
| `rag/` | Findings/questions → documents | Diagnosis |
| `llm/` | Findings + docs → prose | Producing findings or scores |
| `reports/` | Everything → markdown | Analysis |

The strict separation is what makes the system work without an LLM: only the `llm/` layer
is optional, and `compose_fallback_narrative()` substitutes for it using the same
structured inputs.

---

## Adding a new rule

1. Write the rule function in `backend/app/analyzer/rules.py`:

```python
def _rule_my_check(events, counters) -> list[Finding]:
    out = []
    # ... detection logic ...
    out.append(Finding(
        rule_id="MY_RULE_ID",
        title="Human-readable summary including the IRQ number",
        severity=Severity.WARNING,
        confidence=_clamp(0.5 + 0.1 * corroborating_signals),
        irq=irq,
        drivers=[...],
        evidence=["Quote the actual log line or counter value."],
        recommendations=["Concrete, actionable step."],
    ))
    return out
```

2. Register it in `analyze()`.

3. Add retrieval hints in `backend/app/rag/retriever.py`:

```python
RULE_TAG_HINTS["MY_RULE_ID"] = ["relevant kernel terminology"]
```

4. Add tests — **including a negative case** proving a healthy system doesn't trigger it.
   Every existing rule has one; false positives are the main failure mode for a triage tool.

### Rule-writing conventions

- **Evidence must quote real data.** Never write generic text into `evidence`; quote the log
  line or the counter value. The evidence list is what an engineer checks your work against.
- **Confidence is additive from a base**, capped by `_clamp` at `MAX_CONFIDENCE` (0.95).
  Don't invent scores — derive each increment from a specific corroborating signal.
- **State limitations in the evidence itself** when the data can't fully support the claim.
  `IRQ_STORM_CANDIDATE` is the reference example.
- **Severity reflects consequence, not certainty.** A 55%-confidence finding about a disabled
  storage controller is still CRITICAL.

---

## Adding knowledge-base documents

Append to `datasets/kernel_docs/knowledge_base.json`:

```json
{
  "doc_id": "kb-unique-slug",
  "title": "Short descriptive title",
  "source": "Where this came from",
  "tags": ["keyword", "keyword"],
  "text": "A few hundred words of explanatory prose."
}
```

`tags` and `title` are concatenated with the body before embedding, so they carry real
retrieval weight — choose the terms an engineer would actually search for.

The index rebuilds on process start (`get_knowledge_base()` is `lru_cache`d), so restart the
API after editing.

**Note on sourcing:** the bundled documents are original explanatory prose written for this
project, not copied from kernel documentation. If you add material from GPL-licensed kernel
docs or other sources, check the licence and attribute it in the `source` field.

---

## Swapping backends

Backend selection is automatic and logged at startup:

```
INFO app.rag.retriever: Indexed 10 docs (embedder=tfidf, index=numpy).
```

| To get | Do |
|---|---|
| Semantic embeddings | `pip install sentence-transformers` |
| FAISS index | `pip install faiss-cpu` |
| LLM narratives | Run Ollama; set `OLLAMA_HOST` / `OLLAMA_MODEL` |
| Force minimal mode | `INTERRUPTGPT_DISABLE_LLM=1 INTERRUPTGPT_SEMANTIC_EMBEDDINGS=0` |

To add a different LLM provider, implement the `LLMProvider` protocol (a `name` attribute and
`generate(prompt) -> str`) and return it from `build_provider()`. The pipeline catches
`URLError`, `OSError`, `TimeoutError` and `ValueError` from `generate()` and falls back, so a
provider that raises those degrades cleanly rather than failing the request.

---

## Testing strategy

Tests are grouped by layer and run hermetically — no network, no model downloads:

```bash
INTERRUPTGPT_DISABLE_LLM=1 INTERRUPTGPT_SEMANTIC_EMBEDDINGS=0 pytest -q
```

| Group | What it protects |
|---|---|
| `TestDmesgParser` | Prefix formats, handler-block attachment, noise rejection |
| `TestProcInterruptsParser` | Column inference, symbolic rows, missing header |
| `TestAnalyzer` | Each rule, plus negative cases and scoring invariants |
| `TestKnowledgeBase` | Relevance, `k` handling, deduplication |
| `TestPipeline` | End-to-end wiring and report contents |
| `TestAPI` | Every endpoint including 422 paths |

Two tests encode product judgements rather than mechanics, and should not be relaxed without
a deliberate decision:

- `test_never_claims_absolute_certainty` — confidence stays ≤ 95%.
- `test_storm_confirmed_only_by_explicit_log_message` — cumulative counters alone never
  produce a CRITICAL storm verdict.
