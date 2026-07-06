 # FINAL PORTING PLAN: RedTeamAgent → Raphael 2.0

---

## 1. FEATURE TABLE

| # | Feature | Score | Effort | Verdict | Rationale |
|---|---------|-------|--------|---------|-----------|
| 1 | **Case Collection Pipeline** | 9/10 | ~900 LOC, 7 files | **PORT** | Foundational. Unlocks everything else. Without it, Sword remains fire-and-forget. |
| 2 | **Resume / Stall Recovery** | 8/10 | ~700 LOC, 5 files | **PORT** | Operational necessity for multi-day engagements. Depends on Case Collection. |
| 3 | **OpSec / Stealth Modes** | 7/10 | ~400 LOC, 4 files | **PORT** | `cloak:3400` exists but lacks engagement-aware adaptive behavior. Incremental but high-value. |
| 4 | **Reference Library** | 5/10 | ~300 LOC, 8 files | **DEFER** | Overlaps with existing tool binaries. Real value is CAI agent knowledge gap, but requires agent rearchitecture not justified by standalone port. Revisit after Case Collection stabilizes. |
| 5 | **Reporting / Finding Triage** | 5/10 | ~500 LOC, 6 files | **DEFER** | Raphael already generates findings. Structured client reporting is productization, not core capability. Revisit when engagement output volume demands it. |

---

## 2. RANKED IMPLEMENTATION ORDER

### PHASE 1: Case Collection Pipeline (Weeks 1-3)

| Priority | File Path | Purpose |
|----------|-----------|---------|
| 1 | `services/recon-pipeline/schema.sql` | SQLite schema: cases, stages, signatures, priority index |
| 2 | `services/recon-pipeline/models.py` | Pydantic models: Case, CaseType, CaseStage, CaseSignature |
| 3 | `services/recon-pipeline/case_store.py` | CRUD + dedup + atomic stage transitions (single writer) |
| 4 | `services/recon-pipeline/scoring.py` | Configurable priority engine: source_weight × method_bonus × path_bonus |
| 5 | `services/recon-pipeline/producers/katana.py` | Crawl → case ingestion with tor-proxy routing |
| 6 | `services/recon-pipeline/producers/mitmproxy.py` | Extend `services/tor-proxy/mitm_addon.py` for case emission |
| 7 | `services/recon-pipeline/producers/openapi.py` | Spec ingestion for API-heavy targets |
| 8 | `services/mcp-hub/tools/case_tools.py` | MCP tools: `case_fetch`, `case_done`, `case_set_stage`, `case_reset_stale` |
| 9 | `services/sword/orchestrator.py` | Modify: consume cases by stage instead of file globs |
| 10 | `docker-compose.yml` | Volume: `./data/cases.db:/app/cases.db` |

### PHASE 2: Resume / Stall Recovery (Weeks 3-5)

| Priority | File Path | Purpose |
|----------|-----------|---------|
| 1 | `services/brain/engagement_state.py` | `resolve_engagement_dir()`, scope.json validation, auth config schema |
| 2 | `services/brain/resume_manager.py` | Read findings/queue/intel.md, reconstruct in-flight state |
| 3 | `services/recon-pipeline/stale_recovery.py` | `reset_stale(threshold_min=10)` with in-flight guard |
| 4 | `services/brain/auth_monitor.py` | Detect new creds in `findings/creds/` → trigger re-recon |
| 5 | `services/mcp-hub/tools/resume_tools.py` | MCP: `resume_engagement`, `check_stale`, `stop_engagement` |
| 6 | `services/cai-service/agents/chat.py` | `/resume`, `/stop` slash commands |

### PHASE 3: OpSec / Stealth Modes (Weeks 5-6)

| Priority | File Path | Purpose |
|----------|-----------|---------|
| 1 | `services/cloak/engagement_profile.py` | Per-engagement traffic shaping: jitter, user-agent rotation, request timing |
| 2 | `services/cloak/stealth_controller.py` | Adaptive mode: `passive` (default) → `active` (confirmed safe) → `aggressive` (time-critical) |
| 3 | `services/cloak/detection_response.py` | Trigger: 429/403/CAPTCHA → auto-escalate to next stealth tier or pause |
| 4 | `services/sword/orchestrator.py` | Modify: query `cloak` for current stealth tier before dispatch |

### PHASE 4: Deferred (Revisit Q2)

| Feature | Trigger for Revisit |
|---------|---------------------|
| Reference Library | CAI agent hallucination rate >20% in production; or Case Collection produces >500 cases/engagement with no TTP guidance |
| Reporting / Finding Triage | Client demand for structured deliverables; or compliance requirement for audit trail |

---

## 3. TEAM DISAGREEMENTS — FINAL CALL

| Dispute | kimik2.6 | nemotron | **FINAL CALL** | Justification |
|---------|----------|----------|----------------|---------------|
| **Where `cases.db` lives** | New `case-collector:3800` | Inside `recon-pipeline:3503` | **nemotron**: `recon-pipeline` | Single writer pattern requires it. Avoids service sprawl. `recon-pipeline` already owns ingestion. |
| **SQLite writer pattern** | Multi-writer (aiosqlite/WAL/Postgres) | Single-writer via MCP | **nemotron**: Single-writer | SQLite + containers = single writer or corruption. MCP enforces this architecturally. |
| **Priority scoring location** | Hardcoded in producer | Separate `scoring.py` | **nemotron**: Separate module | Testable, configurable, auditable. Required for compliance. |
| **Reference Library score** | (incomplete) | 7/10 | **5/10, DEFER** | Neither identified that tool binaries already exist. Knowledge gap is real but requires agent rearchitecture, not file porting. |
| **OpSec/Stealth score** | (incomplete) | 8/10 | **7/10, PORT** | `cloak` exists; value is integration, not new capability. Lower than nemotron's 8 because incremental. |
| **MCP vs direct calls** | Direct HTTP to `case-collector:3800` | MCP tools | **nemotron**: MCP tools | Brain/CAI agents must not touch DB directly. MCP is Raphael's established contract. |
| **Katana integration pattern** | `katana_bridge.py` monolith | `producers/katana.py` modular | **nemotron**: Producer pattern | Scales to new crawlers (gau, wayback). Bridge is one-off technical debt. |

---

## 4. TOTAL ESTIMATED LOC

| Phase | LOC | Files |
|-------|-----|-------|
| Case Collection Pipeline | 900 | 7 |
| Resume / Stall Recovery | 700 | 5 |
| OpSec / Stealth Modes | 400 | 4 |
| **Subtotal (PORT)** | **2,000** | **16** |
| Reference Library (DEFER) | 300 | 8 |
| Reporting / Finding Triage (DEFER) | 500 | 6 |
| **Grand Total** | **2,800** | **30** |

**Immediate implementation: 2,000 LOC across 16 files.**

---

## 5. INTEGRATION NOTES PER FEATURE

### Case Collection Pipeline

| Raphael Service | Modification |
|-------------------|--------------|
| `services/recon-pipeline/` | **Major**: Add schema, models, case_store, scoring, producers. Becomes case ingestion hub. |
| `services/tor-proxy/` | **Minor**: Extend `mitm_addon.py` to emit cases to `recon-pipeline` internal API. |
| `services/sword/` | **Major**: Orchestrator queries cases by stage instead of scanning file globs. Phase handlers become case-driven. |
| `services/mcp-hub/` | **Minor**: New `case_tools.py` exposes safe read/write interface. |
| `services/brain/` | **Minor**: Agents query `case_fetch` for planning instead of parsing raw tool output. |
| `services/cai-service/` | **Minor**: System prompt updated to reference `case_fetch`/`case_done` tools. |

### Resume / Stall Recovery

| Raphael Service | Modification |
|-------------------|--------------|
| `services/brain/` | **Major**: New `engagement_state.py`, `resume_manager.py`, `auth_monitor.py`. Becomes state authority. |
| `services/recon-pipeline/` | **Minor**: `stale_recovery.py` adds `reset_stale()` with in-flight guard. |
| `services/mcp-hub/` | **Minor**: New `resume_tools.py`. |
| `services/sword/` | **Minor**: On startup, call `resume_manager.resolve_engagement_dir()` before phase 1. |
| `services/cai-service/` | **Minor**: `/resume`, `/stop` slash commands in chat agent. |

### OpSec / Stealth Modes

| Raphael Service | Modification |
|-------------------|--------------|
| `services/cloak/` | **Major**: New `engagement_profile.py`, `stealth_controller.py`, `detection_response.py`. Becomes engagement-aware. |
| `services/sword/` | **Minor**: Query `cloak` for current stealth tier before tool dispatch; adjust parallelism accordingly. |

---

## ARCHITECTURAL DECISIONS (Locked)

| Decision | Rationale |
|----------|-----------|
| **SQLite, not PostgreSQL** | Single-writer pattern eliminates concurrency issues. Simpler ops. Migrate only if multi-engagement parallel processing required later. |
| **No new microservices** | `recon-pipeline` absorbs case collection. `brain` absorbs resume. `cloak` absorbs stealth. Raphael has enough services. |
| **MCP as sole integration layer** | No direct DB access from any service except owner. Enforces contracts, enables audit logging. |
| **Engagement directory on bind mount** | `./engagements/<target_id>/` with `scope.json`, `findings/`, `cases.db`, `intel.md`, `queue.json`. Required for resume. |
| **In-flight guard: file-based, not Redis** | Raphael has no Redis. Use `cases.db` `status='processing'` with heartbeat timestamp. Simpler, no new dependency. |

---

## SUCCESS CRITERIA

| Feature | Done When |
|---------|-----------|
| Case Collection | `sword` orchestrator runs 6 phases without ever parsing raw nmap/nuclei output directly |
| Resume/Stall | Container restart mid-engagement → `resume` command reconstructs exact state within 30 seconds |
| OpSec/Stealth | `cloak` automatically throttles `sword` after 2 consecutive 429 responses; resumes at 50% rate after 10 min |

---

**Decision authority: Lead Architect. No further analysis required. Execute Phase 1.**