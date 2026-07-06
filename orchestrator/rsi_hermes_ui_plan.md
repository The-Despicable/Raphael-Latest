 # FINAL PORTING PLAN: Hermes Agent → Raphael 2.0 UI/UX

## 1. COMPONENT ASSESSMENT TABLE

| Component | Score | Effort | Verdict | Rationale |
|-----------|-------|--------|---------|-----------|
| **A) JSON-RPC Transport** | 8/10 | ~600 LOC, 4 files | **PORT PATTERN** | Transport ABC + WebSocket/Stdio transports 90% reusable. Add MCP transport. Rewrite method registry for Raphael domain. |
| **B) Web Dashboard** | **10/10** | ~3,500 LOC React + ~400 LOC Python, ~25 files | **REUSE TOOLCHAIN, REWRITE DOMAIN** | Critical path. Copy build pipeline verbatim. Rewrite all pages for engagements/modules/evidence. |
| **C) Ink TUI** | 3/10 | ~200 LOC if Textual, ~800 if Ink | **REJECT INK; USE TEXTUAL IF NEEDED** | React-in-terminal overkill. Raphael operators use web + messaging. Textual gives 80% value at 20% effort if CLI TUI ever needed. |
| **D) Messaging Gateway** | 9/10 | ~800 LOC core + ~200 per platform | **PORT CORE, EXTEND RENDERERS** | Domain-agnostic dispatch/consumer/adapter machinery. Add Raphael-specific message renderers. Slack → Telegram → Discord priority. |
| **E) Event Vocabulary** | 8/10 | ~400 LOC dataclasses + dispatch | **REWRITE TYPES, REUSE PATTERN** | Typed dataclass + SSE serialization pattern ports. Replace LLM events with offensive security events. |
| **F) Hook/Plugin System** | 6/10 | ~300 LOC | **INSPIRE** | HookRegistry pattern useful for module marketplace. Adapt for dynamic module loading. |
| **G) Config Management** | 6/10 | ~400 LOC | **PORT PATTERN, REWRITE SCHEMA** | Dynamic config with validation useful. Replace LLM config with targets/modules/MCP/evidence config. |

---

## 2. RANKED BUILD PRIORITY

| Phase | Priority | What | Days | Milestone |
|-------|----------|------|------|-----------|
| **1** | **CRITICAL** | Dashboard pipeline + single "Engagement Status" page | 3 | `localhost:8080/dashboard` shows live engagement with streaming shell output |
| **2** | **HIGH** | JSON-RPC transport layer with WebSocket + MCP bridge | 2 | Orchestrator exposes `engagement.*`, `module.*`, `evidence.*` methods |
| **3** | **HIGH** | Event vocabulary + SSE streaming for tool output | 2 | Real-time nmap/hydra output streams to dashboard |
| **4** | **HIGH** | Messaging gateway (Slack + Telegram adapters) | 3 | Operators control engagements from Slack |
| **5** | **MEDIUM** | Full dashboard pages (Modules, Evidence, Config) | 5 | Complete web UI for engagement lifecycle |
| **6** | **LOW** | Textual TUI (if operator demand) | 2 | Optional: `raphael tui` command |
| **7** | **LOW** | HookRegistry for module marketplace | 2 | Dynamic module discovery/loading UI |

**Total: 19 days (4 weeks with buffer)**

---

## 3. ARCHITECTURE DIAGRAM

```
┌─────────────────────────────────────────────────────────────────────────┐
│                              CLIENTS                                     │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────┐ │
│  │   Web       │  │   Slack/    │  │   Telegram  │  │   CLI (future)  │ │
│  │  Dashboard  │  │   Discord   │  │   Mobile    │  │   Textual TUI   │ │
│  │  (React SPA)│  │   Bot       │  │   Alerts    │  │                 │ │
│  └──────┬──────┘  └──────┬──────┘  └──────┬──────┘  └─────────────────┘ │
│         │                │                │                              │
│         └────────────────┼────────────────┘                              │
│                          ▼                                             │
│              ┌─────────────────────┐                                   │
│              │   WebSocket / SSE   │  ← hermes/web/ api.ts pattern     │
│              │   (real-time events)│     hermes/tui_gateway/ws.py       │
│              └──────────┬──────────┘                                   │
│                         │                                              │
├─────────────────────────┼─────────────────────────────────────────────┤
│                         ▼                                              │
│              ┌─────────────────────┐                                   │
│              │   RAPHAEL ORCHESTRATOR   │                              │
│              │  ┌─────────────────┐ │                                   │
│              │  │  JSON-RPC Server │ │  ← hermes/tui_gateway/server.py  │
│              │  │  dispatch()      │ │     pattern, rewritten methods federally │
│              │  │  method registry │ │                                   │
│              │  └─────────────────┘ │                                   │
│              │  ┌─────────────────┐ │                                   │
│              │  │  Transport Layer │ │  ← hermes/tui_gateway/transport.py │
│              │  │  - WebSocket     │ │     hermes/tui_gateway/ws.py       │
│              │  │  - Stdio         │ │                                   │
│              │  │  - MCP (NEW)     │ │  bridges to :3500 MCP hub        │
│              │  └─────────────────┘ │                                   │
│              │  ┌─────────────────┐ │                                   │
│              │  │  Event Publisher │ │  ← hermes/tui_gateway/          │
│              │  │  SSE stream      │ │     event_publisher.py pattern     │
│              │  └─────────────────┘ │                                   │
│              │  ┌─────────────────┐ │                                   │
│              │  │  Messaging Gateway│ │  ← hermes/gateway/ pattern       │
│              │  │  - Slack adapter  │ │     stream_dispatch.py             │
│              │  │  - Telegram adapter│ │    stream_consumer.py            │
│              │  │  - renderers      │ │    base.py (BasePlatformAdapter)   │
│              │  └─────────────────┘ │                                   │
│              └─────────────────────┘                                   │
│                         │                                              │
│              ┌─────────────────────┐                                   │
│              │   RAPHAEL CORE SERVICES   │                              │
│              │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐        │
│              │  │Engagement│ │ Module  │ │Evidence │ │  MCP    │        │
│              │  │  Engine  │ │Registry │ │ Store   │ │  Hub    │        │
│              │  │         │ │ (100+)  │ │         │ │ :3500   │        │
│              │  └─────────┘ └─────────┘ └─────────┘ └─────────┘        │
│              └─────────────────────┘                                   │
│                         │                                              │
│              ┌─────────────────────┐                                   │
│              │   EXECUTION LAYER    │                                   │
│              │  Docker containers, PTY shells, tool wrappers            │
│              └─────────────────────┘                                   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 4. HERMES FILES TO COPY/REFERENCE

| Hermes Path | Raphael Counterpart | How to Use |
|-------------|---------------------|------------|
| `hermes/web/package.json` | `raphael_2.0/web_dashboard/package.json` | **Copy verbatim** — Vite + React 19 + Tailwind 4 deps |
| `hermes/web/vite.config.ts` | `raphael_2.0/web_dashboard/vite.config.ts` | **Copy verbatim** |
| `hermes/web/tailwind.config.js` | `raphael_2.0/web_dashboard/tailwind.config.js` | **Copy verbatim** |
| `hermes/web/src/api.ts` | `raphael_2.0/web_dashboard/src/api.ts` | **Copy pattern** — typed fetch, SSE, WS hooks. Rewrite endpoint URLs and event types. |
| `hermes/web/src/hooks/useWebSocket.ts` | `raphael_2.0/web_dashboard/src/hooks/useWebSocket.ts` | **Copy with adaptation** — change event type union |
| `hermes/web/src/stores/` (nanostore) | `raphael_2.0/web_dashboard/src/stores/` | **Copy pattern** — engagementStore, moduleStore, evidenceStore |
| `hermes/web/src/components/Layout.tsx` | `raphael_2.0/web_dashboard/src/components/Layout.tsx` | **Copy shell** — sidebar, header, theme. Replace nav items. |
| `hermes/web/src/components/LogStream.tsx` | `raphael_2.0/web_dashboard/src/components/TerminalFeed.tsx` | **Copy with heavy adaptation** — add ANSI escape parsing for PTY output |
| `hermes_cli/web_server.py` | `raphael_2.0/orchestrator/dashboard/server.py` | **Copy pattern** — FastAPI static mount, SPA catch-all route |
| `tui_gateway/server.py` | `raphael_2.0/orchestrator/rpc/dispatch.py` | **Copy pattern** — single dispatch(), method registry dictionary |
| `tui_gateway/transport.py` | `raphael_2.0/orchestrator/rpc/transports/base.py` | **Copy verbatim** — Transport ABC |
| `tui_gateway/ws.py` | `raphael_2.0/orchestrator/rpc/transports/websocket.py` | **Copy with adaptation** — change batch flush from token-delta to line-based |
| `gateway/base.py` | `raphael_2.0/orchestrator/messaging/base.py` | **Copy verbatim** — BasePlatformAdapter ABC |
| `gateway/stream_dispatch.py` | `raphael_2.0/orchestrator/messaging/stream_dispatch.py` | **Copy with adaptation** — change event type routing |
| `gateway/stream_consumer.py` | `raphael_2.0/orchestrator/messaging/stream_consumer.py` | **Copy verbatim** — queue-based sync→async bridge |

---

## 5. WHAT MUST BE REWRITTEN (NON-NEGOTIABLE)

### Security-Critical (Do Not Copy Hermes Logic)

| Area | Why | What to Build Instead |
|------|-----|----------------------|
| **Authentication** | Hermes uses ticket-based auth for single-user LLM chat | **Engagement-scoped API keys + operator JWT + MFA for sensitive actions** |
| **Authorization** | Hermes has no multi-user concept | **RBAC: lead operator, observer, approver roles per engagement** |
| **Input sanitization** | Hermes sanitizes LLM prompts; Raphael receives raw shell commands | **Command allowlist + sandbox validation before PTY execution** |
| **Audit logging** | Hermes logs chat sessions | **Immutable audit trail: who ran what, when, on which target, with what result** |
| **Evidence integrity** | Not applicable to Hermes | **Cryptographic hash chain for all evidence, signed timelines** |

### Raphael-Specific Domain Rewrites

| Hermes Concept | Raphael Replacement | Implementation |
|----------------|---------------------|----------------|
| `Session` | `Engagement` | State machine: `recon` → `exploit` → `post_exploit` → `report` |
| `Message` (chat) | `Operation` (attack step) | Linked list of operations with dependencies |
| `ToolCall` (LLM function) | `ModuleExecution` | Async execution with progress streaming, timeout, kill |
| `TokenDelta` | `ShellOutput`, `ToolProgress`, `VulnFound`, `LootDiscovered` | Typed event dataclasses |
| `ModelConfig` (temperature, etc.) | `TargetConfig`, `ModuleConfig`, `McpServerConfig` | Network targets, tool parameters, MCP server endpoints |
| `EnvPage` (API keys) | `CredentialsVault` | SSH keys, hashes, tokens, certificates with encryption at rest |
| `StatusPage` (agent health) | `CommandCenter` | Engagement state machine visualization, active operations, operator presence |

### WebSocket/SSE Event Types (Complete Rewrite)

```typescript
// Raphael events — NOT Hermes events
type RaphaelEvent =
  // Engagement lifecycle
  | { type: 'engagement:created'; engagement: Engagement }
  | { type: 'engagement:phase_changed'; engagementId: string; from: Phase; to: Phase }
  | { type: 'engagement:operator_joined'; engagementId: string; operator: Operator }
  
  // Real-time execution
  | { type: 'shell:output'; engagementId: string; operationId: string; data: string; isStderr: boolean }
  | { type: 'shell:exit'; engagementId: string; operationId: string; code: number }
  | { type: 'tool:progress'; engagementId: string; operationId: string; tool: string; percent: number; metadata: object }
  | { type: 'tool:result'; engagementId: string; operationId: string; output: object; structured?: boolean }
  
  // Offensive security findings
  | { type: 'vuln:discovered'; engagementId: string; cve?: string; cvss?: number; evidence: string[] }
  | { type: 'loot:discovered'; engagementId: string; path: string; size: number; type: string; hash: string }
  | { type: 'loot:exfiltrated'; engagementId: string; path: string; destination: string }
  
  // Operator coordination
  | { type: 'operator:action_required'; engagementId: string; action: string; context: object }
  | { type: 'operator:approved'; engagementId: string; action: string; operator: string }
  
  // System
  | { type: 'system:agent_connected'; agentId: string }
  | { type: 'system:agent_disconnected'; agentId: string; reason: string };
```

---

## 6. ESTIMATED EFFORT

| Category | LOC | Files | Weeks |
|----------|-----|-------|-------|
| **Reused from Hermes** (patterns, build pipeline, transport ABC, messaging core) | ~2,000 | ~15 | — |
| **Rewritten for Raphael** (pages, components, event types, method registry, renderers) | ~5,500 | ~35 | — |
| **New Raphael-specific** (MCP transport, engagement state machine, credentials vault, audit chain) | ~2,500 | ~15 | — |
| **TOTAL** | **~10,000** | **~65** | **4 weeks** |

### Timeline

| Week | Deliverable |
|------|-------------|
| **Week 1** | Dashboard pipeline live. Single page: create engagement, see real-time shell output. |
| **Week 2** | Transport layer + event vocabulary complete. MCP bridge working. Messaging gateway (Slack). |
| **Week 3** | Full dashboard: engagements, modules, evidence pages. Telegram adapter. |
| **Week 4** | Polish: RBAC, audit logging, credentials vault, performance optimization. |

---

## FINAL DECISION

**Build the web dashboard first.** Copy Hermes' Vite+React+Tailwind+FastAPI build pipeline verbatim. Rewrite every page for Raphael's offensive security domain. Layer on real-time streaming via WebSocket/SSE with Raphael-specific event types. Add messaging gateway for Slack/Telegram operator coordination. Defer Ink TUI indefinitely; use Textual if CLI demand emerges.

The pipeline is the product. Get it live in 3 days.