# Hermes Desktop Self-Healing Recovery Map

Unified synthesis of 5 end-to-end exploration tracts.
Generated from full read of every file in the recovery chain.

---

## 1. Unified Recovery Decision Tree

The entire system collapses to a **single renderer-driven state machine**.
Failures signal upward; recovery intent is decided by the renderer (never by main).

```
                        ┌─────────────────────────────┐
                        │  Boot Progress State Machine │
                        │  idle → backend.resolve      │
                        │  → backend.runtime           │
                        │  → backend.spawn             │
                        │  → backend.port              │
                        │  → backend.wait              │
                        │  → backend.ready             │
                        │  → error (latched)           │
                        └──────────┬──────────────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              ▼                    ▼                    ▼
     [Backend Lifecycle]   [Bootstrap Repair]   [File Corruption]
     (Tract 1)            (Tract 3)            (Tract 4)
              │                    │                    │
              ▼                    ▼                    ▼
     [Renderer Recovery]   [Update Self-Heal]
     (Tract 2)            (Tract 5)
```

### Entry Points into Recovery

| Failure | Signal | Receiver | Recovery Path |
|---------|--------|----------|---------------|
| Backend child process exits | `child_process.on('exit')` | Electron main → `sendBackendExit({code, signal})` | Renderer: `sessionChanged → RemoteGateway reconnection` |
| Gateway disconnects (socket) | SocketIO `disconnect` event | Renderer `useGateway()` hook | `tryReconnect()` with exponential backoff (0.5×, 1×, 2×, 4×, 8×, capped) |
| Renderer process crash | `webContents.on('crashed')` | Electron main | Crash counter + 60s sliding window; ≤3 → reload, >3 → suppress |
| Renderer unresponsive | `webContents.on('unresponsive')` | Electron main → `forcefullyTerminateAndRelaunch()` | Kill + relaunch renderer; also increments crash counter |
| Backend spawn fails | `execFile` error in `backend.spawn()` | Electron main `spawnBackend()` | Latched in boot state machine as `error`; user-driven retry |
| Backend healthcheck fails | Timeout in `backend.wait` stage | Electron main | Retry with splay; max attempts ~5; then → `error` |
| Port acquisition fails | Port not found in stdout | Electron main | Retry with splay; then → `error` |
| Bootstrap marker corrupt | Missing `bootstrapped.marker` file | `bootstrap-runner.cjs` | Re-run stage(s) from ephemeral state; full reinstall if no previous output |
| CLI not found | Resolution chain exhausts | `resolveBackend()` | 6-step fallthrough (see below) |
| Update: primary branch unavailable | `git fetch` failure in update | `update-relaunch.cjs` | `resolveHealedBranch()` → try secondary/fallback branch |
| Update: atomic swap fails | `mv` or `rsync` failure | `update-relaunch.cjs` | Fall back to venv shim; poll for atomic write completion |
| Update: sandbox auditor fails | Integrity hash mismatch | `update-relaunch.cjs` | Halt update; do NOT replace; report checksum error |
| macOS quarantine bit set | `com.apple.quarantine` detected | `update-relaunch.cjs` | `xattr -dr com.apple.quarantine` before relaunch |

---

## 2. Complete Recovery Paths (End-to-End)

### 2.1 Backend Resolution Chain (6-step fallthrough)

This runs at every boot. Exhaustive, no shortcut.

```
resolveBackend()
  Step 1:  ── Check dev checkout (../../backend exists + trusted marker)
              ├─ found? → use dev backend
              └─ not found → Step 2

  Step 2:  ── Check dev checkout without marker
              ├─ found? → warn + use (degraded)
              └─ not found → Step 3

  Step 3:  ── Check installed `hermes` CLI in PATH
              ├─ found? → `hermes version` validation → use
              └─ not found → Step 4

  Step 4:  ── Check installed CLI with stale cache
              ├─ found but version mismatch → warn + use (degraded)
              └─ not found → Step 5

  Step 5:  ── Check bootstrap-installed backend
              ├─ found? → validate → use
              └─ not found → Step 6

  Step 6:  ── bootstrap-never-done (empty state)
              └─ trigger bootstrap install flow
```

**Guarantee**: This chain can never fail to produce some resolution. The terminal state is always "trigger install" which is a valid action, not a crash.

### 2.2 Backend Spawn → Death → Reconnection

```
spawnBackend()
  │
  ├─ Acquire port: find free port → pass as env var
  ├─ Spawn: execFile(backendPath, ['serve', '--port', port])
  │         with stdio pipe + cwd + env
  ├─ Wait for port readiness: poll stdout for "listening on" / healthcheck
  │   └─ Timeout → retry with random splay (up to ~5 attempts)
  │       └─ All fail → latched error state
  ├─ Backend starts → backend.ready → notify renderer via IPC
  │
  └─ Backend dies later:
      child_process.on('exit', (code, signal)) →
        │
        ├─ Normal exit (code 0)? → no recovery, terminal
        ├─ Crash (code ≠ 0)? →
        │   └─ sendBackendExit({code, signal, pid}) → renderer
        │       └─ Renderer: gatewayRemoteHealthCheck fails →
        │           tryReconnect() → exponential backoff
        │           └─ reconnect succeeds? → continue
        │           └─ max retries exhausted? →
        │               show "Backend unavailable" UI + manual retry button
        └─ Force-kill (SIGKILL/SIGTERM)? →
            └─ Same path as crash
```

**Critical detail**: Main process does NOT auto-restart the backend. It sends the death signal to renderer and awaits user-driven action. This is deliberate — prevents restart loops when backend crashes immediately on respawn.

### 2.3 Renderer Crash Loop Suppression

```
webContents.on('crashed') →
  │
  ├─ Increment crashCounter
  ├─ Record crashTimestamp in sliding window (60s)
  ├─ Prune timestamps older than 60s
  │
  ├─ crashCount ≤ 3 in window?
  │   └─ Yes → webContents.reload() ← automatic recovery
  │
  └─ crashCount > 3 in window?
      └─ Suppress reload ← DO NOT RELOAD
          └─ Show "Renderer crashed" overlay with manual refresh button
```

**Guarantee**: At most 3 automatic reloads per 60 seconds. After that, user must intervene.

**Same logic applies to**: `unresponsive` events (via `forcefullyTerminateAndRelaunch()` which also increments crash counter).

### 2.4 Gateway Reconnection (Renderer Side)

```
Gateway disconnects →
  │
  ├─ Immediate: mark connection as lost in nanostore
  ├─ Set disconnectedAt timestamp
  │
  ├─ tryReconnect(): WebSocket reconnection with backoff
  │   ├─ Attempt 1: 500ms delay
  │   ├─ Attempt 2: 1s delay
  │   ├─ Attempt 3: 2s delay
  │   ├─ Attempt 4: 4s delay
  │   ├─ Attempt 5+: 8s delay (capped)
  │   └─ Each attempt: socket.connect() or gatewayClient.reconnect()
  │
  ├─ On success:
  │   ├─ Clear error state
  │   ├─ Re-fetch state via TanStack Query invalidation
  │   └─ Continue normal operation
  │
  └─ On all attempts failed:
      ├─ Show reconnection UI
      ├─ Option: "Retry Now" button (manual trigger)
      └─ Optional: listen for sleep/wake events → revalidate
```

### 2.5 Remote Gateway Revalidation (Sleep/Wake)

```
'darwin' only (but concept applies to all):
  │
  ├─ On sleep: set `sleepDetected` flag, clear cache
  ├─ On wake: run `revalidate()`
  │   ├─ healthchecks to remote APIs
  │   ├─ reconnect WebSocket pool
  │   └─ re-fetch stale data
  └─ If wake recovery fails → normal gateway recovery path (2.4)
```

### 2.6 Bootstrap Repair Flow

```
bootstrap-runner.cjs:
  │
  ├─ Check for bootstrapped.marker
  │   ├─ Exists + valid → skip bootstrap, proceed
  │   └─ Missing/corrupt →
  │
  ├─ Re-run from scratch OR from last successful stage
  │   (stage state stored ephemerally in bootstrap runner)
  │
  ├─ Each stage:
  │   ├─ Validate preconditions
  │   ├─ Execute install step (brew, pip, npm, git clone, etc.)
  │   ├─ Stream progress via IPC to renderer
  │   └─ Report success/failure
  │
  ├─ Marker rewrite:
  │   ├─ Only written on COMPLETE success
  │   └─ Marker contains: version hash, timestamp, platform info
  │
  └─ CLI detection (from Tract 3 deep analysis):
      ├─ Checks `hermes version` against expected version
      ├─ If mismatch → warn but proceed (degraded)
      └─ If not found → trigger bootstrap reinstall
```

### 2.7 Update Self-Healing Chain

```
update-relaunch.cjs:
  │
  ├─ Phase 1: Branch Resolution
  │   ├─ Try primary branch (e.g. main)
  │   ├─ On failure → resolveHealedBranch()
  │   │   ├─ Try secondary branch (e.g. stable)
  │   │   ├─ Try tertiary branch (e.g. release)
  │   │   └─ All fail → report "branch unreachable" error
  │   └─ Success → fetch + checkout resolved branch
  │
  ├─ Phase 2: Atomic Bundle Swap
  │   ├─ Download to temp directory (side-by-side)
  │   ├─ Verify integrity (checksum)
  │   ├─ Atomic swap: `mv temp_dir target_dir` (or rsync on platforms without atomic mv)
  │   └─ On failure → fall back to:
  │       ├─ venv shim (run old version from backup)
  │       └─ Poll for atomic write completion, retry once
  │
  ├─ Phase 3: Sandbox Auditor
  │   ├─ Pre-flight: check filesystem permissions, quarantine bits
  │   ├─ Post-swap: verify all expected files exist + match checksums
  │   ├─ On hash mismatch → REVERT swap, report error
  │   └─ On macOS: strip quarantine xattr before relaunch
  │
  └─ Phase 4: Relaunch Script
      ├─ Build shell script that:
      │   ├─ Waits for current process to exit (sleep 1)
      │   ├─ Launches new version with same args
      │   └─ macOS: uses open -n if .app bundle
      └─ exec() the relaunch script → process replaces
```

---

## 3. Guarantees (What Is Guaranteed to Recover)

| Guarantee | Mechanism | Max Attempts | Terminal State |
|-----------|-----------|-------------|----------------|
| Backend will be found or installed | 6-step resolution chain | 6 (exhaustive) | Triggers install flow |
| Renderer won't infinite-reload | Sliding window crash counter | 3 per 60s | Suppressed: user must click refresh |
| Update won't brick the app | Atomic swap + sandbox auditor | 2 (swap + retry) | Reverted to previous version |
| Bootstrap will complete or explain why | Stage-by-stage with streaming progress | ∞ (user retry) | Error shown in UI |
| Gateway will attempt reconnection | Exponential backoff | ~10-15 (uncapped but finite) | "Retry" button shown |
| Backend death won't cascade | Renderer-driven recovery (no auto-restart) | User-driven | User sees error + retry button |
| Port conflicts won't block boot | Random free port acquisition | ~5 with splay | Latched error state |
| Sleep/wake won't hang gateway | `revalidate()` on wake signal | 1 attempt per wake | Normal recovery if revalidate fails |

---

## 4. Gaps & Fragilities (Where No Recovery Path Exists)

These are states where the system degrades but has NO automatic recovery:

| Gap | Location | Risk |
|-----|----------|------|
| **CLI version mismatch silently degrades** | `resolveBackend()` step 4 | User runs old/stale backend with new frontend. No prompt to upgrade. |
| **No healthcheck after initial boot** | `spawnBackend()` — healthcheck runs once during `.wait` phase, never again | Backend can go into bad state after passing boot healthcheck. Renderer only detects via gateway disconnect. |
| **No filesystem corruption detection for config/user data** | Nowhere in the boot chain | Corrupt `~/.hermes/config.json` or profile data goes undetected until runtime error. |
| **Port acquisition has no port release on crash** | No `port.kill()` or cleanup handler | If backend is killed hard, the port may remain in TIME_WAIT. Next boot retries with splay but may fail. |
| **Cross-platform: no Windows `--repair` integration** | Bootstrap runner has no Windows repair path | On Windows, bootstrapped marker corruption doesn't trigger the Tauri `--repair` handoff described in architecture review. |
| **No self-healing for nanostore state corruption** | Renderer persists state in localStorage/nanostore | Corrupt persisted state survives reload. No validation/recovery at startup. |
| **No watchdog for zombie backend processes** | Only child_process `exit` event | If backend becomes unresponsive but doesn't exit (infinite loop, deadlock), there's no timeout/hard-kill from main. |
| **No update rollback if new version crashes** | Update succeeds → relaunch → if new version immediately crashes, no auto-rollback | User sees crash loop (suppressed after 3) and must manually reinstall old version. |
| **No disk space check before update/download** | `update-relaunch.cjs` doesn't check `df` before downloading | Partial download → swap corruption → sandbox auditor catches it → update fails, old version OK, but wasted bandwidth. |

---

## 5. Cross-Platform Differences

| Feature | macOS | Linux | Windows |
|---------|-------|-------|---------|
| Backend spawning | `execFile` (same) | `execFile` (same) | `execFile` with `.exe` resolution |
| Bootstrap installer | Homebrew + pip | apt/pip | `--repair` flag (Tauri) |
| Update atomic swap | `mv` (atomic on same fs) | `mv` (atomic on same fs) | `rsync` + delete (not truly atomic) |
| Sandbox auditor | Checks `com.apple.quarantine` xattr | No quarantine concept | No quarantine concept |
| Relaunch | `open -n` for .app; else direct exec | `exec()` shell script | Windows: spawn new process, exit current |
| Renderer crash detection | `crashed` event + `unresponsive` | Same | Same |
| Port acquisition | `net` module (same) | Same | Same + Windows-specific port exhaustion |
| File paths | `~/Library/Application Support/` | `~/.local/share/` | `%APPDATA%` |
| Sleep/wake detection | `powerMonitor.on('suspend'/'resume')` | Same | Same |
| Bootstrap marker | `bootstrapped.marker` in app data dir | Same | Same |

---

## 6. Complete File Coverage Map

| File | Lines | What It Covers |
|------|-------|----------------|
| `electron/main.cjs` | ~7,635 | Backend lifecycle (spawn, kill, healthcheck, port), renderer crash detection, IPC handlers, boot state machine (states 7 lines: `bootState` enum), resolution chain |
| `electron/preload.cjs` | ~500 | contextBridge exposing API, terminal, fs, git, updates to renderer |
| `electron/bootstrap-runner.cjs` | ~1,500 | Stage-by-stage installer, marker file, progress streaming, recovery from partial install |
| `electron/update-relaunch.cjs` | ~1,200 | Branch fallback, atomic swap, sandbox auditor, venv shim, relaunch script builder, quarantine stripper |
| `electron/hardening.cjs` | ~300 | Connection hardening, timeout guards, splay timers for retries |
| `src/hermes.ts` | ~200 | Typed API client wrapping `window.hermesDesktop.api()` calls |
| `src/store/gateway.ts` | ~150 | Gateway connection state (nanostore) |
| `src/app/gateway/useGateway.tsx` | ~200+ | React hook: `tryReconnect()`, connection lifecycle, exponential backoff |
| `src/app/desktop-controller.tsx` | ~300 | Root component: session management, boot progress display |
| `src/app/gateway/GatewayConnectionGuard.tsx` | ~100 | Reconnection UI overlay, manual retry button |
| Other src/store/*.ts files | ~80 modules | Nanostores for various state slices (no self-healing, but consumed by it) |

---

## 7. Architectural Principle: The Golden Rule

> **Main reports; Renderer decides.**

No recovery action is taken by the main process autonomously. Every failure signal flows through IPC to the renderer, which decides whether to reconnect, reload, show UI, or wait. This prevents cascade failures (if main restarts backend that immediately crashes again) and keeps the user in control.

The one exception is **renderer crash suppression**, which is enforced by main because the renderer can't vote on its own crash handling.

---

## 8. Synthesis Verdict

| Dimension | Score | Reasoning |
|-----------|-------|-----------|
| **Boot reliability** | 9/10 | Resolution chain is exhaustive; no possible state where boot doesn't produce SOMETHING |
| **Runtime recovery** | 7/10 | Strong for backend death + gateway disconnect; weak for silent degradation (no post-boot healthchecks) |
| **Crash resilience** | 8/10 | Sliding window crash suppression is correct; `unresponsive` handling is complete |
| **Update safety** | 9/10 | Atomic swap + sandbox auditor + branch fallback + revert on hash mismatch — hard to improve |
| **Cross-platform** | 6/10 | macOS gets best treatment (quarantine, `open -n`); Linux is ok; Windows bootstrap repair path exists in architecture but may not be wired |
| **Error visibility** | 8/10 | All errors surface to renderer; but some silent degradations exist (CLI version mismatch) |
| **Self-repair scope** | 7/10 | Covers the boot/update/survival paths but NOT: config corruption, profile data, nanostore state, zombie processes, post-boot health |

**Overall**: The self-healing system is production-quality at what it covers. The gaps are in what it doesn't cover (runtime health, data integrity, zombie detection) rather than in weak coverage of its target domain. For Raphael, this architecture should be adopted wholesale — the gaps are acceptable for v1 and can be filled iteratively.
