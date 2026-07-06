# HRM — Hierarchical Reasoning Model

**Paper:** [arXiv:2506.21734](https://arxiv.org/abs/2506.21734) | **Code:** [github.com/sapientinc/HRM](https://github.com/sapientinc/HRM) | **License:** Apache-2.0 | **Stars:** 12.6k

---

## 1. Paper Summary

**Authors:** Guan Wang, Jin Li, Yuhao Sun, Xing Chen, Changling Liu, Yue Wu, Meng Lu, Sen Song, Yasin Abbasi Yadkori

**Submitted:** 26 Jun 2025 (v1), updated 4 Aug 2025 (v3)

### Abstract

> Reasoning, the process of devising and executing complex goal-oriented action sequences, remains a critical challenge in AI. Current large language models (LLMs) primarily employ Chain-of-Thought (CoT) techniques, which suffer from brittle task decomposition, extensive data requirements, and high latency. Inspired by the hierarchical and multi-timescale processing in the human brain, we propose the Hierarchical Reasoning Model (HRM), a novel recurrent architecture that attains significant computational depth while maintaining both training stability and efficiency. HRM executes sequential reasoning tasks in a single forward pass without explicit supervision of the intermediate process, through two interdependent recurrent modules: a high-level module responsible for slow, abstract planning, and a low-level module handling rapid, detailed computations. With only 27 million parameters, HRM achieves exceptional performance on complex reasoning tasks using only 1000 training samples. The model operates without pre-training or CoT data, yet achieves nearly perfect performance on challenging tasks including complex Sudoku puzzles and optimal path finding in large mazes. Furthermore, HRM outperforms much larger models with significantly longer context windows on the Abstraction and Reasoning Corpus (ARC), a key benchmark for measuring artificial general intelligence capabilities.

### Key Claims

| Claim | Detail |
|-------|--------|
| Parameters | 27 million |
| Training data | 1,000 samples |
| Pre-training | None required |
| CoT data | None used |
| Inference | Single forward pass |
| Architecture | Dual recurrent modules (high-level + low-level) |
| Sudoku Extreme | Near-perfect (9x9, hardest difficulty) |
| Maze 30x30 Hard | Near-perfect pathfinding |
| ARC benchmark | Outperforms much larger LLMs with longer context windows |

---

## 2. Architecture

### 2.1 Dual-Module Design

Inspired by hierarchical and multi-timescale processing in the human brain:

```
┌─────────────────────────────────────────────────────┐
│                    HRM Architecture                    │
│                                                       │
│  ┌─────────────────────────────────────────────┐     │
│  │  High-Level Module (Slow, Abstract)          │     │
│  │  • Strategic planning                        │     │
│  │  • Goal decomposition                        │     │
│  │  • Infrequent state updates                  │     │
│  │  • Coarse latent state: "where are we?"      │     │
│  └──────────────┬──────────────────────────────┘     │
│                 │ halting/continuation signal         │
│  ┌──────────────▼──────────────────────────────┐     │
│  │  Low-Level Module (Fast, Detailed)           │     │
│  │  • Tactical execution                        │     │
│  │  • High-frequency computation                │     │
│  │  • Detailed action sequencing                │     │
│  └─────────────────────────────────────────────┘     │
│                                                       │
│  • No explicit intermediate supervision               │
│  • Single forward pass                                │
│  • Recurrent processing depth without CoT tokens      │
└─────────────────────────────────────────────────────┘
```

### 2.2 Training Characteristics

- No pre-training required — trains from scratch on task-specific data
- 1,000 samples sufficient for complex reasoning tasks
- PyTorch + CUDA 12.6 + FlashAttention 3 (Hopper) / FlashAttention 2 (Ampere)
- Runtime on single GPU (RTX 4070 laptop): ~10 hours for Sudoku Extreme
- Runtime on 8-GPU: ~10 minutes for Sudoku, ~1 hour for Maze, ~24 hours for ARC
- Weights & Biases integration for experiment tracking

---

## 3. GitHub Repository Structure

| Path | Purpose |
|------|---------|
| `models/` | Model architecture (dual-module implementation) |
| `config/` | Hyperparameters and training config |
| `dataset/` | Dataset builders (`build_sudoku_dataset.py`, `build_maze_dataset.py`, `build_arc_dataset.py`) |
| `utils/` | Helper utilities |
| `pretrain.py` | Training entry point |
| `evaluate.py` | Evaluation entry point |
| `arc_eval.ipynb` | ARC-AGI evaluation notebook |
| `puzzle_visualizer.html` | Browser-based puzzle visualization |
| `puzzle_dataset.py` | Puzzle data handling |

### Pre-trained Checkpoints (HuggingFace)

| Checkpoint | Link |
|------------|------|
| ARC-AGI-2 | `sapientinc/HRM-checkpoint-ARC-2` |
| Sudoku 9x9 Extreme (1k) | `sapientinc/HRM-checkpoint-sudoku-extreme` |
| Maze 30x30 Hard (1k) | `sapientinc/HRM-checkpoint-maze-30x30-hard` |

---

## 4. Deep Research Findings

### 4.1 Session Context

- **Topic:** How can HRM's architecture be integrated into Raphael 2.0?
- **Pipeline:** Web search (DuckDuckGo, 9 sources) → Community analysis (minimax + nemotron-super) → RSI improvement plan (mistral-large)
- **Time budget:** 300s
- **Sources found:** 12 (first run), 8 (second run)
- **Sources analyzed:** 5

### 4.2 Community Analysis — minimax

The minimax analysis identified **four key integration insights**:

**1. Architectural Mapping**
HRM's dual-module design maps directly to red-team operational structure:
- High-level module → Campaign orchestration, kill-chain design, target recon strategy
- Low-level module → Exploit generation, payload crafting, step-by-step TTP execution
- Inter-module coupling → Feedback loop between strategic posture and tactical actions
- Single forward pass → End-to-end attack chain planning without discrete plan disclosure

**2. Offensive Capabilities**
- **Hierarchical Attack Chain Generation:** High-level module maps attack surface → abstract graph of viable paths; low-level module generates concrete steps
- **Maze-Solving for Network Pathfinding:** Maze benchmarks directly applicable to Active Directory traversal, cloud permission graphs, micro-segmented networks
- **ARC-Style Abstract Reasoning:** Generalization without prior exposure is valuable for zero-day hunting — evaluate HRM as a zero-day pattern-matching component

**3. Defensive / Evaluation Capabilities**
- **Reasoning Verification Layer:** HRM-A proposes attack chains, HRM-B critiques before execution
- **Detection Signatures:** Profile HRM's inference patterns (latency, request shape, computational footprint)

**4. Framework Engineering Benefits**
- **Efficiency:** Single forward pass vs. multi-token CoT reduces latency
- **Deployability:** 27M params fits on edge devices, air-gapped environments
- **Data Efficiency:** 1,000 samples = rapid retraining on new target architectures

### 4.3 Community Analysis — nemotron-super

- **Strategic Planning:** H-module maintains coarse latent state representing operational phase → Mirrors Raphael's current phase structure (recon → scan → exploit → postex → exfil → phish)
- **Tactical Execution:** L-module handles tool-specific command construction, protocol-level state machines, constraint satisfaction
- **Halting Signal:** HRM's key mechanism where H-module periodically re-abstracts based on accumulated L-module work → Maps to Raphael's phase transitions

### 4.4 RSI Improvement Plan

The RSI phase (mistral-large) produced a **three-phase integration strategy**:

**Phase 1: Assessment & Proof-of-Concept**
- Benchmark HRM against Raphael's existing CoT-based reasoning on 3 test cases:
  - MITRE ATT&CK tactic decomposition
  - Exploit chain planning (privilege escalation pathfinding)
  - Adversary emulation (APT behavior mimicry)
- Curate 1,000 synthetic attack scenarios for fine-tuning
- Develop PoC: wrap HRM in REST API (`POST /plan_attack_chain`)

**Phase 2: Full Integration**
- **Option A — Standalone Module:** Deploy HRM as dedicated "Reasoning Engine" alongside LLMs
  - HRM for bounded, sequential tasks (exploit chains, evasion planning)
  - LLMs for creative tasks (phishing emails, social engineering)
- **Option B — Hybrid Reasoning:**
  - High-level: HRM plans the attack chain
  - Low-level: LLMs execute with creative adaptation

**Phase 3: Production Deployment**
- Embed HRM as core reasoning engine within Raphael's orchestrator
- Replace CoT with HRM for all multi-step planning
- Continuous fine-tuning on real engagement data

---

## 5. Conclusion & Verdict

### Why HRM Fits Raphael 2.0

| Raphael Need | HRM Solution |
|-------------|--------------|
| Multi-step kill-chain planning | Dual-module architecture mirrors strategic/tactical split |
| Fast inference for real-time ops | Single forward pass, no CoT token generation |
| Deployable in target environments | 27M params, runs on laptop GPU |
| Adaptable to new targets | 1,000 samples for task-specific training |
| Stealth operations | No external API calls, fully local inference |
| Phase transitions | Halting/continuation signal between H and L modules |

### Critical Assessment

**Strengths for Raphael:**
1. **Architectural fit is near-perfect** — HRM's H/L module split maps directly to Raphael's strategic planner / tactical executor
2. **Lightweight** — Could run as a Docker microservice within the existing compose stack
3. **No API dependency** — Fully offline capable, critical for air-gapped ops
4. **Rapid adaptation** — Fine-tune on 1k target-specific examples

**Limitations / Risks:**
1. **Not a replacement for LLMs** — HRM excels at bounded sequential reasoning but can't handle open-ended creative tasks (phishing content, social engineering)
2. **CUDA dependency** — Requires NVIDIA GPU with FlashAttention support
3. **Training overhead** — Even at 1k samples, full retraining takes hours on laptop GPU
4. **Provenance** — New architecture, limited real-world red-team validation

### Recommendation

**Proceed with Phase 1 (PoC)** — Clone the repo, train on a red-team-specific dataset (~1k attack scenarios), wrap as a microservice, and benchmark against Raphael's current CoT-based reasoning on:
- MITRE ATT&CK tactic decomposition accuracy
- Exploit chain planning latency
- Zero-day pattern matching (ARC-style generalization)

HRM is not a drop-in replacement for Raphael's LLMs — it's a **complementary reasoning engine** for the specific class of problems LLMs handle poorly: bounded, multi-step, constraint-satisfaction planning with minimal supervision.

---

## 6. References

1. Wang et al., "Hierarchical Reasoning Model," arXiv:2506.21734, 2025. [https://arxiv.org/abs/2506.21734](https://arxiv.org/abs/2506.21734)
2. Sapient Inc., "HRM Official Release," GitHub. [https://github.com/sapientinc/HRM](https://github.com/sapientinc/HRM)
3. Sapient Intelligence, "Open-Sources Hierarchical Reasoning Model," Press Release, July 2025.
4. Chollet, F., "On the Measure of Intelligence," arXiv:1911.01547, 2019. (ARC benchmark)
