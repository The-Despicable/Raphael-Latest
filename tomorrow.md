# AI Penetration Testing Platform Research — July 2026

## Overview

Extensive research on 5 AI pentesting platforms: **XBOW**, **Hadrian**, **HackingBuddyGPT**,
**Zen-AI-Pentest**, and **Kensai**. Sources include vendor sites, GitHub repos, research
papers (arXiv, Springer, USENIX), news coverage (TechRepublic, HelpNetSecurity, GlobeNewswire),
Reddit discussions, Hacker News, and industry comparisons (Astra, Corgea, Spark42, Slashdot).

---

## 1. XBOW

### Quick Facts
- **URL:** https://xbow.com
- **Type:** Commercial SaaS
- **Founded:** ~2023 (team ex-GitHub Copilot)
- **Team:** ~50-100 (Nico Waisman — Head of Security)
- **Funding:** Sequoia Capital-backed
- **Customers:** 150+ security teams (Moderna, Seznam, PuppyGraph, BloomPath, top-5 US bank)
- **Pricing:** Undisclosed (enterprise)

### Architecture
- **Multi-model LLM orchestration** — routes each sub-task to the best frontier model,
  no single-model lock-in. Adopts new models as they ship.
- **Agent swarm** — multiple specialized agents run in parallel across the attack surface,
  coordinated by an orchestrator that prevents duplicated effort.
- **Validators** — automated peer-reviewer agents independently confirm each finding before
  it reaches the team. Uses both LLM-based review and custom programmatic checks.
- **Scoping guardrails** — user-defined scope boundaries; non-destructive execution with
  "production-safe challenges" that prove exploitability without modifying data.
- **Full audit trail** — every agent decision logged, every finding traceable to a complete
  case file (chained attack path, working exploit, tactic log, remediation).

### Key Differentiators

#### #1 on HackerOne US Leaderboard (Q2 2025)
- 1,060+ vulnerability reports submitted in a few months
- 132 confirmed/fixed, 303 under review
- Severity breakdown: 54 critical, 242 high, 524 medium, 65 low
- Reputation score: 2,059
- First autonomous system to top any HackerOne regional leaderboard
- Also ranked 1st autonomous system on Microsoft MSRC leaderboard
- Found a 9.8 critical Microsoft flaw (CVE-2026-45185 — Exim BDAT)
- 14,000+ zero-days found across customer applications

#### Benchmark Performance
- **104 novel challenges:** 85% solved in 28 minutes (humans: 85% in 40 hours)
- **PortSwigger labs:** 75%+ completion
- **Overall accuracy on HackerOne:** ~37.5% (vs 60-80% for top humans)
- **False positive rate (XSS):** ~0%
- **Business logic discovery:** ~0% (known limitation)

#### What It's Strongest At
- Vulnerability chaining — connecting individual flaws into multi-step attack paths
- Black-box web app pentesting at scale
- Continuous testing across the entire portfolio
- Near-zero false positives through multi-layer validation

#### Known Limitations
- Business logic flaws (~0% discovery rate vs humans who excel here)
- Requires human review before submission to bug bounty programs
- Modest per-bounty earnings (largest: $3,000 from Hilton)
- HackerOne leaderboard criticism: country-specific filter excludes many top hunters
- Black-box only; limited white-box support

### News / Press Highlights
- TechRepublic (Jun 2025): "AI Bug Hunter Sets Milestone By Claiming Top Spot"
- Black Hat 2025 Briefings: technical deep-dive on methodology
- Axios (2026): XBOW evaluated Mythos Preview, found it "good but less powerful at validating exploits"
- Vanta partnership (Aug 2025): delivering autonomous pentesting to startups
- Sonatype AI Vulnerability Storm report (2026): 3 Microsoft Patch Tuesday critical RCEs discovered

### Hacker News Discussion Themes
- Skepticism about "fully autonomous" claim vs human review requirement
- Debate about HackerOne leaderboard validity (self-selected country filter)
- Questions about compute cost vs bounty ROI
- Acknowledgment that 85% on 104 novel benchmarks in 28 min is genuinely impressive

### Comparison to Raphael
| Dimension | XBOW | Raphael |
|-----------|------|---------|
| Phase ordering | Multi-agent swarm, LLM-routed | RL Q-table (strategy_learner.py) |
| Exploit validation | Multi-model peer review validators | Circuit breaker + timeout guard |
| Attack chaining | Core strength — multi-step paths | relay_chain.py + exploit_chain.py |
| False positives | Near-zero (validated pipeline) | No formal validation pipeline |
| Business logic | ~0% | 0% (same gap) |
| Model routing | Per-task optimized | Single conductor (conductor.py) |
| RL/learning | Proprietary (not disclosed) | Q-learning with seeded Q-table |

---

## 2. Hadrian (Nova)

### Quick Facts
- **URL:** https://hadrian.io
- **Type:** Commercial SaaS (AMsterdam-based)
- **Founded:** ~2018
- **Team:** 70-99 employees
- **Funding:** Venture-backed
- **Customers:** 300+ enterprises (Damen Shipyards, London Business School, Aroma360, Breeze Airways)
- **Pricing:** Nova from €3,000/test; Atlas (ASM) subscription
- **Certifications:** SOC 2 Type II, ISO 27001
- **Recognition:** GigaOm Radar Leader 3 years running, Gartner Market Guide for AEV (2026)

### Product Lines

#### Atlas (Core ASM Platform)
- Continuous external attack surface discovery (hourly scans)
- Asset inventory: domains, subdomains, IPs, cloud instances, IoT, shadow IT
- AI Orchestrator runs automated pentesting against all assets
- Real-time threat intelligence feeds + infostealer malware data for leaked credentials
- Cuts through 99.5% of false positives
- 80% faster time to resolution

#### Nova (Agentic Pentesting — Launched March 2026)
- On-demand agentic pentesting (24-48 hour tests)
- Fleet of AI hacker agents trained by elite security engineers
- Deep attack path exploration with vulnerability chaining
- Context-rich asset analysis across sessions
- Expert-level offensive reasoning at scale
- Human-in-the-loop verification
- Compliance-ready reports (SOC 2, ISO 27001, NIS2)

#### OpenHack (Released May 2026)
- AI-powered source code review
- Fraction of human cost
- Democratizing AI vulnerability discovery

### Architecture
- Agentic AI trained by elite hackers
- Predictive Discovery Agent (proprietary)
- Autonomous vulnerability chaining + privilege escalation
- ML continuously improves from engagement data
- Three-phase mutation testing for write/delete vulnerabilities

### Key Differentiators
- Combined ASM + agentic pentesting (breadth + depth)
- Infostealer malware data integration for credential leak detection
- Strong European compliance focus (NIS2, DORA, GDPR)
- Per-test pricing (no retainer lock-in)
- Gartner-recognized as Representative Vendor

### Known Limitations
- Primarily external attack surface (less suited for internal network pentesting)
- Nova requires Atlas platform for maximum value
- Deep web app testing not a core focus
- Some customization requires security expertise

### News / Press
- GlobeNewswire (Mar 2026): Nova launch
- HelpNetSecurity (Mar 2026): continuous AI-powered offensive security
- Security Boulevard (Mar 2026): Nova for external attack validation
- TechFinitive (Jun 2026): "always-on offense as security baseline"
- Cybersecurity Excellence Awards (2025): CTEM category

### Comparison to Raphael
| Dimension | Hadrian | Raphael |
|-----------|---------|---------|
| Focus | External ASM + agentic pentest | Full-stack autonomous exploitation |
| Asset discovery | Continuous (hourly scans) | Manual phase selection |
| AI approach | Trained-by-hackers agentic AI | LLM conductor + RL strategy |
| Validation | 99.5% false positive reduction | Basic circuit breaker |
| Pricing | €3K/test | Open-source (self-run) |
| Compliance | SOC 2, ISO 27001, NIS2 | Not addressed |
| Infrastructure | Cloud SaaS | Self-hosted Python |

---

## 3. HackingBuddyGPT

### Quick Facts
- **URL:** https://github.com/ipa-lab/hackingBuddyGPT
- **Type:** Open-source research framework
- **Authors:** Andreas Happe, Manuel Reinsperger (IPA-Lab, TU Wien)
- **Language:** Python 3.10+
- **License:** MIT
- **Stars:** ~400+ on GitHub
- **PyPI:** v0.3.1 (Aug 2024)
- **Docs:** https://docs.hackingbuddy.ai

### Architecture
- **"Wintermute" CLI** — main execution engine
- **LLM-agnostic** — supports OpenAI, Anthropic, Google, local Ollama
- **Two connection modes:** SSH to remote targets, local shell execution
- **Reusable primitives:** 50-line core loop for quick experimentation
- **Context management:** sliding window, summarization strategies
- **Privilege escalation focused** — Linux privesc is the primary use case

### Use Cases / Commands (from wintermute CLI)
- `ExPrivEscLinux` — minimal Linux priv-esc demonstration
- `LinuxPrivesc` — full Linux privilege escalation agent
- `WindowsPrivesc` — Windows privilege escalation agent
- `WebTestingWithExplanation` — web API testing allowing LLM to "talk"
- `SimpleWebAPITesting` — minimal web API testing implementation
- `Replayer` — tool to replay and analyze past sessions

### Research Papers

#### 1. "LLMs as Hackers: Autonomous Linux Privilege Escalation Attacks" (arXiv:2310.11409)
- **Published:** Springer Empirical Software Engineering (Feb 2026)
- **Presented at:** FSE'23 San Francisco, ESSAI 2024
- **Key findings:**
  - GPT-3.5/4 achieved 40-60% success rate on Linux priv-esc benchmarks
  - LLMs good at individual sub-tasks but struggle with multi-step planning
  - Hallucinations occurred infrequently but were notable (e.g., "exploit.sh" suggestions)
  - Reverse shell generation was highly successful when prompted directly
  - Humans still superior for creative attack path discovery
  - Released Linux priv-esc benchmark (https://github.com/ipa-lab/benchmark-privesc-linux)

#### 2. "Towards Automated Software Security Testing" (arXiv:2308.00121)
- **Presented at:** FSE'23
- **Focus:** Augmenting pentesting through LLM-driven command generation
- **Findings:** LLMs can automate reconnaissance and initial exploitation but require
  human oversight for complex multi-step attacks

### Key Differentiators
- **Academic rigor** — peer-reviewed research, published at top venues
- **50-line core** — extremely accessible for researchers
- **Benchmark release** — standard Linux privesc benchmark for the community
- **LLM comparison** — published comparison of multiple LLMs for pentesting tasks
- **Reproducibility** — trajectory data open-sourced

### Known Limitations
- Research-grade, not production-ready
- Linux privesc-focused (limited web app coverage)
- No exploit validation pipeline
- No false positive management
- Requires manual setup for each engagement
- Community small (~400 stars, single maintainer team)

### Community
- Discord: active but small
- GitHub Accelerator 2024 cohort
- Presented at Google Developer Group TU Wien, FSE, ESSAI
- Risk: crypto spam/scam accounts impersonating the project

### Comparison to Raphael
| Dimension | HackingBuddyGPT | Raphael |
|-----------|-----------------|---------|
| Focus | Linux privesc research | Full pentest lifecycle |
| Maturity | Research/experimental | Operational |
| Exploit validation | None | Circuit breaker + timeout |
| RL/learning | None | Q-learning strategy learner |
| Phase coverage | Privesc only | 25+ phases |
| Academic backing | Peer-reviewed papers | None yet |
| Community | ~400 stars | Private repo |

---

## 4. Zen-AI-Pentest

### Quick Facts
- **URL:** https://github.com/SHAdd0WTAka/Zen-Ai-Pentest
- **Type:** Open-source framework
- **Author:** SHAdd0WTAka (single developer, with Kimi AI as co-developer)
- **Language:** Python
- **License:** MIT
- **Stars:** ~388 (GitHub)
- **PyPI:** v3.0.0 (Feb 2026)
- **Phase:** 6 (AI Personas)
- **Commits:** 862+
- **Tools integrated:** 72+
- **Tests:** 43,000+

### Architecture
```
Client Interfaces (React Dashboard / Python CLI / REST API + WebSocket)
  → API Gateway (FastAPI, JWT/RBAC, WebSocket Manager)
    → AI Orchestrator (Agent Manager, Guardrails, Task Queue, Risk Levels, VPN Check, State Machine)
      → Agent Pool (ReAct Agent Loop: Reason → Act → Observe → Reflect)
        → Security Toolkit (Nmap, Nuclei, SQLMap, FFuF, WhatWeb, WAFW00F, Subfinder, etc.)
          → Data Layer (PostgreSQL, Redis, Reports)
```

### 11 AI Personas
Specialized agent personas: Recon, Exploit, Report, Audit, Social Engineering,
Network, Mobile, Red Team, ICS (Industrial Control), Cloud, Crypto.

### Key Features
- **ReAct Agent Loop** — Reason → Act → Observe → Reflect with self-correction + memory
- **Multi-LLM support** — Kimi AI native + OpenRouter, OpenAI, Anthropic, intelligent routing
- **72+ integrated tools** — real execution (no mocks), Docker sandboxed
- **Security guardrails** — IP validation (blocks private networks), domain filtering,
  4-level risk system (Safe to Aggressive), rate limiting
- **VPN integration** — ProtonVPN native + generic OpenVPN/WireGuard
- **Risk Engine** — CVSS/EPSS scoring, false positive reduction, business impact
- **Docker Ready** — one-command docker-compose deployment, agent scaling
- **GitHub MCP Server** — Model Context Protocol integration (v3.0)
- **Global Chat** — AI-powered dashboard chat
- **CI/CD integration** — GitHub Action marketplace

### 72+ Tools (Partial)
- **Network:** Nmap, Masscan, Scapy, Tshark
- **Web:** Nuclei, SQLMap, Nikto, OWASP ZAP, BurpSuite, FFuF, Gobuster
- **Recon:** Subfinder, Amass, HTTPX, WhatWeb, WAFW00F
- **AD:** BloodHound, CrackMapExec, Responder
- **OSINT:** Sherlock, Scout, Ignorant
- **Secrets:** TruffleHog, Trivy, Semgrep

### Key Differentiators
- **Massive tool integration** — 72+ tools under one orchestration layer
- **Single-developer project** with AI co-development (Kimi AI)
- **Fast release cadence** — v3.0 in Feb 2026 (started ~Jan 2026)
- **Enterprise feature set** — JWT auth, RBAC, WebSocket, PostgreSQL
- **Real tool execution** — not simulated, with Docker sandbox safety
- **Phase 6 roadmap** — active development, frequent releases

### Known Limitations
- Single developer (bus factor risk)
- Quality of 43K tests unclear (may be auto-generated)
- Some features appear aspirational vs implemented
- Heavy reliance on Kimi AI for development decisions
- Integration depth per tool may vary
- No published research papers or independent evaluations
- Community small despite feature richness

### Community
- Discord server active
- GitHub Discussions (Q&A, Announcements, Ideas)
- Community CTF events (quarterly)
- Monthly community calls
- OpenSSF Best Practices passing
- Black Hat Arsenal (submitted)

### Comparison to Raphael
| Dimension | Zen-AI-Pentest | Raphael |
|-----------|----------------|---------|
| Tool orchestration | 72+ tools, ReAct agent | 25+ phase modules |
| AI approach | Kimi + OpenRouter multi-LLM | LLM conductor + RL |
| Safety | 4-level risk, guardrails, VPN | Circuit breaker + timeout |
| Architecture | FastAPI + React + PostgreSQL | Python CLI-based |
| Community | Open source, 388 stars | Private |
| RL/learning | None mentioned | Q-learning strategy learner |
| Enterprise features | JWT, RBAC, Docker, CI/CD | None |
| Developer maturity | Rapid but single-dev | Structured but private |

---

## 5. Kensai

### Quick Facts
- **URL:** https://kensai.app
- **Type:** Commercial SaaS (Switzerland-based)
- **Company:** Techfunder World AG (BRNZ.AI venture studio)
- **Team:** Small (part of BRNZ.AI)
- **Language:** Python (Strix AI engine)
- **Certifications:** GDPR compliant (German data processing)
- **Integration:** 33+ security tools
- **CVE Database:** 342K+ synced
- **Content:** 1,400+ security articles in 11 languages

### Architecture (Multi-Model "Panel of Experts")
```
Target → Reconnaissance → [Model A: Infrastructure]
                        → [Model B: Application Logic] → Correlation → Report
                        → [Model C: Code Analysis]
```
- Each model independently generates findings
- Correlation layer chains findings across models
- Low-severity finding from Model A + medium from Model B → critical attack path
- No single model is relied upon for everything

### Product Lines

#### AI Agent Security Scanner (NEW — post-Tsinghua research)
- Tests for 5 Tsinghua attack vectors: skill poisoning, prompt injection,
  memory poisoning, intent drift, stealth command execution
- Launched in response to Tsinghua/Ant Group research paper

#### CVE Intelligence
- 342K+ synced CVE corpus with daily updates
- Correlate known weaknesses for triage and prioritization

#### Vulnerability Scanning
- NIS2 compliance mapping
- Auto-remediation suggestions
- SBOM generation
- Executive PDF reports

#### Security Research
- Daily threat briefs across 11 languages
- Agent security research (e.g., the Tsinghua article user shared)

### Key Differentiators
- **Multi-model "panel of experts"** — different LLMs for infra, app logic, code
- **AI agent security focus** — first-mover in testing AI agents themselves
- **Swiss/German data processing** — GDPR stronghold
- **NIS2 compliance** — built-in compliance mapping
- **Research-first** — 1,400+ published articles, daily briefs
- **CVE intelligence** — not just scanning but correlation

### Known Limitations
- Smaller player compared to XBOW/Hadrian
- Less customer traction (no large-name logos prominently displayed)
- Scanning-focused rather than full exploitation
- No disclosed pricing
- No independent benchmarks found
- Blog/product update focus sometimes feels like SEO content more than product

### Lessons Learned (from BRNZ.AI GitHub guide)
- "Two years and 462+ scans later" — published learnings at
  https://github.com/BrnzAi/autonomous-pentesting-guide
- Cold start problem: needed vulnerable apps (WebGoat, DVWA, HTB, custom builds)
  + bug bounty data (noisy) + synthetic mutation
- Multi-model is essential: single-model approach misses business logic flaws
- False positive management is the hardest problem

### Comparison to Raphael
| Dimension | Kensai | Raphael |
|-----------|--------|---------|
| Architecture | Panel of experts multi-model | Single conductor + RL |
| Focus | Vulnerability scanning + CVE intel | Full exploitation |
| AI Agent Security | First-mover (Tsinghua framework) | Not addressed |
| False positives | Correlation-based reduction | No formal pipeline |
| Compliance | NIS2, SOC 2, ISO 27001 | Not addressed |
| Exploitation | Scanning-focused | Full exploit chain |
| Research output | 1,400+ articles, daily briefs | None public |

---

## Cross-Platform Comparison Matrix

| Feature | XBOW | Hadrian | HackingBuddyGPT | Zen-AI-Pentest | Kensai | Raphael |
|---------|------|---------|-----------------|----------------|--------|---------|
| **License** | Commercial | Commercial | MIT (OSS) | MIT (OSS) | Commercial | Private |
| **Price** | Enterprise | €3K+/test | Free | Free | Undisclosed | Free |
| **Autonomy** | Full | Full (Nova) | Semi (needs SSH) | Full | Semi (scan) | Full |
| **LLM Approach** | Multi-model routed | Trained-by-hackers | Any LLM via API | Kimi + OpenRouter | Panel of experts | Conductor + RL |
| **RL/Learning** | Not disclosed | ML from engagement | None | None | None | Q-learning |
| **Exploit Chain** | Core strength | Core strength | Privesc only | Tool orchestration | No | relay_chain.py |
| **False Positives** | Near-zero | 99.5% reduction | None | Risk engine | Correlation | None |
| **Web App** | ✅ Strong | ✅ (ext) | ❌ | ✅ (72 tools) | ✅ (33 tools) | ✅ Phase-based |
| **API Testing** | ✅ | ✅ | ❌ | ✅ | ✅ | ❌ |
| **Internal Net** | ❌ | ❌ | ✅ (SSH) | ❌ | ❌ | ✅ (VPN) |
| **Code Review** | ❌ | ✅ OpenHack | ❌ | ❌ | ❌ | ❌ |
| **AI Agent Security** | ❌ | ❌ | ❌ | ❌ | ✅ First-mover | ❌ |
| **Compliance** | SOC 2,ISO,PCI | SOC 2,ISO,NIS2 | ❌ | ❌ | NIS2,GDPR | ❌ |
| **Research** | Black Hat | Gartner cited | Peer-reviewed | None | 1,400 articles | None |
| **Community** | 150+ customers | 300+ enterprises | ~400 stars | ~388 stars | Unknown | Private |

## Key Takeaways for Raphael

### Gaps to Fill (from competitors)
1. **Exploit validation pipeline** — XBOW/Hadrian both emphasize validated PoC over raw findings
2. **False positive management** — every major platform has this; Raphael has none
3. **Business logic testing** — universal weakness across all AI pentesting tools
4. **AI agent security testing** — Kensai is first-mover; huge emerging market (Tsinghua 5 vectors)
5. **Continuous asset discovery** — Hadrian's core strength; Raphael relies on manual target input
6. **Compliance reporting** — SOC 2, NIS2, PCI mappings are table stakes for enterprise adoption
7. **Multi-model routing** — XBOW and Kensai both prove single-model isn't enough

### Where Raphael Leads
1. **RL strategy learning** — unique among all 5 competitors (Q-table with cross-session persistence)
2. **Full lifecycle coverage** — recon through exfil in a single autonomous loop
3. **Offline-capable** — no external API dependency for core phase execution (unlike all commercial tools)
4. **Cost** — open-source, self-hosted, no per-test fees
5. **Phase module extensibility** — 25+ phase modules is more granular than any competitor

### Strategic Recommendations
1. **Integrate AI agent security scanning** (Phase 7?) — Kensai has first-mover advantage but
   the Tsinghua framework is public and Raphael could implement it
2. **Add exploit validation layer** — prove findings are exploitable before reporting them
3. **Port to RL strategy learner** — Raphael already has this, competitors don't; major differentiator
4. **Consider compliance mapping** — NIS2/EU AI Act evidence generation as a product feature
5. **Open-source the benchmark** — HackingBuddyGPT's privesc benchmark approach was highly cited
