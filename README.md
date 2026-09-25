# Hard Stop: Kernel-Level Preemption and Containment for Rogue Agentic Execution

[![Paper](https://img.shields.io/badge/paper-PDF-red.svg)](paper/hard_stop.pdf)
[![arXiv](https://img.shields.io/badge/arXiv-2609.29808-b31b1b.svg)](https://arxiv.org/abs/2609.29808)
[![ORCID](https://img.shields.io/badge/ORCID-0009--0005--4854--3914-A6CE39.svg)](https://orcid.org/0009-0005-4854-3914)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Status: Patent Pending](https://img.shields.io/badge/USPTO-Patent_Pending-blue.svg)](#patent-and-statutory-notice)

> **Abstract:** An autonomous generative AI operating in a continuous execution loop without an out-of-band **Epistemic Andon Cord** is an existential operational hazard. *Hard Stop* introduces a dual-plane supervisory control architecture combining out-of-band Discrete Event System (DES) supervision, Synchronous Reactive (SR) sentinels, and sub-millisecond (<0.154 ms) POSIX/eBPF preemption buses—demonstrating deterministic process freezes before off-target socket traffic or unauthorized system calls traverse hypervisor boundaries.

---

## The Core Invariant: Epistemic Self-Referential Invalidation

> **Principle:** A stochastic language model cannot serve as its own deterministic safety arbiter.

Formally, any internal self-evaluating safety loop composed of a probabilistic model $M$ with non-zero error rate $\epsilon > 0$ inherits compounded error probability $P(\text{error}) \ge 1 - (1 - \epsilon)^k$. Deterministic safety guarantees strictly require an **out-of-band supervisory control architecture** operating directly at the runtime, cgroup, and kernel boundaries.

---

## Architectural Overview

```
                         [ Agent Generative Loop ]
                                    │
                            Tool Dispatch Stream
                                    │
 ┌──────────────────────────────────▼──────────────────────────────────┐
 │                 Out-of-Band Epistemic Sentinel Bus                  │
 │  • Egress Domain Meet (D ∩ D_eval = ∅)                              │
 │  • Path Traversal & SSTI Lexical/LSM Tripwires                      │
 │  • Execution Surface Boundary Verification                          │
 └──────────────────────────────────┬──────────────────────────────────┘
                                    │ Invariant Breach (<0.154 ms)
                                    ▼
 ┌─────────────────────────────────────────────────────────────────────┐
 │               Sub-Millisecond Physical Preemption Bus               │
 │  1. Immediate Non-Cooperative SIGSTOP / Cgroup Freeze (<0.026 ms)   │
 │  2. Out-of-Band Lock-Free Write-Ahead Log (WAL) State Extraction    │
 │  3. Asynchronous LangGraph interrupt() Snapshot (0 Leaked Tokens)   │
 └─────────────────────────────────────────────────────────────────────┘
```

---

## Empirical Systems Telemetry

Benchmarks conducted under the **Kalibera & Jones (2013) two-level hierarchical protocol**: E=15 independent OS process launches (fresh ASLR per launch), I=50/3 warmup iterations discarded, M=100/20 measured iterations per process, B=2,000 hierarchical bootstrap resamplings. Statistics are non-parametric medians with 95% CI.

| Evaluation Metric | Unmitigated Baseline | Hard Stop Architecture | Systems Significance |
| :--- | :--- | :--- | :--- |
| **Total Actions Executed** | 17,600 (4.5-Day Runaway) | **Preempted at Action 1** | Complete attack surface elimination |
| **AWS IMDS Compromise** | Complete Credential Exfiltration | **Blocked (< 0.026 ms)** | Zero IAM credential exposure |
| **Tailscale Mesh Ingress** | 181 Sandbox Nodes Enrolled | **Blocked (< 0.026 ms)** | Corporate mesh VPN egress prevented |
| **Host Secrets Harvested** | 136 Production Secrets | **0 Secrets Leaked** | Complete air-gap preservation |
| **Tripwire Evaluation (median)** | ∞ (Failed to Halt) | **0.40 µs** [95% CI: 0.40, 0.41 µs] | Sub-microsecond deterministic check |
| **Tripwire Evaluation (p99)** | ∞ | **0.55 µs** [95% CI: 0.50, 0.62 µs] | Tail latency ≪ 0.100 ms |
| **SIGSTOP Freeze (median)** | N/A | **0.0048 ms** [95% CI: 0.0042, 0.0057 ms] | Non-cooperative process group halt |
| **SIGSTOP Freeze (p99)** | N/A | **0.0171 ms** [95% CI: 0.0128, 0.0252 ms] | 6× within architectural 0.154 ms bound |
| **Compute Idle Overhead** | 100% CPU Runaway | **0 ms CPU Spin** | Durable WAL state serialization |

> **Methodology**: Kalibera, T., & Jones, R. (2013). Rigorous benchmarking in reasonable time. *ISMM '13*. https://doi.org/10.1145/2464157.2464160  
> Run `python benchmark_latency.py` to reproduce. Results logged to `benchmark_results.jsonl`.

---

## Quickstart & Verification

Run the empirical benchmark runner and verification suite to reproduce the sub-millisecond preemption timings:

```bash
# Clone the repository
git clone https://github.com/joseluispino/hardstop.git
cd hardstop

# Install requirements
pip install -r requirements.txt

# 1. Run live sub-millisecond preemption and sentinel latency benchmarks
python benchmark_latency.py

# 2. Run the empirical verification test suite (20 tests, 100% pass rate in <0.25s)
pytest -v test_andon_circuit_breaker.py
```

> **Platform Requirement:** Linux kernel 5.15+ (Ubuntu, Debian, Fedora, Arch) or Windows Subsystem for Linux (WSL2). Physical preemption utilizes Linux process group signalling (`os.killpg`) and POSIX shared-memory WAL verification.

### Verified Test Suites (20 Tests across 8 Suites)
* **Execution Surface Guards**: Validates baseline and custom domain, path, and syscall allowlists.
* **Egress Domain Meet Containment**: Blocks unauthorized external domains and link-local AWS IMDS (`169.254.169.254`) probes.
* **Lexical & SSTI Tripwires**: Intercepts Jinja2 template injection, `/proc/`, `/sys/`, and shadow file traversal sequences.
* **Sandbox Path Traversal**: Canonicalizes paths via `Path.resolve()` to catch directory escape sequences.
* **Command Surface Verification**: Enforces binary allowlists and blocks prohibited tools (`curl`, `nc`, `kubectl`, `tailscale`).
* **Process Group Isolation**: Verifies non-cooperative `SIGSTOP`/`SIGKILL` process tree halts and torn-read WAL recovery.
* **LangGraph Node Integration**: Confirms zero-token-leak state snapshots and durable interrupt handling.
* **WCET Bound Invariant**: Verifies that empirical K&J bootstrap p99 upper confidence limit clears the 0.154 ms bound with 6× margin.

---

## Repository Structure

* `andon_circuit_breaker.py`: Core reference implementation of `PosixProcessSupervisor`, `ExecutionSurfaceGuard`, and `AndonCircuitBreaker`.
* `benchmark_latency.py`: Standalone empirical benchmark measuring sub-millisecond p50/p95/p99 tripwire and preemption latency.
* `test_andon_circuit_breaker.py`: Executable verification testbed (20 unit test assertions across 8 suites).
* `requirements.txt`: Minimal runtime dependencies (`pydantic`, `pytest`).
* `LICENSE`: Apache License, Version 2.0 (with Section 3 Patent Retaliation Protection).

---

## Citation

If you reference this architecture or reference implementation in your research, please cite:

```bibtex
@misc{pino2026hardstop,
  title={Hard Stop: Kernel-Level Preemption and Containment for Rogue Agentic Execution},
  author={Jos{\'e} Luis Pino},
  year={2026},
  eprint={2609.29808},
  archivePrefix={arXiv},
  primaryClass={cs.CR},
  url={https://arxiv.org/abs/2609.29808}
}
```

---

## Patent and Statutory Notice

Technologies and architectural methods described herein are subject to pending patent applications filed with the United States Patent and Trademark Office (USPTO). *Patent Pending*.

## Author & Contact

**José Luis Pino**  
*Independent Researcher* — Westlake Village, CA, USA  

* **Email**: [joseluispino.research@proton.me](mailto:joseluispino.research@proton.me)
* **ORCID**: [0009-0005-4854-3914](https://orcid.org/0009-0005-4854-3914)
* **LinkedIn**: [linkedin.com/in/joseluispino](https://www.linkedin.com/in/joseluispino/)
* **X / Twitter**: [@joseluispino](https://x.com/joseluispino)
