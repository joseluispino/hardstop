# Hard Stop: Kernel-Level Preemption and Containment for Rogue Agentic Execution

[![Paper](https://img.shields.io/badge/paper-PDF-red.svg)](paper/hard_stop.pdf)
[![arXiv](https://img.shields.io/badge/arXiv-2609.29808-b31b1b.svg)](https://arxiv.org/abs/2609.29808)
[![ORCID](https://img.shields.io/badge/ORCID-0009--0005--4854--3914-A6CE39.svg)](https://orcid.org/0009-0005-4854-3914)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Status: Patent Pending](https://img.shields.io/badge/USPTO-Patent_Pending-blue.svg)](#patent-and-statutory-notice)

> **Architectural Comparison: Off-Board Hardware Fabrics (DPUs / SmartNICs) vs. In-Cache Kernel Preemption (Hard Stop)**
> Off-board hardware security architectures route agent execution telemetry out-of-band across host I/O buses (PCIe/CXL) or external network fabrics to dedicated processors (DPUs or smartNICs). This introduces physical transport, SerDes framing, and DMA ring-buffer serialization delays (1.0 to 12.0 ms under cluster congestion) before a quarantine signal can be dispatched. *Hard Stop* provides an in-cache, software-defined alternative: by intercepting execution synchronously in the host CPU's L1/L2 cache via in-line eBPF LSM hooks and rootless `cgroup v2`, this reference implementation achieves **sub-2-microsecond deterministic preemption** (< 1.8 µs) on commodity Linux hardware—enforcing true zero-leakage positive control without requiring specialized silicon.

---

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

## Physical Transport Bounds: In-Cache Preemption vs. Off-Board Fabrics

Off-board security appliances (DPUs, smartNICs, or external network firewalls) are fundamentally bounded by the physics of bus and fabric transit. An external device cannot mathematically beat host CPU cache locality:

```
A. OFF-BOARD HARDWARE FABRIC (DPU / SmartNIC / External Security Switch):
[Agent Syscall] ---> [Host DMA Ring] ---> [PCIe Gen4/5 Bus] ---> [DPU Ingress FIFO] ---> [DPU Policy SoC]
      t=0                 5 - 15 µs           1.5 - 3.0 µs            3 - 5 µs             50 - 500 µs
                                                                                                |
[Host APIC Context Switch] <--- [PCIe MSI-X Interrupt] <--- [Cluster Queue Congestion] <--------+
        10 - 50 µs                     2 - 6 µs                      1.0 - 12.0 ms
Total Quarantine Envelope: 1.0 ms to 12.0 ms (Vulnerable to atomic syscall exfiltration)

B. IN-CACHE KERNEL PREEMPTION (hardstop-rs):
[Agent Syscall] ---> [eBPF LSM Trap] ---> [L1/L2 Cache Policy Trie] ---> [%rax = -EPERM] ---> [cgroup.freeze]
      t=0                 < 0.4 µs                   40 - 90 ns                 t = 60 ns          < 1.8 µs
Total Preemption Envelope: < 2.0 µs (Preempted in-line before bus or network traversal; 555× faster)
```

| Layer / Physical Stage | Transport Medium | Irreducible Physical Constraint | Latency Envelope |
| :--- | :--- | :--- | :--- |
| **Off-Board Hardware Fabrics** | | | |
| 1. Host-to-Device Bus Transit | PCIe Gen 4/5 Bus | TLP Serialization & Root Complex Crossing | 1.5 – 3.0 µs |
| 2. Memory Synchronization | DMA Ring Buffers | Descriptor Ring Updates & MMIO Doorbell | 5.0 – 15.0 µs |
| 3. Optical / PHY Overhead | Fiber / SerDes PHY | Electro-Optic Transduction, PAM-4, FEC Framing | 50 – 100 ns |
| 4. Network Fabric Transit | InfiniBand / RoCEv2 | Optical Fiber (5 ns/m) + Switch Traversal | 3.0 – 80.0 µs |
| 5. Off-Board Classification | SoC ARM / NPU Cores | Hardware Flow Table & Policy Parser | 50.0 – 500.0 µs |
| 6. Multi-Tenant Queue Load | Buffer Memory | Cluster Congestion & Head-of-Line Blocking | 1.0 – 12.0 ms |
| 7. Host Return Interrupt | Host PCIe / APIC | MSI-X Delivery & Core Register Context Switch | 10.0 – 50.0 µs |
| **Off-Board Quarantine Total** | **Bus & Fabric** | **Cumulative Transit & Asynchronous Interrupt** | **1.0 ms – 12.0 ms** |
| | | | |
| **In-Cache Kernel Preemption (hardstop-rs)** | | | |
| 1. Syscall Interception | Host CPU Pipeline | Kernel Entry Vector Trap | < 0.4 µs |
| 2. Tripwire Policy Eval | Host L1/L2 Cache | BPF LPM Radix Trie / Aho-Corasick DFA | 40.0 – 90.0 ns |
| 3. Synchronous LSM Denial | CPU Register (`%rax`) | Native BPF LSM `return -EPERM` Execution | 60.0 ns (exact) |
| 4. Process Group Quiescence | `cgroup v2` Subsystem | Cached Inode File Descriptor to `cgroup.freeze` | < 1.8 µs |
| **In-Cache Preemption Total** | **Host CPU L1/L2** | **Direct In-Line Synchronous Cache Evaluation** | **< 2.0 µs (555× faster)** |

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
