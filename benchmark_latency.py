#!/usr/bin/env python3
# Copyright 2026 José Luis Pino
# SPDX-License-Identifier: Apache-2.0

"""
Hard Stop Empirical Preemption & Sentinel Latency Benchmark.

Implements the Kalibera & Jones (2013) two-level hierarchical benchmarking
methodology for rigorous, non-parametric latency characterization:

    Kalibera, T., & Jones, R. (2013). Rigorous benchmarking in reasonable time.
    In Proceedings of the 2013 ACM SIGPLAN International Symposium on Memory
    Management (ISMM '13), pp. 63–74. https://doi.org/10.1145/2464157.2464160

Execution hierarchy
-------------------
  E outer processes (fresh ASLR / page table / heap layout per launch)
  └── I warmup iterations (discarded — cold cache, page fault, JIT burn-in)
  └── M measured iterations → timing matrix T[E, M]

Statistics
----------
  Location  : median of T (non-parametric; robust to heavy tails)
  Spread    : 95% CI via two-level hierarchical bootstrap (B resamplings)
              — resample E processes with replacement, then M iterations
                within each resampled process with replacement.
  Rationale : Student t-test / standard-error formulas assume i.i.d. normal
              samples and collapse the two-level structure. Bootstrap preserves
              the hierarchy and makes no distributional assumption.

Usage
-----
  # Orchestrator (default): spawns E worker processes and reports statistics
  python benchmark_latency.py

  # Worker (invoked by orchestrator only):
  python benchmark_latency.py --worker --mode tripwire --warmups=5 --iters=30
  python benchmark_latency.py --worker --mode preemption --warmups=2 --iters=20
"""

from __future__ import annotations

import os
import sys
import time
import random
import statistics
import subprocess
import argparse
import json
import datetime
from pathlib import Path
from typing import List, Tuple

from andon_circuit_breaker import AndonCircuitBreaker, PosixProcessSupervisor

# ── Kalibera & Jones parameters ───────────────────────────────────────────────
E_PROCESSES  = 15    # Outer independent OS-process executions
I_WARMUPS_TW = 50    # Warmup iterations per process — tripwire (cheap)
M_ITERS_TW   = 100   # Measured iterations per process — tripwire
I_WARMUPS_PR = 3     # Warmup iterations per process — preemption (expensive)
M_ITERS_PR   = 20    # Measured iterations per process — preemption
BOOTSTRAP_B  = 2000  # Hierarchical bootstrap resamplings
CI_LOWER     = 2.5   # Bootstrap CI lower percentile
CI_UPPER     = 97.5  # Bootstrap CI upper percentile
WCET_BOUND_MS = 0.154  # Architectural WCET bound (ms)


# ── Pure-stdlib statistics helpers ───────────────────────────────────────────

def _percentile(data: List[float], pct: float) -> float:
    """Linear-interpolation percentile (matches numpy default)."""
    if not data:
        return 0.0
    s = sorted(data)
    idx = (len(s) - 1) * (pct / 100.0)
    lo, hi = int(idx), min(int(idx) + 1, len(s) - 1)
    return s[lo] + (idx - lo) * (s[hi] - s[lo])


def _two_level_bootstrap(
    matrix: List[List[float]],
    stat_fn=statistics.median,
    B: int = BOOTSTRAP_B,
) -> Tuple[float, float, float]:
    """
    Kalibera & Jones two-level hierarchical bootstrap.

    Parameters
    ----------
    matrix : list of lists — shape (E, M), each row is one outer process.
    stat_fn : aggregate statistic to bootstrap (default: median).
    B : number of bootstrap resamplings.

    Returns
    -------
    (point_estimate, ci_lower, ci_upper)
    """
    E = len(matrix)
    boot_stats: List[float] = []
    for _ in range(B):
        # Level 1: resample E processes with replacement
        resampled_procs = [matrix[random.randrange(E)] for _ in range(E)]
        # Level 2: resample M iterations within each chosen process w/ replacement
        flat: List[float] = []
        for proc in resampled_procs:
            M = len(proc)
            flat.extend(proc[random.randrange(M)] for _ in range(M))
        boot_stats.append(stat_fn(flat))

    boot_stats.sort()
    n = len(boot_stats)
    ci_lo = boot_stats[int(n * CI_LOWER / 100)]
    ci_hi = boot_stats[int(n * CI_UPPER / 100) - 1]
    # Point estimate over all raw data
    all_raw = [v for row in matrix for v in row]
    return stat_fn(all_raw), ci_lo, ci_hi


# ── Worker-mode measurement functions ────────────────────────────────────────

def _worker_tripwire(warmups: int, iters: int) -> None:
    """
    Run tripwire benchmark inside a fresh worker process.
    Prints M comma-separated µs floats to stdout and exits.
    """
    breaker = AndonCircuitBreaker()

    def _single() -> float:
        t0 = time.perf_counter_ns()
        breaker.evaluate_tripwires(
            target_domain="http://169.254.169.254/latest/meta-data/",
            file_path_accessed="/sandbox/data.json",
            command_str="python3 script.py",
        )
        return (time.perf_counter_ns() - t0) / 1_000.0  # → µs

    for _ in range(warmups):
        _single()

    results = [_single() for _ in range(iters)]
    print(",".join(f"{v:.6f}" for v in results))


def _worker_preemption(warmups: int, iters: int) -> None:
    """
    Run SIGSTOP preemption benchmark inside a fresh worker process.
    Prints M comma-separated ms floats to stdout and exits.

    Each measured iteration spawns its own subprocess — the 'inner loop'
    here is over fresh child processes, not iterations of the same PID,
    so ASLR randomization occurs at two levels: the outer worker process
    and each spawned target child.
    """
    def _single() -> float:
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            preexec_fn=os.setpgrp,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        supervisor = PosixProcessSupervisor(target_pid=proc.pid)
        time.sleep(0.001)  # scheduler settle: allow child to reach sleep()

        t0 = time.perf_counter_ns()
        supervisor.freeze_process_group()
        elapsed_ms = (time.perf_counter_ns() - t0) / 1_000_000.0

        supervisor.terminate_process_group()
        try:
            proc.wait(timeout=1.0)
        except Exception:
            proc.kill()
        return elapsed_ms

    for _ in range(warmups):
        _single()

    results = [_single() for _ in range(iters)]
    print(",".join(f"{v:.6f}" for v in results))


# ── Orchestrator ──────────────────────────────────────────────────────────────

def _spawn_worker(mode: str, warmups: int, iters: int) -> List[float]:
    """Launch a fresh OS process in worker mode; return its timing list."""
    cmd = [
        sys.executable, __file__,
        "--worker",
        f"--mode={mode}",
        f"--warmups={warmups}",
        f"--iters={iters}",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(
            f"Worker process failed (mode={mode}):\n{result.stderr.strip()}"
        )
    return [float(v) for v in result.stdout.strip().split(",")]


def _run_orchestrator() -> None:
    """
    Kalibera & Jones two-level orchestrator.

    Spawns E independent OS processes for each benchmark mode, collects
    timing matrices T[E, M], computes hierarchical bootstrap CI, and prints
    a structured report.
    """
    sep = "=" * 72
    print(sep)
    print("  HARD STOP: KALIBERA & JONES RIGOROUS LATENCY BENCHMARK")
    print("  Two-Level Hierarchical Bootstrap | Non-Parametric 95% CI")
    print(sep)
    print(f"  E={E_PROCESSES} processes | B={BOOTSTRAP_B} bootstrap resamplings")
    print(f"  Tripwire: I={I_WARMUPS_TW} warmups, M={M_ITERS_TW} measured per process")
    print(f"  SIGSTOP:  I={I_WARMUPS_PR} warmups, M={M_ITERS_PR} measured per process")
    print(sep)

    # ── 1. Tripwire benchmark ─────────────────────────────────────────────
    print(f"\n[1] Spawning {E_PROCESSES} worker processes — Tripwire Evaluation...")
    tw_matrix: List[List[float]] = []
    for e in range(1, E_PROCESSES + 1):
        row = _spawn_worker("tripwire", I_WARMUPS_TW, M_ITERS_TW)
        tw_matrix.append(row)
        print(f"    Process {e:2d}/{E_PROCESSES}: "
              f"median={statistics.median(row):.4f} µs  "
              f"p99={_percentile(row, 99):.4f} µs")

    tw_all = [v for row in tw_matrix for v in row]
    tw_med, tw_ci_lo, tw_ci_hi = _two_level_bootstrap(tw_matrix)
    tw_p99_med, tw_p99_lo, tw_p99_hi = _two_level_bootstrap(
        tw_matrix,
        stat_fn=lambda xs: _percentile(xs, 99),
    )

    print(f"\n    Tripwire Evaluation (N={E_PROCESSES}×{M_ITERS_TW}={E_PROCESSES*M_ITERS_TW} samples):")
    print(f"    • Median      : {tw_med:.4f} µs  [95% CI: {tw_ci_lo:.4f}, {tw_ci_hi:.4f} µs]")
    print(f"    • p99 (median): {tw_p99_med:.4f} µs  [95% CI: {tw_p99_lo:.4f}, {tw_p99_hi:.4f} µs]")
    print(f"    • Global min  : {min(tw_all):.4f} µs")
    print(f"    • Global max  : {max(tw_all):.4f} µs")

    # ── 2. SIGSTOP preemption benchmark ──────────────────────────────────
    print(f"\n[2] Spawning {E_PROCESSES} worker processes — SIGSTOP Preemption...")
    pr_matrix: List[List[float]] = []
    for e in range(1, E_PROCESSES + 1):
        row = _spawn_worker("preemption", I_WARMUPS_PR, M_ITERS_PR)
        pr_matrix.append(row)
        print(f"    Process {e:2d}/{E_PROCESSES}: "
              f"median={statistics.median(row):.4f} ms  "
              f"p99={_percentile(row, 99):.4f} ms")

    pr_all = [v for row in pr_matrix for v in row]
    pr_med, pr_ci_lo, pr_ci_hi = _two_level_bootstrap(pr_matrix)
    pr_p99_med, pr_p99_lo, pr_p99_hi = _two_level_bootstrap(
        pr_matrix,
        stat_fn=lambda xs: _percentile(xs, 99),
    )

    print(f"\n    SIGSTOP Preemption (N={E_PROCESSES}×{M_ITERS_PR}={E_PROCESSES*M_ITERS_PR} samples):")
    print(f"    • Median      : {pr_med:.4f} ms  ({pr_med*1000:.2f} µs)  "
          f"[95% CI: {pr_ci_lo:.4f}, {pr_ci_hi:.4f} ms]")
    print(f"    • p99 (median): {pr_p99_med:.4f} ms  ({pr_p99_med*1000:.2f} µs)  "
          f"[95% CI: {pr_p99_lo:.4f}, {pr_p99_hi:.4f} ms]")
    print(f"    • Global min  : {min(pr_all):.4f} ms")
    print(f"    • Global max  : {max(pr_all):.4f} ms")

    # ── 3. WCET bound verification ────────────────────────────────────────
    wcet_pass = pr_p99_hi < WCET_BOUND_MS  # CI upper bound must clear the spec
    status = "PASSED" if wcet_pass else "FAILED"
    print(f"\n[3] Architectural Bound Verification:")
    print(f"    • WCET Bound                : < {WCET_BOUND_MS:.3f} ms")
    print(f"    • Preemption p99 [CI upper] :   {pr_p99_hi:.4f} ms")
    print(f"    • Invariant Status          : [{status}] — CI upper bound within spec")
    print(sep)
    print()
    print("  Reference: Kalibera, T., & Jones, R. (2013). Rigorous benchmarking")
    print("  in reasonable time. ISMM '13. https://doi.org/10.1145/2464157.2464160")

    # ── 4. Append structured record to benchmark_results.jsonl ────────────
    try:
        _sha = subprocess.run(
            ["git", "-C", str(Path(__file__).parent), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=3
        ).stdout.strip()[:12]
    except Exception:
        _sha = "untracked"

    _record = {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "git_commit": _sha,
        "platform": {
            "python_version": sys.version.split()[0],
            "os_uname": str(os.uname()),
        },
        "kj_params": {
            "E_processes": E_PROCESSES,
            "M_iters_tripwire": M_ITERS_TW,
            "M_iters_preemption": M_ITERS_PR,
            "bootstrap_B": BOOTSTRAP_B,
        },
        "tripwire_us": {
            "median": tw_med,
            "ci_lo": tw_ci_lo,
            "ci_hi": tw_ci_hi,
            "p99_median": tw_p99_med,
            "p99_ci_lo": tw_p99_lo,
            "p99_ci_hi": tw_p99_hi,
        },
        "sigstop_ms": {
            "median": pr_med,
            "ci_lo": pr_ci_lo,
            "ci_hi": pr_ci_hi,
            "p99_median": pr_p99_med,
            "p99_ci_lo": pr_p99_lo,
            "p99_ci_hi": pr_p99_hi,
        },
        "wcet_bound_ms": WCET_BOUND_MS,
        "wcet_passed": wcet_pass,
    }
    _log_path = Path(__file__).parent / "benchmark_results.jsonl"
    with open(_log_path, "a", encoding="utf-8") as _f:
        _f.write(json.dumps(_record) + "\n")
    print(f"  📝 Results logged → {_log_path.name}")

    # Optional SQLite persistence to axiom_benchmarks.sqlite
    _vault_root = os.environ.get("AXIOM_VAULT_ROOT", "/home/jpino/Obsidian/Axiom")
    _sqlite_path = Path(_vault_root) / "_Meta/Database/axiom_benchmarks.sqlite"
    if _sqlite_path.exists():
        try:
            import sqlite3
            _conn = sqlite3.connect(str(_sqlite_path))
            _cur = _conn.cursor()
            _run_id = f"kj-hardstop-{_sha}"
            _cur.execute("""
            INSERT OR REPLACE INTO preemption_latency_runs (
                run_id, timestamp, git_commit_sha, platform_cpu, python_version,
                kj_E_processes, kj_M_iters_tripwire, kj_M_iters_preemption, kj_B_bootstrap,
                tripwire_median_us, tripwire_p99_us, tripwire_ci_json,
                sigstop_median_ms, sigstop_p99_ms, sigstop_ci_json,
                wcet_bound_ms, wcet_passed, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                _run_id,
                _record["timestamp"],
                _sha,
                _record["platform"]["os_uname"],
                _record["platform"]["python_version"],
                E_PROCESSES,
                M_ITERS_TW,
                M_ITERS_PR,
                BOOTSTRAP_B,
                tw_med,
                tw_p99_med,
                json.dumps({"ci_lo": tw_ci_lo, "ci_hi": tw_ci_hi, "p99_ci_lo": tw_p99_lo, "p99_ci_hi": tw_p99_hi}),
                pr_med,
                pr_p99_med,
                json.dumps({"ci_lo": pr_ci_lo, "ci_hi": pr_ci_hi, "p99_ci_lo": pr_p99_lo, "p99_ci_hi": pr_p99_hi}),
                WCET_BOUND_MS,
                1 if wcet_pass else 0,
                "Live run from benchmark_latency.py orchestrator"
            ))
            _conn.commit()
            _conn.close()
            print(f"  💾 SQLite persistence verified → {_sqlite_path.name} (run_id: {_run_id})")
        except Exception as _e:
            print(f"  ⚠️ SQLite persistence notice: {_e}")
    print(sep)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--worker", action="store_true",
                        help="Run as worker subprocess (invoked by orchestrator)")
    parser.add_argument("--mode", choices=["tripwire", "preemption"],
                        default="tripwire")
    parser.add_argument("--warmups", type=int, default=I_WARMUPS_TW)
    parser.add_argument("--iters",   type=int, default=M_ITERS_TW)
    args, _ = parser.parse_known_args()

    if args.worker:
        if args.mode == "tripwire":
            _worker_tripwire(args.warmups, args.iters)
        else:
            _worker_preemption(args.warmups, args.iters)
    else:
        _run_orchestrator()


if __name__ == "__main__":
    main()
