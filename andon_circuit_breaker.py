# Copyright 2026 José Luis Pino
# SPDX-License-Identifier: Apache-2.0

"""
Epistemic Andon Circuit Breaker & Process Supervisor
===================================================
Reference Implementation for Out-of-Band Physical Preemption
and Boundary Invariant Enforcement for Autonomous Agents.

From "Hard Stop: The Epistemic Andon Cord for Autonomous Agents" (Pino, 2026).

Key Capabilities:
1. Process Group Quiescence: Uses os.killpg() with process group IDs (pgid) 
   to freeze/terminate entire process trees rather than single PIDs.
2. Execution Surface Allowlists: Enforces allowed_paths and allowed_syscalls 
   alongside allowed_domains in evaluate_tripwires().
3. Torn Read Protection: Safe JSON decoding from WAL shared memory handles 
   incomplete or corrupted mid-write state extractions gracefully.
4. Path Traversal Guard: Canonicalizes file paths (abspath/real path) to ensure
   attempts to read unauthorized system paths (e.g., /etc/shadow, /root/.ssh)
   or use traversal sequences are properly flagged.
"""

import os
import signal
import json
import pathlib
import shlex
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field


class PosixProcessSupervisor:
    """
    Out-of-band OS-level process supervisor enforcing physical preemption
    and decoupled WAL state extraction.
    """

    def __init__(
        self, target_pid: int, wal_shm_path: str = "/dev/shm/andon_wal.bin"
    ):
        self.target_pid = target_pid
        self.wal_shm_path = wal_shm_path

    def _get_target_pgid(self) -> Optional[int]:
        """Helper to get process group ID for target PID."""
        try:
            return os.getpgid(self.target_pid)
        except (ProcessLookupError, PermissionError, OSError):
            return None

    def freeze_process_group(self) -> bool:
        """
        Phase 1: Immediate non-cooperative boundary halt via SIGSTOP
        applied to the entire process group.
        """
        pgid = self._get_target_pgid()
        try:
            if pgid is not None:
                os.killpg(pgid, signal.SIGSTOP)
            else:
                os.kill(self.target_pid, signal.SIGSTOP)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            # Fallback to single PID if killpg lacks cross-group permission
            try:
                os.kill(self.target_pid, signal.SIGSTOP)
                return True
            except (ProcessLookupError, PermissionError):
                return False

    def extract_clean_checkpoint_snapshot(self) -> Dict[str, Any]:
        """
        Phase 2: Out-of-band state extraction from lock-free WAL.
        Guarantees protection against torn reads during mid-write preemption.
        """
        if os.path.exists(self.wal_shm_path):
            try:
                with open(self.wal_shm_path, "rb") as f:
                    raw = f.read()
                if raw:
                    return json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError, OSError) as e:
                # Handle torn read gracefully
                return {
                    "committed_step": -1,
                    "status": "TORN_READ_RECOVERY_MODE",
                    "error": f"Corrupted or incomplete WAL read during preemption: {str(e)}"
                }
        return {"committed_step": 0, "status": "QUIESCED_CLEAN"}

    def terminate_process_group(self) -> bool:
        """Issues non-maskable SIGKILL to isolate rogue process group and its children."""
        pgid = self._get_target_pgid()
        try:
            if pgid is not None:
                os.killpg(pgid, signal.SIGKILL)
            else:
                os.kill(self.target_pid, signal.SIGKILL)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            try:
                os.kill(self.target_pid, signal.SIGKILL)
                return True
            except (ProcessLookupError, PermissionError):
                return False


class ExecutionSurfaceGuard(BaseModel):
    """Execution surface allowlists for domains, paths, and binaries."""

    allowed_domains: List[str] = Field(
        default_factory=lambda: ["internal-eval.local", "api.github.com"]
    )
    allowed_paths: List[str] = Field(
        default_factory=lambda: ["/sandbox", "/tmp"]
    )
    allowed_syscalls: List[str] = Field(
        default_factory=lambda: ["python3", "pytest", "git", "ls", "cat"]
    )


class AndonCircuitBreaker:
    """Epistemic Andon Sentinel evaluating boundary invariants."""

    def __init__(
        self,
        guard: Optional[ExecutionSurfaceGuard] = None,
        supervisor: Optional[PosixProcessSupervisor] = None,
    ):
        self.guard = guard or ExecutionSurfaceGuard()
        self.supervisor = supervisor

    def evaluate_tripwires(
        self,
        target_domain: Optional[str] = None,
        file_path_accessed: Optional[str] = None,
        command_str: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluates active tripwires across 4 security dimensions:
        1. Network Egress Domain & IMDS Probing
        2. Template Injection & Known Prohibited Signatures
        3. Path Traversal & Unauthorized Sandbox File System Access
        4. Unauthorized Execution Surface & Binary Commands
        """
        # 1. Domain Meet Egress Tripwire (AWS IMDS / off-target C2)
        if target_domain:
            imds = "169.254.169.254" in target_domain
            allowed = any(
                target_domain == d or target_domain.endswith("." + d)
                for d in self.guard.allowed_domains
            )
            if imds or not allowed:
                return {
                    "conflict_type": "EXTERNAL_EGRESS_VIOLATION",
                    "target": target_domain,
                }

        # 2. Template Injection & Traversal Prohibited Strings
        payload = f"{file_path_accessed or ''} {command_str or ''}"
        prohibited = [
            "cycler.__init__",
            "__globals__",
            "__builtins__",
            "/proc/",
            "/sys/",
            "/etc/passwd",
            "/etc/shadow",
        ]
        if any(sig in payload for sig in prohibited):
            return {
                "conflict_type": "TEMPLATE_INJECTION",
                "payload": payload.strip(),
            }

        # 3. Path Sandbox Violation Guard (Enforcing allowed_paths)
        if file_path_accessed:
            try:
                resolved_path = pathlib.Path(file_path_accessed).resolve()
                path_str = str(resolved_path)
                in_sandbox = False
                for allowed_p in self.guard.allowed_paths:
                    allowed_resolved = pathlib.Path(allowed_p).resolve()
                    if path_str == str(allowed_resolved) or path_str.startswith(
                        str(allowed_resolved) + os.sep
                    ):
                        in_sandbox = True
                        break
                if not in_sandbox:
                    return {
                        "conflict_type": "PATH_TRAVERSAL_VIOLATION",
                        "path": file_path_accessed,
                        "resolved_path": path_str,
                    }
            except Exception as e:
                return {
                    "conflict_type": "INVALID_PATH_ACCESS",
                    "path": file_path_accessed,
                    "error": str(e),
                }

        # 4. Command Execution Surface Guard (Enforcing allowed_syscalls)
        if command_str:
            prohibited_cmds = ["tailscale", "kubectl", "socket.getaddrinfo", "nc", "curl", "bash", "sh", "socat"]
            if any(sig in command_str for sig in prohibited_cmds):
                return {
                    "conflict_type": "UNAUTHORIZED_EXECUTION_SURFACE",
                    "command": command_str,
                    "reason": "Explicit prohibited keyword matched",
                }

            # Verify executable binary against allowed_syscalls allowlist
            try:
                tokens = shlex.split(command_str)
                if tokens:
                    binary_name = os.path.basename(tokens[0])
                    if binary_name not in self.guard.allowed_syscalls:
                        return {
                            "conflict_type": "UNAUTHORIZED_EXECUTION_SURFACE",
                            "command": command_str,
                            "binary": binary_name,
                            "reason": f"Binary '{binary_name}' not in allowed_syscalls allowlist",
                        }
            except Exception:
                pass

        return None

    def execute_quiescence_and_preempt(
        self, diagnostic: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Executes physical preemption and out-of-band WAL extraction."""
        if self.supervisor:
            self.supervisor.freeze_process_group()
            state = self.supervisor.extract_clean_checkpoint_snapshot()
            return {
                "diagnostic": diagnostic,
                "committed_state": state,
                "quiesced": True,
            }
        return {
            "diagnostic": diagnostic,
            "committed_state": None,
            "quiesced": False,
        }


def andon_circuit_breaker_node(
    state: Dict[str, Any], breaker: AndonCircuitBreaker
) -> Dict[str, Any]:
    """Graph interrupt node; invokes quiescence with 0 ms CPU spin."""
    diagnostic = breaker.evaluate_tripwires(
        target_domain=state.get("target_domain"),
        file_path_accessed=state.get("file_path_accessed"),
        command_str=state.get("command_str"),
    )
    if diagnostic:
        preempt_result = breaker.execute_quiescence_and_preempt(diagnostic)
        return {
            "type": "EPISTEMIC_ANDON_CORD_PULLED",
            "preempt_result": preempt_result,
        }
    return {"diagnostic": None}


if __name__ == "__main__":
    print("=== Testing Epistemic Andon Circuit Breaker ===")
    breaker = AndonCircuitBreaker()

    # Test 1: AWS IMDS Egress
    r1 = breaker.evaluate_tripwires(target_domain="http://169.254.169.254/latest/meta-data/")
    print(f"Test 1 (IMDS Egress): {r1}")

    # Test 2: Unallowed Domain
    r2 = breaker.evaluate_tripwires(target_domain="malicious-c2.com")
    print(f"Test 2 (Unallowed Domain): {r2}")

    # Test 3: Sandbox Path Violation (/root/.ssh/id_rsa)
    r3 = breaker.evaluate_tripwires(file_path_accessed="/root/.ssh/id_rsa")
    print(f"Test 3 (Path Violation): {r3}")

    # Test 4: Template Injection / /proc access
    r4 = breaker.evaluate_tripwires(file_path_accessed="/proc/self/environ")
    print(f"Test 4 (Template Injection): {r4}")

    # Test 5: Unallowed Executable Command (curl)
    r5 = breaker.evaluate_tripwires(command_str="curl -s http://example.com")
    print(f"Test 5 (Unallowed Command 'curl'): {r5}")

    # Test 6: Allowed Sandbox Path & Allowed Command
    r6 = breaker.evaluate_tripwires(file_path_accessed="/sandbox/data.csv", command_str="python3 process.py")
    print(f"Test 6 (Allowed Path & Command): {r6}")
