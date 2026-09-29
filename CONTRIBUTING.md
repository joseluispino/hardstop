# Contributing to HardStop

Thank you for your interest in contributing to **HardStop** (`hardstop-rs`), the low-level Linux kernel preemption and containment engine for autonomous AI agents.

HardStop operates under strict operating-systems invariants: deterministic execution, sub-microsecond preemption (< 1.8 µs), rootless execution (`PR_SET_NO_NEW_PRIVS`), and zero-compromise safety.

---

## 1. Contributor License Agreement (ICLA) & DCO

To protect the project, its users, and future enterprise deployments, all external contributors must agree to the **HardStop Individual Contributor License Agreement (ICLA)** prior to having their Pull Requests merged.

### The Developer Certificate of Origin (DCO 1.1)
All commits must be signed off to certify that you wrote the code or have the right to submit it under the project's license terms:

```bash
git commit -s -m "fix(lsm): resolve socket attach transient on Linux 6.11"
```

The `-s` flag appends:
`Signed-off-by: Your Name <your.email@example.com>`

### Automated ICLA Verification
When you open a Pull Request, our `@cla-assistant` bot will automatically post a comment. Simply authorize the CLA with your GitHub account. 

Under the ICLA, you retain full copyright ownership of your contribution while granting José Luis Pino and his corporate successors/assigns (including **Axiom Lineage Inc.**) a perpetual, worldwide, irrevocable, royalty-free, sublicensable license to distribute your contribution under open-source (FSL-1.0-Apache-2.0 / Apache-2.0) and proprietary commercial terms (**AxiomShield™**).

---

## 2. Clean-Room Invariant

Contributors must adhere to strict clean-room software engineering standards:
* **Zero Employer Code**: Do NOT submit code developed on your employer's equipment, during employer working hours, or derived from employer trade secrets.
* **No Proprietary Decompilation**: Do NOT submit code reverse-engineered from closed-source commercial security suites or hardware SDKs.
* **Clean Clean-Room Provenance**: Contributions must be original works of authorship or sourced from permissively licensed open-source projects with proper attribution.

---

## 3. Engineering & Architectural Invariants

Before submitting a Pull Request, verify that your code adheres to HardStop's core systems invariants:

1. **Sub-Microsecond Latency Guarantee**: Hot paths (eBPF LSM socket inspection, CIDR trie lookups, Shannon entropy checks) must execute in sub-microsecond time. Avoid memory allocations (`malloc`, `clone`, `Box`) on inspection fast-paths.
2. **Deterministic Preemption**: Never use polling loops (`sleep`, `sched_yield`) to wait for processes to exit. Use atomic cgroup v2 freezes (`cgroup.freeze = 1`) or synchronous SIGSTOP signals.
3. **Rootless by Design**: HardStop operates without `sudo` or `CAP_SYS_ADMIN` whenever possible. Any PR requiring root privileges must strictly justify the requirement and provide a rootless fallback.
4. **Zero-Panic Rust**: Library code (`lib.rs`, `lsm/`, `freezer/`) must never `panic!`, `unwrap()`, or `expect()` on runtime inputs. All fallible operations must return typed `Result<T, HardStopError>`.
5. **Deterministic Testing**: Every feature or bug fix must include unit tests and property-based regression tests. All tests must pass:
   ```bash
   cargo test --all-targets
   ```

---

## 4. Pull Request Workflow

1. **Fork the Repository**: Create your branch from `main`:
   ```bash
   git checkout -b fix/lsm-ebpf-return-code
   ```
2. **Make Atomic Changes**: Keep commits focused and logically distinct.
3. **Format & Lint**:
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   ```
4. **Sign Off**: Ensure every commit includes `Signed-off-by:`.
5. **Open Pull Request**: Describe your change, benchmark impact, and motivation clearly.
6. **Accept ICLA**: Authorize the CLA bot prompt.

---

## Questions?
Reach out via GitHub Issues or contact the maintainer at `joseluispino.research@proton.me`.
