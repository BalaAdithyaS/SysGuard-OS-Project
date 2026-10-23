"""
Page 7: System Architecture, Theory, and Security Boundaries.
"""

from __future__ import annotations

import streamlit as st

from sysguard.ui_common import (
    apply_custom_theme,
    init_session_state,
    render_header,
    render_status_sidebar,
)

init_session_state()
render_status_sidebar()
render_header("About SysGuard & OS Security Model", "Theoretical foundations, ptrace mechanics, and security boundary disclosures.")

st.markdown("### 1. Project Purpose & Scope")
st.markdown(
    """
**SysGuard** is an Operating Systems laboratory project developed to demonstrate:
1. **User Mode vs. Kernel Mode Transitions:** How user-space applications invoke system services via machine instructions (`syscall` on x86-64).
2. **Process Tracing Subsystems (`ptrace`):** How parent controllers intercept child processes at system-call boundaries.
3. **Register Manipulation & Call Spoofing:** How altering architecture-specific registers before kernel execution enables deterministic policy enforcement.
4. **Deterministic Auditing:** How high-fidelity telemetry can be gathered safely from target process address spaces without destabilizing the target.
"""
)

st.markdown("---")
st.markdown("### 2. How Syscall Enforcement Works")
st.markdown(
    """
SysGuard uses the standard Linux x86-64 kernel interception technique:

1. **Child Launch:** The child process is created via `fork()`, invokes `ptrace(PTRACE_TRACEME, 0, NULL, NULL)`, and raises `SIGSTOP`.
2. **Controller Configuration:** The parent tracer receives the stop via `waitpid()` and establishes tracing options:
   - `PTRACE_O_TRACESYSGOOD`: Sets bit 7 in the stop signal (`SIGTRAP | 0x80`), clearly distinguishing syscall stops from ordinary signals.
   - `PTRACE_O_TRACEEXEC`: Notifies the tracer when `execve` replaces the process image.
3. **Syscall Entry Interception:** When the target process executes a `syscall` instruction:
   - The Linux kernel pauses the thread and delivers `SIGTRAP | 0x80` to the tracer.
   - The tracer reads the register state using `ptrace(PTRACE_GETREGS, pid, 0, &regs)`.
   - On x86-64, `regs.orig_rax` contains the syscall number, and `regs.rdi`, `regs.rsi`, `regs.rdx`, `regs.r10`, `regs.r8`, `regs.r9` contain arguments.
4. **Enforcement (Nullification):**
   - If the active policy rules that this syscall is **DENIED**, the tracer modifies `regs.orig_rax = -1` (an invalid syscall number) via `ptrace(PTRACE_SETREGS)`.
   - The tracer resumes the child with `PTRACE_SYSCALL`.
   - The Linux kernel checks `orig_rax`, detects an invalid call number, **skips execution of the actual system routine entirely**, and loads `-ENOSYS` (-38) into `rax`.
5. **Syscall Exit Modification:**
   - The child stops again at the syscall-exit boundary (`SIGTRAP | 0x80`).
   - The tracer inspects the exit stop, notices that this call was nullified, and sets `regs.rax = -EPERM` (or `-EACCES`).
   - The tracer resumes execution.
   - The target program's C library receives `-1` and sets `errno = EPERM` (`Operation not permitted`). The destructive operation (such as file deletion) **never took place**.
"""
)

st.markdown("---")
st.markdown("### 3. Critical Security Boundary Disclosures")
st.warning(
    """
    **Academic Sandbox Disclaimer:**
    SysGuard is an educational systems-programming and policy enforcement framework, **NOT a full container or production isolation sandbox.**
    """
)

st.markdown(
    """
Please review the fundamental technical differences between ptrace-based policy enforcement and complete security sandboxes:

- **Time-of-Check to Time-of-Use (TOCTOU) Races:**
  Because pointer arguments (such as file path strings in target memory) are read across process boundaries,
  a multithreaded target could theoretically mutate memory in another thread between inspection and execution.
- **Process Trees & Fork Following:**
  In this version, SysGuard focuses strictly on single-process tracing. Unchecked child processes spawned via `fork()`
  or `clone()` are not automatically traced unless multi-process hierarchy tracking is configured.
- **Performance Overhead:**
  Each traced system call incurs two context switches between the target and the tracer (entry and exit stops),
  introducing measurable execution overhead for I/O-intensive workloads.
- **Production Alternatives:**
  Production sandboxing in Linux is typically implemented using **Linux Seccomp-BPF filters** (in-kernel bytecode evaluation without user-space context switches)
  combined with **Namespaces (cgroups, pivot_root)** and **LSMs (AppArmor, SELinux)**.
"""
)

st.markdown("---")
st.markdown("### 4. Reproducing Included Laboratory Demonstrations")

st.markdown(
    """
To reproduce the demonstrations manually via terminal:

```bash
# 1. Compile backend and examples
make

# 2. Test Allowed Operation
./backend/sysguard-tracer -p policies/read_only_demo.json -- ./examples/basic_read

# 3. Test Denied File Deletion (Enforcement Verification)
./backend/sysguard-tracer -p policies/read_only_demo.json -- ./examples/denied_unlink

# 4. Test Audit-Only Operation
./backend/sysguard-tracer -p policies/audit_all.json -- ./examples/audit_only

# 5. Run Automated Test Suite
pytest tests/ -v
```
"""
)
