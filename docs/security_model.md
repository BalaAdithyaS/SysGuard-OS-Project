# SysGuard Security Model & Boundary Analysis

## 1. Scope & Objective

SysGuard is an Operating Systems educational and research framework designed to study:
- System call interception mechanics
- Policy evaluation architectures
- Dynamic register modification under ptrace
- Forensic audit trail generation

## 2. Ptrace vs. Production Sandboxes

SysGuard explicitly documents the technical distinctions between user-space ptrace enforcement and production container/sandbox isolation mechanisms.

| Characteristic | Ptrace Interception (SysGuard) | Seccomp-BPF (Production) | Linux Containers (Docker, Podman) |
| :--- | :--- | :--- | :--- |
| **Execution Domain** | User-space tracer process | In-kernel BPF engine | Kernel Namespaces + cgroups |
| **Context Switching** | 2 context switches per syscall | 0 user context switches | 0 context switches |
| **TOCTOU Resistance** | Vulnerable if memory inspected across threads | Immune (filters inspect register values or seccomp user_notif) | Immune (kernel-enforced boundaries) |
| **Privilege Requirements** | Non-root (can trace own children) | Non-root (`PR_SET_NO_NEW_PRIVS`) | Root daemon or rootless user namespace |
| **Interception Granularity** | Full dynamic register / memory reading & spoofing | Strict filter / kill / trap / notify | Mount/Network/PID namespace isolation |

## 3. Threat Analysis & Boundary Limitations

### 3.1 Time-of-Check to Time-of-Use (TOCTOU)
When a system call receives a pointer to a string or memory structure (e.g. `openat(AT_FDCWD, path, ...)`), the tracer reads the string from the target address space via `process_vm_readv`. In a multithreaded environment, another thread in the same address space could alter the memory buffer between the moment the tracer inspects it and the moment the kernel accesses it.
*Mitigation:* SysGuard focuses on syscall-level decisions and documents memory inspection as forensic telemetry rather than a cryptographically secure barrier.

### 3.2 Process Hierarchy & Child Spawning
When a process invokes `fork()`, `vfork()`, or `clone()`, the kernel creates a new task. Without `PTRACE_O_TRACEFORK` or full hierarchy tracking, child processes run unmonitored.
*Mitigation:* SysGuard documents single-process scope for this implementation.

### 3.3 Signals & Interrupted System Calls
When a process receives an asynchronous signal during a slow system call, the kernel may restart the call (`restart_syscall`). SysGuard properly forwards signals and preserves state machine consistency.
