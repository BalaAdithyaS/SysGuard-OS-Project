# SysGuard: Linux System Call Interception and Policy Enforcement Framework

SysGuard is an Operating Systems laboratory project developed to demonstrate genuine system call tracing, real-time access policy evaluation, register-level enforcement, and telemetry generation on modern Linux x86-64 platforms.

---

## 1. Project Overview
SysGuard intercepts system calls executed by a target program in user space using the Linux kernel's native `ptrace()` interface. Unlike passive monitoring tools that merely log actions after they occur, SysGuard intercepts system calls **at entry**, evaluates active security rules, and **actively prevents unauthorized operations from executing** by altering architecture registers before the kernel executes the routine.

## 2. Problem Statement
Modern operating systems rely on system calls as the boundary between untrusted user processes and the privileged kernel. In educational and security engineering environments, developers need clear insight into how processes request operating system resources, how policies can be enforced at the system-call boundary, and what physical side-effects occur when a call is denied versus when it executes normally.

## 3. Objectives
1. Launch target executables with arguments safely without invoking a shell.
2. Trace system calls using Linux `ptrace()` with architecture-specific register definitions.
3. Distinguish entry and exit stops using a robust state machine.
4. Safely inspect arguments and decode strings across process address spaces using `process_vm_readv()`.
5. Evaluate deterministic allow, deny, and audit security policies.
6. Physically prevent denied system calls from executing by spoofing invalid syscall numbers (`orig_rax = -1`) and setting exit return values (`rax = -EPERM`).
7. Distinguish between an **observed** call, a **matched** policy, a **successfully blocked** call, and an **enforcement failure**.
8. Provide a modern, professional desktop dashboard using Streamlit and Plotly.
9. Export auditable trace logs in JSON, RFC-4180 CSV, and Markdown.

## 4. Operating Systems Concepts Demonstrated
* **Privilege Rings & Dual-Mode Operation:** User mode (Ring 3) vs Kernel mode (Ring 0).
* **System Call Dispatching:** x86-64 `syscall` instruction, register ABI (`orig_rax`, `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`), and the kernel dispatch table.
* **Process Lifecycle:** `fork()`, `execve()`, `waitpid()`, and signal propagation.
* **Process Tracing Subsystems:** Linux `ptrace(PTRACE_SYSCALL)`, `PTRACE_TRACEME`, and `PTRACE_SETOPTIONS`.
* **Cross-Address-Space Memory Access:** Safe virtual memory reading with `process_vm_readv()`.
* **Deterministic Policy Enforcement:** Rule precedence, default actions, and error synthesis.
* **TOCTOU Race Conditions:** Time-of-Check to Time-of-Use considerations in user-space security tools.

## 5. Architecture
SysGuard consists of a native C tracing helper and a Python management core:

```
+-------------------------------------------------------------+
|                      Streamlit Frontend                     |
|  (Overview, Run Program, Trace Explorer, Policy Editor,     |
|   Security Audit, Reports, About)                           |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                     Python SysGuard Core                    |
|  - PolicyEngine: Validation, precedence, rule evaluation    |
|  - TracerManager: Thread-safe subprocess & WSL bridging     |
|  - EventParser: Streaming JSON Lines parser                 |
|  - ReportGenerator: Multiformat audit export                |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                 Native Linux C Tracing Helper               |
|                 (`backend/sysguard-tracer`)                 |
|  - ptrace event loop (`SIGTRAP | 0x80`)                     |
|  - String reading via `process_vm_readv()`                  |
|  - Syscall nullification: orig_rax = -1, rax = -EPERM       |
+------------------------------+------------------------------+
```

## 6. Technology Stack
* **C Tracing Backend:** C11 (`gcc`), Linux `ptrace()`, POSIX APIs.
* **Python Framework:** Python 3.10+ (tested on Python 3.13 and 3.14).
* **Web Dashboard:** Streamlit 1.40+, Plotly 5.20+, Pandas.
* **Testing:** Pytest 8.0+.
* **Operating Environment:** Linux x86-64 (Ubuntu 22.04 / 24.04 / WSL2).

## 7. Prerequisites
* **Operating System:** Linux x86-64 or Windows with WSL2 (Ubuntu).
* **Build Tools:** `build-essential` (`gcc`, `make`).
* **Python:** Python 3.10+ with `pip`.

## 8. Linux Installation Instructions
On Ubuntu or Debian-based systems:
```bash
sudo apt update
sudo apt install -y build-essential python3 python3-pip python3-venv

# Clone or navigate to the project directory
cd /path/to/sysguard

# Create and activate a Python virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python requirements
pip install -r requirements.txt
```

## 9. Build Instructions
Compile the native C tracer and example test programs:
```bash
# Compile both backend and examples using the root Makefile
make

# Or compile individual targets
make backend
make examples
```

## 10. Run Instructions
Launch the SysGuard interactive dashboard:
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

## 11. Example Commands (CLI Execution)
You can run the native tracer directly from the command line:

```bash
# 1. Run a basic file read under read-only policy
./backend/sysguard-tracer -p policies/read_only_demo.json -- ./examples/basic_read /etc/os-release

# 2. Run denied unlink demo (enforcement verification)
./backend/sysguard-tracer -p policies/read_only_demo.json -- ./examples/denied_unlink /tmp/disposable.txt

# 3. Run audit-only demonstration
./backend/sysguard-tracer -p policies/audit_all.json -- ./examples/audit_only

# 4. Run signal handling test
./backend/sysguard-tracer -p policies/read_only_demo.json -- ./examples/signal_test
```

## 12. Example Policies
Policies are written in JSON. Example: `policies/read_only_demo.json`
```json
{
  "name": "Read-Only Demonstration",
  "description": "Permits reading and auditing, but denies destructive filesystem modifications.",
  "default_action": "allow",
  "rules": [
    { "syscall": "openat", "action": "audit" },
    { "syscall": "open", "action": "audit" },
    { "syscall": "read", "action": "allow" },
    { "syscall": "write", "action": "allow" },
    { "syscall": "unlink", "action": "deny" },
    { "syscall": "unlinkat", "action": "deny" },
    { "syscall": "rmdir", "action": "deny" },
    { "syscall": "rename", "action": "deny" },
    { "syscall": "renameat", "action": "deny" }
  ]
}
```

## 13. How Syscall Tracing Works
1. Target process starts in a traced state via `fork()` and `ptrace(PTRACE_TRACEME)`.
2. Target raises `SIGSTOP`. Tracer intercepts via `waitpid()` and establishes `PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC`.
3. Target issues `PTRACE_SYSCALL`.
4. When target executes a system call, kernel delivers `(SIGTRAP | 0x80)`.
5. Tracer reads `orig_rax` (syscall number) and registers via `PTRACE_GETREGS`.

## 14. How Enforcement Works
1. If the syscall matches a `deny` rule:
   - At **entry stop**: Tracer modifies `regs.orig_rax = -1` via `PTRACE_SETREGS`.
   - Kernel sees invalid call number, **does not run the syscall**, and sets `rax = -ENOSYS` (-38).
2. At **exit stop**:
   - Tracer intercepts nullified stop, modifies `regs.rax = -EPERM` (-1).
   - Target libc sets `errno = EPERM` and returns `-1`. The destructive call is completely prevented.

## 15. How to Run Tests
Execute the automated test suite:
```bash
# In Linux or WSL:
python3 -m pytest tests/ -v

# On Windows host (with WSL2 installed):
python -m pytest tests/ -v
```

## 16. How to Export Reports
From the **Reports** page in the dashboard:
* Download complete audit report as formatted **Markdown** (`sysguard_summary.md`).
* Download raw trace event stream as RFC 4180 **CSV** (`sysguard_trace_events.csv`).
* Download structured execution metadata as **JSON** (`sysguard_audit_report.json`).

## 17. Limitations & Security Boundaries
* **Academic Scope:** SysGuard is a process tracing and policy enforcement framework for OS learning, **not a container sandbox**.
* **TOCTOU Races:** Pointer arguments read across process memory boundaries can be modified by concurrent threads in multithreaded targets.
* **Child Hierarchy:** Single-process tracing is initially enforced. Calls like `fork()` are not traced across multiple generations in this version.
* **Performance Overhead:** Two context switches per system call introduce measurable overhead for I/O heavy processes.

## 18. Troubleshooting
* **Error: `Compiler availability: false`:**
  Install gcc: `sudo apt install build-essential`.
* **Tracer not found:**
  Run `make` in the root workspace directory.
* **Permission denied on Windows:**
  Verify WSL2 is installed: `wsl --install -d Ubuntu`.

## 19. Technical Viva Preparation
See [docs/viva_questions.md](docs/viva_questions.md) for 20 questions and answers covering:
* Kernel vs User mode, `ptrace()`, `waitpid()`
* Syscall ABI registers (`orig_rax`, `rax`, `rdi`-`r9`)
* `execve` state machine mechanics and signal forwarding
* TOCTOU race conditions and Yama LSM ptrace scopes.

## 20. Future Enhancements
* Process-tree tracing supporting `clone()` and `fork()` hierarchies.
* Seccomp-BPF hybrid backend combining in-kernel bytecode filtering with user-space audit logging.
* Network socket address decoding (`sockaddr_in` IP and port extraction).
