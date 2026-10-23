# SysGuard Architecture Specification

## 1. Overview and High-Level Design

SysGuard is structured into two cooperating layers:
1. **Native Linux C Tracing Core (`backend/sysguard-tracer`):** A high-performance, architecture-specific C11 helper responsible for target process spawning, `ptrace` system call interception, argument inspection, register nullification, and structured event streaming.
2. **Python Controller and Telemetry Dashboard (`sysguard/`, `app.py`, `pages/`):** A modular Python 3.10+ application providing policy validation, background execution management, event parsing, telemetry visualization, report generation, and an interactive Streamlit UI.

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
|  +--------------------+  +-------------------------------+  |
|  |   Policy Engine    |  |     TracerManager (Async)     |  |
|  +--------------------+  +---------------+---------------+  |
|  |    Event Parser    |                  |                  |
|  +--------------------+                  v                  |
|  |  Report Generator  |      Subprocess Pipe (JSON Lines)   |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                 Native Linux C Tracing Helper               |
|                 (`backend/sysguard-tracer`)                 |
|  - Process lifecycle (`fork`, `execve`, `waitpid`)          |
|  - `ptrace` system call trap handling (`SIGTRAP | 0x80`)    |
|  - Register reading / writing (`PTRACE_GETREGS / SETREGS`)  |
|  - Syscall nullification (`orig_rax = -1`, `rax = -EPERM`)  |
+------------------------------+------------------------------+
                               |
                               v
+-------------------------------------------------------------+
|                     Linux Kernel (x86_64)                   |
|                   Syscall Subsystem & VFS                   |
+-------------------------------------------------------------+
```

## 2. IPC & Event Protocol

Communication between `sysguard-tracer` and the Python layer occurs via standard Unix pipes using a versioned **JSON Lines** protocol on `stdout`:
- Standard structured events are written to `stdout`, terminated by newlines.
- Human-readable diagnostics and debugging notices are routed strictly to `stderr` so as not to pollute the event stream.

### Protocol Schema

#### Start Event
```json
{
  "event": "start",
  "pid": 1234,
  "target": "/path/to/binary",
  "architecture": "x86_64",
  "policy_name": "Read-Only Demonstration",
  "rule_count": 8,
  "default_action": "allow",
  "audit_only": false,
  "deny_errno": 1,
  "timestamp": 1729620000.123456
}
```

#### Syscall Entry Event
```json
{
  "event": "syscall",
  "type": "entry",
  "pid": 1234,
  "syscall_nr": 87,
  "syscall_name": "unlink",
  "args": [94900535078916, 0, 0, 0, 0, 0],
  "path": "/tmp/test.txt",
  "policy_decision": "DENY",
  "enforcement": "BLOCKED",
  "matched_rule": "unlink",
  "timestamp": 1729620000.123890
}
```

#### Syscall Exit Event
```json
{
  "event": "syscall",
  "type": "exit",
  "pid": 1234,
  "syscall_nr": 87,
  "syscall_name": "unlink",
  "return_value": -1,
  "errno": "EPERM",
  "enforcement": "BLOCKED",
  "timestamp": 1729620000.124010
}
```

#### Exit Event
```json
{
  "event": "exit",
  "pid": 1234,
  "exit_code": 0,
  "term_signal": null,
  "total_events": 79,
  "blocked_count": 1,
  "allowed_count": 36,
  "audit_count": 3,
  "duration_ms": 23.59,
  "timestamp": 1729620000.147046
}
```

## 3. Tracing State Machine

The native tracer maintains an internal state machine per traced PID:
- `in_syscall == 0`: The next `(SIGTRAP | 0x80)` stop is a **syscall entry**. The tracer captures arguments, decodes strings from the target address space via `process_vm_readv`, evaluates active policy rules, and if `DENY` is indicated, nullifies the call by writing `orig_rax = -1`.
- `in_syscall == 1`: The next `(SIGTRAP | 0x80)` stop is a **syscall exit**. If the call was nullified, the tracer overwrites `rax` with `-EPERM` (or configured error code). The return value is logged.
- `PTRACE_EVENT_EXEC`: When an `execve` replaces the process image, Linux issues a `PTRACE_EVENT_EXEC` stop. Crucially, the exit stop of `execve` occurs *after* `PTRACE_EVENT_EXEC`, so `in_syscall` remains `1` until that exit stop concludes.
- Ordinary signals delivered to the target are forwarded unchanged via `ptrace(PTRACE_SYSCALL, pid, 0, sig)`.
