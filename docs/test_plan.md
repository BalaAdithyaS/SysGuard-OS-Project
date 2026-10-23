# SysGuard Comprehensive Test Plan

## 1. Objectives

Verify the correctness, robustness, and deterministic policy enforcement of the SysGuard framework across:
- Environment detection and cross-platform compatibility
- Policy parsing and validation
- Input validation and shell safety
- Native C tracer execution and signal handling
- Kernel register manipulation and true syscall blocking
- Multi-format report export

## 2. Test Matrix & Acceptance Criteria

| ID | Test Name | Target Module | Scope | Expected Outcome | Verified |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **TC-01** | Platform Detection | `sysguard/environment.py` | Unit | Identifies OS, kernel, arch, and WSL correctly | PASSED |
| **TC-02** | Path Translation | `sysguard/environment.py` | Unit | Correctly converts Windows drive paths to `/mnt/<drive>/...` | PASSED |
| **TC-03** | Valid Policy Load | `sysguard/policy_engine.py` | Unit | Parses valid rules and actions without error | PASSED |
| **TC-04** | Invalid Action Rejection | `sysguard/policy_engine.py` | Unit | Rejects unrecognized action names | PASSED |
| **TC-05** | Unsupported Syscall | `sysguard/policy_engine.py` | Unit | Rejects syscalls not in supported architecture table | PASSED |
| **TC-06** | Duplicate Rule Rejection | `sysguard/policy_engine.py` | Unit | Rejects ambiguous duplicate rules | PASSED |
| **TC-07** | Deterministic Precedence | `sysguard/policy_engine.py` | Unit | First matching rule determines action; default action applied if none match | PASSED |
| **TC-08** | Event Parser Start | `sysguard/event_parser.py` | Unit | Correctly parses start event into typed dataclass | PASSED |
| **TC-09** | Event Parser Blocked | `sysguard/event_parser.py` | Unit | Correctly records BLOCKED enforcement metrics | PASSED |
| **TC-10** | Malformed JSON Resilience | `sysguard/event_parser.py` | Unit | Does not crash on truncated or malformed JSON | PASSED |
| **TC-11** | Non-JSON Diagnostic Ignore | `sysguard/event_parser.py` | Unit | Safely ignores plain text child debug output | PASSED |
| **TC-12** | Argument Tokenization | `sysguard/validators.py` | Unit | Splits arguments using POSIX shlex without shell evaluation | PASSED |
| **TC-13** | Working Dir Validation | `sysguard/validators.py` | Unit | Verifies directory exists; rejects invalid dirs | PASSED |
| **TC-14** | Tracer Launch Valid | `tests/integration/test_tracer.py` | Integration | Launches valid binary under ptrace; exit code 0 | PASSED |
| **TC-15** | Denied Unlink Enforcement | `tests/integration/test_tracer.py` | Integration | File remains on disk, target observes errno=EPERM, status=BLOCKED | PASSED |
| **TC-16** | Allowed Operation | `tests/integration/test_tracer.py` | Integration | Permitted syscalls execute successfully | PASSED |
| **TC-17** | Audit-Only Operation | `tests/integration/test_tracer.py` | Integration | Syscall executes and logs `OBSERVED` | PASSED |
| **TC-18** | Signal Forwarding | `tests/integration/test_tracer.py` | Integration | SIGUSR1 is received and handled by target | PASSED |
| **TC-19** | Nonexistent Executable | `tests/integration/test_tracer.py` | Integration | Tracer emits LAUNCH_ERROR without hanging | PASSED |
| **TC-20** | Non-Root Operation | `sysguard-tracer` | Integration | Traces own children without requiring root privileges | PASSED |

## 3. How to Execute Test Suites

```bash
# Run all unit and integration tests (Windows host via Python)
python -m pytest tests/ -v

# Run all tests directly inside Linux WSL2
wsl -d Ubuntu sh -c "cd '/mnt/c/PROJECT/os project' && python3 -m pytest tests/ -v"
```
