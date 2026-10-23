# Linux System Call Tracing with Ptrace

## 1. System Call Architecture on Linux x86-64

On modern x86-64 Linux, user space transitions to kernel space using the fast `syscall` CPU instruction.

### Register Convention (Linux ABI)
* **Syscall Number:** Stored in `rax` (`orig_rax` in `struct user_regs_struct`).
* **Arguments (Up to 6):**
  1. `rdi` (Arg 1)
  2. `rsi` (Arg 2)
  3. `rdx` (Arg 3)
  4. `r10` (Arg 4 - note difference from user-mode call ABI which uses `rcx`)
  5. `r8`  (Arg 5)
  6. `r9`  (Arg 6)
* **Return Value:** Placed in `rax` by the kernel upon return. Values between `-1` and `-4095` represent negative standard errno values (e.g. `-EPERM = -1`, `-ENOENT = -2`, `-EACCES = -13`, `-ENOSYS = -38`).

## 2. Ptrace Mechanics

`ptrace()` is a Linux system call that provides process tracing and debugging primitives:
1. `PTRACE_TRACEME`: Executed by the child before `execve()` to allow the parent to trace it.
2. `PTRACE_SETOPTIONS`:
   - `PTRACE_O_TRACESYSGOOD`: Distinguishes syscall stops (`WSTOPSIG(status) == (SIGTRAP | 0x80)`) from ordinary `SIGTRAP` signals.
   - `PTRACE_O_TRACEEXEC`: Intercepts `execve` completions.
   - `PTRACE_O_TRACEEXIT`: Notifies tracer of process termination.
3. `PTRACE_SYSCALL`: Resumes child process until the next syscall entry or exit stop.
4. `PTRACE_GETREGS` / `PTRACE_SETREGS`: Reads and writes architectural CPU registers.

## 3. Syscall Spoofing & Policy Enforcement

How SysGuard blocks a system call without terminating the process:

1. **Entry Stop:**
   The tracer detects entry stop. It evaluates policy rules. If action is `DENY`:
   ```c
   struct user_regs_struct regs;
   ptrace(PTRACE_GETREGS, pid, 0, &regs);
   regs.orig_rax = (unsigned long long)-1; // invalid syscall number
   ptrace(PTRACE_SETREGS, pid, 0, &regs);
   ptrace(PTRACE_SYSCALL, pid, 0, 0);
   ```
2. **Kernel Processing:**
   The kernel reads `orig_rax == -1`. It recognizes that no syscall corresponds to -1. The kernel **does not invoke the system call implementation**. Instead, it loads `-ENOSYS` (-38) into `rax` and returns to the syscall exit boundary.
3. **Exit Stop:**
   The tracer detects exit stop for the nullified call. It overwrites `rax`:
   ```c
   regs.rax = (unsigned long long)(-EPERM); // -1 errno
   ptrace(PTRACE_SETREGS, pid, 0, &regs);
   ptrace(PTRACE_SYSCALL, pid, 0, 0);
   ```
4. **Target Observation:**
   The target C library wrapper checks `rax`. Seeing a negative value `-1`, it sets `errno = EPERM (1)` and returns `-1` to the calling application code.
   The underlying destructive operation (e.g. file deletion) was completely prevented.
