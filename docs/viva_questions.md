# SysGuard Technical Viva Questions & Answers

This document prepares undergraduate students and researchers for technical viva voce examinations on Operating Systems, Linux systems programming, process tracing, and system call policy enforcement.

---

### Q1: What is a system call, and how does user mode transition to kernel mode on Linux x86-64?
**Answer:** A system call is the programmatic interface provided by the operating system kernel to allow user-mode processes to request privileged hardware and kernel services (such as filesystem I/O, process management, and network communication). On x86-64 architectures, modern CPUs use the fast `syscall` instruction. When executed, the CPU automatically saves the current program counter (`rip`) into `rcx`, saves the flags into `r11`, switches the CPU privilege level from Ring 3 (user mode) to Ring 0 (kernel mode), and jumps to the kernel's system call entry point defined in the Model-Specific Register `MSR_LSTAR`.

---

### Q2: Why can user-space applications not perform hardware I/O directly?
**Answer:** In modern preemptive multitasking operating systems, the hardware enforces memory and instruction protection via CPU rings and page tables. User-space applications run in Ring 3 with restricted instruction privileges and cannot execute privileged CPU instructions (such as `in`, `out`, `cli`, or modifying page table registers `CR3`). This prevents any user program from corrupting memory, monopolizing CPU time, or bypassing access permissions of other processes.

---

### Q3: What is `ptrace()`, and what are its primary use cases in Linux?
**Answer:** `ptrace()` is a Linux system call that provides a mechanism by which one process (the "tracer") can observe and control the execution of another process (the "tracee"), and examine and change the tracee's memory and registers. It is the core underlying mechanism used by debuggers (such as `gdb`), system call tracers (`strace`), code coverage profilers, and dynamic binary analysis tools.

---

### Q4: Explain the difference between `PTRACE_TRACEME` and `PTRACE_ATTACH`.
**Answer:** 
- `PTRACE_TRACEME` is called by the child process itself to declare that it wants its parent to trace it. It is invoked before the child calls `execve()` to load a new program image.
- `PTRACE_ATTACH` is called by an already running tracer process specifying the PID of an arbitrary target process to attach to and begin tracing asynchronously. Attaching requires appropriate privileges (`CAP_SYS_PTRACE` or matching UID subject to Yama LSM restrictions).

---

### Q5: How does `ptrace(PTRACE_SYSCALL, ...)` work, and why does each system call produce two stops?
**Answer:** `PTRACE_SYSCALL` instructs the Linux kernel to restart the stopped tracee and pause it at the next system-call boundary. Each system call generates two separate stops:
1. **Syscall Entry Stop:** Occurs just before the kernel executes the system call. The tracer can inspect the syscall number and arguments.
2. **Syscall Exit Stop:** Occurs immediately after the kernel finishes executing the system call, but before returning control to user space. The tracer can inspect (and alter) the syscall return value and errno.

---

### Q6: How does `PTRACE_O_TRACESYSGOOD` distinguish syscall stops from normal `SIGTRAP` signals?
**Answer:** By default, ptrace stops deliver `SIGTRAP` (signal 5) for both breakpoint traps and syscall traps. When `ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD)` is configured, the kernel sets bit 7 (0x80) on the signal delivered for system-call traps. Consequently, `WSTOPSIG(status)` evaluates to `(SIGTRAP | 0x80)` (0x85), allowing the tracer to unambiguously differentiate syscall stops from ordinary breakpoint or signal stops.

---

### Q7: On Linux x86-64, where are the system call number and arguments stored in registers?
**Answer:** According to the System V AMD64 ABI system-call convention:
- **Syscall Number:** Loaded into `rax` (accessible as `orig_rax` in `struct user_regs_struct`).
- **Argument 1:** `rdi`
- **Argument 2:** `rsi`
- **Argument 3:** `rdx`
- **Argument 4:** `r10` (note: user function calls use `rcx`, but `syscall` uses `r10` because `rcx` is clobbered by the CPU).
- **Argument 5:** `r8`
- **Argument 6:** `r9`
- **Return Value:** Loaded into `rax` upon exit.

---

### Q8: How does SysGuard physically block a system call from executing without killing the target?
**Answer:** At the syscall entry stop, SysGuard checks the syscall number against active policy rules. If the rule specifies `deny`:
1. SysGuard calls `ptrace(PTRACE_GETREGS)` and sets `regs.orig_rax = (unsigned long long)-1`.
2. It writes the modified registers back using `ptrace(PTRACE_SETREGS)` and resumes the child with `PTRACE_SYSCALL`.
3. The kernel reads `orig_rax == -1`, determines that `-1` is an invalid syscall number, bypasses the actual syscall implementation entirely, and sets `rax = -ENOSYS` (-38).
4. At the subsequent syscall exit stop, SysGuard intercepts the child, writes `regs.rax = (unsigned long long)(-EPERM)` via `ptrace(PTRACE_SETREGS)`, and resumes.
5. The target application's libc wrapper sees the `-1` return value, sets `errno = EPERM`, and returns `-1`. The destructive operation was never executed.

---

### Q9: Why must a tracer modify `orig_rax` rather than `rax` at syscall entry on x86-64?
**Answer:** On Linux x86-64, the kernel stores the original syscall number in the internal kernel register struct slot corresponding to `orig_rax`. At syscall entry, the kernel uses `orig_rax` to index the system call dispatcher table (`sys_call_table`). Changing `rax` alone would be ignored or overwritten by the kernel with `-ENOSYS`. Modifying `orig_rax` to `-1` forces the dispatcher to reject the call.

---

### Q10: What is the significance of `waitpid()` in process tracing?
**Answer:** `waitpid(child, &status, 0)` is the primary blocking synchronization primitive used by the tracer. It suspends the tracer until the child state changes (e.g. process stopped by a signal/syscall, terminated normally, or killed by an unhandled signal). The macros `WIFSTOPPED(status)`, `WSTOPSIG(status)`, `WIFEXITED(status)`, and `WIFSIGNALED(status)` allow the tracer to extract exact lifecycle details.

---

### Q11: What is `process_vm_readv()`, and why is it preferred over `PTRACE_PEEKDATA`?
**Answer:** `process_vm_readv()` is a Linux system call that transfers data directly between the address spaces of two processes without passing through the kernel buffer layer. It is significantly faster than `PTRACE_PEEKDATA` (which only transfers a single machine word of 8 bytes per system call) and handles invalid or unmapped addresses safely by returning `-1` with `errno = EFAULT` without terminating either process.

---

### Q12: Why does calling `unlink("file")` in C actually invoke `unlinkat` on modern Linux?
**Answer:** Modern versions of the GNU C Library (glibc) and musl libc have consolidated older path-based syscalls into their newer directory-file-descriptor counterparts (`*at` syscalls introduced in POSIX.1-2008 and Linux 2.6.16). Under the hood, `unlink(path)` is implemented as `unlinkat(AT_FDCWD, path, 0)`. SysGuard's policy engine and test suite account for this by supporting both `unlink` (87) and `unlinkat` (263).

---

### Q13: What happens to ordinary signals (e.g. `SIGUSR1`, `SIGINT`) delivered to a traced process?
**Answer:** When an ordinary signal is delivered to the tracee, the tracee pauses with a signal-delivery-stop. `WSTOPSIG(status)` reports the signal number (not `SIGTRAP | 0x80`). To ensure normal application behavior, the tracer must forward the signal back to the child when calling `ptrace(PTRACE_SYSCALL, pid, 0, sig)`. If the tracer passes `0` instead of `sig`, the signal is suppressed and swallowed.

---

### Q14: Explain the Time-of-Check to Time-of-Use (TOCTOU) race condition in ptrace security tools.
**Answer:** In multithreaded applications, memory is shared across all threads within the process. When a tracer inspects a string argument (e.g. a file path) during a syscall entry stop, another running thread could theoretically modify the bytes in that same buffer in the microsecond before the kernel reads it. This creates a race condition known as TOCTOU, which is why ptrace alone cannot guarantee cryptographic sandbox boundaries without memory locking or seccomp integration.

---

### Q15: How does `execve` affect the ptrace state machine?
**Answer:** When a traced process calls `execve()`, it enters the syscall (`in_syscall = 1`). If `PTRACE_O_TRACEEXEC` is enabled, the kernel delivers a `PTRACE_EVENT_EXEC` stop when the new binary image is loaded. The exit stop of `execve` occurs *after* `PTRACE_EVENT_EXEC` inside the address space of the newly executed binary. Failing to recognize that `execve` exit follows `PTRACE_EVENT_EXEC` will invert the tracer's entry/exit tracking for all subsequent system calls.

---

### Q16: How does Linux Yama LSM (`ptrace_scope`) restrict process tracing?
**Answer:** The Yama Linux Security Module restricts `ptrace` via `/proc/sys/kernel/yama/ptrace_scope`:
- **0 (Classic):** A process can trace any process with the same effective UID.
- **1 (Restricted):** A process can only trace its own direct children spawned with `PTRACE_TRACEME`, or must have `CAP_SYS_PTRACE`.
- **2 (Admin-only):** Only processes with `CAP_SYS_PTRACE` can trace.
- **3 (No trace):** No process can trace; immutable until reboot.
SysGuard uses child `PTRACE_TRACEME`, which is fully supported under standard Scope 1 without root escalation.

---

### Q17: What is the performance overhead of ptrace-based syscall tracing?
**Answer:** Every system call intercepted under ptrace introduces two full process context switches (from child to tracer at entry, and back to child; then from child to tracer at exit, and back to child). For CPU-bound tasks, overhead is negligible; for I/O-intensive workloads making hundreds of thousands of syscalls per second, overhead can exceed 50-200%.

---

### Q18: What is the difference between SysGuard's ptrace tracing and Linux Seccomp-BPF?
**Answer:**
- **Ptrace:** Implemented in user space. High overhead (context switches), but allows arbitrary inspection, register modification, and interactive debugging.
- **Seccomp-BPF:** Implemented directly in kernel space. Uses an in-kernel virtual machine (Berkeley Packet Filter) to evaluate system call numbers and register arguments with zero user context switches. It cannot easily inspect user-space memory pointers without newer `SECCOMP_USER_NOTIF` features.

---

### Q19: Why does SysGuard avoid using `shell=True` when launching target programs?
**Answer:** Using `shell=True` (or passing command strings to `/bin/sh -c`) invites command injection vulnerabilities. If an argument contains metacharacters (such as `;`, `&`, `|`, `` ` ``, `$()`), the shell interprets them as distinct commands, allowing arbitrary command execution outside the tracer. SysGuard uses direct array execution (`execv` in C, argument lists in Python) to pass parameters directly to the binary.

---

### Q20: Why is a system call matching a deny policy not automatically the same as "successfully blocked"?
**Answer:** A policy match is merely an evaluation decision (`DENY`). "Successfully blocked" (`BLOCKED`) requires confirmation that the enforcement mechanism actually intervened:
1. `orig_rax` was successfully set to `-1` via `ptrace(PTRACE_SETREGS)`.
2. The kernel aborted the underlying system call.
3. At exit, `rax` was verified and set to the desired error code (`-EPERM`).
4. Physical side effects (e.g. file deletion) were verified to NOT have occurred.
If `PTRACE_SETREGS` failed, the outcome is classified as `ENFORCEMENT_FAILED`, not `BLOCKED`.
