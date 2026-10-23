"""
Environment and platform compatibility detector for SysGuard.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class EnvironmentStatus:
    os_name: str
    kernel_version: str
    arch: str
    python_version: str
    is_linux: bool
    is_x86_64: bool
    is_wsl: bool
    wsl_available: bool
    wsl_distro: Optional[str]
    compiler_available: bool
    compiler_path: Optional[str]
    make_available: bool
    tracer_compiled: bool
    tracer_binary_path: Optional[str]
    ptrace_supported: bool
    current_user: str
    is_root: bool
    compatibility_message: str
    extra_details: dict = field(default_factory=dict)


def to_wsl_path(win_path: str | Path) -> str:
    """Convert a Windows file path to a WSL mount path."""
    p = str(win_path).replace("\\", "/")
    if len(p) >= 2 and p[1] == ":":
        drive = p[0].lower()
        rest = p[2:]
        if not rest.startswith("/"):
            rest = "/" + rest
        return f"/mnt/{drive}{rest}"
    return p


def to_windows_path(wsl_path: str) -> str:
    """Convert a WSL mount path to a Windows file path."""
    p = str(wsl_path).replace("/", "\\")
    if p.startswith("\\mnt\\") and len(p) >= 7 and p[6] == "\\":
        drive = p[5].upper()
        rest = p[6:]
        return f"{drive}:{rest}"
    return p


class EnvironmentDetector:
    """Detects and reports host platform capabilities and tracing readiness."""

    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = workspace_root or Path(__file__).resolve().parent.parent

    def detect(self) -> EnvironmentStatus:
        os_name = platform.system()
        kernel_version = platform.release()
        arch = platform.machine()
        py_ver = platform.python_version()

        is_linux = (os_name == "Linux")
        is_x86_64 = (arch in ("x86_64", "AMD64"))
        is_wsl = False
        wsl_available = False
        wsl_distro = None

        compiler_available = False
        compiler_path = None
        make_available = False
        tracer_compiled = False
        tracer_binary = None
        ptrace_supported = False
        current_user = os.environ.get("USER", os.environ.get("USERNAME", "unknown"))
        is_root = False

        details = {}

        # Check native Linux details
        if is_linux:
            # Detect if running inside WSL
            try:
                with open("/proc/version", "r", encoding="utf-8") as f:
                    proc_ver = f.read().lower()
                    if "microsoft" in proc_ver or "wsl" in proc_ver:
                        is_wsl = True
            except Exception:
                pass

            compiler_path = shutil.which("gcc") or shutil.which("clang")
            compiler_available = compiler_path is not None
            make_available = shutil.which("make") is not None

            # Check ptrace scope
            try:
                scope_path = Path("/proc/sys/kernel/yama/ptrace_scope")
                if scope_path.exists():
                    scope_val = scope_path.read_text(encoding="utf-8").strip()
                    details["yama_ptrace_scope"] = scope_val
                else:
                    details["yama_ptrace_scope"] = "0 (Yama not active)"
            except Exception as e:
                details["yama_ptrace_scope"] = f"unreadable: {e}"

            try:
                is_root = (os.geteuid() == 0)
            except AttributeError:
                is_root = False

            ptrace_supported = is_x86_64

            # Check if backend binary exists
            tracer_candidate = self.workspace_root / "backend" / "sysguard-tracer"
            if tracer_candidate.exists() and os.access(tracer_candidate, os.X_OK):
                tracer_compiled = True
                tracer_binary = str(tracer_candidate)

            if ptrace_supported:
                compat_msg = "Native Linux x86-64 platform detected. Kernel ptrace subsystem is fully operational."
            else:
                compat_msg = f"Linux detected on non-x86_64 architecture ({arch}). Tracing x86-64 registers is not supported."

        elif os_name == "Windows":
            # On Windows host: inspect WSL2 availability
            wsl_exe = shutil.which("wsl") or shutil.which("wsl.exe")
            if wsl_exe:
                try:
                    res = subprocess.run(
                        ["wsl.exe", "-l", "-v"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    out = res.stdout.replace("\x00", "")
                    if "Ubuntu" in out or "docker-desktop" in out or "VERSION" in out:
                        wsl_available = True
                        if "Ubuntu" in out:
                            wsl_distro = "Ubuntu"
                        elif "docker-desktop" in out:
                            wsl_distro = "docker-desktop"
                except Exception as e:
                    details["wsl_check_error"] = str(e)

            # Check if tracer is compiled in WSL or in workspace
            tracer_local = self.workspace_root / "backend" / "sysguard-tracer"
            if tracer_local.exists():
                tracer_compiled = True
                tracer_binary = str(tracer_local)

            if wsl_available:
                # Check gcc inside WSL distro
                distro_arg = ["-d", wsl_distro] if wsl_distro else []
                try:
                    chk = subprocess.run(
                        ["wsl.exe"] + distro_arg + ["which", "gcc", "make"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    compiler_available = ("gcc" in chk.stdout)
                    make_available = ("make" in chk.stdout)
                except Exception:
                    pass

                ptrace_supported = True
                compat_msg = (
                    f"Windows host detected with active WSL2 ({wsl_distro or 'default'}). "
                    f"SysGuard bridges commands directly to the native Linux x86-64 kernel backend."
                )
            else:
                compat_msg = (
                    "Windows host detected without an active WSL2 Linux environment. "
                    "Linux ptrace() requires a real Linux kernel. Please install WSL2 (wsl --install -d Ubuntu)."
                )

        else:
            compat_msg = f"Operating system '{os_name}' is unsupported. SysGuard requires Linux x86-64 or WSL2."

        return EnvironmentStatus(
            os_name=os_name,
            kernel_version=kernel_version,
            arch=arch,
            python_version=py_ver,
            is_linux=is_linux,
            is_x86_64=is_x86_64,
            is_wsl=is_wsl,
            wsl_available=wsl_available,
            wsl_distro=wsl_distro,
            compiler_available=compiler_available,
            compiler_path=compiler_path,
            make_available=make_available,
            tracer_compiled=tracer_compiled,
            tracer_binary_path=tracer_binary,
            ptrace_supported=ptrace_supported,
            current_user=current_user,
            is_root=is_root,
            compatibility_message=compat_msg,
            extra_details=details,
        )
