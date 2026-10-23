"""
Tracer Process Manager: Subprocess lifecycle, asynchronous stream reader, and WSL2 bridging.
"""

from __future__ import annotations

import os
import queue
import signal
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

from sysguard.environment import EnvironmentDetector, EnvironmentStatus, to_wsl_path
from sysguard.event_parser import EventParser, TraceEvent, TraceSummary
from sysguard.validators import TargetValidator, ValidationError


class TracerManager:
    """Manages the background execution of sysguard-tracer and streams parsed events."""

    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = workspace_root or Path(__file__).resolve().parent.parent
        self.env_detector = EnvironmentDetector(self.workspace_root)
        self.env_status: EnvironmentStatus = self.env_detector.detect()

        self.process: Optional[subprocess.Popen] = None
        self.parser = EventParser()
        self.event_queue: queue.Queue = queue.Queue()
        self.reader_thread: Optional[threading.Thread] = None
        self._stop_requested = False
        self.lock = threading.Lock()

        # State tracking
        self.is_active = False
        self.target_command = ""
        self.target_args: List[str] = []
        self.policy_file: Optional[str] = None
        self.exit_code: Optional[int] = None
        self.error_message: Optional[str] = None

    def refresh_environment(self) -> EnvironmentStatus:
        self.env_status = self.env_detector.detect()
        return self.env_status

    def build_backend(self) -> Tuple[bool, str]:
        """Trigger native make clean && make in the backend directory."""
        if self.env_status.is_linux:
            cmd = ["make", "-C", str(self.workspace_root / "backend")]
        elif self.env_status.is_wsl or self.env_status.wsl_available:
            wsl_dir = to_wsl_path(self.workspace_root / "backend")
            distro_args = ["-d", self.env_status.wsl_distro] if self.env_status.wsl_distro else []
            cmd = ["wsl.exe"] + distro_args + ["sh", "-c", f"cd '{wsl_dir}' && make clean && make"]
        else:
            return False, "Cannot compile backend: neither Linux nor WSL2 is available."

        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode == 0:
                self.refresh_environment()
                return True, "Build succeeded."
            return False, f"Build failed with exit code {res.returncode}:\n{res.stderr or res.stdout}"
        except Exception as e:
            return False, f"Build error: {e}"

    def start_trace(
        self,
        executable: str,
        args: List[str],
        policy_path: Optional[str | Path] = None,
        default_action: str = "allow",
        audit_only: bool = False,
        deny_errno: str = "EPERM",
        on_event_callback: Optional[Callable[[TraceEvent], None]] = None,
    ) -> bool:
        """Launches the target executable under sysguard-tracer asynchronously."""
        with self.lock:
            if self.is_active:
                raise RuntimeError("A tracing session is already actively running.")

            self.refresh_environment()
            self.parser = EventParser()
            self.event_queue = queue.Queue()
            self._stop_requested = False
            self.exit_code = None
            self.error_message = None
            self.target_command = executable
            self.target_args = list(args)
            self.policy_file = str(policy_path) if policy_path else None

            # Prepare tracer command
            tracer_bin = self.workspace_root / "backend" / "sysguard-tracer"
            if not tracer_bin.exists():
                raise FileNotFoundError(
                    f"Tracer binary '{tracer_bin}' not found. Please compile the backend first."
                )

            # Build command list
            tracer_args = []
            if policy_path:
                pol_p = Path(policy_path).resolve()
                if not pol_p.exists():
                    raise FileNotFoundError(f"Policy file '{pol_p}' does not exist.")
                if self.env_status.os_name == "Windows":
                    tracer_args.extend(["-p", to_wsl_path(pol_p)])
                else:
                    tracer_args.extend(["-p", str(pol_p)])

            if default_action.lower() == "deny":
                tracer_args.extend(["-d", "deny"])
            if audit_only:
                tracer_args.append("-a")
            if deny_errno in ("EPERM", "EACCES"):
                tracer_args.extend(["-e", deny_errno])

            # Prepare target binary and arguments
            if self.env_status.os_name == "Windows":
                # Translate paths for WSL
                wsl_tracer = to_wsl_path(tracer_bin)
                wsl_target = to_wsl_path(executable) if (":" in executable or "\\" in executable) else executable
                wsl_args = [to_wsl_path(a) if (":" in a or "\\" in a) else a for a in args]

                distro_args = ["-d", self.env_status.wsl_distro] if self.env_status.wsl_distro else []
                full_cmd = ["wsl.exe"] + distro_args + [wsl_tracer] + tracer_args + ["--", wsl_target] + wsl_args
            else:
                full_cmd = [str(tracer_bin)] + tracer_args + ["--", executable] + args

            try:
                self.process = subprocess.Popen(
                    full_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                )
            except Exception as e:
                self.error_message = str(e)
                raise RuntimeError(f"Failed to launch tracer process: {e}") from e

            self.is_active = True

            # Start background reader thread
            self.reader_thread = threading.Thread(
                target=self._reader_loop,
                args=(on_event_callback,),
                daemon=True,
                name="SysGuard-ReaderThread",
            )
            self.reader_thread.start()
            return True

    def _reader_loop(self, callback: Optional[Callable[[TraceEvent], None]]) -> None:
        if not self.process or not self.process.stdout:
            self.is_active = False
            return

        try:
            for line in iter(self.process.stdout.readline, ""):
                if not line:
                    break
                event = self.parser.parse_line(line)
                if event:
                    self.event_queue.put(event)
                    if callback:
                        try:
                            callback(event)
                        except Exception:
                            pass
        except Exception as e:
            self.error_message = f"Reader stream error: {e}"
        finally:
            self.process.stdout.close()
            self.exit_code = self.process.wait()
            self.is_active = False

    def stop_trace(self, timeout_sec: float = 3.0) -> None:
        """Safely stops the active trace without leaving orphan processes."""
        with self.lock:
            if not self.is_active or not self.process:
                return

            self._stop_requested = True
            try:
                if self.env_status.os_name == "Windows":
                    # Send taskkill or terminate
                    self.process.terminate()
                else:
                    self.process.send_signal(signal.SIGINT)

                self.process.wait(timeout=timeout_sec)
            except subprocess.TimeoutExpired:
                try:
                    self.process.kill()
                    self.process.wait(timeout=2.0)
                except Exception:
                    pass
            except Exception as e:
                self.error_message = f"Error during trace termination: {e}"
            finally:
                self.is_active = False

    def get_new_events(self) -> List[TraceEvent]:
        """Retrieve any events queued since last poll."""
        events = []
        while not self.event_queue.empty():
            try:
                events.append(self.event_queue.get_nowait())
            except queue.Empty:
                break
        return events

    def get_all_events(self) -> List[TraceEvent]:
        return self.parser.get_events()

    def get_summary(self) -> TraceSummary:
        return self.parser.get_summary()

    def is_running(self) -> bool:
        if self.process and self.is_active:
            poll_res = self.process.poll()
            if poll_res is not None:
                self.is_active = False
                self.exit_code = poll_res
        return self.is_active
