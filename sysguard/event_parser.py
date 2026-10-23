"""
Robust streaming JSON Lines parser for SysGuard tracer events.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class TraceEvent:
    raw: str
    event: str
    timestamp: float
    pid: Optional[int] = None
    event_type: Optional[str] = None  # "entry" | "exit"
    syscall_nr: Optional[int] = None
    syscall_name: Optional[str] = None
    args: List[int] = field(default_factory=list)
    path: Optional[str] = None
    policy_decision: Optional[str] = None  # "ALLOW" | "DENY" | "AUDIT"
    enforcement: Optional[str] = None  # "ALLOWED" | "BLOCKED" | "OBSERVED" | "ENFORCEMENT_FAILED"
    matched_rule: Optional[str] = None
    return_value: Optional[int] = None
    errno_str: Optional[str] = None
    signal: Optional[int] = None
    signal_name: Optional[str] = None
    exit_code: Optional[int] = None
    error_msg: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TraceSummary:
    total_events: int = 0
    allowed_count: int = 0
    denied_attempts: int = 0
    blocked_count: int = 0
    audit_count: int = 0
    enforcement_failures: int = 0
    distinct_syscalls: set = field(default_factory=set)
    exit_code: Optional[int] = None
    term_signal: Optional[int] = None
    target_pid: Optional[int] = None
    target_path: Optional[str] = None
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_ms: Optional[float] = None
    malformed_lines_count: int = 0


class EventParser:
    """Parses streaming lines from sysguard-tracer and aggregates trace metrics."""

    def __init__(self):
        self.summary = TraceSummary()
        self.events: List[TraceEvent] = []

    def parse_line(self, line: str) -> Optional[TraceEvent]:
        line = line.strip()
        if not line:
            return None

        # Ignore pure diagnostic logs on stdout if any
        if not line.startswith("{"):
            return None

        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            self.summary.malformed_lines_count += 1
            return TraceEvent(
                raw=line,
                event="malformed_json",
                timestamp=0.0,
                error_msg=f"Failed to parse JSON: {line[:80]}",
            )

        if not isinstance(data, dict):
            self.summary.malformed_lines_count += 1
            return None

        event_name = data.get("event", "unknown")
        ts = float(data.get("timestamp", 0.0))
        pid = data.get("pid")

        event = TraceEvent(
            raw=line,
            event=event_name,
            timestamp=ts,
            pid=pid,
            extra=data,
        )

        if event_name == "start":
            self.summary.start_time = ts
            self.summary.target_pid = pid
            self.summary.target_path = data.get("target")

        elif event_name == "syscall":
            self.summary.total_events += 1
            event.event_type = data.get("type")
            event.syscall_nr = data.get("syscall_nr")
            event.syscall_name = data.get("syscall_name", "unknown")
            event.args = data.get("args", [])
            event.path = data.get("path")
            event.policy_decision = data.get("policy_decision")
            event.enforcement = data.get("enforcement")
            event.matched_rule = data.get("matched_rule")
            event.return_value = data.get("return_value")
            event.errno_str = data.get("errno")

            if event.syscall_name:
                self.summary.distinct_syscalls.add(event.syscall_name)

            # Update metrics on entry stops
            if event.event_type == "entry":
                if event.policy_decision == "DENY":
                    self.summary.denied_attempts += 1
                    if event.enforcement == "BLOCKED":
                        self.summary.blocked_count += 1
                    elif event.enforcement == "ENFORCEMENT_FAILED":
                        self.summary.enforcement_failures += 1
                elif event.policy_decision == "AUDIT":
                    self.summary.audit_count += 1
                elif event.policy_decision == "ALLOW":
                    self.summary.allowed_count += 1

        elif event_name == "signal":
            event.signal = data.get("signal")
            event.signal_name = data.get("signal_name")

        elif event_name == "exit":
            self.summary.end_time = ts
            self.summary.exit_code = data.get("exit_code")
            self.summary.term_signal = data.get("term_signal")
            self.summary.duration_ms = data.get("duration_ms")
            event.exit_code = self.summary.exit_code

        elif event_name == "error":
            event.error_msg = data.get("error")

        self.events.append(event)
        return event

    def get_events(self) -> List[TraceEvent]:
        return list(self.events)

    def get_summary(self) -> TraceSummary:
        return self.summary
