"""
SysGuard Audit Report Generator: Exports execution traces and policy decisions to JSON, CSV, and Markdown.
"""

from __future__ import annotations

import csv
import io
import json
import time
from dataclasses import asdict
from typing import Any, Dict, List, Optional

from sysguard.environment import EnvironmentStatus
from sysguard.event_parser import TraceEvent, TraceSummary
from sysguard.policy_engine import Policy


class ReportGenerator:
    """Generates structured audit reports and exports in multiple formats."""

    @classmethod
    def generate_report_dict(
        cls,
        summary: TraceSummary,
        events: List[TraceEvent],
        policy: Optional[Policy],
        env_status: EnvironmentStatus,
        target_path: str,
        target_args: List[str],
    ) -> Dict[str, Any]:
        duration_ms = summary.duration_ms
        if duration_ms is None and summary.start_time and summary.end_time:
            duration_ms = (summary.end_time - summary.start_time) * 1000.0

        # Extract security audit violations (DENY decisions at entry)
        violations = []
        for i, ev in enumerate(events):
            if ev.event_type == "entry" and (ev.policy_decision == "DENY" or ev.enforcement == "BLOCKED"):
                ret_val = -1
                errno_val = "EPERM"
                for j in range(i + 1, min(i + 10, len(events))):
                    if events[j].event_type == "exit" and events[j].syscall_nr == ev.syscall_nr:
                        ret_val = events[j].return_value if events[j].return_value is not None else -1
                        errno_val = events[j].errno_str or "EPERM"
                        break
                violations.append({
                    "timestamp": ev.timestamp,
                    "event_type": ev.event_type,
                    "pid": ev.pid,
                    "syscall_nr": ev.syscall_nr,
                    "syscall_name": ev.syscall_name,
                    "path": ev.path,
                    "matched_rule": ev.matched_rule,
                    "enforcement": ev.enforcement or "BLOCKED",
                    "return_value": ret_val,
                    "errno": errno_val,
                })

        # Calculate syscall frequency
        syscall_freq: Dict[str, int] = {}
        for ev in events:
            if ev.event == "syscall" and ev.event_type == "entry" and ev.syscall_name:
                syscall_freq[ev.syscall_name] = syscall_freq.get(ev.syscall_name, 0) + 1

        return {
            "project": "SysGuard: Linux System Call Interception and Policy Enforcement Framework",
            "generation_timestamp": time.time(),
            "target": {
                "executable": target_path,
                "arguments": target_args,
                "pid": summary.target_pid,
                "exit_code": summary.exit_code,
                "term_signal": summary.term_signal,
            },
            "environment": {
                "os": env_status.os_name,
                "kernel": env_status.kernel_version,
                "architecture": env_status.arch,
                "python_version": env_status.python_version,
                "is_wsl": env_status.is_wsl or env_status.wsl_available,
                "wsl_distro": env_status.wsl_distro,
                "ptrace_supported": env_status.ptrace_supported,
            },
            "policy": {
                "name": policy.name if policy else "Default Policy",
                "description": policy.description if policy else "",
                "default_action": policy.default_action if policy else "allow",
                "rule_count": len(policy.rules) if policy else 0,
            },
            "metrics": {
                "total_events": summary.total_events,
                "allowed_calls": summary.allowed_count,
                "denied_attempts": summary.denied_attempts,
                "successfully_blocked": summary.blocked_count,
                "audited_calls": summary.audit_count,
                "enforcement_failures": summary.enforcement_failures,
                "duration_ms": duration_ms,
                "distinct_syscalls_count": len(summary.distinct_syscalls),
            },
            "syscall_frequency": syscall_freq,
            "security_violations": violations,
        }

    @classmethod
    def export_json(cls, report_dict: Dict[str, Any], indent: int = 2) -> str:
        return json.dumps(report_dict, indent=indent, default=str)

    @classmethod
    def export_csv(cls, events: List[TraceEvent]) -> str:
        """Export trace events to RFC 4180 CSV format."""
        output = io.StringIO()
        fieldnames = [
            "timestamp", "event", "type", "pid", "syscall_nr", "syscall_name",
            "path", "policy_decision", "enforcement", "matched_rule",
            "return_value", "errno", "signal", "exit_code", "error"
        ]
        writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()

        for ev in events:
            writer.writerow({
                "timestamp": f"{ev.timestamp:.6f}",
                "event": ev.event,
                "type": ev.event_type or "",
                "pid": ev.pid if ev.pid is not None else "",
                "syscall_nr": ev.syscall_nr if ev.syscall_nr is not None else "",
                "syscall_name": ev.syscall_name or "",
                "path": ev.path or "",
                "policy_decision": ev.policy_decision or "",
                "enforcement": ev.enforcement or "",
                "matched_rule": ev.matched_rule or "",
                "return_value": ev.return_value if ev.return_value is not None else "",
                "errno": ev.errno_str or "",
                "signal": ev.signal if ev.signal is not None else "",
                "exit_code": ev.exit_code if ev.exit_code is not None else "",
                "error": ev.error_msg or "",
            })

        return output.getvalue()

    @classmethod
    def export_markdown(cls, report_dict: Dict[str, Any]) -> str:
        t = report_dict["target"]
        env = report_dict["environment"]
        m = report_dict["metrics"]
        p = report_dict["policy"]

        lines = [
            f"# {report_dict['project']}",
            f"**Audit Report Generated:** {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(report_dict['generation_timestamp']))}",
            "",
            "## 1. Target Execution Summary",
            f"- **Executable:** `{t['executable']}`",
            f"- **Arguments:** `{' '.join(t['arguments']) if t['arguments'] else '(none)'}`",
            f"- **PID:** `{t['pid']}`",
            f"- **Exit Code:** `{t['exit_code']}`",
            f"- **Terminating Signal:** `{t['term_signal'] or 'None'}`",
            f"- **Duration:** `{m['duration_ms']:.2f} ms`" if m['duration_ms'] else "- **Duration:** N/A",
            "",
            "## 2. Platform Environment",
            f"- **Operating System:** {env['os']} ({env['kernel']})",
            f"- **Architecture:** {env['architecture']}",
            f"- **Python Version:** {env['python_version']}",
            f"- **WSL Bridging:** {'Active (' + str(env['wsl_distro']) + ')' if env['is_wsl'] else 'Native'}",
            f"- **Kernel ptrace Support:** {'Operational' if env['ptrace_supported'] else 'Unsupported'}",
            "",
            "## 3. Active Policy",
            f"- **Policy Name:** {p['name']}",
            f"- **Description:** {p['description']}",
            f"- **Default Action:** `{p['default_action']}`",
            f"- **Active Rules:** {p['rule_count']}",
            "",
            "## 4. Enforcement Metrics",
            "| Metric | Count |",
            "| :--- | :--- |",
            f"| Total Syscall Events | **{m['total_events']}** |",
            f"| Allowed System Calls | **{m['allowed_calls']}** |",
            f"| Denied Attempts | **{m['denied_attempts']}** |",
            f"| Successfully Blocked | **{m['successfully_blocked']}** |",
            f"| Audited System Calls | **{m['audited_calls']}** |",
            f"| Enforcement Failures | **{m['enforcement_failures']}** |",
            f"| Distinct Syscalls Intercepted | **{m['distinct_syscalls_count']}** |",
            "",
            "## 5. Security Audit Violations",
        ]

        violations = report_dict.get("security_violations", [])
        if not violations:
            lines.append("*(No policy violations or blocked operations observed during this execution)*")
        else:
            lines.append("| Timestamp | PID | Syscall | Path / Target | Matched Rule | Enforcement | Result |")
            lines.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |")
            for v in violations:
                lines.append(
                    f"| {v['timestamp']:.6f} | {v['pid']} | `{v['syscall_name']}` | `{v['path'] or 'N/A'}` | `{v['matched_rule']}` | **{v['enforcement']}** | ret={v['return_value']}, errno={v['errno']} |"
                )

        lines.append("")
        lines.append("---")
        lines.append("*Report generated by SysGuard Linux Policy Enforcement Framework.*")
        return "\n".join(lines)
