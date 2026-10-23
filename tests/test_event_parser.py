"""
Unit tests for EventParser.
"""

from sysguard.event_parser import EventParser


def test_parse_valid_start_event():
    parser = EventParser()
    line = '{"event": "start", "pid": 1024, "target": "/bin/ls", "timestamp": 100.0}'
    ev = parser.parse_line(line)
    assert ev is not None
    assert ev.event == "start"
    assert ev.pid == 1024
    assert parser.summary.target_pid == 1024
    assert parser.summary.target_path == "/bin/ls"


def test_parse_entry_syscall_blocked():
    parser = EventParser()
    line = '{"event": "syscall", "type": "entry", "pid": 1024, "syscall_nr": 87, "syscall_name": "unlink", "path": "/tmp/a", "policy_decision": "DENY", "enforcement": "BLOCKED", "matched_rule": "unlink", "timestamp": 100.5}'
    ev = parser.parse_line(line)
    assert ev is not None
    assert ev.event == "syscall"
    assert ev.event_type == "entry"
    assert ev.syscall_name == "unlink"
    assert ev.policy_decision == "DENY"
    assert ev.enforcement == "BLOCKED"
    assert parser.summary.denied_attempts == 1
    assert parser.summary.blocked_count == 1


def test_parse_malformed_json_graceful():
    parser = EventParser()
    line = '{"event": "syscall", "unterminated_json: ...'
    ev = parser.parse_line(line)
    assert ev is not None
    assert ev.event == "malformed_json"
    assert parser.summary.malformed_lines_count == 1


def test_parse_non_json_diagnostic_line():
    parser = EventParser()
    line = "Random debug output from child printf"
    ev = parser.parse_line(line)
    assert ev is None


def test_parse_exit_event():
    parser = EventParser()
    line = '{"event": "exit", "pid": 1024, "exit_code": 0, "term_signal": null, "total_events": 50, "duration_ms": 12.5, "timestamp": 101.0}'
    ev = parser.parse_line(line)
    assert ev is not None
    assert ev.exit_code == 0
    assert parser.summary.exit_code == 0
    assert parser.summary.duration_ms == 12.5
