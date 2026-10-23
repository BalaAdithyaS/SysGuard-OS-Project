"""
Unit tests for SysGuard PolicyEngine.
"""

import json
import pytest
from sysguard.policy_engine import (
    PolicyEngine,
    PolicyValidationError,
    SUPPORTED_SYSCALLS,
)


def test_valid_policy_parsing():
    raw = {
        "name": "Test Policy",
        "description": "Testing validation",
        "default_action": "allow",
        "rules": [
            {"syscall": "unlink", "action": "deny"},
            {"syscall": "openat", "action": "audit"},
            {"syscall": "read", "action": "allow"},
        ],
    }
    pol = PolicyEngine.validate_dict(raw)
    assert pol.name == "Test Policy"
    assert pol.default_action == "allow"
    assert len(pol.rules) == 3
    assert pol.rules[0].syscall == "unlink"
    assert pol.rules[0].action == "deny"


def test_reject_invalid_action():
    raw = {
        "name": "Invalid Action",
        "rules": [{"syscall": "unlink", "action": "destroy"}],
    }
    with pytest.raises(PolicyValidationError, match="Unknown action 'destroy'"):
        PolicyEngine.validate_dict(raw)


def test_reject_unsupported_syscall():
    raw = {
        "name": "Invalid Syscall",
        "rules": [{"syscall": "fake_syscall_xyz", "action": "deny"}],
    }
    with pytest.raises(PolicyValidationError, match="not in the supported architecture"):
        PolicyEngine.validate_dict(raw)


def test_reject_duplicate_syscall_rules():
    raw = {
        "name": "Duplicate Rules",
        "rules": [
            {"syscall": "unlink", "action": "deny"},
            {"syscall": "unlink", "action": "allow"},
        ],
    }
    with pytest.raises(PolicyValidationError, match="Duplicate rule for syscall 'unlink'"):
        PolicyEngine.validate_dict(raw)


def test_reject_malformed_json_root():
    with pytest.raises(PolicyValidationError, match="must be a JSON object"):
        PolicyEngine.validate_dict(["not", "a", "dict"])


def test_deterministic_rule_precedence():
    raw = {
        "name": "Precedence Test",
        "default_action": "deny",
        "rules": [
            {"syscall": "read", "action": "allow"},
            {"syscall": "write", "action": "audit"},
        ],
    }
    pol = PolicyEngine.validate_dict(raw)

    act_read, rule_read = PolicyEngine.evaluate(pol, "read")
    assert act_read == "allow"
    assert rule_read.syscall == "read"

    act_write, rule_write = PolicyEngine.evaluate(pol, "write")
    assert act_write == "audit"

    act_unlisted, rule_unlisted = PolicyEngine.evaluate(pol, "openat")
    assert act_unlisted == "deny"
    assert rule_unlisted is None


def test_supported_syscalls_list():
    syscalls = PolicyEngine.get_supported_syscalls()
    assert "unlink" in syscalls
    assert "unlinkat" in syscalls
    assert "openat" in syscalls
    assert "execve" in syscalls
    assert "read" in syscalls
