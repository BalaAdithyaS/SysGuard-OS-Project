"""
Integration tests: Runs native sysguard-tracer against test demonstration binaries.
"""

import os
import subprocess
import time
from pathlib import Path
import pytest

from sysguard.environment import EnvironmentDetector, to_wsl_path
from sysguard.tracer_manager import TracerManager
from sysguard.policy_engine import PolicyEngine

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(scope="module")
def env_check():
    detector = EnvironmentDetector(WORKSPACE_ROOT)
    status = detector.detect()
    if not status.is_linux and not status.wsl_available:
        pytest.skip("Integration tests require Linux or active WSL2.")
    return status


def test_integration_basic_read(env_check):
    manager = TracerManager(WORKSPACE_ROOT)
    policy_path = WORKSPACE_ROOT / "policies" / "read_only_demo.json"

    if env_check.os_name == "Windows":
        target = "/mnt/c/PROJECT/os project/examples/basic_read"
    else:
        target = str(WORKSPACE_ROOT / "examples" / "basic_read")

    started = manager.start_trace(
        executable=target,
        args=[],
        policy_path=policy_path,
    )
    assert started is True

    # Wait for completion
    timeout = 10.0
    start = time.time()
    while manager.is_running() and time.time() - start < timeout:
        time.sleep(0.1)

    assert not manager.is_running()
    summary = manager.get_summary()
    assert summary.exit_code == 0
    assert summary.total_events > 0

    events = manager.get_all_events()
    syscall_names = [e.syscall_name for e in events if e.syscall_name]
    assert "openat" in syscall_names or "read" in syscall_names


def test_integration_denied_unlink_enforcement(env_check):
    """
    CRITICAL TEST: Verifies that a denied unlink is truly BLOCKED:
    1. Tracer intercepts entry, sets orig_rax = -1.
    2. Tracer intercepts exit, sets rax = -EPERM.
    3. Target program verifies file still exists and errno == EPERM.
    4. Target program exits with code 0 (which it only does if file exists and errno == EPERM).
    """
    manager = TracerManager(WORKSPACE_ROOT)
    policy_path = WORKSPACE_ROOT / "policies" / "read_only_demo.json"

    if env_check.os_name == "Windows":
        target = "/mnt/c/PROJECT/os project/examples/denied_unlink"
    else:
        target = str(WORKSPACE_ROOT / "examples" / "denied_unlink")

    started = manager.start_trace(
        executable=target,
        args=[],
        policy_path=policy_path,
    )
    assert started is True

    timeout = 10.0
    start = time.time()
    while manager.is_running() and time.time() - start < timeout:
        time.sleep(0.1)

    assert not manager.is_running()
    summary = manager.get_summary()

    # Exit code 0 means target observed EPERM and verified file remained present
    assert summary.exit_code == 0
    assert summary.blocked_count >= 1

    events = manager.get_all_events()
    blocked_events = [
        e for e in events
        if e.syscall_name in ("unlink", "unlinkat") and e.enforcement == "BLOCKED"
    ]
    assert len(blocked_events) >= 1
    assert blocked_events[0].policy_decision == "DENY"


def test_integration_allowed_operation(env_check):
    manager = TracerManager(WORKSPACE_ROOT)
    policy_path = WORKSPACE_ROOT / "policies" / "read_only_demo.json"

    if env_check.os_name == "Windows":
        target = "/mnt/c/PROJECT/os project/examples/allowed_operation"
    else:
        target = str(WORKSPACE_ROOT / "examples" / "allowed_operation")

    started = manager.start_trace(
        executable=target,
        args=[],
        policy_path=policy_path,
    )
    assert started is True

    timeout = 10.0
    start = time.time()
    while manager.is_running() and time.time() - start < timeout:
        time.sleep(0.1)

    assert not manager.is_running()
    summary = manager.get_summary()
    assert summary.exit_code == 0
    assert summary.allowed_count > 0


def test_integration_audit_only(env_check):
    manager = TracerManager(WORKSPACE_ROOT)
    policy_path = WORKSPACE_ROOT / "policies" / "audit_all.json"

    if env_check.os_name == "Windows":
        target = "/mnt/c/PROJECT/os project/examples/audit_only"
    else:
        target = str(WORKSPACE_ROOT / "examples" / "audit_only")

    started = manager.start_trace(
        executable=target,
        args=[],
        policy_path=policy_path,
    )
    assert started is True

    timeout = 10.0
    start = time.time()
    while manager.is_running() and time.time() - start < timeout:
        time.sleep(0.1)

    assert not manager.is_running()
    summary = manager.get_summary()
    assert summary.exit_code == 0
    assert summary.audit_count > 0


def test_integration_signal_handling(env_check):
    manager = TracerManager(WORKSPACE_ROOT)
    policy_path = WORKSPACE_ROOT / "policies" / "read_only_demo.json"

    if env_check.os_name == "Windows":
        target = "/mnt/c/PROJECT/os project/examples/signal_test"
    else:
        target = str(WORKSPACE_ROOT / "examples" / "signal_test")

    started = manager.start_trace(
        executable=target,
        args=[],
        policy_path=policy_path,
    )
    assert started is True

    timeout = 10.0
    start = time.time()
    while manager.is_running() and time.time() - start < timeout:
        time.sleep(0.1)

    assert not manager.is_running()
    summary = manager.get_summary()
    assert summary.exit_code == 0

    events = manager.get_all_events()
    sig_events = [e for e in events if e.event == "signal"]
    assert len(sig_events) >= 1
    assert sig_events[0].signal == 10  # SIGUSR1


def test_integration_invalid_executable(env_check):
    manager = TracerManager(WORKSPACE_ROOT)
    started = manager.start_trace(
        executable="/nonexistent/binary/xyz",
        args=[],
    )
    assert started is True

    timeout = 5.0
    start = time.time()
    while manager.is_running() and time.time() - start < timeout:
        time.sleep(0.1)

    assert not manager.is_running()
    events = manager.get_all_events()
    error_events = [e for e in events if e.event == "error"]
    assert len(error_events) >= 1
    assert "Executable not found" in (error_events[0].error_msg or "")


def test_integration_security_violator(env_check):
    manager = TracerManager(WORKSPACE_ROOT)
    policy_path = WORKSPACE_ROOT / "policies" / "read_only_demo.json"

    if env_check.os_name == "Windows":
        target = "/mnt/c/PROJECT/os project/examples/security_violator"
    else:
        target = str(WORKSPACE_ROOT / "examples" / "security_violator")

    started = manager.start_trace(
        executable=target,
        args=[],
        policy_path=policy_path,
    )
    assert started is True

    timeout = 10.0
    start = time.time()
    while manager.is_running() and time.time() - start < timeout:
        time.sleep(0.1)

    assert not manager.is_running()
    summary = manager.get_summary()
    assert summary.exit_code == 0
    assert summary.blocked_count >= 4
