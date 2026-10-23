"""
Page 2: Launch and Trace Target Programs under SysGuard.
"""

from __future__ import annotations

import time
from pathlib import Path
import streamlit as st

from sysguard.environment import to_wsl_path
from sysguard.policy_engine import PolicyEngine
from sysguard.ui_common import (
    get_workspace_root,
    init_session_state,
    render_header,
    render_status_sidebar,
)
from sysguard.validators import TargetValidator, ValidationError

init_session_state()
render_status_sidebar()
render_header("Run & Trace Target Executable", "Execute native Linux binaries under ptrace policy enforcement.")

manager = st.session_state.tracer_manager
env_status = st.session_state.env_status
workspace_root = get_workspace_root()

st.markdown("### 1. Quick Demonstration Presets")
st.caption("Select a pre-compiled OS laboratory test program to populate the target parameters:")

preset_col1, preset_col2, preset_col3, preset_col4, preset_col5, preset_col6 = st.columns(6)

if "target_exe_input" not in st.session_state:
    st.session_state.target_exe_input = str(workspace_root / "examples" / "security_violator")
if "target_args_input" not in st.session_state:
    st.session_state.target_args_input = ""

with preset_col1:
    if st.button("Security Violator", type="primary", help="Deliberately attempts 5 prohibited operations (unlink, rmdir, rename, kill, unlinkat) to generate security audit violations"):
        st.session_state.target_exe_input = str(workspace_root / "examples" / "security_violator")
        st.session_state.target_args_input = ""
        st.rerun()

with preset_col2:
    if st.button("Denied Unlink", help="Attempts disposable file deletion under deny policy"):
        st.session_state.target_exe_input = str(workspace_root / "examples" / "denied_unlink")
        st.session_state.target_args_input = "/tmp/sysguard_demo_disposable.txt"
        st.rerun()

with preset_col3:
    if st.button("Basic Read", help="Predictably opens and reads /etc/os-release"):
        st.session_state.target_exe_input = str(workspace_root / "examples" / "basic_read")
        st.session_state.target_args_input = "/etc/os-release"
        st.rerun()

with preset_col4:
    if st.button("Allowed Call", help="Performs permitted getpid() and write() operations"):
        st.session_state.target_exe_input = str(workspace_root / "examples" / "allowed_operation")
        st.session_state.target_args_input = ""
        st.rerun()

with preset_col5:
    if st.button("Audit Only", help="Opens /etc/hosts matching an audit rule"):
        st.session_state.target_exe_input = str(workspace_root / "examples" / "audit_only")
        st.session_state.target_args_input = ""
        st.rerun()

with preset_col6:
    if st.button("Signal Test", help="Tests SIGUSR1 delivery and handling under ptrace"):
        st.session_state.target_exe_input = str(workspace_root / "examples" / "signal_test")
        st.session_state.target_args_input = ""
        st.rerun()

st.markdown("---")
st.markdown("### 2. Execution Configuration")

col_left, col_right = st.columns([2, 1])

with col_left:
    target_exe = st.text_input(
        "Executable Path (Linux path or workspace file):",
        value=st.session_state.target_exe_input,
        help="Full path or command name. Executed directly via execve, never through a shell.",
    )
    st.session_state.target_exe_input = target_exe

    target_args_str = st.text_input(
        "Command-Line Arguments (space-separated, quoted for strings):",
        value=st.session_state.target_args_input,
        help="Arguments parsed safely with POSIX shlex. No shell redirection or chaining permitted.",
    )
    st.session_state.target_args_input = target_args_str

    working_dir = st.text_input(
        "Working Directory:",
        value=str(workspace_root),
        help="Process current working directory.",
    )

with col_right:
    # Discover available policies
    policy_files = list((workspace_root / "policies").glob("*.json"))
    policy_names = [p.name for p in policy_files]
    default_idx = 0
    for idx, p in enumerate(policy_files):
        if p.name == "read_only_demo.json":
            default_idx = idx
            break

    selected_policy_name = st.selectbox(
        "Active Security Policy:",
        options=policy_names,
        index=default_idx if policy_names else 0,
    )

    selected_policy_path = workspace_root / "policies" / selected_policy_name if policy_names else None

    default_action = st.selectbox(
        "Default Action for Unlisted Calls:",
        options=["allow", "deny"],
        index=0,
        help="SysGuard defaults to 'allow' for safety, unless configured otherwise.",
    )

    audit_only_toggle = st.checkbox(
        "Audit-Only Mode (Observe without blocking)",
        value=False,
        help="If enabled, matching deny rules will log without nullifying registers.",
    )

    deny_errno_choice = st.selectbox(
        "Denial Error Code (returned to blocked calls):",
        options=["EPERM (Operation not permitted)", "EACCES (Permission denied)"],
        index=0,
    )
    deny_errno = "EPERM" if "EPERM" in deny_errno_choice else "EACCES"

st.markdown("---")

col_btn1, col_btn2, col_stat = st.columns([1, 1, 3])

with col_btn1:
    start_btn = st.button("Start Tracing", type="primary", disabled=manager.is_running())

with col_btn2:
    stop_btn = st.button("Stop Tracing", disabled=not manager.is_running())

with col_stat:
    if manager.is_running():
        st.warning(f"**Tracing Active:** Target PID `{manager.process.pid if manager.process else '?'}`")
    else:
        st.info("**Tracer Status:** Idle (Ready for execution)")

if stop_btn:
    manager.stop_trace()
    st.success("Trace process stopped cleanly.")
    st.rerun()

if start_btn:
    try:
        TargetValidator.validate_working_dir(working_dir)
        args_list = TargetValidator.parse_and_validate_args(target_args_str)

        # Validate policy
        if selected_policy_path:
            st.session_state.active_policy = PolicyEngine.load_from_file(selected_policy_path)
            st.session_state.active_policy_path = str(selected_policy_path)

        with st.spinner("Spawning target under native Linux tracer..."):
            manager.start_trace(
                executable=target_exe,
                args=args_list,
                policy_path=selected_policy_path,
                default_action=default_action,
                audit_only=audit_only_toggle,
                deny_errno=deny_errno,
            )

        st.success(f"Target process launched successfully under ptrace! Target PID: `{manager.target_command}`")

        # Wait briefly and refresh events
        time.sleep(0.5)
        st.session_state.events_history = manager.get_all_events()
        st.rerun()

    except ValidationError as ve:
        st.error(f"Validation Error: {ve}")
    except Exception as e:
        st.error(f"Execution Error: {e}")

# Live Event Stream Preview
st.markdown("### 3. Execution Status & Live Telemetry")
summary = manager.get_summary()

if summary.target_pid or summary.total_events > 0:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Target PID", summary.target_pid or "N/A")
    c2.metric("Total Syscalls", summary.total_events)
    c3.metric("Blocked Syscalls", summary.blocked_count)
    c4.metric("Exit Code", summary.exit_code if summary.exit_code is not None else "Running...")

    events = manager.get_all_events()
    st.session_state.events_history = events

    st.markdown(f"**Recent Trace Events ({len(events)} total logged):**")
    recent = events[-10:] if len(events) > 10 else events
    rows = []
    for ev in reversed(recent):
        rows.append({
            "Time": f"{ev.timestamp:.4f}",
            "Type": ev.event_type or ev.event,
            "Syscall": ev.syscall_name or "-",
            "Decision": ev.policy_decision or "-",
            "Enforcement": ev.enforcement or "-",
            "Path / Detail": ev.path or (f"ret={ev.return_value}" if ev.return_value is not None else "-"),
        })
    st.dataframe(rows, use_container_width=True)
else:
    st.text("No active or completed trace session. Launch a target above to see live events.")
