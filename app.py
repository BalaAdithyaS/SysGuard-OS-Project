"""
SysGuard: Linux System Call Interception and Policy Enforcement Framework
Main Application Dashboard.
"""

from __future__ import annotations

import streamlit as st

st.set_page_config(
    page_title="SysGuard | Linux Syscall Interception Framework",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

from sysguard.ui_common import (
    apply_custom_theme,
    get_workspace_root,
    init_session_state,
    render_header,
    render_status_sidebar,
)

init_session_state()
render_status_sidebar()
render_header(
    title="SYSGUARD",
    subtitle="Linux System Call Interception & Deterministic Policy Enforcement Framework",
)

manager = st.session_state.tracer_manager
env_status = st.session_state.env_status
summary = manager.get_summary()

st.markdown(
    """
SysGuard is a genuine Operating Systems laboratory framework designed to trace, evaluate, and enforce
security policies on Linux processes using the native `ptrace()` kernel interface on x86-64.

Unlike tools that merely observe and log events, **SysGuard actively intercepts system calls at entry,
matches them against deterministic rules, and physically prevents denied operations from executing
by modifying kernel registers before restoration.**
"""
)

st.markdown("### System Readiness")

col1, col2, col3, col4 = st.columns(4)

with col1:
    backend_ready = env_status.tracer_compiled
    color = "var(--status-green)" if backend_ready else "var(--status-amber)"
    val_text = "READY" if backend_ready else "NOT BUILT"
    st.markdown(
        f"""
        <div class="sysguard-card">
            <div class="sysguard-card-title">Backend Status</div>
            <div class="sysguard-card-value" style="color: {color};">{val_text}</div>
            <div class="sysguard-card-sub">Native C11 Tracer (ptrace)</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col2:
    is_active = manager.is_running()
    color = "var(--status-amber)" if is_active else "var(--accent-blue)"
    val_text = "ACTIVE" if is_active else "IDLE"
    st.markdown(
        f"""
        <div class="sysguard-card">
            <div class="sysguard-card-title">Tracer Lifecycle</div>
            <div class="sysguard-card-value" style="color: {color};">{val_text}</div>
            <div class="sysguard-card-sub">PID: {summary.target_pid or 'None'}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col3:
    st.markdown(
        f"""
        <div class="sysguard-card">
            <div class="sysguard-card-title">Enforced Blocks</div>
            <div class="sysguard-card-value" style="color: var(--status-red);">{summary.blocked_count}</div>
            <div class="sysguard-card-sub">Blocked via orig_rax=-1</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with col4:
    st.markdown(
        f"""
        <div class="sysguard-card">
            <div class="sysguard-card-title">Platform Kernel</div>
            <div class="sysguard-card-value" style="font-size: 1.25rem;">{env_status.kernel_version[:14]}</div>
            <div class="sysguard-card-sub">{env_status.os_name} ({env_status.arch})</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("### Platform Compatibility Diagnosis")
if env_status.is_linux:
    st.success(f"**Native Linux Platform:** {env_status.compatibility_message}")
elif env_status.wsl_available:
    st.info(f"**WSL2 Bridge Active:** {env_status.compatibility_message}")
else:
    st.error(f"**Incompatible Environment:** {env_status.compatibility_message}")

st.markdown("### Module Navigation")
col_nav1, col_nav2, col_nav3 = st.columns(3)

with col_nav1:
    st.markdown("#### **[1. Overview](Overview)**")
    st.write("Examine system metrics, host diagnostics, and execution statistics.")

    st.markdown("#### **[2. Run Program](Run_Program)**")
    st.write("Launch a target executable with policy enforcement and real-time process monitoring.")

with col_nav2:
    st.markdown("#### **[3. Live Trace Explorer](Trace_Explorer)**")
    st.write("Inspect detailed system call entry/exit events, arguments, return values, and filters.")

    st.markdown("#### **[4. Policy Editor](Policy_Editor)**")
    st.write("Review, edit, validate, and save JSON access control policies.")

with col_nav3:
    st.markdown("#### **[5. Security Audit](Security_Audit)**")
    st.write("Analyze policy violations, blocked syscall timeline, and frequency charts.")

    st.markdown("#### **[6. Reports & Audit Export](Reports)**")
    st.write("Generate and download comprehensive audit reports in JSON, CSV, and Markdown.")
