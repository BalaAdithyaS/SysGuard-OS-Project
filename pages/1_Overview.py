"""
Page 1: System Overview and Diagnostics.
"""

from __future__ import annotations

import streamlit as st

from sysguard.ui_common import (
    apply_custom_theme,
    init_session_state,
    render_header,
    render_status_sidebar,
)

init_session_state()
render_status_sidebar()
render_header("System Overview & Runtime Status", "Platform diagnostics, backend metrics, and execution telemetry.")

manager = st.session_state.tracer_manager
env_status = st.session_state.env_status
summary = manager.get_summary()

st.markdown("### 1. Platform & Environment Diagnostics")

col_p1, col_p2, col_p3 = st.columns(3)
with col_p1:
    st.markdown("**Host Operating System**")
    st.code(f"{env_status.os_name} {env_status.kernel_version}")
    st.markdown("**CPU Architecture**")
    st.code(env_status.arch)

with col_p2:
    st.markdown("**Python Environment**")
    st.code(f"Python {env_status.python_version}")
    st.markdown("**Current User**")
    st.code(f"{env_status.current_user} (Root: {env_status.is_root})")

with col_p3:
    st.markdown("**WSL2 Bridging Mode**")
    if env_status.wsl_available:
        st.code(f"Active Distro: {env_status.wsl_distro or 'default'}")
    elif env_status.is_linux:
        st.code("Native Linux Subsystem")
    else:
        st.code("Unavailable")
    st.markdown("**Kernel ptrace Support**")
    st.code("Verified (x86_64)" if env_status.ptrace_supported else "Unsupported")

if env_status.extra_details:
    with st.expander("Diagnostic Security Subsystem Details"):
        for k, v in env_status.extra_details.items():
            st.text(f"{k}: {v}")

st.markdown("---")
st.markdown("### 2. Live Telemetry & Real Metrics")

m1, m2, m3, m4 = st.columns(4)
with m1:
    st.metric("Total Intercepted Events", summary.total_events)
with m2:
    st.metric("Allowed System Calls", summary.allowed_count)
with m3:
    st.metric("Successfully Blocked", summary.blocked_count)
with m4:
    st.metric("Audited System Calls", summary.audit_count)

m5, m6, m7, m8 = st.columns(4)
with m5:
    st.metric("Denied Attempts", summary.denied_attempts)
with m6:
    st.metric("Enforcement Failures", summary.enforcement_failures)
with m7:
    exit_val = summary.exit_code if summary.exit_code is not None else "N/A"
    st.metric("Target Exit Code", exit_val)
with m8:
    dur_val = f"{summary.duration_ms:.2f} ms" if summary.duration_ms else "N/A"
    st.metric("Execution Duration", dur_val)

st.markdown("---")
st.markdown("### 3. Backend Compilation & Health")

c1, c2 = st.columns(2)
with c1:
    st.markdown("**C11 Tracer Helper:** `backend/sysguard-tracer`")
    if env_status.tracer_compiled:
        st.success("Tracer binary is compiled and executable.")
    else:
        st.warning("Tracer binary is not compiled.")
        if st.button("Trigger Native Rebuild", key="ov_rebuild"):
            with st.spinner("Rebuilding tracer backend..."):
                ok, msg = manager.build_backend()
                if ok:
                    st.success("Rebuild completed cleanly!")
                    st.session_state.env_status = manager.refresh_environment()
                    st.rerun()
                else:
                    st.error(f"Build failed:\n{msg}")

with c2:
    st.markdown("**Active Security Policy:**")
    active_pol = st.session_state.active_policy
    if active_pol:
        st.info(f"**{active_pol.name}**\n\nDefault Action: `{active_pol.default_action}` | Rules: {len(active_pol.rules)}")
    else:
        st.text("No policy selected.")
