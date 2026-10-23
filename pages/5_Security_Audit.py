"""
Page 5: Security Audit and Policy Violation Analysis.
"""

from __future__ import annotations

import pandas as pd
import plotly.express as px
import streamlit as st

from sysguard.event_parser import TraceEvent
from sysguard.ui_common import (
    apply_custom_theme,
    init_session_state,
    render_header,
    render_status_sidebar,
)

init_session_state()
render_status_sidebar()
render_header("Security Audit & Policy Violations", "Chronological audit timeline, denied syscall analysis, and violation breakdowns.")

manager = st.session_state.tracer_manager
events: list[TraceEvent] = manager.get_all_events()

if not events and st.session_state.events_history:
    events = st.session_state.events_history

summary = manager.get_summary()

# High level cards
c1, c2, c3, c4 = st.columns(4)
c1.metric("Denied Attempts", summary.denied_attempts)
c2.metric("Successfully Blocked", summary.blocked_count)
c3.metric("Enforcement Failures", summary.enforcement_failures)
c4.metric("Audited Calls", summary.audit_count)

st.markdown("---")

if not events:
    st.info("No trace events recorded yet. Navigate to **Run Program** to launch an executable.")
    st.stop()

# Filter security audit violations (DENY or AUDIT decisions)
violations = [e for e in events if e.policy_decision in ("DENY", "AUDIT") and e.event_type == "entry"]

st.markdown("### 1. Chronological Security Audit Timeline")
st.caption(
    "Every denied or audited syscall intercepted at entry stop, linked to underlying register state and documented outcome."
)

if violations:
    v_rows = []
    for idx, v in enumerate(violations, 1):
        ret_val = -1 if v.enforcement == "BLOCKED" else "-"
        errno_val = "EPERM" if v.enforcement == "BLOCKED" else "-"
        for ev in events:
            if ev.event_type == "exit" and ev.syscall_nr == v.syscall_nr and ev.timestamp >= v.timestamp:
                ret_val = ev.return_value if ev.return_value is not None else ret_val
                errno_val = ev.errno_str or errno_val
                break

        v_rows.append({
            "Seq": idx,
            "Timestamp": f"{v.timestamp:.6f}",
            "PID": v.pid,
            "Syscall": v.syscall_name,
            "Syscall Nr": v.syscall_nr,
            "Target Path / Arg": v.path or "-",
            "Rule Matched": v.matched_rule or "-",
            "Policy Decision": v.policy_decision,
            "Enforcement Status": v.enforcement,
            "Kernel Outcome": f"ret={ret_val}, errno={errno_val}",
        })
    v_df = pd.DataFrame(v_rows)
    st.dataframe(v_df, use_container_width=True)
else:
    st.success("No policy violations or audited operations were triggered in this session.")

st.markdown("---")
st.markdown("### 2. Telemetry Visualizations")

chart_col1, chart_col2 = st.columns(2)

with chart_col1:
    st.markdown("#### Policy Decisions Distribution")
    decisions_count = {
        "Allowed": summary.allowed_count,
        "Blocked (Enforced)": summary.blocked_count,
        "Audited": summary.audit_count,
        "Failed Enforcement": summary.enforcement_failures,
    }
    chart_df = pd.DataFrame([
        {"Outcome": k, "Count": v} for k, v in decisions_count.items() if v > 0
    ])

    if not chart_df.empty:
        fig1 = px.pie(
            chart_df,
            names="Outcome",
            values="Count",
            color="Outcome",
            color_discrete_map={
                "Allowed": "#3fb950",
                "Blocked (Enforced)": "#f85149",
                "Audited": "#58a6ff",
                "Failed Enforcement": "#d29922",
            },
            hole=0.4,
        )
        fig1.update_layout(
            margin=dict(l=20, r=20, t=30, b=20),
            paper_bgcolor="#161b22",
            plot_bgcolor="#161b22",
            font_color="#f0f6fc",
        )
        st.plotly_chart(fig1, use_container_width=True)
    else:
        st.text("No decision metrics to display.")

with chart_col2:
    st.markdown("#### Top System Calls by Frequency")
    freq: dict[str, int] = {}
    for ev in events:
        if ev.event == "syscall" and ev.event_type == "entry" and ev.syscall_name:
            freq[ev.syscall_name] = freq.get(ev.syscall_name, 0) + 1

    if freq:
        top_sc = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10]
        bar_df = pd.DataFrame(top_sc, columns=["Syscall", "Count"])
        fig2 = px.bar(
            bar_df,
            x="Syscall",
            y="Count",
            text="Count",
            color="Count",
            color_continuous_scale="Purples",
        )
        fig2.update_layout(
            margin=dict(l=20, r=20, t=30, b=20),
            paper_bgcolor="#161b22",
            plot_bgcolor="#161b22",
            font_color="#f0f6fc",
            showlegend=False,
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.text("No syscall frequency data available.")
