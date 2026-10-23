"""
Page 6: Audit Reports and Multiformat Export.
"""

from __future__ import annotations

import streamlit as st

from sysguard.event_parser import TraceEvent
from sysguard.report_generator import ReportGenerator
from sysguard.ui_common import (
    apply_custom_theme,
    get_workspace_root,
    init_session_state,
    render_header,
    render_status_sidebar,
)

init_session_state()
render_status_sidebar()
render_header("Audit Reports & Data Export", "Generate formal operating system laboratory audit reports.")

manager = st.session_state.tracer_manager
env_status = st.session_state.env_status
events: list[TraceEvent] = manager.get_all_events()

if not events and st.session_state.events_history:
    events = st.session_state.events_history

summary = manager.get_summary()
active_policy = st.session_state.active_policy

if not events and summary.total_events == 0:
    st.info("No trace events recorded. Execute a program in **Run Program** before generating a report.")
    st.stop()

# Generate Report Dictionary
report_dict = ReportGenerator.generate_report_dict(
    summary=summary,
    events=events,
    policy=active_policy,
    env_status=env_status,
    target_path=manager.target_command or "None",
    target_args=manager.target_args,
)

st.session_state.last_report = report_dict

st.markdown("### 1. Report Preview")
md_content = ReportGenerator.export_markdown(report_dict)

with st.expander("Formatted Markdown Audit Report Preview", expanded=True):
    st.markdown(md_content)

st.markdown("---")
st.markdown("### 2. Export Audit Artifacts")

col_exp1, col_exp2, col_exp3 = st.columns(3)

with col_exp1:
    json_str = ReportGenerator.export_json(report_dict, indent=2)
    st.download_button(
        "Download JSON Report",
        data=json_str.encode("utf-8"),
        file_name="sysguard_audit_report.json",
        mime="application/json",
        use_container_width=True,
    )

with col_exp2:
    csv_str = ReportGenerator.export_csv(events)
    st.download_button(
        "Download Trace Events (CSV)",
        data=csv_str.encode("utf-8"),
        file_name="sysguard_trace_events.csv",
        mime="text/csv",
        use_container_width=True,
    )

with col_exp3:
    st.download_button(
        "Download Markdown Summary",
        data=md_content.encode("utf-8"),
        file_name="sysguard_summary.md",
        mime="text/markdown",
        use_container_width=True,
    )

st.markdown("---")
st.markdown("### 3. Raw JSON Inspector")
with st.expander("Inspect Raw Report JSON"):
    st.json(report_dict)
