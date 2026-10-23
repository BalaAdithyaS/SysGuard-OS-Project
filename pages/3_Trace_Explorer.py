"""
Page 3: Live Trace Explorer and Event Inspection Table.
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from sysguard.event_parser import TraceEvent
from sysguard.report_generator import ReportGenerator
from sysguard.ui_common import (
    apply_custom_theme,
    init_session_state,
    render_header,
    render_status_sidebar,
)

init_session_state()
render_status_sidebar()
render_header("Live Trace Explorer", "Inspect granular system call entry/exit events, arguments, and registers.")

manager = st.session_state.tracer_manager
events: list[TraceEvent] = manager.get_all_events()

# If session state has cached history from previous runs, use it
if not events and st.session_state.events_history:
    events = st.session_state.events_history

st.markdown(f"**Total Events Captured:** `{len(events)}`")

if not events:
    st.info("No trace events recorded yet. Navigate to **Run Program** to launch an executable.")
    st.stop()

# Build DataFrame for filtering
data_rows = []
for ev in events:
    arg_summary = ", ".join(f"0x{a:x}" if a > 4096 else str(a) for a in ev.args) if ev.args else ""
    data_rows.append({
        "timestamp": ev.timestamp,
        "time_str": f"{ev.timestamp:.6f}",
        "pid": str(ev.pid) if ev.pid is not None else "-",
        "event": ev.event,
        "type": ev.event_type or ev.event,
        "syscall_nr": str(ev.syscall_nr) if ev.syscall_nr is not None else "-",
        "syscall": ev.syscall_name or "-",
        "path": ev.path or "",
        "arguments": arg_summary,
        "decision": ev.policy_decision or "-",
        "enforcement": ev.enforcement or "-",
        "return_val": str(ev.return_value) if ev.return_value is not None else "-",
        "errno": ev.errno_str or "-",
        "matched_rule": ev.matched_rule or "-",
    })

df = pd.DataFrame(data_rows)

# Filtering Controls
st.markdown("### Filter & Search")
f_col1, f_col2, f_col3, f_col4 = st.columns(4)

with f_col1:
    search_query = st.text_input("Search (Syscall or Path):", value="")

with f_col2:
    all_decisions = ["ALL"] + sorted([d for d in df["decision"].unique() if d != "-"])
    selected_decision = st.selectbox("Filter by Decision:", all_decisions)

with f_col3:
    all_enforce = ["ALL"] + sorted([e for e in df["enforcement"].unique() if e != "-"])
    selected_enforce = st.selectbox("Filter by Enforcement:", all_enforce)

with f_col4:
    all_syscalls = ["ALL"] + sorted([s for s in df["syscall"].unique() if s != "-"])
    selected_sc = st.selectbox("Filter by Syscall:", all_syscalls)

filtered_df = df.copy()

if search_query:
    q = search_query.lower()
    filtered_df = filtered_df[
        filtered_df["syscall"].str.lower().str.contains(q)
        | filtered_df["path"].str.lower().str.contains(q)
    ]

if selected_decision != "ALL":
    filtered_df = filtered_df[filtered_df["decision"] == selected_decision]

if selected_enforce != "ALL":
    filtered_df = filtered_df[filtered_df["enforcement"] == selected_enforce]

if selected_sc != "ALL":
    filtered_df = filtered_df[filtered_df["syscall"] == selected_sc]

st.markdown(f"**Showing {len(filtered_df)} of {len(df)} events**")

display_df = filtered_df[[
    "time_str", "pid", "type", "syscall", "path", "decision",
    "enforcement", "return_val", "errno", "arguments", "matched_rule"
]].rename(columns={
    "time_str": "Timestamp",
    "pid": "PID",
    "type": "Type",
    "syscall": "Syscall",
    "path": "Decoded Path",
    "decision": "Policy Decision",
    "enforcement": "Enforcement",
    "return_val": "Return Value",
    "errno": "Errno",
    "arguments": "Raw Registers",
    "matched_rule": "Matched Rule"
})

st.dataframe(display_df, use_container_width=True, height=450)

# Export buttons
st.markdown("### Export Trace Data")
exp_c1, exp_c2 = st.columns(2)

with exp_c1:
    csv_bytes = ReportGenerator.export_csv(events).encode("utf-8")
    st.download_button(
        "Download Complete Trace (CSV)",
        data=csv_bytes,
        file_name="sysguard_trace.csv",
        mime="text/csv",
    )

with exp_c2:
    json_bytes = display_df.to_json(orient="records", indent=2).encode("utf-8")
    st.download_button(
        "Download Filtered Trace (JSON)",
        data=json_bytes,
        file_name="sysguard_filtered_trace.json",
        mime="application/json",
    )
