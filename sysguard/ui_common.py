"""
Common UI components, custom developer styling, and session state management for SysGuard.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional
import streamlit as st

from sysguard.environment import EnvironmentDetector, EnvironmentStatus
from sysguard.policy_engine import Policy, PolicyEngine
from sysguard.tracer_manager import TracerManager

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent


def get_workspace_root() -> Path:
    return WORKSPACE_ROOT


def init_session_state() -> None:
    """Initialize persistent session state variables."""
    if "tracer_manager" not in st.session_state:
        st.session_state.tracer_manager = TracerManager(WORKSPACE_ROOT)

    if "env_status" not in st.session_state:
        st.session_state.env_status = st.session_state.tracer_manager.refresh_environment()

    if "active_policy" not in st.session_state:
        default_policy_file = WORKSPACE_ROOT / "policies" / "read_only_demo.json"
        if default_policy_file.exists():
            st.session_state.active_policy = PolicyEngine.load_from_file(default_policy_file)
            st.session_state.active_policy_path = str(default_policy_file)
        else:
            st.session_state.active_policy = Policy(
                name="Default Allow Policy",
                description="Default configuration",
                default_action="allow",
                rules=[],
            )
            st.session_state.active_policy_path = None

    if "events_history" not in st.session_state:
        st.session_state.events_history = []

    if "last_report" not in st.session_state:
        st.session_state.last_report = None


def apply_custom_theme() -> None:
    """Injects professional, high-contrast dark navy developer theme CSS."""
    st.markdown(
        """
        <style>
        /* Base typography & palette */
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-card: #21262d;
            --border-color: #30363d;
            --text-primary: #f0f6fc;
            --text-secondary: #8b949e;
            --accent-indigo: #6366f1;
            --accent-blue: #58a6ff;
            --status-green: #3fb950;
            --status-red: #f85149;
            --status-amber: #d29922;
        }

        /* Hide Streamlit default deploy button and menu for clean desktop UI */
        .stDeployButton, [data-testid="stToolbarActions"], header[data-testid="stHeader"] {
            display: none !important;
        }
        #MainMenu, footer {
            visibility: hidden;
        }
        .sysguard-header {
            background: linear-gradient(135deg, #161b22 0%, #1e1e2f 100%);
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.5rem;
        }
        .sysguard-title {
            font-size: 1.6rem;
            font-weight: 700;
            color: #f0f6fc;
            margin: 0;
            letter-spacing: -0.02em;
        }
        .sysguard-subtitle {
            font-size: 0.9rem;
            color: #8b949e;
            margin-top: 0.25rem;
            margin-bottom: 0;
        }

        /* Metric cards */
        .sysguard-card {
            background-color: #161b22;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 1rem;
            margin-bottom: 0.75rem;
        }
        .sysguard-card-title {
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: #8b949e;
            margin-bottom: 0.35rem;
        }
        .sysguard-card-value {
            font-size: 1.75rem;
            font-weight: 700;
            color: #f0f6fc;
            line-height: 1.2;
        }
        .sysguard-card-sub {
            font-size: 0.8rem;
            color: #8b949e;
            margin-top: 0.3rem;
        }

        /* Status badge tags */
        .badge {
            display: inline-block;
            padding: 0.2rem 0.55rem;
            font-size: 0.75rem;
            font-weight: 600;
            border-radius: 4px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .badge-allowed {
            background-color: rgba(63, 185, 80, 0.15);
            color: #3fb950;
            border: 1px solid rgba(63, 185, 80, 0.4);
        }
        .badge-blocked {
            background-color: rgba(248, 81, 73, 0.15);
            color: #f85149;
            border: 1px solid rgba(248, 81, 73, 0.4);
        }
        .badge-audit {
            background-color: rgba(88, 166, 255, 0.15);
            color: #58a6ff;
            border: 1px solid rgba(88, 166, 255, 0.4);
        }
        .badge-fail {
            background-color: rgba(210, 153, 34, 0.15);
            color: #d29922;
            border: 1px solid rgba(210, 153, 34, 0.4);
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_header(title: str, subtitle: str) -> None:
    apply_custom_theme()
    st.markdown(
        f"""
        <div class="sysguard-header">
            <h1 class="sysguard-title">{title}</h1>
            <p class="sysguard-subtitle">{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_status_sidebar() -> None:
    """Render backend readiness and environment info in the sidebar."""
    init_session_state()
    manager: TracerManager = st.session_state.tracer_manager
    status: EnvironmentStatus = st.session_state.env_status

    st.sidebar.markdown("### SysGuard Engine")

    # Platform Indicator
    if status.is_linux:
        st.sidebar.success(f"Platform: Native Linux ({status.arch})")
    elif status.wsl_available:
        st.sidebar.info(f"Platform: Windows via WSL2 ({status.wsl_distro or 'default'})")
    else:
        st.sidebar.error("Platform: Incompatible Host (No WSL2/Linux)")

    # Backend compiled status
    if status.tracer_compiled:
        st.sidebar.success("Tracer Backend: Ready")
    else:
        st.sidebar.warning("Tracer Backend: Not Compiled")
        if st.sidebar.button("Compile Backend", key="sb_btn_build"):
            with st.spinner("Compiling native C backend..."):
                ok, msg = manager.build_backend()
                if ok:
                    st.sidebar.success("Compilation succeeded!")
                    st.session_state.env_status = manager.refresh_environment()
                    st.rerun()
                else:
                    st.sidebar.error(f"Build failed:\n{msg}")

    # Tracing state
    if manager.is_running():
        st.sidebar.warning(f"Trace Active (PID: {manager.process.pid if manager.process else '?'})")
        if st.sidebar.button("Stop Trace", key="sb_btn_stop"):
            manager.stop_trace()
            st.rerun()
    else:
        st.sidebar.text("Trace State: Idle")

    st.sidebar.markdown("---")
    st.sidebar.caption("SysGuard v1.0.0 | OS Lab Project")
