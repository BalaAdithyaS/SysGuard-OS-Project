"""
Page 4: Policy Editor, Rule Builder, and Syscall Catalog.
"""

from __future__ import annotations

import json
from pathlib import Path
import streamlit as st

from sysguard.policy_engine import (
    Policy,
    PolicyEngine,
    PolicyRule,
    PolicyValidationError,
    SUPPORTED_SYSCALLS,
    VALID_ACTIONS,
)
from sysguard.ui_common import (
    get_workspace_root,
    init_session_state,
    render_header,
    render_status_sidebar,
)

init_session_state()
render_status_sidebar()
render_header("Security Policy Editor", "Define, validate, and save access control and auditing rules.")

workspace_root = get_workspace_root()
policy_dir = workspace_root / "policies"
policy_files = sorted(list(policy_dir.glob("*.json")))

st.markdown("### 1. Load or Create Policy")

col_sel1, col_sel2 = st.columns([2, 1])

with col_sel1:
    selected_file = st.selectbox(
        "Select Existing Policy File:",
        options=[p.name for p in policy_files],
        index=0 if policy_files else None,
    )

with col_sel2:
    if st.button("Load Policy Into Editor"):
        if selected_file:
            path = policy_dir / selected_file
            st.session_state.editor_content = path.read_text(encoding="utf-8")
            st.session_state.editor_path = str(path)
            st.success(f"Loaded '{selected_file}'")

if "editor_content" not in st.session_state:
    # Default to read_only_demo.json
    default_p = policy_dir / "read_only_demo.json"
    if default_p.exists():
        st.session_state.editor_content = default_p.read_text(encoding="utf-8")
        st.session_state.editor_path = str(default_p)
    else:
        st.session_state.editor_content = "{\n  \"name\": \"New Policy\",\n  \"description\": \"\",\n  \"default_action\": \"allow\",\n  \"rules\": []\n}"
        st.session_state.editor_path = str(policy_dir / "new_policy.json")

st.markdown("---")
st.markdown("### 2. Policy JSON Configuration")

editor_text = st.text_area(
    "Policy JSON Definition:",
    value=st.session_state.editor_content,
    height=320,
    help="Define policy object with 'name', 'default_action' ('allow'|'deny'), and 'rules' list.",
)
st.session_state.editor_content = editor_text

col_act1, col_act2, col_act3 = st.columns(3)

with col_act1:
    validate_btn = st.button("Validate Policy", type="primary")

with col_act2:
    save_filename = st.text_input(
        "Save Filename:",
        value=Path(st.session_state.editor_path).name if "editor_path" in st.session_state else "custom_policy.json",
    )

with col_act3:
    save_btn = st.button("Save Policy to Disk")

if validate_btn:
    try:
        validated_policy = PolicyEngine.load_from_string(editor_text)
        st.success(
            f"**Validation PASSED!** Policy '{validated_policy.name}' has {len(validated_policy.rules)} valid rules. Default action: `{validated_policy.default_action}`."
        )
        st.session_state.active_policy = validated_policy
    except PolicyValidationError as pve:
        st.error(f"**Validation FAILED:** {pve}")

if save_btn:
    try:
        validated_policy = PolicyEngine.load_from_string(editor_text)
        target_save_path = policy_dir / save_filename
        PolicyEngine.save_to_file(validated_policy, target_save_path)
        st.success(f"Policy successfully saved to `{target_save_path}`!")
        st.session_state.active_policy = validated_policy
        st.session_state.active_policy_path = str(target_save_path)
    except PolicyValidationError as pve:
        st.error(f"Cannot save invalid policy: {pve}")
    except Exception as e:
        st.error(f"Save error: {e}")

st.markdown("---")
st.markdown("### 3. Supported Syscall Reference & Limitations")

with st.expander("View Supported x86-64 System Calls"):
    st.write(
        "SysGuard natively decodes and enforces rules for the following Linux x86-64 system calls. "
        "Any rule specifying an unlisted syscall will be rejected by the validation engine."
    )
    supported_list = PolicyEngine.get_supported_syscalls()
    sc_cols = st.columns(4)
    chunk_size = (len(supported_list) + 3) // 4
    for i in range(4):
        with sc_cols[i]:
            for sc in supported_list[i * chunk_size : (i + 1) * chunk_size]:
                st.code(sc, language="text")

with st.expander("Policy Precedence & Enforcement Semantics"):
    st.markdown(
        """
        - **Deterministic Precedence:** Rules are evaluated sequentially in the order listed.
          The first rule matching the intercepted syscall number or name determines the outcome.
        - **Default Action Fallback:** If no rule matches, the policy's `default_action` (`allow` or `deny`) is applied.
        - **Duplicate Rule Prohibition:** Duplicate rules for the same syscall are rejected during validation to eliminate ambiguity.
        - **Modern Glibc Syscall Substitution:** Modern glibc transparently calls `openat` instead of `open`,
          and `unlinkat` instead of `unlink`. To block file deletions reliably across all libraries, include both `unlink` and `unlinkat`.
        - **Enforcement Method:** Denied calls have their register `orig_rax` modified to `-1` at entry stop,
          causing the Linux kernel to bypass the syscall. At exit stop, `rax` is set to `-EPERM` (-1).
        """
    )
