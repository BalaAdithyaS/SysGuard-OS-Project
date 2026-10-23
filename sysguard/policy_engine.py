"""
SysGuard Policy Engine: Policy loading, validation, and deterministic evaluation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

VALID_ACTIONS = {"allow", "deny", "audit"}
DEFAULT_ACTION = "allow"

SUPPORTED_SYSCALLS = {
    "read", "write", "open", "close", "stat", "fstat", "lstat",
    "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
    "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
    "writev", "access", "pipe", "select", "sched_yield",
    "dup", "dup2", "getpid", "socket", "connect", "accept",
    "sendto", "recvfrom", "bind", "listen", "clone", "fork", "vfork",
    "execve", "exit", "wait4", "kill", "uname", "fcntl", "getcwd",
    "chdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink",
    "symlink", "readlink", "chmod", "fchmod", "chown", "getuid",
    "getgid", "geteuid", "getegid", "statfs", "prctl", "arch_prctl",
    "futex", "set_tid_address", "exit_group", "openat", "mkdirat",
    "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat",
    "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll",
    "pipe2", "prlimit64", "getrandom", "execveat", "statx",
    "close_range", "openat2", "faccessat2"
}


@dataclass
class PolicyRule:
    syscall: str
    action: str

    def to_dict(self) -> Dict[str, str]:
        return {"syscall": self.syscall, "action": self.action}


@dataclass
class Policy:
    name: str
    description: str
    default_action: str = DEFAULT_ACTION
    rules: List[PolicyRule] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "default_action": self.default_action,
            "rules": [r.to_dict() for r in self.rules],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class PolicyValidationError(Exception):
    """Raised when policy schema or rules violate validation constraints."""
    pass


class PolicyEngine:
    """Manages policy loading, validation, saving, and runtime rule evaluation."""

    @staticmethod
    def validate_dict(data: Dict[str, Any]) -> Policy:
        if not isinstance(data, dict):
            raise PolicyValidationError("Policy root must be a JSON object.")

        name = data.get("name")
        if not name or not isinstance(name, str):
            raise PolicyValidationError("Policy 'name' must be a non-empty string.")

        description = data.get("description", "")
        if not isinstance(description, str):
            raise PolicyValidationError("Policy 'description' must be a string.")

        default_action = data.get("default_action", DEFAULT_ACTION).lower()
        if default_action not in ("allow", "deny"):
            raise PolicyValidationError(
                f"Invalid default_action '{default_action}'. Must be 'allow' or 'deny'."
            )

        raw_rules = data.get("rules")
        if raw_rules is None:
            raw_rules = []
        elif not isinstance(raw_rules, list):
            raise PolicyValidationError("Policy 'rules' must be a JSON array.")

        parsed_rules: List[PolicyRule] = []
        seen_syscalls = set()

        for idx, item in enumerate(raw_rules):
            if not isinstance(item, dict):
                raise PolicyValidationError(f"Rule at index {idx} must be an object.")

            sc = item.get("syscall")
            if not sc or not isinstance(sc, str):
                raise PolicyValidationError(
                    f"Rule {idx}: 'syscall' must be a non-empty string."
                )

            sc_clean = sc.strip().lower()
            if sc_clean not in SUPPORTED_SYSCALLS:
                raise PolicyValidationError(
                    f"Rule {idx}: Syscall '{sc_clean}' is not in the supported architecture syscall table."
                )

            if sc_clean in seen_syscalls:
                raise PolicyValidationError(
                    f"Rule {idx}: Duplicate rule for syscall '{sc_clean}'. Ambiguous duplicate rules are rejected."
                )
            seen_syscalls.add(sc_clean)

            act = item.get("action")
            if not act or not isinstance(act, str):
                raise PolicyValidationError(
                    f"Rule {idx}: 'action' must be a non-empty string."
                )

            act_clean = act.strip().lower()
            if act_clean not in VALID_ACTIONS:
                raise PolicyValidationError(
                    f"Rule {idx}: Unknown action '{act_clean}'. Supported actions are: {sorted(list(VALID_ACTIONS))}."
                )

            parsed_rules.append(PolicyRule(syscall=sc_clean, action=act_clean))

        return Policy(
            name=name.strip(),
            description=description.strip(),
            default_action=default_action,
            rules=parsed_rules,
        )

    @classmethod
    def load_from_file(cls, path: str | Path) -> Policy:
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Policy file not found: {p}")
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise PolicyValidationError(f"Malformed JSON in policy file '{p}': {e}") from e

        return cls.validate_dict(data)

    @classmethod
    def load_from_string(cls, json_str: str) -> Policy:
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise PolicyValidationError(f"Malformed JSON string: {e}") from e
        return cls.validate_dict(data)

    @staticmethod
    def save_to_file(policy: Policy, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(policy.to_json(indent=2))

    @staticmethod
    def evaluate(policy: Policy, syscall_name: str) -> Tuple[str, Optional[PolicyRule]]:
        """
        Evaluate syscall against policy rules.
        Precedence: First matching rule wins. If none match, return default_action.
        """
        target = syscall_name.strip().lower()
        for rule in policy.rules:
            if rule.syscall == target:
                return rule.action, rule
        return policy.default_action, None

    @staticmethod
    def get_supported_syscalls() -> List[str]:
        return sorted(list(SUPPORTED_SYSCALLS))
