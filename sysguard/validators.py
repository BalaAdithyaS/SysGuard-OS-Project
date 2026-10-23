"""
Input validators for target executables, command line arguments, and working directories.
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path
from typing import List, Tuple


class ValidationError(Exception):
    """Raised when an input target or argument fails safety and validity checks."""
    pass


class TargetValidator:
    """Validates target binary paths and arguments without invoking a shell."""

    DANGEROUS_PATTERNS = re.compile(r"[`$;&|<>]")

    @classmethod
    def validate_executable(cls, path_str: str, is_wsl: bool = False) -> str:
        if not path_str or not path_str.strip():
            raise ValidationError("Target executable path cannot be empty.")

        cleaned = path_str.strip()

        # If on Windows checking a local Windows path
        if not is_wsl and os.name == "nt":
            p = Path(cleaned)
            # If absolute or relative local path
            if p.exists():
                if not p.is_file():
                    raise ValidationError(f"Target path '{cleaned}' is not a regular file.")
                return str(p.resolve())

        # For Linux or WSL paths
        if cleaned.startswith("/") or cleaned.startswith("./") or cleaned.startswith("../"):
            return cleaned

        # Otherwise a command name like 'ls', 'cat'
        return cleaned

    @classmethod
    def parse_and_validate_args(cls, args_str: str) -> List[str]:
        """Safely parse an argument string into a list of arguments without using a shell."""
        if not args_str or not args_str.strip():
            return []

        try:
            tokens = shlex.split(args_str, posix=True)
        except ValueError as e:
            raise ValidationError(f"Malformed argument string: {e}") from e

        return tokens

    @classmethod
    def validate_working_dir(cls, dir_str: str) -> Path:
        if not dir_str or not dir_str.strip():
            return Path.cwd()

        p = Path(dir_str.strip()).resolve()
        if not p.exists():
            raise ValidationError(f"Working directory '{dir_str}' does not exist.")
        if not p.is_dir():
            raise ValidationError(f"Working directory '{dir_str}' is not a directory.")
        return p
