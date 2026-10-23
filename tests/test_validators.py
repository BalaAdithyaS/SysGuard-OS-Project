"""
Unit tests for TargetValidator.
"""

import pytest
from sysguard.validators import TargetValidator, ValidationError


def test_parse_arguments_safe():
    args = TargetValidator.parse_and_validate_args('--flag "some argument" -n 42')
    assert args == ["--flag", "some argument", "-n", "42"]


def test_parse_empty_arguments():
    assert TargetValidator.parse_and_validate_args("") == []
    assert TargetValidator.parse_and_validate_args("   ") == []


def test_empty_executable_rejected():
    with pytest.raises(ValidationError, match="cannot be empty"):
        TargetValidator.validate_executable("")


def test_validate_working_dir_current():
    wd = TargetValidator.validate_working_dir(".")
    assert wd.exists()
    assert wd.is_dir()


def test_validate_working_dir_nonexistent():
    with pytest.raises(ValidationError, match="does not exist"):
        TargetValidator.validate_working_dir("/definitely/nonexistent/directory/xyz")
