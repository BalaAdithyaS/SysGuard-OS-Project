"""
Unit tests for EnvironmentDetector and path conversion.
"""

from pathlib import Path
from sysguard.environment import EnvironmentDetector, to_windows_path, to_wsl_path


def test_to_wsl_path_conversion():
    assert to_wsl_path("C:\\PROJECT\\os project") == "/mnt/c/PROJECT/os project"
    assert to_wsl_path("D:\\test\\file.txt") == "/mnt/d/test/file.txt"
    assert to_wsl_path("/tmp/test") == "/tmp/test"


def test_to_windows_path_conversion():
    assert to_windows_path("/mnt/c/PROJECT/os project") == "C:\\PROJECT\\os project"
    assert to_windows_path("/mnt/d/test/file.txt") == "D:\\test\\file.txt"


def test_environment_detector_status():
    detector = EnvironmentDetector()
    status = detector.detect()
    assert status.os_name in ("Linux", "Windows", "Darwin")
    assert status.arch != ""
    assert status.python_version != ""
    assert status.compatibility_message != ""
