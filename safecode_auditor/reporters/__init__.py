"""Output reporters."""

from .json_reporter import build_json_report
from .sarif import build_sarif_report

__all__ = ["build_json_report", "build_sarif_report"]
