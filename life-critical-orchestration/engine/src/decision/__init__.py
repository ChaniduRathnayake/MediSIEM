"""Decision logic — Security-vs-Life classifier."""

from .classifier import classify, EXTREME_CVSS_THRESHOLD
from .rationale import build_rationale

__all__ = ["classify", "EXTREME_CVSS_THRESHOLD", "build_rationale"]
