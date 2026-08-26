"""Decision logic — Security-vs-Life classifier."""

from .classifier import classify, EXTREME_CAS_THRESHOLD
from .rationale import build_rationale

__all__ = ["classify", "EXTREME_CAS_THRESHOLD", "build_rationale"]
