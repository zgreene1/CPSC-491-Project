"""CVSS v3.1 Base scoring from a complete Base vector.

CVSS Base Scores describe intrinsic vulnerability severity. They do not
account for current exploit activity or a particular deployment's environment.
See https://www.first.org/cvss/v3.1/specification-document.
"""

from __future__ import annotations

import math


class CVSSVectorError(ValueError):
    """Raised when a CVSS v3.1 Base vector is malformed or incomplete."""


_METRICS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 1.0},
    "C": {"N": 0.0, "L": 0.22, "H": 0.56},
    "I": {"N": 0.0, "L": 0.22, "H": 0.56},
    "A": {"N": 0.0, "L": 0.22, "H": 0.56},
}
_REQUIRED = frozenset(_METRICS)


def _round_up(value: float) -> float:
    """CVSS Roundup: round upward to one decimal place."""
    return math.ceil(value * 10.0 - 1e-10) / 10.0


def score_cvss31(vector: str) -> float:
    """Calculate a CVSS v3.1 Base Score from a Base vector string."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3.1/"):
        raise CVSSVectorError("CVSS vector must use the CVSS:3.1 prefix.")

    parsed: dict[str, str] = {}
    for token in vector[len("CVSS:3.1/"):].split("/"):
        key, separator, value = token.partition(":")
        if not separator or key in parsed or key not in _METRICS:
            raise CVSSVectorError(f"Invalid or unsupported CVSS Base metric: {token!r}.")
        if value not in _METRICS[key]:
            raise CVSSVectorError(f"Invalid value for CVSS metric {key}: {value!r}.")
        parsed[key] = value

    missing = _REQUIRED - parsed.keys()
    if missing:
        raise CVSSVectorError(f"CVSS Base vector is missing metrics: {', '.join(sorted(missing))}.")

    scope_changed = parsed["S"] == "C"
    pr_weights = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.50 if scope_changed else 0.27}
    exploitability = (
        8.22
        * _METRICS["AV"][parsed["AV"]]
        * _METRICS["AC"][parsed["AC"]]
        * pr_weights[parsed["PR"]]
        * _METRICS["UI"][parsed["UI"]]
    )

    confidentiality = _METRICS["C"][parsed["C"]]
    integrity = _METRICS["I"][parsed["I"]]
    availability = _METRICS["A"][parsed["A"]]
    impact_subscore_base = 1.0 - (1.0 - confidentiality) * (1.0 - integrity) * (1.0 - availability)

    if scope_changed:
        impact = 7.52 * (impact_subscore_base - 0.029) - 3.25 * (impact_subscore_base - 0.02) ** 15
    else:
        impact = 6.42 * impact_subscore_base

    if impact <= 0:
        return 0.0
    base = min(impact + exploitability, 10.0) if not scope_changed else min(1.08 * (impact + exploitability), 10.0)
    return _round_up(base)


def cvss31_severity(score: float) -> str:
    """Map a CVSS v3.1 Base Score to its standard qualitative rating."""
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score) or not 0 <= score <= 10:
        raise ValueError("CVSS score must be a finite number from 0.0 through 10.0.")
    if score == 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"
