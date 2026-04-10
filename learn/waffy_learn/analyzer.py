"""
Parameter type inference engine.

Analyzes observed values for each parameter and infers the tightest type
and constraints that cover the configured confidence threshold of traffic.
"""

import re
from dataclasses import dataclass, field
from enum import Enum

import numpy as np


class ParamType(Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    UUID = "uuid"
    EMAIL = "email"
    IPV4 = "ipv4"
    ISO_DATE = "iso_date"
    JWT = "jwt"
    BASE64 = "base64"
    HEX = "hex"
    ENUM = "enum"


# Ordered from most specific to least specific
TYPE_PATTERNS: list[tuple[ParamType, re.Pattern]] = [
    (ParamType.BOOLEAN, re.compile(r"^(true|false|0|1)$", re.I)),
    (ParamType.UUID, re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.I,
    )),
    (ParamType.IPV4, re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$"
    )),
    (ParamType.EMAIL, re.compile(
        r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    )),
    (ParamType.ISO_DATE, re.compile(
        r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$"
    )),
    (ParamType.JWT, re.compile(
        r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$"
    )),
    (ParamType.INTEGER, re.compile(r"^-?\d+$")),
    (ParamType.FLOAT, re.compile(r"^-?\d+\.\d+$")),
    (ParamType.HEX, re.compile(r"^[0-9a-fA-F]+$")),
    (ParamType.BASE64, re.compile(r"^[A-Za-z0-9+/]+=*$")),
]


@dataclass
class ParamConstraints:
    """Inferred constraints for a single parameter."""

    min_length: int = 0
    max_length: int = 0
    regex: str | None = None
    min_value: int | None = None
    max_value: int | None = None
    enum_values: list[str] = field(default_factory=list)


@dataclass
class ParamProfile:
    """Complete profile for a single parameter."""

    name: str
    source: str  # "query", "body", "header", "cookie"
    inferred_type: ParamType = ParamType.STRING
    required: bool = False
    constraints: ParamConstraints = field(default_factory=ParamConstraints)
    sample_count: int = 0
    present_count: int = 0  # How many requests included this param


class TypeInferrer:
    """Infers parameter types from observed values."""

    def __init__(self, confidence: float = 0.95,
                 enum_max_cardinality: int = 50,
                 outlier_percentile: float = 0.5):
        self.confidence = confidence
        self.enum_max_cardinality = enum_max_cardinality
        self.outlier_pct = outlier_percentile

    def infer(self, values: list[str], total_requests: int,
              present_count: int) -> ParamProfile:
        """
        Infer the type and constraints for a parameter from its observed values.

        Args:
            values: All observed values for this parameter
            total_requests: Total requests to this location+method
            present_count: How many requests included this parameter
        """
        profile = ParamProfile(
            name="",  # Caller sets this
            source="",
            sample_count=len(values),
            present_count=present_count,
        )

        if not values:
            return profile

        # Required if present in >95% of requests
        profile.required = (present_count / total_requests) >= self.confidence

        unique_values = set(values)

        # 1. Check for constant
        if len(unique_values) == 1:
            profile.inferred_type = ParamType.ENUM
            profile.constraints.enum_values = list(unique_values)
            return profile

        # 2. Check for enum (low cardinality)
        if len(unique_values) <= self.enum_max_cardinality:
            profile.inferred_type = ParamType.ENUM
            profile.constraints.enum_values = sorted(unique_values)
            return profile

        # 3. Try structured type detection
        detected_type = self._detect_type(values)
        if detected_type is not None:
            profile.inferred_type = detected_type

        # 4. Compute length bounds
        lengths = np.array([len(v) for v in values])
        lo_pct = self.outlier_pct
        hi_pct = 100 - self.outlier_pct
        profile.constraints.min_length = max(0, int(np.percentile(lengths, lo_pct)))
        profile.constraints.max_length = int(np.percentile(lengths, hi_pct))

        # 5. Compute numeric ranges
        if profile.inferred_type in (ParamType.INTEGER, ParamType.FLOAT):
            try:
                nums = np.array([float(v) for v in values])
                profile.constraints.min_value = int(np.percentile(nums, lo_pct))
                profile.constraints.max_value = int(np.percentile(nums, hi_pct))
            except (ValueError, OverflowError):
                pass

        # 6. Generate regex for string types
        if profile.inferred_type == ParamType.STRING:
            profile.constraints.regex = self._generate_charset_regex(values)

        return profile

    def _detect_type(self, values: list[str]) -> ParamType | None:
        """Try each type pattern in order. Return first that matches >= confidence."""
        threshold = int(len(values) * self.confidence)

        for param_type, pattern in TYPE_PATTERNS:
            match_count = sum(1 for v in values if pattern.match(v))
            if match_count >= threshold:
                return param_type

        return None

    def _generate_charset_regex(self, values: list[str]) -> str:
        """
        Generate a character-class regex that covers the observed values.

        Strategy: identify which character classes appear, build a regex
        from the union of observed classes.
        """
        has_upper = False
        has_lower = False
        has_digit = False
        has_space = False
        special_chars: set[str] = set()

        for v in values:
            for ch in v:
                if ch.isupper():
                    has_upper = True
                elif ch.islower():
                    has_lower = True
                elif ch.isdigit():
                    has_digit = True
                elif ch.isspace():
                    has_space = True
                else:
                    special_chars.add(ch)

        # Build character class
        parts = []
        if has_upper and has_lower:
            parts.append("a-zA-Z")
        elif has_lower:
            parts.append("a-z")
        elif has_upper:
            parts.append("A-Z")

        if has_digit:
            parts.append("0-9")

        if has_space:
            parts.append(r"\s")

        # Escape and add special characters
        for ch in sorted(special_chars):
            if ch in r"\.^$*+?{}[]|()/":
                parts.append(f"\\{ch}")
            else:
                parts.append(ch)

        charset = "".join(parts)
        return f"^[{charset}]+$"


def is_freetext_field(profile: ParamProfile) -> bool:
    """
    Detect if a parameter is likely a free-text field that needs
    a hybrid blacklist overlay.

    Heuristic: if the charset includes characters commonly used in
    injection attacks (<, >, ', ", ;, |) and max_length > 50.
    """
    if profile.inferred_type != ParamType.STRING:
        return False
    if profile.constraints.max_length <= 50:
        return False
    if profile.constraints.regex is None:
        return True

    dangerous_chars = set("<>\"';|&")
    regex_chars = set(profile.constraints.regex)
    return bool(dangerous_chars & regex_chars)
