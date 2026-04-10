"""
Pattern generalization engine.

Takes a set of observed values and generates the tightest regex pattern
that covers the target percentage of samples.
"""

import re
from collections import Counter


# Attack patterns for hybrid blacklist overlay on free-text fields
BLACKLIST_PATTERNS: list[dict[str, str]] = [
    {"name": "sqli_union", "pattern": r"(?i)union\s+(all\s+)?select"},
    {"name": "sqli_comment", "pattern": r"(--|#|/\*)\s"},
    {"name": "sqli_or_true", "pattern": r"(?i)\bor\b\s+\d+\s*=\s*\d+"},
    {"name": "sqli_semicolon", "pattern": r";\s*(drop|alter|insert|update|delete)\b"},
    {"name": "xss_script", "pattern": r"<\s*script"},
    {"name": "xss_event", "pattern": r"\bon\w+\s*="},
    {"name": "xss_javascript", "pattern": r"(?i)javascript\s*:"},
    {"name": "path_traversal", "pattern": r"\.\./"},
    {"name": "path_traversal_encoded", "pattern": r"%2e%2e[/\\%]"},
    {"name": "cmd_injection", "pattern": r"[;|`]\s*\w+"},
    {"name": "cmd_subshell", "pattern": r"\$\(\w+"},
    {"name": "null_byte", "pattern": r"%00"},
    {"name": "crlf_injection", "pattern": r"%0[da]"},
    {"name": "ssi_injection", "pattern": r"<!--\s*#\s*(exec|include)"},
    {"name": "ldap_injection", "pattern": r"[)(|*\\]\s*\w+\s*="},
    {"name": "xml_entity", "pattern": r"<!ENTITY"},
    {"name": "xxe", "pattern": r"<!DOCTYPE[^>]+SYSTEM"},
]


def generalize_pattern(values: list[str],
                       coverage: float = 0.995) -> str | None:
    """
    Generate a regex pattern that covers at least `coverage` fraction
    of the provided values.

    Strategy:
    1. Find common structural patterns (prefix, suffix, separators)
    2. Classify character segments
    3. Build a minimal regex

    Returns None if no useful pattern can be derived.
    """
    if not values:
        return None

    # Check for common prefix
    prefix = _common_prefix(values)
    # Check for common suffix
    suffix = _common_suffix(values)

    # Strip prefix/suffix and analyze the middle
    stripped = []
    for v in values:
        middle = v
        if prefix:
            middle = middle[len(prefix):]
        if suffix:
            middle = middle[:-len(suffix)] if suffix else middle
        stripped.append(middle)

    # Analyze structure of middle parts
    structure = _analyze_structure(stripped)

    # Build regex
    parts = []
    if prefix:
        parts.append(re.escape(prefix))
    parts.append(structure)
    if suffix:
        parts.append(re.escape(suffix))

    pattern = "^" + "".join(parts) + "$"

    # Verify coverage
    try:
        compiled = re.compile(pattern)
        matched = sum(1 for v in values if compiled.match(v))
        actual_coverage = matched / len(values)

        if actual_coverage >= coverage:
            return pattern
    except re.error:
        pass

    # Fallback: charset + length based regex
    return _charset_pattern(values)


def _common_prefix(strings: list[str]) -> str:
    if not strings:
        return ""
    prefix = strings[0]
    for s in strings[1:]:
        while not s.startswith(prefix):
            prefix = prefix[:-1]
            if not prefix:
                return ""
    # Don't return prefix that's the entire string
    if all(s == prefix for s in strings):
        return ""
    return prefix


def _common_suffix(strings: list[str]) -> str:
    if not strings:
        return ""
    suffix = strings[0]
    for s in strings[1:]:
        while not s.endswith(suffix):
            suffix = suffix[1:]
            if not suffix:
                return ""
    if all(s == suffix for s in strings):
        return ""
    return suffix


def _analyze_structure(values: list[str]) -> str:
    """Analyze the character structure of values and return a regex fragment."""
    if not values:
        return ".*"

    # Check if all values have the same length
    lengths = set(len(v) for v in values)
    fixed_length = len(lengths) == 1

    # Find separator characters
    separators = _find_separators(values)

    if separators:
        # Split by separator and analyze each segment
        sep = separators[0]
        segments = [v.split(sep) for v in values]
        max_parts = max(len(s) for s in segments)
        min_parts = min(len(s) for s in segments)

        if max_parts == min_parts:
            # Fixed number of segments
            part_patterns = []
            for i in range(max_parts):
                part_values = [s[i] for s in segments if i < len(s)]
                part_patterns.append(_segment_pattern(part_values))
            return re.escape(sep).join(part_patterns)

    # No clear structure — fall back to charset
    return _segment_pattern(values)


def _find_separators(values: list[str]) -> list[str]:
    """Find characters that appear in the same position across most values."""
    candidates = ["-", "_", ".", "/", ":", " ", ","]
    result = []

    for sep in candidates:
        # Check if this separator appears in >90% of values
        count = sum(1 for v in values if sep in v)
        if count / len(values) > 0.9:
            result.append(sep)

    return result


def _segment_pattern(values: list[str]) -> str:
    """Generate a regex for a single segment (no separators)."""
    if not values or all(v == "" for v in values):
        return ""

    has_alpha = any(c.isalpha() for v in values for c in v)
    has_upper = any(c.isupper() for v in values for c in v)
    has_lower = any(c.islower() for v in values for c in v)
    has_digit = any(c.isdigit() for v in values for c in v)
    all_digit = all(c.isdigit() for v in values for c in v if v)

    lengths = [len(v) for v in values if v]
    if not lengths:
        return ""

    min_len = min(lengths)
    max_len = max(lengths)

    if all_digit:
        if min_len == max_len:
            return f"\\d{{{min_len}}}"
        return f"\\d{{{min_len},{max_len}}}"

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

    charset = "".join(parts)
    if min_len == max_len:
        return f"[{charset}]{{{min_len}}}"
    return f"[{charset}]{{{min_len},{max_len}}}"


def _charset_pattern(values: list[str]) -> str:
    """Fallback: generate a simple charset+length regex."""
    chars: set[str] = set()
    for v in values:
        chars.update(v)

    lengths = [len(v) for v in values]
    min_len = min(lengths) if lengths else 0
    max_len = max(lengths) if lengths else 0

    parts = []
    if any(c.islower() for c in chars):
        parts.append("a-z")
    if any(c.isupper() for c in chars):
        parts.append("A-Z")
    if any(c.isdigit() for c in chars):
        parts.append("0-9")

    special = sorted(c for c in chars
                     if not c.isalnum() and not c.isspace())
    for c in special:
        if c in r"\.^$*+?{}[]|()/":
            parts.append(f"\\{c}")
        else:
            parts.append(c)

    if any(c.isspace() for c in chars):
        parts.append(r"\s")

    charset = "".join(parts)
    return f"^[{charset}]{{{min_len},{max_len}}}$"
