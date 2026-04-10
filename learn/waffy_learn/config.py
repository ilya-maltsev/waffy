"""Configuration for the learning engine."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class LearnConfig:
    """Top-level learning configuration."""

    # Input sources
    access_log_path: Path | None = None
    mirror_listen: str = "127.0.0.1:9999"

    # Output
    profile_output_dir: Path = Path("/var/waffy/profiles")

    # Learning parameters
    min_samples: int = 100          # Minimum requests before profiling
    training_window_hours: int = 168  # 7 days default
    type_confidence: float = 0.95   # % of values that must match a type
    enum_max_cardinality: int = 50  # Max distinct values to treat as enum
    outlier_percentile: float = 0.5 # Percentile to trim for length/range bounds

    # Pattern generalization
    pattern_coverage: float = 0.995 # Generated regex must cover this % of samples
    max_pattern_length: int = 4096

    # Locations to learn (empty = learn all)
    include_locations: list[str] = field(default_factory=list)
    exclude_locations: list[str] = field(default_factory=lambda: [
        "/static/", "/assets/", "/favicon.ico", "/robots.txt",
    ])
