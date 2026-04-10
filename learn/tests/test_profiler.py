"""Tests for the per-location profile builder."""

import tempfile
from pathlib import Path

import pytest

from waffy_learn.config import LearnConfig
from waffy_learn.profiler import ProfileBuilder, RequestSample


@pytest.fixture
def builder():
    config = LearnConfig(min_samples=5)
    return ProfileBuilder(config)


def make_sample(location="/api/users", method="POST", **params):
    return RequestSample(
        location=location,
        method=method,
        params=params,
        param_sources={k: "body" for k in params},
        content_type="application/json",
    )


class TestProfileBuilder:
    def test_add_sample(self, builder):
        builder.add_sample(make_sample(name="Alice", age="30"))
        assert len(builder.locations) == 1
        key = "POST /api/users"
        assert builder.locations[key].total_requests == 1

    def test_multiple_samples(self, builder):
        for i in range(10):
            builder.add_sample(make_sample(name=f"User{i}", age=str(20 + i)))

        key = "POST /api/users"
        assert builder.locations[key].total_requests == 10
        assert len(builder.locations[key].param_values["name"]) == 10

    def test_analyze_produces_profiles(self, builder):
        for i in range(100):
            builder.add_sample(make_sample(
                name=f"User{i}",
                age=str(20 + i),
                role="admin" if i % 3 == 0 else "user",
            ))

        results = builder.analyze()
        key = "POST /api/users"
        assert "name" in results[key].param_profiles
        assert "age" in results[key].param_profiles
        assert "role" in results[key].param_profiles

    def test_min_samples_filter(self, builder):
        builder.config.min_samples = 50
        for i in range(10):
            builder.add_sample(make_sample(name=f"User{i}"))

        results = builder.analyze()
        key = "POST /api/users"
        # Should have no profiles — not enough samples
        assert len(results[key].param_profiles) == 0

    def test_export_yaml(self, builder):
        for i in range(100):
            builder.add_sample(make_sample(name=f"User{i}", age=str(i)))

        builder.analyze()

        with tempfile.TemporaryDirectory() as tmpdir:
            written = builder.export_yaml(Path(tmpdir))
            assert len(written) == 1
            assert written[0].suffix == ".yaml"

            content = written[0].read_text()
            assert "/api/users" in content
            assert "name" in content

    def test_location_exclusion(self, builder):
        builder.config.exclude_locations = ["/static/"]
        builder.add_sample(make_sample(location="/static/logo.png"))
        assert len(builder.locations) == 0

    def test_separate_locations(self, builder):
        builder.add_sample(make_sample(location="/api/users", method="GET", q="test"))
        builder.add_sample(make_sample(location="/api/users", method="POST", name="Alice"))

        assert len(builder.locations) == 2
        assert "GET /api/users" in builder.locations
        assert "POST /api/users" in builder.locations
