"""Tests for the type inference engine."""

import pytest
from waffy_learn.analyzer import TypeInferrer, ParamType, is_freetext_field


@pytest.fixture
def inferrer():
    return TypeInferrer(confidence=0.95, enum_max_cardinality=50)


class TestTypeDetection:
    def test_integer_detection(self, inferrer):
        values = [str(i) for i in range(200)]
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        assert profile.inferred_type == ParamType.INTEGER

    def test_uuid_detection(self, inferrer):
        import uuid
        values = [str(uuid.uuid4()) for _ in range(200)]
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        assert profile.inferred_type == ParamType.UUID

    def test_email_detection(self, inferrer):
        values = [f"user{i}@example.com" for i in range(200)]
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        assert profile.inferred_type == ParamType.EMAIL

    def test_enum_detection(self, inferrer):
        values = ["admin"] * 50 + ["user"] * 100 + ["editor"] * 50
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        assert profile.inferred_type == ParamType.ENUM
        assert set(profile.constraints.enum_values) == {"admin", "user", "editor"}

    def test_boolean_detection(self, inferrer):
        values = ["true", "false"] * 100
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        # With only 2 unique values, should be detected as enum
        assert profile.inferred_type == ParamType.ENUM

    def test_ipv4_detection(self, inferrer):
        values = [f"192.168.1.{i}" for i in range(200)]
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        assert profile.inferred_type == ParamType.IPV4

    def test_string_fallback(self, inferrer):
        values = [f"mixed-{i}-value_{'x' * (i % 10)}" for i in range(200)]
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        assert profile.inferred_type == ParamType.STRING
        assert profile.constraints.regex is not None


class TestConstraints:
    def test_required_detection(self, inferrer):
        values = ["test"] * 200
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        assert profile.required is True

    def test_optional_detection(self, inferrer):
        values = ["test"] * 50
        profile = inferrer.infer(values, total_requests=200, present_count=50)
        assert profile.required is False

    def test_integer_range(self, inferrer):
        values = [str(i) for i in range(1, 201)]
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        assert profile.constraints.min_value is not None
        assert profile.constraints.max_value is not None
        assert profile.constraints.min_value >= 1
        assert profile.constraints.max_value <= 200

    def test_length_bounds(self, inferrer):
        values = ["a" * i for i in range(5, 55)]
        profile = inferrer.infer(values, total_requests=200, present_count=50)
        assert profile.constraints.min_length >= 5
        assert profile.constraints.max_length <= 54


class TestFreetext:
    def test_freetext_detection(self, inferrer):
        values = [f"Hello world! This is a <b>test</b> #{i}" for i in range(200)]
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        profile.name = "comment"
        profile.source = "body"
        assert is_freetext_field(profile) is True

    def test_non_freetext(self, inferrer):
        values = [f"user-{i:04d}" for i in range(200)]
        profile = inferrer.infer(values, total_requests=200, present_count=200)
        profile.name = "user_id"
        profile.source = "body"
        assert is_freetext_field(profile) is False
