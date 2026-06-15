"""
app/tests/test_helpers.py

Unit tests for app/utils/helpers.py.

Covers all three utility functions:
  - none_if_empty : None, empty string, whitespace-only, normal string
  - format_datetime: None input, valid datetime with default and custom format
  - truncate       : None input, short string, long string, exact boundary
"""

from datetime import datetime, timezone

import pytest

from app.utils.helpers import first_validation_error, format_datetime, none_if_empty, truncate


class TestNoneIfEmpty:
    def test_none_input_returns_none(self):
        assert none_if_empty(None) is None

    def test_empty_string_returns_none(self):
        assert none_if_empty("") is None

    def test_whitespace_only_returns_none(self):
        assert none_if_empty("   ") is None

    def test_normal_string_returns_stripped(self):
        assert none_if_empty("  github  ") == "github"

    def test_non_whitespace_string_unchanged(self):
        assert none_if_empty("example.com") == "example.com"


class TestFormatDatetime:
    def test_none_returns_empty_string(self):
        assert format_datetime(None) == ""

    def test_valid_datetime_default_format(self):
        dt = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        assert format_datetime(dt) == "Jun 15, 2024"

    def test_valid_datetime_custom_format(self):
        dt = datetime(2024, 6, 15, tzinfo=timezone.utc)
        assert format_datetime(dt, "%Y-%m-%d") == "2024-06-15"

    def test_naive_datetime_formats(self):
        dt = datetime(2025, 1, 1)
        result = format_datetime(dt)
        assert result == "Jan 01, 2025"


class TestTruncate:
    def test_none_returns_empty_string(self):
        assert truncate(None) == ""

    def test_short_string_unchanged(self):
        assert truncate("hello") == "hello"

    def test_string_at_exact_limit_unchanged(self):
        text = "a" * 50
        assert truncate(text) == text

    def test_long_string_truncated_with_ellipsis(self):
        text = "a" * 60
        result = truncate(text)
        assert result == "a" * 50 + "..."

    def test_custom_max_length(self):
        result = truncate("Hello world", max_length=5)
        assert result == "Hello..."

    def test_empty_string_stays_empty(self):
        assert truncate("") == ""
