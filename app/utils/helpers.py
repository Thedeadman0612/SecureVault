"""
app/utils/helpers.py

Shared utility functions used across route handlers.

Kept deliberately minimal — only functions that are either duplicated across
multiple modules or are certain to be needed by future routes belong here.
"""

from pydantic import ValidationError


def first_validation_error(exc: ValidationError) -> str:
    """Extract the first human-readable message from a Pydantic ValidationError.

    Pydantic v2 prefixes field-validator and model-validator messages raised
    via ValueError with "Value error, ". This helper strips that prefix so
    templates receive a clean, user-facing string.

    Args:
        exc: A Pydantic ValidationError caught in a route handler.

    Returns:
        The first error message with any "Value error, " prefix removed.

    Example:
        "Value error, Passwords do not match." → "Passwords do not match."
        "Field required"                        → "Field required"
    """
    msg: str = exc.errors()[0]["msg"]
    if msg.startswith("Value error, "):
        msg = msg[len("Value error, "):]
    return msg


def none_if_empty(value: str | None) -> str | None:
    """Convert a blank or whitespace-only string to None.

    HTML forms submit unedited optional fields as empty strings, not None.
    This helper normalises them so service-layer schemas treat untouched
    fields as "no change" rather than "set to empty string".

    Args:
        value: A string from a form field, or None.

    Returns:
        None if value is None, empty, or whitespace-only; otherwise the
        original string stripped of leading/trailing whitespace.

    Example:
        ""        → None
        "  "      → None
        " github" → "github"
        None      → None
    """
    if value is None:
        return None
    return value.strip() or None
