"""
app/utils/helpers.py

Shared utility functions used across route handlers.

Kept deliberately minimal — only functions that are either duplicated across
multiple modules or are certain to be needed by future routes belong here.
"""

from datetime import datetime, timezone

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


def utcnow() -> datetime:
    """Return the current UTC datetime with timezone info.

    Use this wherever a "now" timestamp is needed so callers never have to
    import ``datetime`` and ``timezone`` themselves, and so the function can
    be passed directly as a SQLAlchemy ``default=`` / ``onupdate=`` callable
    without a wrapper lambda.

    Example (ORM model)::

        from app.utils.helpers import utcnow

        created_at = mapped_column(DateTime(timezone=True), default=utcnow)
        updated_at = mapped_column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)
    """
    return datetime.now(timezone.utc)


def format_datetime(dt: datetime | None, fmt: str = "%b %d, %Y") -> str:
    """Format a datetime object to a human-readable string.

    Defaults to ``"May 19, 2026"`` style (``%b %d, %Y``). Returns an empty
    string when *dt* is ``None`` so templates never crash on a missing
    timestamp.

    Args:
        dt:  A timezone-aware or naive datetime, or ``None``.
        fmt: A :func:`~datetime.datetime.strftime` format string.

    Returns:
        Formatted date string, or ``""`` if *dt* is ``None``.

    Example::

        format_datetime(entry.created_at)          # "May 19, 2026"
        format_datetime(entry.created_at, "%Y-%m") # "2026-05"
        format_datetime(None)                      # ""
    """
    if dt is None:
        return ""
    return dt.strftime(fmt)


def truncate(text: str | None, max_length: int = 50) -> str:
    """Truncate a string to *max_length* characters, appending ``"..."`` if cut.

    Returns an empty string when *text* is ``None`` so callers never need a
    separate ``or ""`` guard. The ``"..."`` suffix counts against
    *max_length* — the returned string is always ``<= max_length + 3`` chars,
    which keeps table columns predictable.

    Args:
        text:       The string to truncate, or ``None``.
        max_length: Maximum number of characters before truncation (default 50).

    Returns:
        Original string if within limit, truncated string with ``"..."``
        appended, or ``""`` if *text* is ``None``.

    Example::

        truncate("GitHub personal token")        # "GitHub personal token"  (short)
        truncate("A very long title …", 10)      # "A very lon..."
        truncate(None)                           # ""
    """
    if text is None:
        return ""
    return text if len(text) <= max_length else text[:max_length] + "..."
