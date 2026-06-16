"""
app/security/audit.py

Structured security-audit logger.

Emits one newline-delimited JSON record per security event to the
"securevault.audit" logger. main.py routes that logger to logs/audit.log
with a %(message)s-only formatter so the file contains pure JSON lines,
separate from the operational app.log.

Usage:
    from app.security.audit import log_event
    log_event("login_success", user_id=1, ip="127.0.0.1")

Fields must never include passwords, decrypted values, or encryption keys.
"""

import json
import logging
from datetime import datetime, timezone

_AUDIT_LOGGER_NAME = "securevault.audit"


def log_event(event: str, **fields: object) -> None:
    """Emit a single structured audit record.

    Args:
        event:    Snake-case event name, e.g. "login_success".
        **fields: Contextual fields — user_id, ip, entry_id, count, etc.
                  Never pass passwords, keys, or decrypted field values.
    """
    record: dict[str, object] = {
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "event": event,
        **fields,
    }
    logging.getLogger(_AUDIT_LOGGER_NAME).info(json.dumps(record, default=str))
