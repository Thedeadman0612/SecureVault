"""
app/templates_config.py

Single shared Jinja2Templates instance used by all route modules.

Having one instance means:
  - env.globals and env.filters set here apply to every template rendered by
    any router — not just the one that happened to construct its own instance.
  - The template directory is an absolute path resolved relative to this file,
    so the app works regardless of which directory uvicorn is started from.

Import pattern in route modules:
    from app.templates_config import templates
"""

from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.config.settings import settings
from app.utils.helpers import format_datetime, truncate

# Absolute path: this file lives at app/templates_config.py, so
# Path(__file__).parent == app/ and the templates dir is app/templates/.
_TEMPLATES_DIR = Path(__file__).parent / "templates"

templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))

# Global function available as {{ format_datetime(dt) }} in every template.
templates.env.globals["format_datetime"] = format_datetime

# Filter available as {{ text | truncate_str }} in every template.
templates.env.filters["truncate_str"] = truncate

# Session timeout in seconds — read by session_timeout.js via <meta name="sv-timeout">.
templates.env.globals["session_timeout_seconds"] = settings.SESSION_TIMEOUT_MINUTES * 60
