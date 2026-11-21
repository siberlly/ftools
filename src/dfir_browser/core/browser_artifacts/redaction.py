from __future__ import annotations

import re
from urllib.parse import urlsplit, urlunsplit

_URL_RE = re.compile(r"(?P<url>[A-Za-z][A-Za-z0-9+.\-]*://[^\s\"'<>]+)")
_SENSITIVE_PARAMS = re.compile(
    r"(?i)(token|key|secret|password|passwd|pwd|session|sid|auth|code|sig)"
)


def redact_url(url: str | None) -> str | None:
    """Strip query and fragment from a URL for application logs.

    Full URLs stay in the forensic database and in the analyst UI. Logs and
    errors use this function so tokens, session ids and form data never reach
    a log file.
    """
    if not url:
        return url
    text = str(url)
    try:
        parts = urlsplit(text)
    except ValueError:
        return "<unparsable-url>"
    if not parts.scheme:
        return text.split("?", 1)[0].split("#", 1)[0]
    netloc = parts.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))


def redact_text(text: str | None) -> str | None:
    """Redact every URL embedded in a free-form log/error string."""
    if not text:
        return text
    return _URL_RE.sub(lambda m: redact_url(m.group("url")) or "", str(text))


def looks_sensitive(url: str | None) -> bool:
    if not url:
        return False
    try:
        query = urlsplit(str(url)).query
    except ValueError:
        return False
    return bool(query and _SENSITIVE_PARAMS.search(query))
