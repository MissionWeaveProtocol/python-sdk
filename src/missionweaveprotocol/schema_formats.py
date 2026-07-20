"""Shared JSON Schema format-checker configuration."""

from __future__ import annotations

import re

from jsonschema import FormatChecker
from jsonschema.exceptions import FormatError

_STANDARD_FORMAT_CHECKER = FormatChecker()
_MALFORMED_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def protocol_format_checker() -> FormatChecker:
    """Return the standards checker with strict URI percent escapes."""

    checker = FormatChecker()
    checker.checks("uri")(_strict_uri)
    return checker


def _strict_uri(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        _STANDARD_FORMAT_CHECKER.check(value, "uri")
    except FormatError:
        return False
    return _MALFORMED_PERCENT_ESCAPE.search(value) is None
