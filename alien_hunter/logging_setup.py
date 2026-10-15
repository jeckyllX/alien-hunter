"""
Centralized logging configuration for Alien Hunter.

Exposes a single shared stdlib logger so defensive packet parsers can surface
diagnostic detail (raw-socket permission failures, interface teardown,
malformed frames) without changing default console verbosity.

Default level is WARNING so normal operation stays quiet. The ``--debug`` CLI
flag raises the shared logger to DEBUG, emitting the exceptions that defensive
``except Exception`` blocks would otherwise swallow.
"""

import logging
import sys

# Canonical logger name shared by every module via logging.getLogger(LOGGER_NAME).
LOGGER_NAME = "alien_hunter"

_configured = False


def get_logger(name: str = LOGGER_NAME) -> logging.Logger:
    """Returns the shared Alien Hunter logger (or a named child logger)."""
    return logging.getLogger(name)


def configure(debug: bool = False) -> logging.Logger:
    """
    Configures the shared logger and returns it.

    Idempotently installs a single stderr handler and sets the level to DEBUG
    when ``debug`` is set, otherwise WARNING. Safe to call multiple times.
    """
    global _configured
    level = logging.DEBUG if debug else logging.WARNING
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)

    if not _configured:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
        logger.addHandler(handler)
        # Own the output; do not double-emit through the root logger.
        logger.propagate = False
        _configured = True

    for handler in logger.handlers:
        handler.setLevel(level)

    return logger
