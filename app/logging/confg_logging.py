import logging
import sys

import structlog

from app.utils.utils import add_correlation_id

# --- STEP 1: Configure Standard Logging (The Destination) ---
# This connects the Python logger to your console (stdout)
logging.basicConfig(
    format="%(message)s",
    stream=sys.stdout,
    level=logging.INFO,  # Change to DEBUG if you want to see everything
)

# --- STEP 2: Configure Structlog (The Formatter) ---
structlog.configure(
    processors=[
        # Add the name of the log level (e.g., "info", "error")
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        add_correlation_id,
        # If an exception occurs, add the stack trace
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.JSONRenderer()
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
)

LOGGER = logger = structlog.get_logger()
