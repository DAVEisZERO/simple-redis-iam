import uuid
from asgi_correlation_id.context import correlation_id

"""
################################################################################
###                                   DOCS                                   ###
################################################################################

Utilities Module
------------------
Provides helper functions for UUID generation and distributed tracing via
correlation IDs. Integrates with structlog for enhanced logging capabilities.

Functions:
    create_user_id: Generates a unique user identifier using UUID4.
        Returns: str (hexadecimal UUID without hyphens)
        
    add_correlation_id: Structlog processor that injects correlation ID into logs.
        Input: logger (Logger), method_name (str), event_dict (dict)
        Returns: dict (event_dict with correlation_id field added if available)
        Usage: Used by structlog to track requests across distributed systems.

################################################################################
"""

def create_user_id() -> str:
    """Create a UUID based on the user's email."""
    return uuid.uuid4().hex

# 2. Configure Structlog (The "Formatter")
def add_correlation_id(logger, method_name, event_dict):
    request_id = correlation_id.get()
    if request_id:
        event_dict["correlation_id"] = request_id
    return event_dict