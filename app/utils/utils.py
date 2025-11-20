import uuid
from asgi_correlation_id.context import correlation_id

def create_user_id() -> str:
    """Create a UUID based on the user's email."""
    return uuid.uuid4().hex

# 2. Configure Structlog (The "Formatter")
def add_correlation_id(logger, method_name, event_dict):
    request_id = correlation_id.get()
    if request_id:
        event_dict["correlation_id"] = request_id
    return event_dict