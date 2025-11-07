import uuid

def create_user_id() -> uuid.UUID:
    """Create a UUID based on the user's email."""
    return uuid.uuid4()