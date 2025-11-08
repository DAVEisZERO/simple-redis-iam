import uuid

def create_user_id() -> str:
    """Create a UUID based on the user's email."""
    return uuid.uuid4().hex