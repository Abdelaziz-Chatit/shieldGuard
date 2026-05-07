from datetime import datetime
from typing import Optional, Any
from schemas.schemas import APIResponse


def make_response(data: Any = None, error: Optional[str] = None) -> APIResponse:
    """
    Create a standardized API response.
    
    Args:
        data: Response payload (or None)
        error: Error message (or None if success)
    
    Returns:
        APIResponse object
    """
    return APIResponse(
        success=error is None,
        data=data,
        error=error,
        timestamp=datetime.utcnow()
    )
