import logging
from fastapi import APIRouter, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Query, Request
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from database.database import get_db
from database.models import User, Alert, UserRole, AlertSeverity
from core.dependencies import get_current_user, require_admin
from schemas.schemas import AlertResponse, AlertListResponse, AlertResolveRequest
from utils import make_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["alerts"])


@router.get("/alerts")
async def list_alerts(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    severity: str = Query(None),
    type_: str = Query(None, alias="type"),
    resolved: bool = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List alerts with pagination and optional filtering.
    Admin sees all alerts, users see only their own.
    """
    query = db.query(Alert)
    
    # Filter by user (unless admin)
    if current_user.role != UserRole.ADMIN:
        query = query.filter(Alert.user_id == current_user.id)
    
    # Apply optional filters
    if severity:
        query = query.filter(Alert.severity == severity)
    
    if type_:
        query = query.filter(Alert.type == type_)
    
    if resolved is not None:
        query = query.filter(Alert.resolved == resolved)
    
    # Get total count
    total = query.count()
    
    # Paginate
    offset = (page - 1) * limit
    alerts = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
    
    alert_responses = [AlertResponse.model_validate(alert) for alert in alerts]
    
    response_data = AlertListResponse(
        alerts=alert_responses,
        total=total,
        page=page,
        limit=limit
    )
    
    return make_response(data=response_data)


@router.get("/alerts/{alert_id}")
async def get_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get a specific alert.
    Users can only access their own; admin can access all.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    # Check authorization
    if current_user.role != UserRole.ADMIN and alert.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to access this alert"
        )
    
    alert_response = AlertResponse.model_validate(alert)
    return make_response(data=alert_response)


@router.put("/alerts/{alert_id}/resolve")
async def resolve_alert(
    alert_id: int,
    resolve_request: AlertResolveRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Mark an alert as resolved.
    Users can resolve their own; admin can resolve any.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    # Check authorization
    if current_user.role != UserRole.ADMIN and alert.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to resolve this alert"
        )
    
    # Update alert
    alert.resolved = True
    alert.resolved_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    
    logger.info(f"Alert {alert_id} resolved by {current_user.username}")
    
    alert_response = AlertResponse.model_validate(alert)
    return make_response(data=alert_response)


@router.delete("/alerts/{alert_id}")
async def delete_alert(
    alert_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Delete an alert.
    Admin only.
    """
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    db.delete(alert)
    db.commit()
    
    logger.info(f"Alert {alert_id} deleted by {current_user.username}")
    
    return make_response(data=None)


@router.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket, request: Request):
    """
    WebSocket endpoint for real-time alert streaming.
    No authentication required (Electron connects locally).
    """
    event_broker = request.app.state.event_broker
    
    await event_broker.connect(websocket)
    logger.info("WebSocket client connected")
    
    try:
        while True:
            # Keep connection alive
            # Client should receive broadcasts from event_broker
            await websocket.receive_text()
    except WebSocketDisconnect:
        event_broker.disconnect(websocket)
        logger.info("WebSocket client disconnected")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        event_broker.disconnect(websocket)
