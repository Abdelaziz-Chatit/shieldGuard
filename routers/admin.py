import logging
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Query, Request
from sqlalchemy.orm import Session
from sqlalchemy import func
from datetime import datetime, timedelta
from database.database import get_db
from database.models import User, Alert, ScanHistory, AlertSeverity, Whitelist, SystemConfig, UserRole
from core.dependencies import require_admin
from schemas.schemas import (
    StatsResponse, ModelStatusResponse, UserListResponse, UserResponse,
    SignatureCreate, SignatureResponse, WhitelistCreate, WhitelistResponse,
    ConfigUpdate, BulkImportResponse
)
from services.ml_engine import MLEngine
from services.signature_engine import SignatureEngine
from utils import make_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin", tags=["admin"])


@router.get("/stats")
async def get_stats(
    current_user: User = Depends(require_admin),
    request: Request = None,
    db: Session = Depends(get_db)
):
    """
    Get system statistics and health information.
    """
    ml_engine: MLEngine = request.app.state.ml_engine
    
    # Get today's date (UTC)
    today = datetime.utcnow().date()
    today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    
    # Total alerts
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    
    # Alerts created today
    alerts_today = db.query(func.count(Alert.id)).filter(
        Alert.created_at >= today_start
    ).scalar() or 0
    
    # Alerts by severity
    by_severity = {}
    severity_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    for severity, count in severity_counts:
        by_severity[severity.value if hasattr(severity, 'value') else str(severity)] = count
    
    # Alerts by type
    by_type = {}
    type_counts = db.query(Alert.type, func.count(Alert.id)).group_by(Alert.type).all()
    for alert_type, count in type_counts:
        by_type[alert_type.value if hasattr(alert_type, 'value') else str(alert_type)] = count
    
    # Total scans
    total_scans = db.query(func.count(ScanHistory.id)).scalar() or 0
    
    # Scans today
    scans_today = db.query(func.count(ScanHistory.id)).filter(
        ScanHistory.created_at >= today_start
    ).scalar() or 0
    
    # Threats blocked (unresolved HIGH/CRITICAL alerts)
    threats_blocked = db.query(func.count(Alert.id)).filter(
        Alert.resolved == False,
        Alert.severity.in_([AlertSeverity.HIGH, AlertSeverity.CRITICAL])
    ).scalar() or 0
    
    # Model status
    model_status = ml_engine.get_status()
    model_status_response = ModelStatusResponse(
        cnn_gru_loaded=model_status["cnn_gru_loaded"],
        char_cnn_loaded=model_status["char_cnn_loaded"],
        if_loaded=model_status["if_loaded"],
        errors=model_status["errors"]
    )
    
    response_data = StatsResponse(
        total_alerts=total_alerts,
        alerts_today=alerts_today,
        by_severity=by_severity,
        by_type=by_type,
        total_scans=total_scans,
        scans_today=scans_today,
        threats_blocked=threats_blocked,
        model_status=model_status_response
    )
    
    return make_response(data=response_data)


@router.get("/users")
async def list_users(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    List all users with pagination.
    """
    query = db.query(User)
    total = query.count()
    
    offset = (page - 1) * limit
    users = query.order_by(User.created_at.desc()).offset(offset).limit(limit).all()
    
    user_responses = [UserResponse.model_validate(user) for user in users]
    
    response_data = UserListResponse(
        users=user_responses,
        total=total
    )
    
    return make_response(data=response_data)


@router.put("/users/{user_id}")
async def update_user(
    user_id: int,
    update_data: dict,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Update user role or active status.
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update fields
    if "role" in update_data:
        user.role = update_data["role"]
    if "is_active" in update_data:
        user.is_active = update_data["is_active"]
    
    db.commit()
    db.refresh(user)
    
    logger.info(f"User {user_id} updated by {current_user.username}")
    
    user_response = UserResponse.model_validate(user)
    return make_response(data=user_response)


@router.get("/signatures")
async def list_signatures(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: str = Query(None),
    current_user: User = Depends(require_admin),
    request: Request = None
):
    """
    List signatures with pagination and optional search.
    """
    signature_engine: SignatureEngine = request.app.state.signature_engine
    
    result = signature_engine.list_signatures(page=page, limit=limit, search=search)
    
    signatures = [
        SignatureResponse(
            sha256=sig["sha256"],
            name=sig["name"],
            severity=sig["severity"],
            category=sig["category"],
            source=sig["source"],
            added_at=datetime.fromisoformat(sig["added_at"]) if isinstance(sig["added_at"], str) else sig["added_at"]
        )
        for sig in result["signatures"]
    ]
    
    return make_response(data={
        "signatures": signatures,
        "total": result["total"],
        "page": page,
        "limit": limit
    })


@router.post("/signatures")
async def create_signature(
    sig_create: SignatureCreate,
    current_user: User = Depends(require_admin),
    request: Request = None
):
    """
    Add a single signature to the database.
    """
    signature_engine: SignatureEngine = request.app.state.signature_engine
    
    success = signature_engine.add_signature(
        sha256=sig_create.sha256,
        name=sig_create.name,
        severity=sig_create.severity,
        category=sig_create.category,
        source=sig_create.source
    )
    
    if not success:
        return make_response(
            data=None,
            error="Signature already exists or failed to add"
        )
    
    logger.info(f"Signature added by {current_user.username}: {sig_create.name}")
    
    response_data = SignatureResponse(
        sha256=sig_create.sha256,
        name=sig_create.name,
        severity=sig_create.severity,
        category=sig_create.category,
        source=sig_create.source,
        added_at=datetime.utcnow()
    )
    
    return make_response(data=response_data)


@router.post("/signatures/import")
async def import_signatures(
    file: UploadFile = File(...),
    current_user: User = Depends(require_admin),
    request: Request = None
):
    """
    Bulk import signatures from CSV file.
    """
    signature_engine: SignatureEngine = request.app.state.signature_engine
    
    # Read CSV content
    csv_content = (await file.read()).decode('utf-8')
    
    # Import
    result = signature_engine.bulk_import_csv(csv_content)
    
    logger.info(f"Signatures imported by {current_user.username}: {result['imported']} imported, {result['skipped']} skipped")
    
    response_data = BulkImportResponse(
        imported=result["imported"],
        skipped=result["skipped"],
        errors=result["errors"]
    )
    
    return make_response(data=response_data)


@router.delete("/signatures/{sha256}")
async def delete_signature(
    sha256: str,
    current_user: User = Depends(require_admin),
    request: Request = None
):
    """
    Delete a signature from the database.
    """
    signature_engine: SignatureEngine = request.app.state.signature_engine
    
    success = signature_engine.delete_signature(sha256)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Signature not found"
        )
    
    logger.info(f"Signature deleted by {current_user.username}: {sha256}")
    
    return make_response(data=None)


@router.get("/whitelist")
async def list_whitelist(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    List whitelist entries with pagination.
    """
    query = db.query(Whitelist)
    total = query.count()
    
    offset = (page - 1) * limit
    entries = query.order_by(Whitelist.created_at.desc()).offset(offset).limit(limit).all()
    
    whitelist_responses = [WhitelistResponse.model_validate(entry) for entry in entries]
    
    return make_response(data={
        "whitelist": whitelist_responses,
        "total": total,
        "page": page,
        "limit": limit
    })


@router.post("/whitelist")
async def create_whitelist(
    whitelist_create: WhitelistCreate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Add an entry to the whitelist.
    """
    whitelist = Whitelist(
        type=whitelist_create.type,
        value=whitelist_create.value,
        added_by=current_user.id
    )
    
    db.add(whitelist)
    db.commit()
    db.refresh(whitelist)
    
    logger.info(f"Whitelist entry added by {current_user.username}: {whitelist_create.type}={whitelist_create.value}")
    
    whitelist_response = WhitelistResponse.model_validate(whitelist)
    return make_response(data=whitelist_response)


@router.delete("/whitelist/{whitelist_id}")
async def delete_whitelist(
    whitelist_id: int,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Delete a whitelist entry.
    """
    entry = db.query(Whitelist).filter(Whitelist.id == whitelist_id).first()
    
    if not entry:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Whitelist entry not found"
        )
    
    db.delete(entry)
    db.commit()
    
    logger.info(f"Whitelist entry deleted by {current_user.username}: {entry.type}={entry.value}")
    
    return make_response(data=None)


@router.get("/config")
async def get_config(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Get all system configuration values.
    """
    configs = db.query(SystemConfig).all()
    config_dict = {config.key: config.value for config in configs}
    
    return make_response(data=config_dict)


@router.put("/config")
async def update_config(
    config_update: ConfigUpdate,
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """
    Update a system configuration value.
    """
    config = db.query(SystemConfig).filter(SystemConfig.key == config_update.key).first()
    
    if not config:
        config = SystemConfig(key=config_update.key)
        db.add(config)
    
    config.value = config_update.value
    config.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(config)
    
    logger.info(f"Config updated by {current_user.username}: {config_update.key}")
    
    return make_response(data={
        "key": config.key,
        "value": config.value,
        "updated_at": config.updated_at
    })
