import logging
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from datetime import datetime
from database.database import get_db
from database.models import User, Whitelist, WhitelistType, Alert, AlertType, AlertSeverity, ScanHistory, ScanResult
from core.dependencies import get_current_user
from schemas.schemas import URLRequest, URLResponse
from services.ml_engine import MLEngine
from utils import make_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["url"])


@router.post("/analyze/url")
async def analyze_url(
    url_request: URLRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyze a URL for phishing using Char-CNN model.
    """
    url = url_request.url
    ml_engine: MLEngine = request.app.state.ml_engine
    
    # Check whitelist
    whitelist_entry = db.query(Whitelist).filter(
        Whitelist.type == WhitelistType.URL,
        Whitelist.value == url
    ).first()
    
    if whitelist_entry:
        # Return safe response for whitelisted URL
        response_data = URLResponse(
            url=url,
            score=0.0,
            is_phishing=False,
            verdict="SAFE",
            model_used="WHITELIST",
            cached=True,
            created_at=datetime.utcnow()
        )
        return make_response(data=response_data)
    
    # Predict using ML engine
    prediction = ml_engine.predict_url(url)
    
    # Save to scan history
    scan_history = ScanHistory(
        user_id=current_user.id,
        model_used=prediction["model_used"],
        target=url,
        result=ScanResult.MALICIOUS if prediction["is_phishing"] else ScanResult.SAFE,
        score=prediction["score"],
        metadata={"url": url}
    )
    db.add(scan_history)
    
    # Create alert if phishing detected
    if prediction["is_phishing"]:
        severity = AlertSeverity.HIGH if prediction["score"] > 0.7 else AlertSeverity.MEDIUM
        alert = Alert(
            user_id=current_user.id,
            type=AlertType.URL,
            severity=severity,
            title=f"Phishing URL detected",
            description=f"Potential phishing link: {url}",
            source=url,
            score=prediction["score"],
            model_used=prediction["model_used"],
            resolved=False
        )
        db.add(alert)
        
        # Broadcast WebSocket event
        if hasattr(request.app.state, 'event_broker'):
            event = {
                "event_type": "URL_ALERT",
                "severity": severity.value,
                "title": f"Phishing URL detected",
                "description": f"URL: {url}",
                "source": url,
                "score": prediction["score"],
                "timestamp": datetime.utcnow().isoformat()
            }
            await request.app.state.event_broker.broadcast(event)
        
        logger.warning(f"Phishing URL detected by {current_user.username}: {url}")
    
    db.commit()
    
    response_data = URLResponse(
        url=url,
        score=prediction["score"],
        is_phishing=prediction["is_phishing"],
        verdict=prediction["verdict"],
        model_used=prediction["model_used"],
        cached=False,
        created_at=datetime.utcnow()
    )
    
    return make_response(data=response_data)
