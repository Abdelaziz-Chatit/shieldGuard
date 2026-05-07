import logging
from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from datetime import datetime
from database.database import get_db
from database.models import User, Alert, AlertType, AlertSeverity, ScanHistory, ScanResult
from core.dependencies import get_current_user
from schemas.schemas import NetworkFeaturesRequest, NetworkResponse
from services.ml_engine import MLEngine
from utils import make_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["network"])


@router.post("/analyze/traffic")
async def analyze_network_traffic(
    network_request: NetworkFeaturesRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyze network traffic for malicious patterns.
    Uses CNN-GRU on first 68 features and Isolation Forest on full 78 features.
    """
    ml_engine: MLEngine = request.app.state.ml_engine
    features_dict = network_request.features
    
    # Extract features for CNN-GRU (first 68 features in order)
    if ml_engine.cnn_gru_scaler is not None:
        # Get the ordered feature names (first 68)
        feature_names_68 = ml_engine.if_features[:68] if ml_engine.if_features else []
        feature_values_68 = [
            features_dict.get(name, 0.0) for name in feature_names_68
        ]
    else:
        feature_values_68 = []
    
    # Predict using CNN-GRU
    cnn_prediction = ml_engine.predict_network_cnn(feature_values_68) if feature_values_68 else {
        "score": 0.0,
        "is_malicious": False,
        "verdict": "UNKNOWN",
        "model_used": "CNN_GRU"
    }
    
    # Predict using Isolation Forest
    if_prediction = ml_engine.predict_anomaly_if(features_dict)
    
    # Combine predictions
    is_malicious = cnn_prediction["is_malicious"] or if_prediction["is_anomaly"]
    score_cnn = cnn_prediction["score"]
    score_if = if_prediction["score"]
    final_score = max(score_cnn, score_if)
    
    # Save to scan history
    combined_model = f"{cnn_prediction['model_used']}+{if_prediction['model_used']}"
    scan_history = ScanHistory(
        user_id=current_user.id,
        model_used=combined_model,
        target="network_traffic",
        result=ScanResult.MALICIOUS if is_malicious else ScanResult.SAFE,
        score=final_score,
        metadata={
            "cnn_score": score_cnn,
            "if_score": score_if,
            "feature_count": len(features_dict)
        }
    )
    db.add(scan_history)
    
    # Create alert if malicious
    if is_malicious:
        if final_score > 0.85:
            severity = AlertSeverity.CRITICAL
        elif final_score > 0.65:
            severity = AlertSeverity.HIGH
        else:
            severity = AlertSeverity.MEDIUM
        
        alert = Alert(
            user_id=current_user.id,
            type=AlertType.NETWORK,
            severity=severity,
            title="Malicious network traffic detected",
            description=f"Potentially malicious network traffic identified (CNN: {score_cnn:.2f}, IF: {score_if:.2f})",
            source="network_traffic",
            score=final_score,
            model_used=combined_model,
            resolved=False
        )
        db.add(alert)
        
        # Broadcast WebSocket event
        if hasattr(request.app.state, 'event_broker'):
            event = {
                "event_type": "NETWORK_ALERT",
                "severity": severity.value,
                "title": "Malicious network traffic detected",
                "description": f"CNN Score: {score_cnn:.2f}, IF Score: {score_if:.2f}",
                "source": "network_traffic",
                "score": final_score,
                "timestamp": datetime.utcnow().isoformat()
            }
            await request.app.state.event_broker.broadcast(event)
        
        logger.warning(f"Malicious network traffic detected by {current_user.username}: CNN={score_cnn:.2f}, IF={score_if:.2f}")
    
    db.commit()
    
    response_data = NetworkResponse(
        score_cnn=score_cnn,
        score_if=score_if,
        is_malicious=is_malicious,
        verdict="MALICIOUS" if is_malicious else "SAFE",
        model_used=combined_model,
        created_at=datetime.utcnow()
    )
    
    return make_response(data=response_data)
