import logging
import math
from fastapi import APIRouter, Depends, Request, UploadFile, File
from sqlalchemy.orm import Session
from datetime import datetime
from database.database import get_db
from database.models import User, Alert, AlertType, AlertSeverity, ScanHistory, ScanResult
from core.dependencies import get_current_user
from schemas.schemas import FileResponse
from services.ml_engine import MLEngine
from services.signature_engine import SignatureEngine
from utils import make_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["file"])

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB


@router.post("/analyze/file")
async def analyze_file(
    file: UploadFile = File(...),
    request: Request = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Analyze a file for malware using signature database and Isolation Forest.
    """
    ml_engine: MLEngine = request.app.state.ml_engine
    signature_engine: SignatureEngine = request.app.state.signature_engine
    
    # Read file content
    file_content = await file.read()
    
    if len(file_content) > MAX_FILE_SIZE:
        return make_response(
            data=None,
            error=f"File size exceeds {MAX_FILE_SIZE / (1024*1024):.0f}MB limit"
        )
    
    # Check signature database
    signature_check = signature_engine.check_file(file_content)
    
    verdict = "SAFE"
    score_if = 0.0
    blacklist_match = None
    
    if signature_check["found"]:
        # Found in blacklist - definitely malicious
        verdict = "MALICIOUS"
        score_if = 1.0
        blacklist_match = {
            "name": signature_check["name"],
            "severity": signature_check["severity"],
            "category": signature_check["category"],
            "source": signature_check["source"]
        }
        
        # Create alert
        alert = Alert(
            user_id=current_user.id,
            type=AlertType.FILE,
            severity=AlertSeverity.CRITICAL,
            title=f"Known malware detected: {signature_check['name']}",
            description=f"SHA-256: {signature_check['sha256']}, Category: {signature_check['category']}",
            source=file.filename,
            score=1.0,
            model_used="SIGNATURE",
            resolved=False
        )
        db.add(alert)
        
        logger.warning(f"Known malware detected by {current_user.username}: {file.filename}")
    else:
        # Not in blacklist - use behavioral features and Isolation Forest
        features_dict = _extract_file_features(file_content, file.filename)
        if_prediction = ml_engine.predict_anomaly_if(features_dict)
        score_if = if_prediction["score"]
        
        if if_prediction["is_anomaly"]:
            if score_if > 0.8:
                verdict = "MALICIOUS"
            else:
                verdict = "SUSPICIOUS"
        else:
            verdict = "SAFE"
        
        # Create alert if suspicious/malicious
        if verdict != "SAFE":
            severity = AlertSeverity.HIGH if verdict == "MALICIOUS" else AlertSeverity.MEDIUM
            alert = Alert(
                user_id=current_user.id,
                type=AlertType.FILE,
                severity=severity,
                title=f"Suspicious file detected: {file.filename}",
                description=f"File shows anomalous characteristics (Isolation Forest score: {score_if:.2f})",
                source=file.filename,
                score=score_if,
                model_used="ISOLATION_FOREST",
                resolved=False
            )
            db.add(alert)
            
            logger.warning(f"Suspicious file detected by {current_user.username}: {file.filename} (score: {score_if:.2f})")
    
    # Save to scan history
    scan_history = ScanHistory(
        user_id=current_user.id,
        model_used="SIGNATURE" if signature_check["found"] else "ISOLATION_FOREST",
        target=file.filename,
        result=ScanResult.MALICIOUS if verdict == "MALICIOUS" else (ScanResult.ANOMALY if verdict == "SUSPICIOUS" else ScanResult.SAFE),
        score=score_if if score_if > 0 else (1.0 if signature_check["found"] else 0.0),
        metadata={
            "filename": file.filename,
            "size_bytes": len(file_content),
            "sha256": signature_check["sha256"]
        }
    )
    db.add(scan_history)
    db.commit()
    
    # Broadcast WebSocket event if alert created
    if verdict != "SAFE" and hasattr(request.app.state, 'event_broker'):
        severity = AlertSeverity.CRITICAL if signature_check["found"] else (AlertSeverity.HIGH if verdict == "MALICIOUS" else AlertSeverity.MEDIUM)
        event = {
            "event_type": "FILE_ALERT",
            "severity": severity.value,
            "title": f"Suspicious file detected: {file.filename}",
            "description": f"Score: {score_if:.2f}" if not signature_check["found"] else f"Known malware: {signature_check['name']}",
            "source": file.filename,
            "score": score_if if score_if > 0 else 1.0,
            "timestamp": datetime.utcnow().isoformat()
        }
        await request.app.state.event_broker.broadcast(event)
    
    response_data = FileResponse(
        filename=file.filename,
        sha256=signature_check["sha256"],
        size_bytes=len(file_content),
        found_in_blacklist=signature_check["found"],
        blacklist_match=blacklist_match,
        score_if=score_if if not signature_check["found"] else 1.0,
        verdict=verdict,
        created_at=datetime.utcnow()
    )
    
    return make_response(data=response_data)


def _extract_file_features(file_content: bytes, filename: str) -> dict:
    """
    Extract basic behavioral features from file for IF model.
    Returns a dict of features that can be used with Isolation Forest.
    """
    features = {}
    
    # File size
    features["file_size"] = float(len(file_content))
    
    # Entropy
    entropy = _calculate_entropy(file_content)
    features["entropy"] = float(entropy)
    
    # Is executable (check extension and PE header)
    executable_extensions = {".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".msi", ".scr", ".com"}
    file_ext = filename[filename.rfind("."):].lower() if "." in filename else ""
    features["is_executable"] = 1.0 if file_ext in executable_extensions else 0.0
    
    # PE header check
    features["has_pe_header"] = 1.0 if file_content.startswith(b'MZ') else 0.0
    
    # Ratio of null bytes
    null_byte_count = file_content.count(b'\x00')
    features["null_byte_ratio"] = float(null_byte_count) / max(len(file_content), 1)
    
    # High entropy sections might indicate packing
    features["high_entropy_indicator"] = 1.0 if entropy > 7.0 else 0.0
    
    return features


def _calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.
    High entropy (>7) often indicates compression or encryption.
    """
    if not data:
        return 0.0
    
    # Count byte frequencies
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts.values():
        if count > 0:
            p = count / data_len
            entropy -= p * math.log2(p)
    
    return entropy
