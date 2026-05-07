# ShieldGuard API Quick Reference

## Authentication

All endpoints require JWT Bearer token except:
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `GET /health`
- `WebSocket /ws/events` (unauthenticated for Electron)

### Get Token
```bash
curl -X POST http://localhost:8765/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"ShieldGuard2026!"}'
```

Use token as:
```bash
curl -H "Authorization: Bearer <token>" ...
```

## Analysis Endpoints

### URL Analysis
```bash
POST /api/v1/analyze/url
Content-Type: application/json
Authorization: Bearer <token>

{
  "url": "https://example.com"
}

Response:
{
  "success": true,
  "data": {
    "url": "https://example.com",
    "score": 0.35,
    "is_phishing": false,
    "verdict": "SAFE",
    "model_used": "CHAR_CNN",
    "cached": false,
    "created_at": "2026-05-07T10:00:00"
  },
  "error": null,
  "timestamp": "2026-05-07T10:00:00"
}
```

### Network Analysis
```bash
POST /api/v1/analyze/traffic
Content-Type: application/json
Authorization: Bearer <token>

{
  "features": {
    "Destination Port": 443,
    "Protocol": 6,
    "Flow Duration": 1000,
    ...up to 78 CICIDS2017 features
  }
}

Response:
{
  "success": true,
  "data": {
    "score_cnn": 0.45,
    "score_if": 0.52,
    "is_malicious": false,
    "verdict": "SAFE",
    "model_used": "CNN_GRU+ISOLATION_FOREST",
    "created_at": "2026-05-07T10:00:00"
  }
}
```

### File Analysis
```bash
POST /api/v1/analyze/file
Content-Type: multipart/form-data
Authorization: Bearer <token>

file: <binary file content>

Response:
{
  "success": true,
  "data": {
    "filename": "document.exe",
    "sha256": "abc123...",
    "size_bytes": 102400,
    "found_in_blacklist": false,
    "blacklist_match": null,
    "score_if": 0.62,
    "verdict": "MALICIOUS",
    "created_at": "2026-05-07T10:00:00"
  }
}
```

## Alert Management

### List Alerts
```bash
GET /api/v1/alerts?page=1&limit=20&severity=HIGH&resolved=false
Authorization: Bearer <token>

Response: AlertListResponse with pagination
```

### Resolve Alert
```bash
PUT /api/v1/alerts/{id}/resolve
Content-Type: application/json
Authorization: Bearer <token>

{
  "notes": "False positive - whitelisting URL"
}
```

## Admin Endpoints

### System Statistics
```bash
GET /api/v1/admin/stats
Authorization: Bearer <admin_token>
```

### User Management
```bash
GET /api/v1/admin/users?page=1&limit=20
PUT /api/v1/admin/users/{id}
{
  "role": "admin",
  "is_active": true
}
```

### Signature Management
```bash
GET /api/v1/admin/signatures?page=1&limit=20&search=
POST /api/v1/admin/signatures
{
  "sha256": "abc123...",
  "name": "Trojan.Generic",
  "severity": "HIGH",
  "category": "trojan",
  "source": "VirusTotal"
}
POST /api/v1/admin/signatures/import (multipart CSV)
DELETE /api/v1/admin/signatures/{sha256}
```

### Whitelist Management
```bash
GET /api/v1/admin/whitelist
POST /api/v1/admin/whitelist
{
  "type": "url",
  "value": "https://trusted-site.com"
}
DELETE /api/v1/admin/whitelist/{id}
```

### Configuration
```bash
GET /api/v1/admin/config
PUT /api/v1/admin/config
{
  "key": "THREAT_THRESHOLD_URL",
  "value": "0.5"
}
```

## WebSocket Events

Connect to `/ws/events` for real-time alerts:

```javascript
const ws = new WebSocket('ws://localhost:8765/ws/events');

ws.onmessage = (event) => {
  const alert = JSON.parse(event.data);
  console.log(alert);
  // {
  //   event_type: "URL_ALERT|NETWORK_ALERT|FILE_ALERT|PROCESS_ALERT",
  //   severity: "LOW|MEDIUM|HIGH|CRITICAL",
  //   title: "...",
  //   description: "...",
  //   source: "...",
  //   score: 0.95,
  //   timestamp: "2026-05-07T10:00:00"
  // }
};
```

## Error Responses

### 400 Bad Request
```json
{
  "success": false,
  "data": null,
  "error": "Invalid request format",
  "timestamp": "2026-05-07T10:00:00"
}
```

### 401 Unauthorized
```json
{
  "success": false,
  "data": null,
  "error": "Invalid or expired token",
  "timestamp": "2026-05-07T10:00:00"
}
```

### 403 Forbidden
```json
{
  "success": false,
  "data": null,
  "error": "Admin privileges required",
  "timestamp": "2026-05-07T10:00:00"
}
```

### 404 Not Found
```json
{
  "success": false,
  "data": null,
  "error": "Alert not found",
  "timestamp": "2026-05-07T10:00:00"
}
```

## Common Patterns

### Admin User (Default)
- Username: `admin`
- Password: `ShieldGuard2026!`
- Email: `admin@shieldguard.local`
- Role: `admin`

### Severity Levels
- `CRITICAL`: Action required immediately
- `HIGH`: Requires investigation
- `MEDIUM`: Monitor and investigate
- `LOW`: Informational

### Alert Types
- `URL`: Phishing/malicious URL
- `NETWORK`: Malicious traffic detected
- `FILE`: Suspicious or known malware file
- `PROCESS`: Suspicious process (RAT, etc.)

### Verdicts
- `SAFE`: No threat detected
- `MALICIOUS`: Confirmed threat
- `ANOMALY`: Suspicious pattern
- `UNKNOWN`: Unable to determine

## Rate Limiting

Currently unlimited. Implement rate limiting in production:
```python
from slowapi import Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
```

## Pagination

List endpoints support:
- `page`: Page number (1-indexed, default: 1)
- `limit`: Items per page (default: 20, max: 100)

## Filtering

Alert endpoints support:
- `severity`: LOW|MEDIUM|HIGH|CRITICAL
- `type`: URL|NETWORK|FILE|PROCESS
- `resolved`: true|false

## Response Times

Typical response times:
- URL analysis: 50-200ms
- Network analysis: 100-300ms
- File analysis: 200-1000ms (depends on file size)
- List operations: 10-50ms

## Limits

- File upload: 50MB
- URL length: 2048 characters
- Network features: 78 maximum
- Whitelist entries: Unlimited (indexed)
- Signatures: Unlimited (indexed)
