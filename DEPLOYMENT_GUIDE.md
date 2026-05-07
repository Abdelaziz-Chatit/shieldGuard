# ShieldGuard Backend Deployment Guide

Complete guide for setting up and deploying the ShieldGuard FastAPI backend.

## Quick Start

### 1. Prerequisites

Ensure you have:
- Python 3.9 or higher
- MySQL 8.0 or higher
- Pre-trained ML models (keras, pkl, and json files)

### 2. Environment Setup

```bash
# Navigate to the backend directory
cd fastapi-backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
.\venv\Scripts\activate
# On Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration

```bash
# Copy example configuration
cp .env.example .env

# Edit .env with your settings
# Required fields:
# - DATABASE_URL: MySQL connection string
# - SECRET_KEY: Random secret key for JWT
# - Model paths: Ensure paths to ML model files are correct
```

### 4. Database Setup

```bash
# Initialize database
python -c "
from database.database import init_db
init_db()
"

# This will:
# - Create all MySQL tables
# - Seed default admin user (username: admin, password: ShieldGuard2026!)
# - Initialize system configuration
```

### 5. Run the Server

```bash
# Development with auto-reload
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8765

# Production (using Gunicorn + Uvicorn)
pip install gunicorn
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:8765
```

The API will be available at `http://localhost:8765`

## Configuration Details

### .env File

```env
# Database - Required
DATABASE_URL=mysql+pymysql://username:password@localhost:3306/shieldguard

# JWT - Generate a secure random key
SECRET_KEY=your_random_secret_key_here_minimum_32_characters_long
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440  # 24 hours

# API
API_PORT=8765

# ML Model Paths - Ensure files exist
CNN_GRU_MODEL_PATH=models/cnn_gru/model.keras
CNN_GRU_SCALER_PATH=models/cnn_gru/scaler.pkl
CHAR_CNN_MODEL_PATH=models/char_cnn/model.keras
CHAR_CNN_VOCAB_PATH=models/char_cnn/vocab.json
IF_MODEL_PATH=models/isolation_forest/model.pkl
IF_SCALER_PATH=models/isolation_forest/scaler.pkl
IF_FEATURES_PATH=models/isolation_forest/features.pkl
IF_REPORT_PATH=models/isolation_forest/if_report.json

# Thresholds
THREAT_THRESHOLD_URL=0.5
THREAT_THRESHOLD_NETWORK=0.5
THREAT_THRESHOLD_IF=0.61607

# Signature Database
SIGNATURE_DB_PATH=signatures/malware_hashes.db

# Features
ENABLE_PROCESS_MONITOR=true
```

### Database Setup Script

For a fresh MySQL database:

```sql
-- Create database
CREATE DATABASE shieldguard CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Create user (if needed)
CREATE USER 'shieldguard'@'localhost' IDENTIFIED BY 'secure_password_here';

-- Grant privileges
GRANT ALL PRIVILEGES ON shieldguard.* TO 'shieldguard'@'localhost';
FLUSH PRIVILEGES;
```

## First Time Setup Checklist

- [ ] Python 3.9+ installed
- [ ] MySQL running and accessible
- [ ] Virtual environment created and activated
- [ ] Dependencies installed (`pip install -r requirements.txt`)
- [ ] `.env` file created with correct settings
- [ ] ML model files in correct paths
- [ ] Database initialized (`init_db()`)
- [ ] Server started and responding to `/health`

## Testing the API

### Health Check
```bash
curl http://localhost:8765/health
```

### Register User
```bash
curl -X POST http://localhost:8765/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "SecurePassword123!"
  }'
```

### Login
```bash
curl -X POST http://localhost:8765/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "SecurePassword123!"
  }'
```

### Analyze URL
```bash
TOKEN="your_jwt_token_here"

curl -X POST http://localhost:8765/api/v1/analyze/url \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://suspicious-phishing-site.com"
  }'
```

### Analyze File
```bash
TOKEN="your_jwt_token_here"

curl -X POST http://localhost:8765/api/v1/analyze/file \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/path/to/file.exe"
```

## Troubleshooting

### Issue: Models not loading

**Solution:**
1. Check `config.py` model path settings
2. Verify files exist: `ls models/*/`
3. Check file permissions
4. Review logs for specific errors

```bash
# Example check
ls -la models/cnn_gru/model.keras
ls -la models/char_cnn/model.keras
ls -la models/isolation_forest/model.pkl
```

### Issue: Database connection failed

**Solution:**
1. Verify MySQL is running: `mysql -u root -p -e "SELECT 1;"`
2. Check `DATABASE_URL` format in `.env`
3. Verify database exists: `mysql -u root -p -e "USE shieldguard;"`

```bash
# Example URL format
DATABASE_URL=mysql+pymysql://username:password@localhost:3306/shieldguard
```

### Issue: JWT Token errors

**Solution:**
1. Generate new `SECRET_KEY` in `.env`
2. Ensure token is correctly passed in `Authorization: Bearer <token>` header
3. Check token expiration time

### Issue: WebSocket connection fails

**Solution:**
1. Verify API is running on correct port
2. Check CORS configuration in `main.py`
3. Ensure WebSocket endpoint is accessible: `ws://localhost:8765/ws/events`

## Performance Tuning

### Database Connection Pooling
Adjust in `database/database.py`:
```python
pool_size=10,  # Number of connections to maintain
max_overflow=20,  # Additional connections beyond pool_size
pool_recycle=3600,  # Recycle connections after 1 hour
```

### Worker Processes
For production, use multiple workers:
```bash
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker
```

### ML Model Optimization
Models are loaded once at startup. To reduce memory:
- Use GPU acceleration (set `CUDA_VISIBLE_DEVICES`)
- Reduce batch sizes if needed
- Monitor with: `nvidia-smi` or `ps aux`

## Monitoring and Logging

### Check Logs
```bash
# Tail logs (if running in foreground)
# Press Ctrl+C to stop

# Or check system logs
tail -f /var/log/shieldguard.log
```

### Monitor Health
```bash
# Check API is responsive
watch -n 5 'curl -s http://localhost:8765/health | python -m json.tool'
```

### Database Health
```sql
-- Check table sizes
SELECT table_name, ROUND(((data_length + index_length) / 1024 / 1024), 2) AS size_mb
FROM information_schema.TABLES
WHERE table_schema = 'shieldguard';

-- Check alert count
SELECT COUNT(*) FROM alerts;
SELECT COUNT(*) FROM scan_history;
```

## Backup and Recovery

### Database Backup
```bash
# Backup
mysqldump -u root -p shieldguard > shieldguard_backup.sql

# Restore
mysql -u root -p shieldguard < shieldguard_backup.sql
```

### Signature Database Backup
```bash
# SQLite backup (just copy the file)
cp signatures/malware_hashes.db signatures/malware_hashes_backup.db
```

## Security Considerations

1. **Change default admin password**:
   - Use endpoint: `PUT /api/v1/admin/users/1`
   - Or update database: `UPDATE users SET password_hash='...' WHERE id=1`

2. **Secure SECRET_KEY**:
   - Generate random 32+ character string
   - Store securely, never commit to version control

3. **Database Security**:
   - Use strong passwords
   - Restrict database access to backend only
   - Enable MySQL SSL/TLS

4. **API Security**:
   - Use HTTPS in production
   - Implement rate limiting
   - Add request validation
   - Monitor access logs

5. **File Uploads**:
   - Current limit: 50MB
   - Adjust in `routers/file.py` if needed
   - Implement virus scanning on uploaded files

## Scaling

### Horizontal Scaling
1. Deploy multiple instances behind load balancer
2. Share database across instances
3. Share `signatures/` directory (NFS or S3)
4. Use centralized logging (ELK, CloudWatch)

### Vertical Scaling
1. Increase worker processes
2. Increase database connection pool
3. Use GPU acceleration for ML models
4. Increase server memory

## Update and Maintenance

### Update dependencies
```bash
pip install --upgrade -r requirements.txt
```

### Update signatures
```bash
# Via API
curl -X POST http://localhost:8765/api/v1/admin/signatures/import \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -F "file=@signatures.csv"
```

### Rotate logs
Implement log rotation:
```python
# In main.py
from logging.handlers import RotatingFileHandler

handler = RotatingFileHandler('shieldguard.log', maxBytes=10_000_000, backupCount=5)
logger.addHandler(handler)
```

## Support

For issues:
1. Check logs: `tail -f` the running server output
2. Review `/health` endpoint status
3. Check database connection
4. Verify configuration in `.env`
5. Review API documentation in `README.md`
