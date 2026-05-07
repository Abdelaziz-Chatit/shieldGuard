import logging
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from config import settings
from database.models import Base, User, SystemConfig, UserRole
from core.security import hash_password

logger = logging.getLogger(__name__)

# Create engine with connection pooling
engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    pool_pre_ping=True,
    pool_recycle=3600,
    connect_args={"charset": "utf8mb4"}
)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Initialize database: create tables and seed default data"""
    try:
        # Create all tables
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        
        # Seed default data
        db = SessionLocal()
        try:
            # Check if users exist
            user_count = db.query(User).count()
            if user_count == 0:
                # Create default admin user
                admin_user = User(
                    username="admin",
                    email="admin@shieldguard.local",
                    password_hash=hash_password("ShieldGuard2026!"),
                    role=UserRole.ADMIN,
                    is_active=True
                )
                db.add(admin_user)
                logger.info("Created default admin user")
            
            # Check if system config exists
            config_count = db.query(SystemConfig).count()
            if config_count == 0:
                # Seed default thresholds
                default_configs = [
                    SystemConfig(key="THREAT_THRESHOLD_URL", value="0.5"),
                    SystemConfig(key="THREAT_THRESHOLD_NETWORK", value="0.5"),
                    SystemConfig(key="THREAT_THRESHOLD_IF", value="0.61607"),
                    SystemConfig(key="ENABLE_PROCESS_MONITOR", value="true"),
                ]
                for config in default_configs:
                    db.add(config)
                logger.info("Seeded default system configuration")
            
            db.commit()
            logger.info("Database initialization completed successfully")
        except Exception as e:
            db.rollback()
            logger.error(f"Error seeding database: {e}")
            raise
        finally:
            db.close()
    
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        raise


def get_db():
    """Dependency: get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
