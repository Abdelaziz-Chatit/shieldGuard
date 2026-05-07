import logging
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database.database import get_db
from database.models import User
from core.security import hash_password, verify_password, create_access_token
from core.dependencies import get_current_user
from schemas.schemas import UserCreate, UserLogin, TokenResponse, UserResponse
from utils import make_response

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


@router.post("/register")
async def register(user_create: UserCreate, db: Session = Depends(get_db)):
    """
    Register a new user.
    No authentication required.
    """
    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.username == user_create.username) | (User.email == user_create.email)
    ).first()
    
    if existing_user:
        logger.warning(f"Registration attempt with existing username or email: {user_create.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Create new user
    user = User(
        username=user_create.username,
        email=user_create.email,
        password_hash=hash_password(user_create.password),
        role="user",
        is_active=True
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    logger.info(f"New user registered: {user.username}")
    
    response_data = UserResponse.model_validate(user)
    return make_response(data=response_data)


@router.post("/login")
async def login(user_login: UserLogin, db: Session = Depends(get_db)):
    """
    Authenticate user and return JWT access token.
    """
    # Find user by username
    user = db.query(User).filter(User.username == user_login.username).first()
    
    if not user or not verify_password(user_login.password, user.password_hash):
        logger.warning(f"Failed login attempt for user: {user_login.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    # Create JWT token
    access_token = create_access_token(data={"sub": str(user.id)})
    
    logger.info(f"User logged in: {user.username}")
    
    user_response = UserResponse.model_validate(user)
    response_data = TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=user_response
    )
    
    return make_response(data=response_data)


@router.get("/me")
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Get current authenticated user information.
    """
    user_response = UserResponse.model_validate(current_user)
    return make_response(data=user_response)
