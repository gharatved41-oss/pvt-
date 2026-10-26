from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ...core.database import get_db
from ...core.security import verify_password, get_password_hash, create_access_token
from ...models.models import User
from ...schemas.schemas import UserCreate, UserLogin, Token, UserResponse
from ...services.audit_service import audit_service
from ..deps import get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email address already exists"
        )
    
    # Enforce role restriction on public register
    assigned_role = "admin" if db.query(User).count() == 0 else (user_in.role if user_in.role in ["analyst", "viewer"] else "analyst")

    user = User(
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        full_name=user_in.full_name,
        role=assigned_role,
        is_active=True
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    audit_service.log_event(
        db=db,
        event_type="auth",
        action="user_registered",
        user_id=user.id,
        user_email=user.email,
        details={"role": user.role}
    )
    return user

@router.post("/login", response_model=Token)
def login(login_in: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == login_in.email).first()
    if not user or not verify_password(login_in.password, user.hashed_password):
        audit_service.log_event(
            db=db,
            event_type="auth",
            action="login_failed",
            user_email=login_in.email,
            details={"reason": "invalid_credentials"}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Account is deactivated")

    token = create_access_token(subject=user.id, role=user.role)

    audit_service.log_event(
        db=db,
        event_type="auth",
        action="login_success",
        user_id=user.id,
        user_email=user.email,
        details={"role": user.role}
    )

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.role,
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "role": user.role
        }
    }

@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user
