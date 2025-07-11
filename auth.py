from fastapi import APIRouter, HTTPException, Depends, status, Path
from sqlalchemy.orm import Session
from passlib.context import CryptContext
import re

from database import SessionLocal
from models import User
from schemas import UserCreate, UserResponse, UserLogin
from jose import jwt
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError
from typing import List
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi import Limiter
from slowapi.extension import Limiter as LimiterExtension
from fastapi import Request
from fastapi.responses import JSONResponse
from pydantic import EmailStr

# Use the limiter from main.py
from rate_limit import limiter

# In-memory token blacklist for logout (for demo; use Redis in production)
blacklisted_tokens = set()

# Router for authentication endpoints
router = APIRouter(prefix="/auth", tags=["auth"])

# Secret key for JWT (in a real app, keep this secret and safe!)
SECRET_KEY = "supersecretkey"  # Change this in production!
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing context (bcrypt)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme for getting the token from the request
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Dependency to get a database session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Function to hash a password
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# Function to check password strength
def is_strong_password(password: str) -> bool:
    # At least 8 chars, at least one special character
    return len(password) >= 8 and bool(re.search(r"[^a-zA-Z0-9]", password))

# Function to verify a password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Function to create a JWT token
def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Helper: sanitize input (basic example)
def sanitize_input(value: str) -> str:
    # Remove leading/trailing spaces and dangerous characters
    return re.sub(r'[<>"\'%;()&+]', '', value.strip())

# Health check endpoint (should be in main.py, but included here for clarity)
from fastapi import APIRouter
health_router = APIRouter()
@health_router.get("/health", tags=["health"])
def health_check():
    return {"status": "ok"}

# Override get_current_user to check for blacklisted tokens
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if token in blacklisted_tokens:
        raise HTTPException(status_code=401, detail="Token has been invalidated. Please log in again.")
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

# Dependency to check if current user is admin
def admin_required(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required.")
    return current_user

# Registration endpoint
@router.post("/register", response_model=UserResponse)
@limiter.limit("3/minute")  # Registration: 3 per minute per IP
async def register(user: UserCreate, db: Session = Depends(get_db), request: Request = None):
    # Check password strength
    if not is_strong_password(user.password):
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters and include a special character.")

    # Check for duplicate username or email
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Username already taken.")
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered.")

    # Hash the password
    hashed_pw = hash_password(user.password)

    # Create new user
    new_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_pw,
        role="user"  # Default role
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# Login endpoint
@router.post("/login")
@limiter.limit("5/minute")  # Login: 5 per minute per IP
async def login(form_data: UserLogin, db: Session = Depends(get_db), request: Request = None):
    # Find user by username
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    # Create JWT token with user info
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Protected endpoint to get current user info
@router.get("/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

# Admin-only: Get all users
@router.get("/users", response_model=List[UserResponse], tags=["admin"])
def get_all_users(
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    return db.query(User).all()

# Admin-only: Change user role
@router.put("/users/{user_id}/role", response_model=UserResponse, tags=["admin"])
def change_user_role(
    user_id: int = Path(..., description="ID of the user to change role for"),
    role: str = "user",
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.role = role
    db.commit()
    db.refresh(user)
    return user

# Admin-only: Delete user
@router.delete("/users/{user_id}", tags=["admin"])
def delete_user(
    user_id: int = Path(..., description="ID of the user to delete"),
    current_user: User = Depends(admin_required),
    db: Session = Depends(get_db)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete(user)
    db.commit()
    return {"detail": "User deleted"}

# Refresh JWT token endpoint
@router.post("/refresh")
@limiter.limit("10/minute")  # General API rate limit
async def refresh_token(request: Request, current_user: User = Depends(get_current_user)):
    # Issue a new token for the current user
    access_token = create_access_token(
        data={"sub": current_user.username, "role": current_user.role},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Logout endpoint (invalidate token)
@router.post("/logout")
@limiter.limit("20/minute")
async def logout(request: Request, token: str = Depends(oauth2_scheme)):
    blacklisted_tokens.add(token)
    return {"detail": "Logged out successfully"}

# Password reset request endpoint
@router.post("/forgot-password")
@limiter.limit("1/minute")
async def forgot_password(request: Request, email: EmailStr):
    # Sanitize and validate email
    email_clean = sanitize_input(email)
    # In a real app, send a reset email here
    # For demo, just return a message
    return {"detail": f"If {email_clean} exists, a reset link has been sent."} 