from datetime import datetime, timezone, timedelta
from jose import jwt, JWTError
from typing import Optional
from fastapi import Request, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from schemas import UserPublic
from database import get_user

import os

SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_token_from_request(request: Request, token: Optional[str] = Depends(oauth2_scheme)) -> Optional[str]:
    # prefer Authorization header token, fall back to cookie
    if token:
        return token
    return request.cookies.get("access_token")


async def get_current_user(token: Optional[str] = Depends(get_token_from_request)) -> UserPublic:
    cred_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise cred_exc
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise cred_exc
    except JWTError:
        raise cred_exc
    user = get_user(username)
    if not user:
        raise cred_exc
    return UserPublic(username=user["username"], role=user.get("role", "patient"), full_name=user.get("full_name"), email=user.get("email"), phone=user.get("phone"))


async def get_current_user_optional(token: Optional[str] = Depends(get_token_from_request)) -> Optional[UserPublic]:
    if not token:
        return None
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            return None
    except JWTError:
        return None
    user = get_user(username)
    if not user:
        return None
    return UserPublic(username=user["username"], role=user.get("role", "patient"), full_name=user.get("full_name"), email=user.get("email"), phone=user.get("phone"))
