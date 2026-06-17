from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer

from datetime import datetime, timedelta, timezone
from typing import Optional
from pydantic import BaseModel, Field
from jose import jwt, JWTError
from passlib.context import CryptContext
from contextlib import asynccontextmanager
from database import init_db, get_user, create_user, create_doctor, create_patient
from dotenv import load_dotenv

import hashlib
import os

load_dotenv()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-this")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))


app = FastAPI(title="Healthcare", lifespan=lifespan)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login", auto_error=False)


class PatientSignup(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None


class DoctorCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    specialty: Optional[str] = None
    details: Optional[str] = None


class UserPublic(BaseModel):
    username: str
    role: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None


def hash_password(password: str):
    password = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    plain_password = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return pwd_context.verify(plain_password, hashed_password)

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


templates = Jinja2Templates(directory="templates")


def render(request: Request, name: str, context: dict | None = None, user: Optional[UserPublic] = None):
    payload = {"request": request}
    if user:
        payload["user"] = user
    if context:
        payload.update(context)
    return templates.TemplateResponse(request=request, name=name, context=payload)


def require_admin(current_user: UserPublic = Depends(get_current_user)) -> UserPublic:
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user


@app.get("/login/")
async def login_page(request: Request, current_user: Optional[UserPublic] = Depends(get_current_user_optional)):
    return render(request, "login.html", user=current_user)


@app.post("/login/", response_class=HTMLResponse)
async def login_view(request: Request, username: str = Form(...), password: str = Form(...)):
    user = get_user(username)
    if not user or not verify_password(password, user["hashed_password"]):
        return render(request, "login.html", {"error": "Invalid username or password"})
    access_token = create_access_token({"sub": user["username"]})
    response = RedirectResponse(url="/dashboard/", status_code=302)
    response.set_cookie("access_token", access_token, httponly=True, max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    return response


@app.get('/signup/')
async def signup_page(request: Request, current_user: Optional[UserPublic] = Depends(get_current_user_optional)):
    return render(request, 'signup.html', user=current_user)


@app.post('/signup/', response_class=HTMLResponse)
async def signup_view(request: Request, username: str = Form(...), full_name: str = Form(""), email: str = Form(""), phone: str = Form(""), dob: Optional[str] = Form(None), address: str = Form(""), password: str = Form(...)):
    if not username or not password:
        return render(request, 'signup.html', {"error": "Username and password are required"})
    try:
        hashed = hash_password(password)
        # create user as patient
        create_user(username, hashed, role='patient', full_name=full_name or "", email=email or "", phone=phone or "")
        create_patient(username, full_name or username, email or "", phone or "", dob=dob, address=address or "")
        return render(request, 'signup.html', {"success": "Account created! Please log in."})
    except HTTPException as e:
        return render(request, 'signup.html', {"error": e.detail})


@app.get('/admin/doctors/new')
async def new_doctor_page(request: Request, admin: UserPublic = Depends(require_admin)):
    return render(request, 'doctor_create.html', user=admin)


@app.post('/admin/doctors/', response_class=HTMLResponse)
async def create_doctor_endpoint(request: Request, username: str = Form(...), password: str = Form(...), name: str = Form(...), email: str = Form(""), phone: str = Form(""), address: str = Form(""), specialty: str = Form(""), details: str = Form(""), admin: UserPublic = Depends(require_admin)):
    # create user with doctor role then doctor record
    try:
        hashed = hash_password(password)
        create_user(username, hashed, role='doctor', full_name=name or username, email=email or "", phone=phone or "")
        create_doctor(username, name, email or "", phone or "", address or "", specialty or "", details or "")
        return render(request, 'doctor_create.html', {"success": "Doctor created successfully"}, user=admin)
    except HTTPException as e:
        return render(request, 'doctor_create.html', {"error": e.detail}, user=admin)


@app.get('/profile/')
async def profile(request: Request, current_user: UserPublic = Depends(get_current_user)):
    return render(request, 'profile.html', {"current_user": current_user}, user=current_user)


@app.get('/logout/')
async def logout():
    response = RedirectResponse(url='/', status_code=302)
    response.delete_cookie('access_token')
    return response


@app.get("/")
async def home(request: Request, current_user: Optional[UserPublic] = Depends(get_current_user_optional)):
    return render(request, "home.html", {"current_user": current_user} if current_user else {}, user=current_user)


@app.get("/dashboard/")
async def dashboard(request: Request, current_user: UserPublic = Depends(get_current_user)):
    return render(request, "dashboard.html", {"current_user": current_user}, user=current_user)