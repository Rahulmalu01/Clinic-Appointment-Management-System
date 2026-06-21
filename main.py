from fastapi import FastAPI, Request, Depends, HTTPException, Form
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse

from typing import Optional
from passlib.context import CryptContext
from contextlib import asynccontextmanager
from database import init_db, get_user, create_user, create_doctor, create_patient, log_activity, create_appointment, get_appointment_by_id, update_appointment_status, reschedule_appointment, extend_appointment_duration, get_todays_appointments_for_doctor, get_appointments_for_patient, get_appointments_for_doctor, get_all_appointments, get_history_for_user, get_recent_activity, create_prescription, get_prescriptions_for_patient, get_prescriptions_by_doctor, get_all_prescriptions, create_medical_history, get_medical_history_for_patient, update_medical_history
from dotenv import load_dotenv

from schemas import PatientSignup, DoctorCreate, UserPublic, AppointmentCreate
from access_token import create_access_token, get_current_user, get_current_user_optional, get_token_from_request
import hashlib
import os

load_dotenv()
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

app = FastAPI(title="Healthcare", lifespan=lifespan)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str):
    password = hashlib.sha256(password.encode("utf-8")).hexdigest()
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    plain_password = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return pwd_context.verify(plain_password, hashed_password)


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


def require_doctor(current_user: UserPublic = Depends(get_current_user)) -> UserPublic:
    if current_user.role != "doctor":
        raise HTTPException(status_code=403, detail="Doctor privileges required")
    return current_user


def require_patient(current_user: UserPublic = Depends(get_current_user)) -> UserPublic:
    if current_user.role != "patient":
        raise HTTPException(status_code=403, detail="Patient privileges required")
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


@app.get('/appointments/')
async def appointments(request: Request, current_user: UserPublic = Depends(get_current_user)):
    if current_user.role == 'patient':
        appointments = get_appointments_for_patient(current_user.username)
    elif current_user.role == 'doctor':
        appointments = get_appointments_for_doctor(current_user.username)
    else:
        appointments = get_all_appointments()
    return render(request, 'appointments.html', {"appointments": appointments, "current_user": current_user}, user=current_user)


@app.post('/appointments/book/', response_class=HTMLResponse)
async def book_appointment(request: Request, doctor_username: str = Form(...), scheduled_at: str = Form(...), duration_minutes: int = Form(30), notes: str = Form(""), current_user: UserPublic = Depends(require_patient)):
    appointment_id = create_appointment(current_user.username, doctor_username, scheduled_at, duration_minutes, notes or "")
    log_activity(current_user.username, current_user.role, "booked_appointment", doctor_username, f"Appointment ID {appointment_id}")
    return render(request, 'appointments.html', {"success": "Appointment booked successfully", "appointments": get_appointments_for_patient(current_user.username), "current_user": current_user}, user=current_user)


@app.get('/doctor/schedule/')
async def doctor_schedule(request: Request, current_user: UserPublic = Depends(require_doctor)):
    appointments = get_todays_appointments_for_doctor(current_user.username)
    return render(request, 'doctor_schedule.html', {"appointments": appointments, "current_user": current_user}, user=current_user)


@app.post('/doctor/appointment/{appointment_id}/status/', response_class=HTMLResponse)
async def doctor_update_appointment_status(request: Request, appointment_id: int, status: str = Form(...), current_user: UserPublic = Depends(require_doctor)):
    appointment = get_appointment_by_id(appointment_id)
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    if appointment[2] != current_user.username:
        raise HTTPException(status_code=403, detail="Cannot modify appointments for another doctor")
    if status not in {"approved", "completed", "canceled"}:
        raise HTTPException(status_code=400, detail="Invalid appointment status")
    update_appointment_status(appointment_id, status)
    log_activity(current_user.username, current_user.role, f"appointment_{status}", appointment[1], f"Appointment ID {appointment_id}")
    appointments = get_todays_appointments_for_doctor(current_user.username)
    return render(request, 'doctor_schedule.html', {"appointments": appointments, "current_user": current_user, "success": f"Appointment {status} successfully."}, user=current_user)


@app.post('/doctor/appointment/{appointment_id}/reschedule/', response_class=HTMLResponse)
async def doctor_reschedule_appointment(request: Request, appointment_id: int, scheduled_at: str = Form(...), current_user: UserPublic = Depends(require_doctor)):
    appointment = get_appointment_by_id(appointment_id)
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    if appointment[2] != current_user.username:
        raise HTTPException(status_code=403, detail="Cannot modify appointments for another doctor")
    reschedule_appointment(appointment_id, scheduled_at)
    log_activity(current_user.username, current_user.role, "appointment_rescheduled", appointment[1], f"Appointment ID {appointment_id} rescheduled to {scheduled_at}")
    appointments = get_todays_appointments_for_doctor(current_user.username)
    return render(request, 'doctor_schedule.html', {"appointments": appointments, "current_user": current_user, "success": "Appointment rescheduled successfully."}, user=current_user)


@app.post('/doctor/appointment/{appointment_id}/extend/', response_class=HTMLResponse)
async def doctor_extend_appointment(request: Request, appointment_id: int, extra_minutes: int = Form(...), current_user: UserPublic = Depends(require_doctor)):
    appointment = get_appointment_by_id(appointment_id)
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    if appointment[2] != current_user.username:
        raise HTTPException(status_code=403, detail="Cannot modify appointments for another doctor")
    if extra_minutes <= 0:
        raise HTTPException(status_code=400, detail="Extra minutes must be positive")
    extend_appointment_duration(appointment_id, extra_minutes)
    log_activity(current_user.username, current_user.role, "appointment_extended", appointment[1], f"Appointment ID {appointment_id} extended by {extra_minutes} minutes")
    appointments = get_todays_appointments_for_doctor(current_user.username)
    return render(request, 'doctor_schedule.html', {"appointments": appointments, "current_user": current_user, "success": "Appointment extended successfully."}, user=current_user)


@app.get('/history/')
async def history(request: Request, current_user: UserPublic = Depends(get_current_user)):
    logs = get_history_for_user(current_user.username)
    return render(request, 'history.html', {"logs": logs, "current_user": current_user}, user=current_user)


@app.get('/admin/summary/')
async def admin_summary(request: Request, admin: UserPublic = Depends(require_admin)):
    appointments = get_all_appointments()
    recent_activity = get_recent_activity(50)
    return render(request, 'admin_summary.html', {"appointments": appointments, "recent_activity": recent_activity, "current_user": admin}, user=admin)


@app.get('/prescriptions/')
async def view_prescriptions(request: Request, current_user: UserPublic = Depends(get_current_user)):
    if current_user.role == 'patient':
        prescriptions = get_prescriptions_for_patient(current_user.username)
    elif current_user.role == 'doctor':
        prescriptions = get_prescriptions_by_doctor(current_user.username)
    else:
        prescriptions = get_all_prescriptions()
    return render(request, 'prescriptions.html', {"prescriptions": prescriptions, "current_user": current_user}, user=current_user)


@app.get('/prescriptions/new/')
async def new_prescription_page(request: Request, current_user: UserPublic = Depends(require_doctor)):
    # Doctor can issue prescriptions
    return render(request, 'prescription_create.html', {"current_user": current_user}, user=current_user)


@app.post('/prescriptions/', response_class=HTMLResponse)
async def create_prescription_endpoint(request: Request, patient_username: str = Form(...), medication_name: str = Form(...), dosage: str = Form(...), frequency: str = Form(...), duration_days: int = Form(30), instructions: str = Form(""), appointment_id: Optional[int] = Form(None), current_user: UserPublic = Depends(require_doctor)):
    try:
        prescription_id = create_prescription(patient_username, current_user.username, medication_name, dosage, frequency, duration_days, instructions, appointment_id)
        log_activity(current_user.username, current_user.role, "issued_prescription", patient_username, f"Prescription ID {prescription_id} for {medication_name}")
        prescriptions = get_prescriptions_by_doctor(current_user.username)
        return render(request, 'prescriptions.html', {"prescriptions": prescriptions, "current_user": current_user, "success": "Prescription issued successfully"}, user=current_user)
    except Exception as e:
        return render(request, 'prescription_create.html', {"error": str(e), "current_user": current_user}, user=current_user)


@app.get('/medical-history/')
async def view_medical_history(request: Request, current_user: UserPublic = Depends(get_current_user)):
    if current_user.role == 'patient':
        history = get_medical_history_for_patient(current_user.username)
        return render(request, 'medical_history.html', {"history": history, "current_user": current_user}, user=current_user)
    else:
        # Doctors can access patient history (future: implement patient selection)
        return render(request, 'medical_history.html', {"history": [], "current_user": current_user}, user=current_user)


@app.get('/medical-history/new/')
async def new_medical_history_page(request: Request, current_user: UserPublic = Depends(require_patient)):
    return render(request, 'medical_history_create.html', {"current_user": current_user}, user=current_user)


@app.post('/medical-history/', response_class=HTMLResponse)
async def create_medical_history_endpoint(request: Request, condition_name: str = Form(...), diagnosed_date: Optional[str] = Form(None), treatment: str = Form(""), notes: str = Form(""), current_user: UserPublic = Depends(require_patient)):
    try:
        history_id = create_medical_history(current_user.username, condition_name, diagnosed_date, "active", treatment, notes)
        log_activity(current_user.username, current_user.role, "added_medical_history", None, f"Added {condition_name} to medical history")
        history = get_medical_history_for_patient(current_user.username)
        return render(request, 'medical_history.html', {"history": history, "current_user": current_user, "success": "Medical history added successfully"}, user=current_user)
    except Exception as e:
        return render(request, 'medical_history_create.html', {"error": str(e), "current_user": current_user}, user=current_user)


@app.get('/patient/{patient_username}/medical-history/')
async def view_patient_medical_history(request: Request, patient_username: str, current_user: UserPublic = Depends(require_doctor)):
    history = get_medical_history_for_patient(patient_username)
    return render(request, 'patient_medical_history.html', {"history": history, "patient_username": patient_username, "current_user": current_user}, user=current_user)


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