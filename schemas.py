from typing import Optional
from pydantic import BaseModel, Field

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


class AppointmentCreate(BaseModel):
    doctor_username: str
    scheduled_at: str
    duration_minutes: int = 30
    notes: Optional[str] = None

