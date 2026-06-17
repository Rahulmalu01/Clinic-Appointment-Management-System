import psycopg2
from fastapi import HTTPException
from typing import Optional
from dotenv import load_dotenv
import os

load_dotenv()

def get_connection():
    return psycopg2.connect(os.getenv("DATABASE_URL"))


def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    # users table stores common auth info and role
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            hashed_password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'patient',
            full_name TEXT DEFAULT '',
            email TEXT DEFAULT '',
            phone TEXT DEFAULT ''
        )
    """)

    # doctors table stores doctor-specific details and references users.username
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS doctors (
            username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
            name TEXT,
            email TEXT,
            phone TEXT,
            address TEXT,
            specialty TEXT DEFAULT '',
            details TEXT DEFAULT ''
        )
    """)

    # patients table stores patient-specific details
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            username TEXT PRIMARY KEY REFERENCES users(username) ON DELETE CASCADE,
            name TEXT,
            email TEXT,
            phone TEXT,
            dob DATE DEFAULT NULL,
            address TEXT DEFAULT ''
        )
    """)

    # appointments table stores appointments between patients and doctors
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS appointments (
            id SERIAL PRIMARY KEY,
            patient_username TEXT REFERENCES users(username) ON DELETE CASCADE,
            doctor_username TEXT REFERENCES users(username) ON DELETE CASCADE,
            scheduled_at TIMESTAMP WITH TIME ZONE NOT NULL,
            duration_minutes INT NOT NULL DEFAULT 30,
            status TEXT NOT NULL DEFAULT 'scheduled',
            notes TEXT DEFAULT '',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
    """)

    # activity log for patient/doctor/admin actions
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id SERIAL PRIMARY KEY,
            username TEXT REFERENCES users(username) ON DELETE SET NULL,
            role TEXT,
            action TEXT NOT NULL,
            target_username TEXT,
            details TEXT DEFAULT '',
            created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
        )
    """)

    conn.commit()
    cursor.close()
    conn.close()


def get_user(username: str) -> Optional[dict]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, hashed_password, role, full_name, email, phone FROM users WHERE username = %s",
        (username,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    if row:
        return {
            "username": row[0],
            "hashed_password": row[1],
            "role": row[2],
            "full_name": row[3],
            "email": row[4],
            "phone": row[5],
        }
    return None


def log_activity(username: Optional[str], role: Optional[str], action: str, target_username: Optional[str] = None, details: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO activity_logs (username, role, action, target_username, details) VALUES (%s, %s, %s, %s, %s)",
            (username, role, action, target_username, details)
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def create_appointment(patient_username: str, doctor_username: str, scheduled_at: str, duration_minutes: int = 30, notes: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO appointments (patient_username, doctor_username, scheduled_at, duration_minutes, notes) VALUES (%s, %s, %s, %s, %s)",
            (patient_username, doctor_username, scheduled_at, duration_minutes, notes)
        )
        conn.commit()
        cursor.execute("SELECT id FROM appointments ORDER BY id DESC LIMIT 1")
        appointment_id = cursor.fetchone()[0]
        return appointment_id
    finally:
        cursor.close()
        conn.close()


def get_appointment_by_id(appointment_id: int):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, patient_username, doctor_username, scheduled_at, duration_minutes, status, notes, created_at FROM appointments WHERE id = %s",
        (appointment_id,)
    )
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row


def update_appointment_status(appointment_id: int, status: str):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE appointments SET status = %s WHERE id = %s",
            (status, appointment_id)
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def reschedule_appointment(appointment_id: int, scheduled_at: str):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE appointments SET scheduled_at = %s, status = 'rescheduled' WHERE id = %s",
            (scheduled_at, appointment_id)
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def extend_appointment_duration(appointment_id: int, extra_minutes: int):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE appointments SET duration_minutes = duration_minutes + %s WHERE id = %s",
            (extra_minutes, appointment_id)
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def get_todays_appointments_for_doctor(username: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, patient_username, scheduled_at, duration_minutes, status, notes, created_at FROM appointments WHERE doctor_username = %s AND DATE(scheduled_at AT TIME ZONE 'UTC') = CURRENT_DATE ORDER BY scheduled_at ASC",
        (username,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def get_appointments_for_patient(username: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, doctor_username, scheduled_at, duration_minutes, status, notes, created_at FROM appointments WHERE patient_username = %s ORDER BY scheduled_at DESC",
        (username,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def get_appointments_for_doctor(username: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, patient_username, scheduled_at, duration_minutes, status, notes, created_at FROM appointments WHERE doctor_username = %s ORDER BY scheduled_at DESC",
        (username,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def get_all_appointments():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, patient_username, doctor_username, scheduled_at, duration_minutes, status, notes, created_at FROM appointments ORDER BY scheduled_at DESC"
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def get_history_for_user(username: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, role, action, target_username, details, created_at FROM activity_logs WHERE username = %s ORDER BY created_at DESC",
        (username,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def get_recent_activity(limit: int = 50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, role, action, target_username, details, created_at FROM activity_logs ORDER BY created_at DESC LIMIT %s",
        (limit,)
    )
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def create_user(username: str, hashed_password: str, role: str = "patient", full_name: str = "", email: str = "", phone: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, hashed_password, role, full_name, email, phone) VALUES (%s, %s, %s, %s, %s, %s)",
            (username, hashed_password, role, full_name, email, phone)
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Username already taken")
    finally:
        cursor.close()
        conn.close()


def create_doctor(username: str, name: str, email: str, phone: str, address: str, specialty: str = "", details: str = ""):
    # assumes user record already exists with role 'doctor'
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO doctors (username, name, email, phone, address, specialty, details) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (username, name, email, phone, address, specialty, details)
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Doctor record already exists or user missing")
    finally:
        cursor.close()
        conn.close()


def create_patient(username: str, name: str, email: str, phone: str, dob: Optional[str] = None, address: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO patients (username, name, email, phone, dob, address) VALUES (%s, %s, %s, %s, %s, %s)",
            (username, name, email, phone, dob, address)
        )
        conn.commit()
    except psycopg2.IntegrityError:
        conn.rollback()
        raise HTTPException(status_code=409, detail="Patient record already exists or user missing")
    finally:
        cursor.close()
        conn.close()
