import psycopg2
from fastapi import HTTPException
from typing import Optional
from dotenv import load_dotenv
import os

load_dotenv()

def get_connection():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

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
