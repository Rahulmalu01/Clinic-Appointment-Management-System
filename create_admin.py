from passlib.context import CryptContext
from dotenv import load_dotenv
import os
from database import create_user

load_dotenv()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def create_admin(username: str, password: str, full_name: str = "Admin"):
    hashed = pwd_context.hash(password)
    # role 'admin'
    create_user(username, hashed, role='admin', full_name=full_name, email='', phone='')
    print(f"Admin user '{username}' created.")

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 3:
        print('Usage: python create_admin.py <username> <password> [full_name]')
        sys.exit(1)
    username = sys.argv[1]
    password = sys.argv[2]
    full_name = sys.argv[3] if len(sys.argv) > 3 else 'Admin'
    create_admin(username, password, full_name)
