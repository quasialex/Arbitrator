"""Explicitly create a local administrator with a private password prompt.
Usage: python -m scripts.create_admin
"""
import getpass
from app.database import init_db,SessionLocal
from app.auth import create_user,seed_roles

def main():
    init_db()
    with SessionLocal() as session:
        seed_roles(session)
        username=input('Admin username: ').strip()
        name=input('Display name: ').strip()
        email=input('Email: ').strip()
        pwd=getpass.getpass('Password (12+ characters): ')
        confirm=getpass.getpass('Confirm: ')
        if pwd != confirm: raise SystemExit('Passwords differ; no account created')
        user=create_user(session,username,name,email,pwd,[],superuser=True)
        print('Administrator created:',user.username)
if __name__=='__main__': main()
