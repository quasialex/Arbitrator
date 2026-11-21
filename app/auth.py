"""Local accounts: scrypt passwords, opaque DB-backed cookie sessions, granular RBAC.

This is not enterprise SSO and must be deployed only behind HTTPS when exposed.
"""
from __future__ import annotations
import hashlib
import hmac
import secrets
from datetime import timedelta
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload
from app.models import AccessRole, RolePermission, UserAccount, UserRole, LoginSession, utcnow

PERMISSIONS = {
  'dashboard.read': 'View overview and summary metrics',
  'assessments.read': 'View assessments and scope',
  'assessments.write': 'Create and edit assessments',
  'imports.read': 'View import history',
  'imports.write': 'Upload and normalize assessment results',
  'observations.read': 'View technical evidence',
  'findings.read': 'View findings',
  'findings.assign': 'Assign responsible remediation team',
  'assets.read': 'View global asset inventory',
  'assets.write': 'Edit asset identity and classification',
  'teams.read': 'View remediation team directory',
  'teams.write': 'Manage remediation teams',
  'routing.read': 'View responsibility mapping rules',
  'routing.write': 'Create, edit and apply mapping rules',
  'governance.read': 'View governance queue and outcomes',
  'governance.approve': 'Record governance decisions',
  'governance.directory': 'Manage decision-maker contacts and role catalog',
  'governance.tasks.read': 'View governance work items',
  'governance.tasks.create': 'Create and route governance work items',
  'governance.tasks.resolve': 'Work on assigned escalation and remediation reviews',
  'governance.tasks.approve': 'Approve or reject assigned risk requests',
  'governance.tasks.manage': 'Manage and cancel governance work items',
  'accounts.manage': 'Create accounts, set roles and manage role permissions',
  'integrations.manage': 'Configure and test organization-wide external connectors',
}
READ = {'dashboard.read','assessments.read','imports.read','observations.read','findings.read',
        'assets.read','teams.read','routing.read','governance.read','governance.tasks.read'}
DEFAULT_ROLES = {
 'Read-only Viewer': READ,
 'Offensive Security Analyst': READ | {'assessments.write','imports.write','governance.tasks.create','governance.tasks.resolve'},
 'Offensive Security Manager': READ | {'assessments.write','imports.write','findings.assign','governance.tasks.resolve','integrations.manage'},
 'Security Specialist': READ | {'assessments.write','imports.write','findings.assign','assets.write','governance.tasks.create','governance.tasks.resolve'},
 'Governance Analyst': READ | {'findings.assign','assets.write','governance.tasks.create','governance.tasks.resolve'},
 'Governance Approver': READ | {'governance.approve','governance.tasks.approve'},
 'Governance Manager': READ | {'governance.approve','findings.assign','teams.write','routing.write','governance.directory','governance.tasks.create','governance.tasks.manage','governance.tasks.resolve','governance.tasks.approve','integrations.manage'},
 'Business Representative': READ | {'governance.tasks.resolve'},
 'Administrator': set(PERMISSIONS),
}
COOKIE_NAME = 'agp_session'
SESSION_HOURS = 8

def seed_roles(session: Session) -> None:
    """Only create defaults once; subsequent admin edits are never overwritten."""
    if session.scalar(select(AccessRole.id).limit(1)) is not None: return
    for name, permissions in DEFAULT_ROLES.items():
        role=AccessRole(name=name, description=f'Initial {name} role')
        role.permissions=[RolePermission(permission=p) for p in sorted(permissions)]
        session.add(role)
    session.commit()


def hash_password(password: str) -> str:
    if not 12 <= len(password) <= 128: raise ValueError('Password must have 12–128 characters')
    salt=secrets.token_bytes(16)
    hashed=hashlib.scrypt(password.encode('utf-8'), salt=salt, n=2**14, r=8, p=1)
    return 'scrypt$'+salt.hex()+'$'+hashed.hex()


def verify_password(password: str, encoded: str) -> bool:
    try:
        method,salt_hex,digest_hex=encoded.split('$')
        if method!='scrypt': return False
        derived=hashlib.scrypt(password.encode('utf-8'), salt=bytes.fromhex(salt_hex),n=2**14,r=8,p=1)
        return hmac.compare_digest(derived,bytes.fromhex(digest_hex))
    except (ValueError,UnicodeError): return False


def create_user(session: Session, username: str, name: str, email: str, password: str,
                role_ids: list[int], superuser: bool = False) -> UserAccount:
    username,name,email=username.strip().lower(),name.strip(),email.strip().lower()
    if not 3<=len(username)<=80 or not username.replace('_','').replace('-','').isalnum():
        raise ValueError('Username must be 3–80 letters, digits, hyphens or underscores')
    if not name or len(name)>160 or len(email)>254 or '@' not in email:
        raise ValueError('Valid display name and email are required')
    if session.scalar(select(UserAccount).where((UserAccount.username==username)|(UserAccount.email==email))):
        raise ValueError('Username or email already exists')
    ids=set(role_ids)
    known=session.scalars(select(AccessRole).where(AccessRole.id.in_(ids))).all() if ids else []
    if len(known)!=len(ids): raise ValueError('One or more roles do not exist')
    user=UserAccount(username=username,name=name,email=email,password_hash=hash_password(password),is_superuser=superuser)
    user.roles=[UserRole(role_id=r.id) for r in known]
    session.add(user);session.commit();return user


def login(session: Session, username: str, password: str) -> str | None:
    user=session.scalar(select(UserAccount).where(UserAccount.username==username.strip().lower()))
    # Equalize password-hashing work when username is invalid.
    if not user:
        verify_password(password,hash_password('not-a-real-account-password'))
        return None
    now=utcnow()
    if not user.is_active or (user.locked_until and user.locked_until>now): return None
    if not verify_password(password,user.password_hash):
        user.failed_logins+=1
        if user.failed_logins>=5:
            user.locked_until=now+timedelta(minutes=15)
            user.failed_logins=0
        session.commit();return None
    user.failed_logins=0;user.locked_until=None
    raw=secrets.token_urlsafe(32)
    record=LoginSession(token_hash=hashlib.sha256(raw.encode()).hexdigest(), user_id=user.id,
                        csrf_token=secrets.token_hex(32),expires_at=now+timedelta(hours=SESSION_HOURS))
    session.add(record);session.commit();return raw


def resolve_session(session: Session, raw: str):
    if not raw: return None
    record=session.scalar(select(LoginSession).where(LoginSession.token_hash==hashlib.sha256(raw.encode()).hexdigest())
                          .options(selectinload(LoginSession.user).selectinload(UserAccount.roles)
                                   .selectinload(UserRole.role).selectinload(AccessRole.permissions)))
    if not record or record.expires_at<=utcnow() or not record.user.is_active: return None
    user=record.user
    perms=set(PERMISSIONS) if user.is_superuser else {p.permission for link in user.roles for p in link.role.permissions}
    return user, perms, record.csrf_token


def revoke_session(session: Session, raw: str) -> None:
    if raw:
        item=session.scalar(select(LoginSession).where(LoginSession.token_hash==hashlib.sha256(raw.encode()).hexdigest()))
        if item: session.delete(item);session.commit()


def update_role(session: Session, role: AccessRole, name: str, description: str, permissions: list[str]):
    name=name.strip()
    if not 2<=len(name)<=100 or len(description)>350: raise ValueError('Invalid role name or description')
    requested=set(permissions)
    if requested-set(PERMISSIONS): raise ValueError('Unknown permission selected')
    existing=session.scalar(select(AccessRole).where(AccessRole.name==name, AccessRole.id!=role.id))
    if existing: raise ValueError('Role name already exists')
    role.name=name;role.description=description.strip()
    role.permissions.clear()
    session.flush()  # remove old unique(role_id,permission) keys before inserting replacements
    role.permissions.extend(RolePermission(permission=p) for p in sorted(requested))
    session.commit()


def assign_roles(session: Session, account: UserAccount, role_ids: list[int], active: bool):
    ids=set(role_ids)
    known=session.scalars(select(AccessRole).where(AccessRole.id.in_(ids))).all() if ids else []
    if len(known)!=len(ids): raise ValueError('Unknown access role')
    account.roles.clear()
    session.flush()  # avoid duplicate unique(user_id,role_id) on overlapping assignments
    account.roles.extend(UserRole(role_id=r.id) for r in known)
    account.is_active=bool(active)
    session.query(LoginSession).filter(LoginSession.user_id==account.id).delete()
    session.commit()
