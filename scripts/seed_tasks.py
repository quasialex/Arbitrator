"""Seed fictional governance work items AFTER running create_admin and seed_demo."""
from datetime import date, timedelta
from sqlalchemy import select
from app.database import init_db, SessionLocal
from app.auth import seed_roles
from app.models import GovernanceWorkItem, Finding, AccessRole, UserAccount
from app.governance_tasks import create_work_item


def seed_work_items(db):
    seed_roles(db)
    if db.scalar(select(GovernanceWorkItem.id).limit(1)):
        print('Governance work items already exist; no new items added')
        return
    admin=db.scalar(select(UserAccount).where(UserAccount.is_superuser.is_(True)).order_by(UserAccount.id))
    owned=db.scalars(select(Finding).where(Finding.assigned_owner_id.is_not(None)).order_by(Finding.id)).all()
    approver=db.scalar(select(AccessRole).where(AccessRole.name=='Governance Approver'))
    specialist=db.scalar(select(AccessRole).where(AccessRole.name=='Security Specialist'))
    if not (admin and len(owned)>=3 and approver and specialist):
        print('Create administrator and seed the synthetic campaign before task seeding.')
        return
    fixtures=[
        dict(finding_id=owned[0].id,kind='risk_approval',title='Review temporary risk exception',
             assignee_role_id=approver.id,assignee_user_id=None,due_date=(date.today()+timedelta(days=5)).isoformat(),
             description='Review the documented exception and confirm the next review date.'),
        dict(finding_id=owned[1].id,kind='escalation',title='Investigate overdue remediation escalation',
             assignee_role_id=specialist.id,assignee_user_id=None,due_date=(date.today()-timedelta(days=2)).isoformat(),
             description='Confirm the technical impact and propose next steps.'),
        dict(finding_id=owned[2].id,kind='remediation_review',title='Verify remediation evidence',
             assignee_user_id=admin.id,assignee_role_id=None,due_date=(date.today()+timedelta(days=10)).isoformat(),
             description='Review evidence before concluding remediation status.'),
    ]
    for values in fixtures:
        create_work_item(db,**values,created_by_id=admin.id)
    print('Created 3 synthetic governance work items (including one intentionally overdue).')


def main():
    init_db()
    with SessionLocal() as db:
        seed_work_items(db)

if __name__=='__main__':main()
