"""Governance work-item state machine and assignment policy.

All task mutations are server-side permission checked. A task is not itself a
risk decision; final risk acceptance uses the pre-existing governance decision
workflow, with the authenticated actor and normal remediation prerequisites.
"""
from __future__ import annotations
from datetime import date, datetime
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models import (Finding, GovernanceWorkItem, GovernanceWorkEvent, UserAccount,
                        AccessRole, UserRole, RolePermission, utcnow)
from app.workflows import record_authenticated_decision

KINDS = {"escalation": "Escalation", "risk_approval": "Risk approval", "remediation_review": "Remediation review"}
STATUSES = ("pending", "in_progress", "approved", "rejected", "completed", "cancelled")
OPEN_STATUSES = ("pending", "in_progress")
TRANSITIONS = {
    "pending": {"in_progress", "approved", "rejected", "completed", "cancelled"},
    "in_progress": {"approved", "rejected", "completed", "cancelled"},
    "approved": set(), "rejected": set(), "completed": set(), "cancelled": set(),
}


def task_assigned(session: Session, task: GovernanceWorkItem, user_id: int) -> bool:
    if task.assignee_user_id is not None:
        return task.assignee_user_id == user_id
    if task.assignee_role_id is not None:
        return session.scalar(select(UserRole.id).where(UserRole.user_id == user_id,
                                                        UserRole.role_id == task.assignee_role_id).limit(1)) is not None
    return False


def create_work_item(session: Session, *, finding_id: int, kind: str, title: str,
                     description: str, assignee_user_id: int | None, assignee_role_id: int | None,
                     due_date: str, created_by_id: int) -> GovernanceWorkItem:
    if kind not in KINDS: raise ValueError("Select a valid work item type")
    if bool(assignee_user_id) == bool(assignee_role_id):
        raise ValueError("Assign the item to exactly one user or access role")
    if not session.get(Finding, finding_id): raise ValueError("Finding not found")
    if not session.get(UserAccount, created_by_id): raise ValueError("Creator not found")
    needed = 'governance.tasks.approve' if kind == 'risk_approval' else 'governance.tasks.resolve'
    if assignee_user_id:
        account = session.get(UserAccount, assignee_user_id)
        if not account or not account.is_active: raise ValueError("Choose an active user")
        role_ids = select(UserRole.role_id).where(UserRole.user_id==assignee_user_id)
        if not account.is_superuser and not session.scalar(select(RolePermission.id).where(
                RolePermission.role_id.in_(role_ids),RolePermission.permission==needed).limit(1)):
            raise ValueError("Selected user lacks the permission required for this task type")
    if assignee_role_id:
        role = session.get(AccessRole, assignee_role_id)
        if not role: raise ValueError("Choose a registered role")
        if not session.scalar(select(RolePermission.id).where(
               RolePermission.role_id==assignee_role_id,RolePermission.permission==needed).limit(1)):
            raise ValueError("Selected role lacks the permission required for this task type")
    title = title.strip(); description = description.strip()
    if not 4 <= len(title) <= 240: raise ValueError("Title must contain 4–240 characters")
    if len(description) > 5000: raise ValueError("Description too long")
    try: due = datetime.strptime(due_date, "%Y-%m-%d")
    except ValueError: raise ValueError("Due date must use YYYY-MM-DD") from None
    item = GovernanceWorkItem(finding_id=finding_id,kind=kind,title=title,description=description,
                              assignee_user_id=assignee_user_id,assignee_role_id=assignee_role_id,
                              created_by_id=created_by_id,due_at=due)
    session.add(item); session.flush()
    session.add(GovernanceWorkEvent(work_item_id=item.id,actor_user_id=created_by_id,event="created",
                                    to_status="pending",note="Work item created"))
    session.commit(); return item


def update_work_item(session: Session, *, item_id: int, actor_id: int, permissions: set[str],
                     status: str, rationale: str, review_date: str = "") -> GovernanceWorkItem:
    item = session.get(GovernanceWorkItem,item_id)
    if not item: raise ValueError("Work item not found")
    if status not in TRANSITIONS[item.status]: raise ValueError("Invalid work item transition")
    if item.kind == 'risk_approval' and status == 'completed':
        raise ValueError('Risk approvals must be approved or rejected, not completed')
    manager = 'governance.tasks.manage' in permissions
    if not (manager or task_assigned(session,item,actor_id)):
        raise PermissionError("This work item is not assigned to you")
    if status == 'cancelled' and not manager: raise PermissionError("Only managers can cancel work items")
    if status in {'approved','rejected'}:
        if item.kind != 'risk_approval': raise ValueError("Approval applies only to risk-approval items")
        if 'governance.tasks.approve' not in permissions: raise PermissionError("Risk-approval permission required")
    elif status not in {'cancelled'} and not manager and 'governance.tasks.resolve' not in permissions:
        raise PermissionError("Work-item processing permission required")
    rationale = rationale.strip()
    if len(rationale)<10 or len(rationale)>5000: raise ValueError("Provide 10–5000 characters of rationale")
    # A task approval is a real governance outcome only when the existing decision
    # workflow can record a signed-in, justified risk acceptance.
    if status == 'approved':
        record_authenticated_decision(session,item.finding_id,'accept_risk',actor_id,rationale,review_date,commit=False)
    old=item.status
    item.status=status; item.updated_at=utcnow()
    session.add(GovernanceWorkEvent(work_item_id=item.id,actor_user_id=actor_id,event='status_changed',
                                    from_status=old,to_status=status,note=rationale))
    session.commit(); return item


def reassign_work_item(session:Session,*,item_id:int,actor_id:int,assignee_user_id:int|None,
                       assignee_role_id:int|None,due_date:str,note:str) -> GovernanceWorkItem:
    """Only callable after a manager permission check at the HTTP boundary."""
    item=session.get(GovernanceWorkItem,item_id)
    if not item: raise ValueError('Work item not found')
    if item.status not in OPEN_STATUSES: raise ValueError('Only open work items can be reassigned')
    if bool(assignee_user_id)==bool(assignee_role_id): raise ValueError('Choose exactly one user or role')
    needed='governance.tasks.approve' if item.kind=='risk_approval' else 'governance.tasks.resolve'
    if assignee_user_id:
        user=session.get(UserAccount,assignee_user_id)
        if not user or not user.is_active: raise ValueError('Select an active user')
        if not user.is_superuser and not session.scalar(select(RolePermission.id).where(
              RolePermission.role_id.in_(select(UserRole.role_id).where(UserRole.user_id==user.id)),
              RolePermission.permission==needed).limit(1)):
            raise ValueError('Selected user lacks task permission')
    if assignee_role_id:
        if not session.scalar(select(RolePermission.id).where(RolePermission.role_id==assignee_role_id,
                          RolePermission.permission==needed).limit(1)):
            raise ValueError('Selected role lacks task permission')
    try: due=datetime.strptime(due_date,'%Y-%m-%d')
    except ValueError: raise ValueError('Due date must use YYYY-MM-DD') from None
    if not 8<=len(note.strip())<=5000: raise ValueError('Provide a reason for reassignment')
    old_assignee = (f'user:{item.assignee_user_id}' if item.assignee_user_id else f'role:{item.assignee_role_id}')
    new_assignee = (f'user:{assignee_user_id}' if assignee_user_id else f'role:{assignee_role_id}')
    old_due = item.due_at.date().isoformat()
    item.assignee_user_id=assignee_user_id; item.assignee_role_id=assignee_role_id
    item.due_at=due;item.updated_at=utcnow()
    history_note = f'{old_assignee} → {new_assignee}; due {old_due} → {due.date().isoformat()}. {note.strip()}'
    session.add(GovernanceWorkEvent(work_item_id=item.id,actor_user_id=actor_id,event='reassigned',
                                    from_status=item.status,to_status=item.status,note=history_note))
    session.commit();return item
