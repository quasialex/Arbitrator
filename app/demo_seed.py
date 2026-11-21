"""Explicit opt-in fictional campaign seeding, never run during app startup."""
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from app.models import (Engagement, Assessment, Asset, Finding, Observation,
                        ImportBatch, Owner, RoutingRule, GovernanceWorkItem,
                        GovernanceDecision, DecisionMaker)

# Account and access-role records are deliberately excluded: they can coexist
# with a new, clean assessment workspace. Everything domain-related must be empty.
_DOMAIN_TABLES = (Engagement, Assessment, Asset, Finding, Observation,
                  ImportBatch, Owner, RoutingRule, GovernanceWorkItem,
                  GovernanceDecision, DecisionMaker)


def sample_data_status(session: Session) -> dict:
    counts = {model.__tablename__: session.scalar(select(func.count()).select_from(model))
              for model in _DOMAIN_TABLES}
    empty = not any(counts.values())
    return {'can_load': empty,
            'existing_demo': bool(session.scalar(select(Engagement.id).where(
                Engagement.name == 'Atlas Labs — 2026 Research'))),
            'counts': counts}


def load_sample_campaign(session: Session) -> dict:
    """Install known samples only when the workspace has no domain records.

    Does not modify users, access roles, existing findings or import history.
    A database-level separate deployment/backup is preferable for real use.
    """
    status = sample_data_status(session)
    if not status['can_load']:
        raise ValueError('Sample data can be loaded only into an empty assessment workspace; existing data was preserved.')
    # Imported here to keep scripts independent of the server and to preserve the
    # original deterministic fixture definitions and importer behavior.
    from scripts.seed_demo import seed_campaign
    from scripts.seed_tasks import seed_work_items
    seed_campaign(session)
    seed_work_items(session)
    return {
        'assessments': session.scalar(select(func.count()).select_from(Assessment)),
        'assets': session.scalar(select(func.count()).select_from(Asset)),
        'findings': session.scalar(select(func.count()).select_from(Finding)),
        'observations': session.scalar(select(func.count()).select_from(Observation)),
        'tasks': session.scalar(select(func.count()).select_from(GovernanceWorkItem)),
    }
