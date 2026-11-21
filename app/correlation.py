"""Conservative cross-source correlation suggestions, never automatic merges.

The canonical per-source finding identities are deliberately unchanged. Different
scanner plugins are *candidates* for analyst review when evidence overlaps.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload
from app.models import Finding

_CVE=re.compile(r'CVE-\d{4}-\d{4,}',re.IGNORECASE)

@dataclass(frozen=True)
class Candidate:
    finding: Finding
    confidence: str
    reason: str


def _cves(text: str | None)->set[str]:
    return {x.upper() for x in _CVE.findall(text or '')}


def _title(text: str)->str:
    return ' '.join(text.casefold().split())


def find_candidates(session:Session,finding_id:int,limit:int=10)->list[Candidate]:
    reference=session.scalar(select(Finding).where(Finding.id==finding_id).options(joinedload(Finding.vulnerability)))
    if reference is None:return []
    vuln=reference.vulnerability
    cves=_cves(vuln.cve)
    potential=session.scalars(select(Finding).where(Finding.asset_id==reference.asset_id,
                     Finding.id!=reference.id).options(joinedload(Finding.vulnerability)).order_by(Finding.id)).all()
    matches=[]
    for other in potential:
        peer=other.vulnerability
        if peer.source==vuln.source:continue
        # Service locations that differ can be different instances of the same CVE.
        same_location=bool(reference.location and other.location and reference.location==other.location)
        shared=cves & _cves(peer.cve)
        if shared:
            reason='Shared '+', '.join(sorted(shared))
            matches.append(Candidate(other,'High' if same_location else 'Review',reason))
        elif (_title(vuln.title)==_title(peer.title) and len(_title(vuln.title))>=12
              and (not reference.location or not other.location or same_location)):
            matches.append(Candidate(other,'Review','Matching normalized title'))
    return sorted(matches,key=lambda item:(item.confidence!='High',item.finding.id))[:limit]
