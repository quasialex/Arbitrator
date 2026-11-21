"""Independent assessment and risk governance application."""
from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import date, datetime
from math import ceil
from pathlib import Path
from urllib.parse import urlencode, quote

from fastapi import FastAPI, Depends, Request, UploadFile, File, Form, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select, func, or_, and_, case
from sqlalchemy.orm import Session, joinedload, selectinload

from app.database import get_session, init_db, SessionLocal
from app.importers import ImportValidationError, MAX_UPLOAD_BYTES
from app.connectors import (ConnectorError, has_tenable_credentials, save_tenable_credentials,
    delete_tenable_credentials, export_tenable_vulnerabilities, check_tenable_connection, check_servicenow_connection, connection_check, record_connection_check, clear_connection_check,
    has_servicenow_credentials, save_servicenow_credentials, _connector_row, _read_credentials, read_servicenow_credentials, _fernet)
from app.models import (Asset, Finding, Vulnerability, Observation, GovernanceDecision,
                        ImportBatch, Assessment, Engagement, Owner, DecisionMaker, AssetTeam, GovernanceRole, RoutingRule, UserAccount, AccessRole, UserRole, LoginSession, GovernanceWorkItem, GovernanceWorkEvent, UserPreference, UserConnectorCredential, ServiceNowGroupMapping, ServiceNowIncidentLink, ServiceNowSyncRecord)
from app.services import import_findings, create_assessment
from app.correlation import find_candidates
from app.servicenow import configure_group, create_incident, refresh_incident, sync_finding_notes, search_groups, select_group
from app.routing import create_routing_rule, update_routing_rule, apply_routing, route_finding
from app.auth import (COOKIE_NAME, PERMISSIONS, seed_roles, hash_password, verify_password, create_user,
                      login, revoke_session, resolve_session, assign_roles, update_role)
import secrets
import json
from app.governance_tasks import KINDS, OPEN_STATUSES, create_work_item, update_work_item, task_assigned, reassign_work_item
from app.workflows import (edit_asset, assign_assets, assign_finding, create_team,
                           create_decision_maker, record_decision, record_authenticated_decision, update_team, update_decision_maker)

BASE_DIR = Path(__file__).resolve().parent
SEVERITIES = ("Critical", "High", "Medium", "Low", "Informational")
NETWORK_CLASSES = ("Internal", "External", "Review required")
DEFAULT_ROLES = ("Security lead", "Security reviewer", "Risk approver", "Risk officer",
                 "Security manager", "Risk lead", "Business service representative")
PAGE_SIZES = (10, 20, 50, 100)


@asynccontextmanager
async def lifespan(_):
    init_db()
    with SessionLocal() as session: seed_roles(session)
    yield


app = FastAPI(title="Arbitrator", version="0.18.0", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


def required_permission(path: str, method: str) -> str | None:
    """Fail-closed route policy: every nonpublic endpoint requires a listed permission."""
    if path.startswith('/admin/'): return 'accounts.manage'
    if path.startswith('/work-items'):
        if method == 'GET' or path.endswith('/action'): return 'governance.tasks.read'
        if path.endswith('/create'): return 'governance.tasks.create'
        return 'governance.tasks.manage'
    if path.startswith('/integrations'): return None
    if path.startswith('/account/'): return None  # own profile requires sign-in, not dashboard permission
    if path.startswith('/assessments'):
        return 'assessments.write' if method != 'GET' else 'assessments.read'
    if path.startswith('/imports'):
        return 'imports.write' if method != 'GET' else 'imports.read'
    if path.startswith('/observations'): return 'observations.read'
    if path.startswith('/assets'):
        return 'assets.write' if method != 'GET' else 'assets.read'
    if path.startswith('/findings'):
        if method == 'GET': return 'findings.read'
        if path.endswith('/decisions'): return 'governance.approve'
        return 'findings.assign'
    if path.startswith('/governance'): return 'governance.read'
    if path.startswith('/ownership/routing'):
        return 'routing.write' if method != 'GET' else 'routing.read'
    if path.startswith('/ownership/teams'):
        return 'teams.write' if method != 'GET' else 'teams.read'
    if path.startswith('/ownership/approvers') or path.startswith('/ownership/roles'):
        return 'governance.directory'
    if path.startswith('/ownership'): return 'teams.read'
    if path == '/': return 'dashboard.read'
    return None  # unknown paths fall through to 404


@app.middleware('http')
async def verify_identity(request: Request, call_next):
    path=request.url.path
    if path in {'/login','/health'} or path.startswith('/static/'):
        return await call_next(request)
    raw=request.cookies.get(COOKIE_NAME,'')
    with SessionLocal() as db:
        resolved=resolve_session(db, raw)
        if not resolved:
            if request.method == 'GET': return RedirectResponse('/login',status_code=303)
            return PlainTextResponse('Authentication required',status_code=401)
        user,permissions,csrf=resolved
        request.state.current_user=user
        request.state.permissions=permissions
        request.state.csrf_token=csrf
    if path == '/logout' or path == '/account/password':
        return await call_next(request)
    permission=required_permission(path,request.method)
    if permission and permission not in permissions:
        return PlainTextResponse('Permission denied: '+permission,status_code=403)
    return await call_next(request)


def require_csrf(request: Request, csrf_token: str = Form(...)):
    expected=getattr(request.state,'csrf_token','')
    if not expected or not secrets.compare_digest(expected,csrf_token):
        raise HTTPException(403,'Invalid CSRF token')


def page(request: Request, name: str, **data):
    data.setdefault("current_user", getattr(request.state, "current_user", None))
    data.setdefault("can", lambda perm: perm in getattr(request.state, "permissions", set()))
    user = data["current_user"]
    preference = None
    if user:
        with SessionLocal() as db:
            preference = db.get(UserPreference, user.id)
    data.setdefault("theme", preference.theme if preference and preference.theme in {"light","dark"} else "light")
    response=templates.TemplateResponse(request=request, name=name, context=data)
    response.headers['Cache-Control']='no-store'
    return response


def redirect_to(path: str, **updates):
    if updates:
        path += ("&" if "?" in path else "?") + urlencode(updates)
    return RedirectResponse(path, status_code=303)


def page_href(request: Request, **changes):
    values = dict(request.query_params)
    values.update({k: str(v) for k, v in changes.items()})
    return request.url.path + "?" + urlencode(values)


def paginate(session: Session, stmt, requested_page: int, page_size: int):
    size = page_size if page_size in PAGE_SIZES else 10
    count = session.scalar(select(func.count()).select_from(stmt.order_by(None).subquery()))
    pages = max(1, ceil(count / size))
    current = min(max(requested_page, 1), pages)
    records = session.scalars(stmt.limit(size).offset((current - 1) * size)).all()
    return records, dict(page=current, pages=pages, total=count, page_size=size)



def ordered(stmt, sort: str, direction: str, allowed: dict, default_key: str = "id", default_dir: str = "desc", tie=None):
    """Whitelisted SQL sorting BEFORE pagination, with deterministic tie-breaking."""
    key = sort if sort in allowed else default_key
    dir_value = direction if direction in {"asc", "desc"} else default_dir
    col = allowed[key]
    stmt = stmt.order_by(None).order_by(col.asc() if dir_value == "asc" else col.desc())
    if tie is not None and col is not tie:
        stmt = stmt.order_by(tie.desc())
    return stmt, {"key": key, "direction": dir_value}

SEVERITY_RANK = case((Finding.severity=="Critical",4),(Finding.severity=="High",3),
                     (Finding.severity=="Medium",2),(Finding.severity=="Low",1),else_=0)

def teams(session: Session):
    return session.scalars(select(Owner).order_by(Owner.name)).all()


def approvers(session: Session):
    return session.scalars(select(DecisionMaker).where(DecisionMaker.active.is_(True)).order_by(DecisionMaker.name)).all()


def governance_roles(session: Session):
    if session.scalar(select(func.count()).select_from(GovernanceRole)) == 0:
        session.add_all(GovernanceRole(name=name, description="Initial governance role") for name in DEFAULT_ROLES)
        session.commit()
    return session.scalars(select(GovernanceRole).where(GovernanceRole.active.is_(True)).order_by(GovernanceRole.name)).all()


def validate_governance_role(session: Session, proposed: str):
    if not any(r.name.casefold() == proposed.strip().casefold() for r in governance_roles(session)):
        raise ValueError("Choose a predefined active governance role")


def require_contact_email(email: str):
    if not email.strip() or len(email) > 254 or "@" not in email or email.strip().endswith("@"):
        raise ValueError("A contact email is required for new directory entries")


def effective_owner_predicate():
    return Finding.assigned_owner_id


def due_review_query():
    latest_ids = select(func.max(GovernanceDecision.id)).group_by(GovernanceDecision.finding_id)
    return select(GovernanceDecision.finding_id).where(
        GovernanceDecision.id.in_(latest_ids),
        GovernanceDecision.review_date.is_not(None),
        GovernanceDecision.review_date <= date.today().isoformat(),
    )


def unassigned_query():
    return select(Finding).where(effective_owner_predicate().is_(None))


@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request, session: Session = Depends(get_session)):
    totals = {
        "assets": session.scalar(select(func.count()).select_from(Asset)),
        "assessments": session.scalar(select(func.count()).select_from(Assessment)),
        "findings": session.scalar(select(func.count()).select_from(Finding)),
        "observations": session.scalar(select(func.count()).select_from(Observation)),
        "decisions": session.scalar(select(func.count()).select_from(GovernanceDecision)),
        "unassigned": session.scalar(select(func.count()).select_from(unassigned_query().subquery())),
        "pending": session.scalar(select(func.count()).select_from(Finding).join(Asset).where(
            Finding.workflow_state == "pending_triage", effective_owner_predicate().is_not(None))),
        "decided": session.scalar(select(func.count()).select_from(Finding).where(Finding.workflow_state != "pending_triage")),
        "review_due": session.scalar(select(func.count()).select_from(Finding).where(Finding.id.in_(due_review_query()))),
    }
    severities = dict(session.execute(select(Finding.severity, func.count(Finding.id)).group_by(Finding.severity)).all())
    latest = session.scalars(select(Finding).options(joinedload(Finding.asset), joinedload(Finding.assigned_owner), joinedload(Finding.vulnerability))
                             .order_by(Finding.id.desc()).limit(5)).all()
    task_counts = {"mine":0,"overdue":0,"approvals":0}
    if 'governance.tasks.read' in request.state.permissions:
        assigned = work_item_scope(session,request.state.current_user,request.state.permissions)
        task_counts['mine']=session.scalar(select(func.count()).select_from(GovernanceWorkItem).where(
            assigned,GovernanceWorkItem.status.in_(OPEN_STATUSES)))
        task_counts['overdue']=session.scalar(select(func.count()).select_from(GovernanceWorkItem).where(
            assigned,GovernanceWorkItem.status.in_(OPEN_STATUSES),
            GovernanceWorkItem.due_at<datetime.combine(date.today(),datetime.min.time())))
        task_counts['approvals']=session.scalar(select(func.count()).select_from(GovernanceWorkItem).where(
            assigned,GovernanceWorkItem.kind=='risk_approval',GovernanceWorkItem.status.in_(OPEN_STATUSES)))
    return page(request, "dashboard.html", totals=totals, severities=severities,
                latest=latest, task_counts=task_counts,
                today=date.today(), active="dashboard")


@app.get("/assessments", response_class=HTMLResponse)
def assessments_page(request: Request, page_num: int = 1, page_size: int = 10, sort: str = "id", direction: str = "desc",
                     session: Session = Depends(get_session)):
    stmt = select(Assessment).options(joinedload(Assessment.engagement)).order_by(Assessment.id.desc())
    stmt = stmt.join(Engagement)
    stmt, sorting = ordered(stmt,sort,direction,{"id": Assessment.id,"name":func.lower(Assessment.name),
        "engagement":func.lower(Engagement.name),"type":Assessment.assessment_type,
        "start":Assessment.started_at,"end":Assessment.ended_at,"status":Assessment.status},tie=Assessment.id)
    rows, paging = paginate(session, stmt, page_num, page_size)
    return page(request, "assessments.html", assessments=rows, paging=paging, sorting=sorting,
                link=lambda **kw: page_href(request, **kw), active="assessments",
                error=request.query_params.get("error"))


@app.post("/assessments", dependencies=[Depends(require_csrf)])
def new_assessment(engagement_name: str = Form(...), assessment_name: str = Form(...),
                   client: str = Form(default="Synthetic organization"), scope: str = Form(default=""),
                   methodology: str = Form(default="Penetration test"), assessment_type: str = Form(default="Hybrid"),
                   started_on: str = Form(default=""),
                   ended_on: str = Form(default=""), session: Session = Depends(get_session)):
    try:
        assessment = create_assessment(session, engagement_name, assessment_name, client, scope, methodology, started_on, ended_on, assessment_type)
    except ValueError as exc:
        return redirect_to("/assessments", error=str(exc))
    return redirect_to(f"/assessments/{assessment.id}")


@app.get("/assessments/{assessment_id}", response_class=HTMLResponse)
def assessment_detail(assessment_id: int, request: Request, page_num: int = 1,
                      page_size: int = 10, sort: str = 'id', direction: str = 'desc',
                      batch_sort: str = 'id', batch_direction: str = 'desc',
                      session: Session = Depends(get_session)):
    assessment = session.scalar(select(Assessment).where(Assessment.id == assessment_id)
                                .options(joinedload(Assessment.engagement)))
    if assessment is None:
        raise HTTPException(404, "Assessment not found")
    batch_stmt, batch_sorting = ordered(select(ImportBatch).where(ImportBatch.assessment_id==assessment_id),
       batch_sort,batch_direction,{'id':ImportBatch.id,'file':func.lower(ImportBatch.original_filename),
       'format':ImportBatch.source,'rows':ImportBatch.row_count},tie=ImportBatch.id)
    batches = session.scalars(batch_stmt).all()
    stmt = (select(Finding).join(Observation).join(ImportBatch)
            .where(ImportBatch.assessment_id == assessment_id)
            .options(joinedload(Finding.asset), joinedload(Finding.assigned_owner), joinedload(Finding.vulnerability))
            .distinct().order_by(Finding.id.desc()))
    stmt=stmt.join(Vulnerability,Finding.vulnerability_id==Vulnerability.id).join(Asset,Finding.asset_id==Asset.id)
    stmt,sorting=ordered(stmt,sort,direction,{'id':Finding.id,'finding':func.lower(Vulnerability.title),
              'asset':func.lower(Asset.display_name),'severity':SEVERITY_RANK},tie=Finding.id)
    findings, paging = paginate(session, stmt, page_num, page_size)
    return page(request, "assessment_detail.html", assessment=assessment,
                batches=batches, findings=findings, paging=paging, sorting=sorting, batch_sorting=batch_sorting,
                link=lambda **kw: page_href(request, **kw), active="assessments")


@app.get("/imports", response_class=HTMLResponse)
def imports_page(request: Request, page_num: int = 1, page_size: int = 10, sort: str = "id", direction: str = "desc",
                 session: Session = Depends(get_session)):
    stmt = select(ImportBatch).join(Assessment).options(joinedload(ImportBatch.assessment))
    stmt, sorting = ordered(stmt,sort,direction,{"id":ImportBatch.id,"file":func.lower(ImportBatch.original_filename),
        "assessment":func.lower(Assessment.name),"format":ImportBatch.source,
        "rows":ImportBatch.row_count,"date":ImportBatch.imported_at},tie=ImportBatch.id)
    batches, paging = paginate(session,stmt,page_num,page_size)
    assessments = session.scalars(select(Assessment).options(joinedload(Assessment.engagement))
                                  .order_by(Assessment.id.desc())).all()
    return page(request, "imports.html", batches=batches, assessments=assessments, sorting=sorting,
                paging=paging, link=lambda **kw: page_href(request, **kw),
                selected_assessment=request.query_params.get("assessment_id"),
                error=request.query_params.get('error'), result=None, active="imports",
                notice=request.query_params.get('notice'),
                tenable_connected=has_tenable_credentials(session,connector_owner_id(session)))


@app.post("/imports", response_class=HTMLResponse, dependencies=[Depends(require_csrf)])
async def upload_findings(request: Request, source: str = Form(...), assessment_id: int = Form(...),
                          uploaded: UploadFile = File(...), session: Session = Depends(get_session)):
    suffixes = {"generic_csv": (".csv",), "nessus_csv": (".csv",),
                "sec1_csv": (".csv",), "old_sec1_csv": (".csv",), "nuclei_jsonl": (".jsonl",),
                "plextrac_json": (".json", ".ptrac"), "nessus_html": (".html", ".htm"),
                "tenable_json": (".json",)}
    expected = suffixes.get(source)
    if not expected or not uploaded.filename or not uploaded.filename.lower().endswith(expected):
        error, result = "Select a supported source and upload the corresponding file type", None
    else:
        raw = await uploaded.read(MAX_UPLOAD_BYTES + 1)
        try:
            result = import_findings(session, raw, uploaded.filename, source, assessment_id=assessment_id)
            error = None
        except ImportValidationError as exc:
            error, result = str(exc), None
    batches = session.scalars(select(ImportBatch).options(joinedload(ImportBatch.assessment))
                             .order_by(ImportBatch.id.desc()).limit(25)).all()
    assessments = session.scalars(select(Assessment).options(joinedload(Assessment.engagement))
                                  .order_by(Assessment.id.desc())).all()
    return page(request, "imports.html", batches=batches, assessments=assessments, sorting={"key":"id","direction":"desc"},
                paging=None, selected_assessment=str(assessment_id), error=error, result=result,
                tenable_connected=has_tenable_credentials(session,connector_owner_id(session)),
                link=lambda **kw:page_href(request,**kw), active="imports")


@app.get("/observations", response_class=HTMLResponse)
def observations_page(request: Request, source: str = "", assessment_id: str = "", sort: str = "id", direction: str = "desc",
                      page_num: int = 1, page_size: int = 10,
                      session: Session = Depends(get_session)):
    stmt = (select(Observation).join(ImportBatch)
            .options(joinedload(Observation.finding).joinedload(Finding.vulnerability),
                     joinedload(Observation.finding).joinedload(Finding.asset),
                     joinedload(Observation.batch).joinedload(ImportBatch.assessment))
            .order_by(Observation.id.desc()))
    if source in {"generic_csv", "nessus_csv", "sec1_csv", "old_sec1_csv", "nuclei_jsonl",
                  "plextrac_json", "tenable_json", "nessus_html"}:
        stmt = stmt.where(ImportBatch.source == source)
    if assessment_id.isdecimal():
        stmt = stmt.where(ImportBatch.assessment_id == int(assessment_id))
    stmt = stmt.join(Finding, Observation.finding_id==Finding.id).join(Asset,Finding.asset_id==Asset.id)               .join(Vulnerability,Finding.vulnerability_id==Vulnerability.id).join(Assessment,ImportBatch.assessment_id==Assessment.id)
    stmt, sorting = ordered(stmt,sort,direction,{"id":Observation.id,"finding":func.lower(Vulnerability.title),
        "asset":func.lower(Asset.display_name),"assessment":func.lower(Assessment.name),
        "format":ImportBatch.source,"date":Observation.detected_at},tie=Observation.id)
    rows, paging = paginate(session, stmt, page_num, page_size)
    assessments = session.scalars(select(Assessment).options(joinedload(Assessment.engagement))
                                  .order_by(Assessment.id.desc())).all()
    return page(request, "observations.html", observations=rows, assessments=assessments, sorting=sorting,
                paging=paging, selected=dict(source=source, assessment_id=assessment_id),
                link=lambda **kw: page_href(request, **kw), active="observations")


@app.get("/ownership")
def former_directory():
    return redirect_to("/ownership/teams")


@app.post("/ownership/teams", dependencies=[Depends(require_csrf)])
def add_team(name: str = Form(...), email: str = Form(default=""), session: Session = Depends(get_session)):
    try:
        require_contact_email(email)
        create_team(session, name, email)
    except ValueError as exc:
        return redirect_to("/ownership/teams", error=str(exc))
    return redirect_to("/ownership/teams", notice="Remediation team created")


@app.post("/ownership/approvers", dependencies=[Depends(require_csrf)])
def add_approver(name: str = Form(...), role: str = Form(...), email: str = Form(default=""),
                 session: Session = Depends(get_session)):
    try:
        require_contact_email(email)
        validate_governance_role(session, role)
        create_decision_maker(session, name, role, email)
    except ValueError as exc:
        return redirect_to("/ownership/approvers", error=str(exc))
    return redirect_to("/ownership/approvers", notice="Decision maker created")


@app.post("/ownership/teams/{team_id}", dependencies=[Depends(require_csrf)])
def edit_team_record(team_id: int, name: str = Form(...), email: str = Form(default=""),
                     session: Session = Depends(get_session)):
    try:
        require_contact_email(email)
        update_team(session, team_id, name, email)
    except ValueError as exc:
        return redirect_to("/ownership/teams", error=str(exc))
    return redirect_to("/ownership/teams", notice="Remediation team updated")


@app.post("/ownership/approvers/{person_id}", dependencies=[Depends(require_csrf)])
def edit_approver_record(person_id: int, name: str = Form(...), role: str = Form(...),
                         email: str = Form(default=""), active: str = Form(default=""),
                         session: Session = Depends(get_session)):
    try:
        require_contact_email(email)
        validate_governance_role(session, role)
        update_decision_maker(session, person_id, name, role, email, active == "on")
    except ValueError as exc:
        return redirect_to("/ownership/approvers", error=str(exc))
    return redirect_to("/ownership/approvers", notice="Decision maker updated")


@app.get("/ownership/roles", response_class=HTMLResponse)
def roles_page(request: Request, session: Session = Depends(get_session)):
    governance_roles(session)
    return page(request, "roles.html", roles=session.scalars(select(GovernanceRole).order_by(GovernanceRole.name)).all(), active="ownership",
                error=request.query_params.get("error"), notice=request.query_params.get("notice"))


@app.post("/ownership/roles", dependencies=[Depends(require_csrf)])
def create_role(name: str = Form(...), description: str = Form(default=""),
                session: Session = Depends(get_session)):
    name = name.strip()
    if len(name) < 2 or len(name) > 120 or len(description) > 350:
        return redirect_to("/ownership/roles", error="Role name must contain 2–120 characters; description max 350")
    governance_roles(session)
    if session.scalar(select(GovernanceRole).where(func.lower(GovernanceRole.name) == name.lower())):
        return redirect_to("/ownership/roles", error="Role already exists")
    session.add(GovernanceRole(name=name, description=description.strip()))
    session.commit()
    return redirect_to("/ownership/roles", notice="Governance role created")


@app.post("/ownership/roles/{role_id}", dependencies=[Depends(require_csrf)])
def edit_role(role_id: int, name: str = Form(...), description: str = Form(default=""),
              active: str = Form(default=""), session: Session = Depends(get_session)):
    role = session.get(GovernanceRole, role_id)
    if role is None: raise HTTPException(404, "Role not found")
    name = name.strip()
    if not 2 <= len(name) <= 120 or len(description) > 350:
        return redirect_to("/ownership/roles", error="Invalid role name or description")
    other = session.scalar(select(GovernanceRole).where(func.lower(GovernanceRole.name) == name.lower(),
                                                       GovernanceRole.id != role_id))
    if other:
        return redirect_to("/ownership/roles", error="Role already exists")
    # Existing people retain their historic assignment string for traceability;
    # changing a role catalog entry does not silently change their role.
    role.name, role.description, role.active = name, description.strip(), active == "on"
    session.commit()
    return redirect_to("/ownership/roles", notice="Role updated; existing people retain their assigned role until edited")


# Legacy v0.5 classification rule URL redirects to the global responsibility mapping screen.
@app.get("/assets/rules")
def former_classification_rules():
    return redirect_to("/ownership/routing", notice="Classification policy was retired; configure global ownership routing here")


@app.get("/ownership/teams", response_class=HTMLResponse)
def teams_directory(request: Request, page_num: int = 1, page_size: int = 10, sort: str = "name", direction: str = "asc",
                    session: Session = Depends(get_session)):
    stmt, sorting = ordered(select(Owner),sort,direction,{"name":func.lower(Owner.name),"contact":func.lower(Owner.email)},
                            default_key="name",default_dir="asc",tie=Owner.id)
    groups, paging = paginate(session,stmt,page_num,page_size)
    return page(request, "teams.html", groups=groups, paging=paging, sorting=sorting,
                link=lambda **kw: page_href(request, **kw), active="ownership",
                error=request.query_params.get("error"), notice=request.query_params.get("notice"))


@app.get("/ownership/teams/{team_id}/edit", response_class=HTMLResponse)
def team_edit_page(team_id: int, request: Request, session: Session = Depends(get_session)):
    team = session.get(Owner, team_id)
    if team is None: raise HTTPException(404, "Team not found")
    return page(request, "team_edit.html", team=team, active="ownership", error=request.query_params.get("error"))


@app.get("/ownership/approvers", response_class=HTMLResponse)
def approvers_directory(request: Request, page_num: int = 1, page_size: int = 10, sort: str = "name", direction: str = "asc",
                        session: Session = Depends(get_session)):
    stmt, sorting = ordered(select(DecisionMaker),sort,direction,{"name":func.lower(DecisionMaker.name),
        "role":func.lower(DecisionMaker.role),"email":func.lower(DecisionMaker.email)},
        default_key="name",default_dir="asc",tie=DecisionMaker.id)
    people, paging = paginate(session,stmt,page_num,page_size)
    return page(request, "approvers.html", people=people, paging=paging, sorting=sorting,
                link=lambda **kw: page_href(request, **kw), roles=governance_roles(session),
                active="ownership", error=request.query_params.get("error"), notice=request.query_params.get("notice"))


@app.get("/ownership/routing", response_class=HTMLResponse)
def routing_page(request: Request, page_num: int = 1, page_size: int = 10, sort: str = "id", direction: str = "asc",
                 session: Session = Depends(get_session)):
    stmt = select(RoutingRule).join(Owner).options(joinedload(RoutingRule.team))
    stmt, sorting = ordered(stmt,sort,direction,{"id":RoutingRule.id,"team":func.lower(Owner.name),
        "asset":RoutingRule.asset_kind,"finding":RoutingRule.finding_kind},default_dir="asc",tie=RoutingRule.id)
    rules,paging = paginate(session,stmt,page_num,page_size)
    # Bounded suggestions keep the form responsive even with large finding inventories.
    import ipaddress
    recent_findings = session.execute(
        select(Finding.id, Vulnerability.title, Asset.display_name)
        .join(Finding.vulnerability).join(Finding.asset)
        .order_by(Finding.id.desc()).limit(60)
    ).all()
    recent_assets = session.scalars(select(Asset).order_by(Asset.id.desc()).limit(120)).all()
    hostnames, service_codes, networks = set(), set(), set()
    for asset in recent_assets:
        hostname = (asset.hostname or asset.identity_key or '').strip()
        if hostname and '.' in hostname and any(c.isalpha() for c in hostname) and '://' not in hostname:
            hostnames.add(hostname)
        if asset.service_code:
            service_codes.add(asset.service_code)
        ip = asset.ip_address or asset.identity_key
        try:
            address = ipaddress.ip_address(ip)
            networks.add(f'{address}/{address.max_prefixlen}')
        except ValueError:
            pass
    route_suggestions = {
        'findings': [{'id': id_, 'title': title, 'asset': asset}
                     for id_, title, asset in recent_findings],
        'hostnames': sorted(hostnames, key=str.casefold),
        'service_codes': sorted(service_codes, key=str.casefold),
        'cidr': sorted(networks),
    }
    return page(request, "routing.html", rules=rules, paging=paging, sorting=sorting,
                link=lambda **kw: page_href(request, **kw), groups=teams(session),
                route_suggestions=route_suggestions,
                error=request.query_params.get("error"), notice=request.query_params.get("notice"), active="routing")


@app.post("/ownership/routing", dependencies=[Depends(require_csrf)])
def new_routing_rule(team_id: int = Form(...), asset_kind: str = Form("none"),
                     asset_pattern: str = Form(""), finding_kind: str = Form("none"),
                     finding_pattern: str = Form(""), session: Session = Depends(get_session)):
    try:
        create_routing_rule(session, team_id, asset_kind, asset_pattern, finding_kind, finding_pattern)
    except ValueError as exc:
        return redirect_to("/ownership/routing", error=str(exc))
    return redirect_to("/ownership/routing", notice="Global rule saved. Apply rules to existing findings")


@app.get("/ownership/routing/{rule_id}/edit", response_class=HTMLResponse)
def edit_routing_page(rule_id: int, request: Request, session: Session = Depends(get_session)):
    rule = session.get(RoutingRule, rule_id)
    if rule is None: raise HTTPException(404, "Rule not found")
    return page(request, "routing_edit.html", rule=rule, groups=teams(session), active="routing",
                error=request.query_params.get("error"))


@app.post("/ownership/routing/{rule_id}/edit", dependencies=[Depends(require_csrf)])
def save_routing_rule(rule_id: int, team_id: int = Form(...), asset_kind: str = Form("none"),
                      asset_pattern: str = Form(""), finding_kind: str = Form("none"),
                      finding_pattern: str = Form(""), session: Session = Depends(get_session)):
    try: update_routing_rule(session, rule_id, team_id, asset_kind, asset_pattern, finding_kind, finding_pattern)
    except ValueError as exc: return redirect_to(f"/ownership/routing/{rule_id}/edit", error=str(exc))
    return redirect_to("/ownership/routing", notice="Rule updated. Explicitly reapply to change existing findings")


@app.post("/ownership/routing/apply", dependencies=[Depends(require_csrf)])
def apply_team_routing(session: Session = Depends(get_session)):
    counts = apply_routing(session)
    return redirect_to("/ownership/routing", notice=(f"Evaluated {counts['total']} findings: "
        f"{counts['matched']} routed, {counts['unassigned']} unassigned, "
        f"{counts['conflicts']} conflicts; {counts['preserved']} manual assignments kept"))


@app.post('/ownership/routing/apply-scoped', dependencies=[Depends(require_csrf)])
def apply_scoped_routing(request:Request,scope:str=Form('finding'),pattern:str=Form(''),
                         session: Session=Depends(get_session)):
    import ipaddress
    import regex
    if scope == 'all':
        return redirect_to('/ownership/routing',error='Use the dedicated Re-evaluate all findings button for a full run')
    if scope not in {'finding','hostname','service_code','cidr','team'}:
        return redirect_to('/ownership/routing',error='Invalid evaluation scope')
    pattern=pattern.strip()
    if not pattern or len(pattern)>180:
        return redirect_to('/ownership/routing',error='Specify a scope pattern (up to 180 characters)')
    if scope == 'finding' and (not pattern.isdecimal() or session.get(Finding,int(pattern)) is None):
        return redirect_to('/ownership/routing',error='Choose a valid finding ID')
    network=None
    if scope=='cidr':
        try: network=ipaddress.ip_network(pattern,strict=False)
        except ValueError: return redirect_to('/ownership/routing',error='Enter a valid network CIDR')
    if scope=='team':
        if not pattern.isdigit() or not session.get(Owner,int(pattern)):
            return redirect_to('/ownership/routing',error='Select a valid remediation team')
    scope_matcher=None
    if scope in {'hostname','service_code'}:
        try: scope_matcher=regex.compile(pattern,regex.I|regex.VERSION1)
        except regex.error: return redirect_to('/ownership/routing',error='Invalid regex pattern')
    stats={'total':0,'matched':0,'conflicts':0,'unassigned':0,'preserved':0}
    for f in session.scalars(select(Finding).options(joinedload(Finding.asset),joinedload(Finding.vulnerability))).all():
        a=f.asset
        if scope=='finding' and str(f.id)!=pattern: continue
        if scope=='team' and str(f.assigned_owner_id or '')!=pattern: continue
        if scope=='hostname':
            try:
                if not scope_matcher.search(a.hostname or a.identity_key,timeout=.02): continue
            except TimeoutError: continue
        if scope=='service_code':
            try:
                if not scope_matcher.search(a.service_code or '',timeout=.02): continue
            except TimeoutError: continue
        if scope=='cidr':
            try:
                if ipaddress.ip_address(a.ip_address or a.identity_key) not in network: continue
            except ValueError:continue
        stats['total']+=1
        if f.assignment_source=='manual': stats['preserved']+=1;continue
        route_finding(session,f)
        if f.assignment_source=='rule':stats['matched']+=1
        if f.assignment_source=='conflict':stats['conflicts']+=1
        if f.assigned_owner_id is None:stats['unassigned']+=1
    session.commit()
    return redirect_to('/ownership/routing',notice=f"Evaluated {stats['total']} scoped findings: {stats['matched']} routed, {stats['unassigned']} unassigned, {stats['conflicts']} conflicts; {stats['preserved']} manual assignments preserved")


@app.get("/assets", response_class=HTMLResponse)
def assets_page(request: Request, q: str = "", exposure: str = "", owner: str = "", sort: str = "name", direction: str = "asc",
                page_num: int = 1, page_size: int = 10, session: Session = Depends(get_session)):
    stmt = select(Asset).options(selectinload(Asset.memberships).joinedload(AssetTeam.team)).order_by(Asset.display_name, Asset.id)
    if q.strip():
        qlike = "%" + q.strip()[:100] + "%"
        stmt = stmt.where(or_(Asset.display_name.ilike(qlike), Asset.identity_key.ilike(qlike),
                              Asset.external_ref.ilike(qlike), Asset.service_code.ilike(qlike)))
    if exposure in NETWORK_CLASSES:
        stmt = stmt.where(Asset.exposure == exposure)
    if owner == "unassigned":
        stmt = stmt.where(~Asset.memberships.any())
    elif owner.isdecimal():
        stmt = stmt.where(Asset.memberships.any(AssetTeam.team_id == int(owner)))
    stmt, sorting = ordered(stmt,sort,direction,{"id":Asset.id,"identifier":func.lower(Asset.identity_key),
        "name":func.lower(Asset.display_name),"service":func.lower(Asset.service_code),
        "exposure":Asset.exposure},default_key="name",default_dir="asc",tie=Asset.id)
    rows, paging = paginate(session, stmt, page_num, page_size)
    return page(request, "assets.html", assets=rows, paging=paging, sorting=sorting, groups=teams(session),
                selected=dict(q=q, exposure=exposure, owner=owner), link=lambda **kw: page_href(request, **kw),
                notice=request.query_params.get("notice"), error=request.query_params.get("error"), active="assets")


@app.post("/assets/assign", dependencies=[Depends(require_csrf)])
def bulk_assign_asset(asset_ids: list[int] = Form(default=[]), owner_id: str = Form(default=""),
                      session: Session = Depends(get_session)):
    try:
        count = assign_assets(session, asset_ids, owner_id)
    except ValueError as exc:
        return redirect_to("/assets", error=str(exc))
    return redirect_to("/assets", notice=f"Added an asset stakeholder team to {count} assets")


@app.get("/assets/{asset_id}", response_class=HTMLResponse)
def asset_detail(asset_id: int, request: Request, page_num: int = 1, page_size: int = 10, sort: str = "id", direction: str = "desc",
                 session: Session = Depends(get_session)):
    asset = session.scalar(select(Asset).where(Asset.id == asset_id).options(selectinload(Asset.memberships).joinedload(AssetTeam.team)))
    if asset is None:
        raise HTTPException(404, "Asset not found")
    stmt=select(Finding).where(Finding.asset_id==asset_id).join(Vulnerability).outerjoin(Owner,
       Owner.id==Finding.assigned_owner_id).options(joinedload(Finding.vulnerability),joinedload(Finding.assigned_owner))
    stmt,sorting=ordered(stmt,sort,direction,{'id':Finding.id,'finding':func.lower(Vulnerability.title),
         'severity':SEVERITY_RANK,'owner':func.lower(Owner.name),'state':Finding.workflow_state},tie=Finding.id)
    related,paging=paginate(session,stmt,page_num,page_size)
    return page(request, "asset_detail.html", asset=asset, related=related, paging=paging, sorting=sorting,
                link=lambda **kw: page_href(request, **kw), groups=teams(session),
                error=request.query_params.get("error"), notice=request.query_params.get("notice"), active="assets")


@app.post("/assets/{asset_id}", dependencies=[Depends(require_csrf)])
def update_asset(asset_id: int, display_name: str = Form(...), exposure: str = Form(...),
                 team_ids: list[int] = Form(default=[]), external_ref: str = Form(default=""),
                 service_code: str = Form(default=""),
                 hostname: str = Form(default=""), ip_address: str = Form(default=""),
                 session: Session = Depends(get_session)):
    try:
        # Asset-level stakeholder controls are not exposed in v0.10. Preserve any
        # historical associations rather than deleting them on an unrelated edit.
        if not team_ids:
            asset = session.get(Asset, asset_id)
            if asset is not None:
                team_ids = [membership.team_id for membership in asset.memberships]
        edit_asset(session, asset_id, display_name, exposure, team_ids, external_ref, service_code, hostname, ip_address)
    except ValueError as exc:
        return redirect_to(f"/assets/{asset_id}", error=str(exc))
    return redirect_to(f"/assets/{asset_id}", notice="Asset updated")


@app.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, severity: str = "", q: str = "", owner: str = "", sort: str = "id", direction: str = "desc",
                  exposure: str = "", state: str = "", engagement_id: str = "",
                  page_num: int = 1, page_size: int = 10, session: Session = Depends(get_session)):
    stmt = (select(Finding).join(Asset).join(Vulnerability)
            .options(joinedload(Finding.asset),
                     joinedload(Finding.assigned_owner), joinedload(Finding.vulnerability))
            .order_by(Finding.id.desc()))
    if severity in SEVERITIES:
        stmt = stmt.where(Finding.severity == severity)
    if q.strip():
        qlike = "%" + q.strip()[:100] + "%"
        stmt = stmt.where(or_(Vulnerability.title.ilike(qlike), Asset.identity_key.ilike(qlike),
                              Asset.display_name.ilike(qlike), Vulnerability.external_key.ilike(qlike),
                              Vulnerability.cve.ilike(qlike)))
    if owner == "unassigned":
        stmt = stmt.where(effective_owner_predicate().is_(None))
    elif owner.isdecimal():
        stmt = stmt.where(effective_owner_predicate() == int(owner))
    if exposure in NETWORK_CLASSES:
        stmt = stmt.where(Asset.exposure == exposure)
    if state:
        stmt = stmt.where(Finding.workflow_state == state)
    if engagement_id.isdecimal():
        observed_ids = (select(Observation.finding_id).join(ImportBatch).join(Assessment)
                        .where(Assessment.engagement_id == int(engagement_id)))
        stmt = stmt.where(Finding.id.in_(observed_ids))
    stmt = stmt.outerjoin(Owner, Owner.id==Finding.assigned_owner_id)
    stmt, sorting = ordered(stmt,sort,direction,{"id":Finding.id,"name":func.lower(Vulnerability.title),
        "asset":func.lower(Asset.display_name),"severity":SEVERITY_RANK,"owner":func.lower(Owner.name),
        "exposure":Asset.exposure,"governance":Finding.workflow_state},tie=Finding.id)
    rows, paging = paginate(session, stmt, page_num, page_size)
    engagements = session.scalars(select(Engagement).order_by(Engagement.name)).all()
    return page(request, "findings.html", findings=rows, paging=paging, sorting=sorting, groups=teams(session),
                engagements=engagements, selected=dict(severity=severity, q=q, owner=owner,
                exposure=exposure, state=state, engagement_id=engagement_id),
                link=lambda **kw: page_href(request, **kw), active="findings",
                notice=request.query_params.get("notice"), error=request.query_params.get("error"))


@app.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(finding_id: int, request: Request, session: Session = Depends(get_session)):
    finding = session.scalar(select(Finding).where(Finding.id == finding_id)
                             .options(joinedload(Finding.asset),
                                      joinedload(Finding.assigned_owner), joinedload(Finding.vulnerability)))
    if finding is None:
        raise HTTPException(404, "Finding not found")
    observations = session.scalars(select(Observation).where(Observation.finding_id == finding_id)
                                   .options(joinedload(Observation.batch).joinedload(ImportBatch.assessment))
                                   .order_by(Observation.id.desc())).all()
    decisions = session.scalars(select(GovernanceDecision).where(GovernanceDecision.finding_id == finding_id)
                                .order_by(GovernanceDecision.id.desc())).all()
    return page(request, "finding_detail.html", finding=finding, observations=observations,
                correlation_candidates=find_candidates(session,finding_id),
                decisions=decisions, groups=teams(session), approvers=approvers(session),
                 snow_incident=session.get(ServiceNowIncidentLink,finding_id),
                 snow_connected=has_servicenow_credentials(session,connector_owner_id(session)),
                 active="findings",
                error=request.query_params.get("error"), notice=request.query_params.get("notice"))


@app.post("/findings/{finding_id}/assign", dependencies=[Depends(require_csrf)])
def update_finding_team(finding_id: int, owner_id: str = Form(default=""),
                        session: Session = Depends(get_session)):
    try:
        assign_finding(session, finding_id, owner_id)
    except ValueError as exc:
        return redirect_to(f"/findings/{finding_id}", error=str(exc))
    return redirect_to(f"/findings/{finding_id}", notice="Finding assignment updated")


@app.post("/findings/{finding_id}/decisions", dependencies=[Depends(require_csrf)])
def create_decision(finding_id: int, request: Request, action: str = Form(...),
                    rationale: str = Form(...), review_date: str = Form(default=""),
                    session: Session = Depends(get_session)):
    try:
        decision=record_authenticated_decision(session, finding_id, action, request.state.current_user.id, rationale, review_date)
    except ValueError as exc:
        return redirect_to(f"/findings/{finding_id}", error=str(exc))
    # A decision is saved locally first; a downstream outage must not erase it.
    if session.get(ServiceNowIncidentLink,finding_id):
        if has_servicenow_credentials(session,connector_owner_id(session)):
            try:
                sync_finding_notes(session,finding_id,request.state.current_user.id,
                                   only_decision_id=decision.id,credential_user_id=connector_owner_id(session))
            except ConnectorError:
                return redirect_to(f"/findings/{finding_id}",
                    notice="Decision recorded. ServiceNow sync pending; use Sync notes to retry.")
        else:
            return redirect_to(f"/findings/{finding_id}",
                notice="Decision recorded. ServiceNow sync pending (connection required).")
    return redirect_to(f"/findings/{finding_id}", notice="Governance decision recorded")


@app.get("/governance", response_class=HTMLResponse)
def governance_queue(request: Request, bucket: str = "all", page_num: int = 1, page_size: int = 10, sort: str = "id", direction: str = "desc",
                     session: Session = Depends(get_session)):
    stmt = select(Finding).join(Asset).options(
        joinedload(Finding.asset), joinedload(Finding.assigned_owner),
        joinedload(Finding.vulnerability), selectinload(Finding.decisions)).order_by(Finding.id.desc())
    if bucket == "unassigned":
        stmt = stmt.where(effective_owner_predicate().is_(None))
    elif bucket == "pending":
        stmt = stmt.where(Finding.workflow_state == "pending_triage", effective_owner_predicate().is_not(None))
    elif bucket == "decided":
        stmt = stmt.where(Finding.workflow_state != "pending_triage")
    elif bucket == "review_due":
        stmt = stmt.where(Finding.id.in_(due_review_query()))
    stmt = stmt.join(Vulnerability, Finding.vulnerability_id==Vulnerability.id).outerjoin(Owner,Owner.id==Finding.assigned_owner_id)
    stmt, sorting = ordered(stmt,sort,direction,{"id":Finding.id,"name":func.lower(Vulnerability.title),
        "severity":SEVERITY_RANK,"owner":func.lower(Owner.name),"state":Finding.workflow_state},tie=Finding.id)
    rows, paging = paginate(session, stmt, page_num, page_size)
    counts = {
        "unassigned": session.scalar(select(func.count()).select_from(unassigned_query().subquery())),
        "pending": session.scalar(select(func.count()).select_from(Finding).join(Asset).where(
            Finding.workflow_state == "pending_triage", effective_owner_predicate().is_not(None))),
        "decided": session.scalar(select(func.count()).select_from(Finding).where(Finding.workflow_state != "pending_triage")),
        "review_due": session.scalar(select(func.count()).select_from(Finding).where(Finding.id.in_(due_review_query()))),
    }
    return page(request, "governance.html", findings=rows, paging=paging, sorting=sorting, counts=counts,
                bucket=bucket, link=lambda **kw: page_href(request, **kw), today=date.today().isoformat(), active="governance")


@app.get("/health")
def health():
    return {"status": "ok", "version": "0.18.0"}


@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request, error: str = ''):
    return page(request,'login.html',error=error)


@app.post('/login')
def login_form(request: Request, username: str = Form(...), password: str = Form(...),
               session: Session = Depends(get_session)):
    raw=login(session,username,password)
    if not raw:
        return page(request,'login.html',error='Invalid credentials or temporarily locked account')
    response=redirect_to('/')
    response.set_cookie(COOKIE_NAME,raw,httponly=True,samesite='lax',secure=request.url.scheme=='https',
                        max_age=8*60*60,path='/')
    response.headers['Cache-Control']='no-store'
    return response


@app.post('/logout', dependencies=[Depends(require_csrf)])
def logout(request: Request, session: Session = Depends(get_session)):
    revoke_session(session,request.cookies.get(COOKIE_NAME,''))
    response=redirect_to('/login')
    response.delete_cookie(COOKIE_NAME,path='/')
    return response


@app.get('/account/password',response_class=HTMLResponse)
def account_password(request: Request):
    return redirect_to('/account/profile', **dict(request.query_params))


@app.post('/account/password',dependencies=[Depends(require_csrf)])
def change_my_password(request: Request, previous: str = Form(...), password: str = Form(...),
                       confirm: str = Form(...), session: Session = Depends(get_session)):
    account=session.get(UserAccount,request.state.current_user.id)
    if not verify_password(previous,account.password_hash):
        return redirect_to('/account/profile',error='Current password is incorrect')
    if password!=confirm: return redirect_to('/account/profile',error='New passwords differ')
    try: account.password_hash=hash_password(password)
    except ValueError as exc: return redirect_to('/account/profile',error=str(exc))
    # Rotate all login sessions on password change; user signs in again.
    session.query(LoginSession).filter(LoginSession.user_id==account.id).delete()
    session.commit()
    response=redirect_to('/login')
    response.delete_cookie(COOKIE_NAME,path='/')
    return response


@app.get('/admin/sample-data', response_class=HTMLResponse)
def sample_data_page(request: Request, session: Session = Depends(get_session)):
    # This is an opt-in fixture loader, never an automatic production migration.
    from app.demo_seed import sample_data_status
    status = sample_data_status(session)
    return page(request, 'admin_sample_data.html', status=status, active='accounts',
                notice=request.query_params.get('notice'), error=request.query_params.get('error'))


@app.post('/admin/sample-data', dependencies=[Depends(require_csrf)])
def load_sample_data(session: Session = Depends(get_session)):
    from app.demo_seed import load_sample_campaign
    try:
        stats = load_sample_campaign(session)
    except ValueError as exc:
        return redirect_to('/admin/sample-data', error=str(exc))
    return redirect_to('/admin/sample-data', notice=(
        f"Sample campaign loaded: {stats['assessments']} assessments, "
        f"{stats['assets']} assets, {stats['findings']} findings, "
        f"{stats['observations']} observations and {stats['tasks']} work items"))


@app.get('/admin/users',response_class=HTMLResponse)
def admin_users_page(request: Request,session:Session=Depends(get_session)):
    users=session.scalars(select(UserAccount).options(selectinload(UserAccount.roles)
                     .joinedload(UserRole.role)).order_by(UserAccount.username)).all()
    roles=session.scalars(select(AccessRole).order_by(AccessRole.name)).all()
    return page(request,'admin_users.html',users=users,roles=roles,active='accounts',
                error=request.query_params.get('error'),notice=request.query_params.get('notice'))


@app.get('/admin/users/new', response_class=HTMLResponse)
def admin_new_user_page(request: Request, session: Session = Depends(get_session)):
    roles = session.scalars(select(AccessRole).order_by(AccessRole.name)).all()
    return page(request, 'admin_user_new.html', roles=roles, active='accounts')


@app.post('/admin/users',dependencies=[Depends(require_csrf)])
def admin_new_user(username:str=Form(...),name:str=Form(...),email:str=Form(...),password:str=Form(...),
                   role_ids:list[int]=Form(default=[]),session:Session=Depends(get_session)):
    try: create_user(session,username,name,email,password,role_ids)
    except ValueError as exc: return redirect_to('/admin/users',error=str(exc))
    return redirect_to('/admin/users',notice='Account created; share the temporary password securely')


@app.get('/admin/users/{user_id}/edit',response_class=HTMLResponse)
def admin_user_edit(user_id:int,request:Request,session:Session=Depends(get_session)):
    user=session.scalar(select(UserAccount).where(UserAccount.id==user_id)
                         .options(selectinload(UserAccount.roles)))
    if not user: raise HTTPException(404,'User not found')
    roles=session.scalars(select(AccessRole).order_by(AccessRole.name)).all()
    return page(request,'admin_user_edit.html',user=user,roles=roles,active='accounts',
                error=request.query_params.get('error'))


@app.post('/admin/users/{user_id}/edit',dependencies=[Depends(require_csrf)])
def admin_save_user(user_id:int,request:Request,role_ids:list[int]=Form(default=[]),
                    active:str=Form(default=''),session:Session=Depends(get_session)):
    if user_id==request.state.current_user.id and active!='on':
        return redirect_to(f'/admin/users/{user_id}/edit',error='You cannot deactivate your own account')
    user=session.get(UserAccount,user_id)
    if not user: raise HTTPException(404,'User not found')
    try: assign_roles(session,user,role_ids,active=='on')
    except ValueError as exc: return redirect_to(f'/admin/users/{user_id}/edit',error=str(exc))
    return redirect_to('/admin/users',notice='Access roles updated; existing login sessions revoked')


@app.post('/admin/users/{user_id}/password',dependencies=[Depends(require_csrf)])
def admin_reset_password(user_id:int,password:str=Form(...),session:Session=Depends(get_session)):
    user=session.get(UserAccount,user_id)
    if not user: raise HTTPException(404,'User not found')
    try: user.password_hash=hash_password(password)
    except ValueError as exc: return redirect_to(f'/admin/users/{user_id}/edit',error=str(exc))
    session.query(LoginSession).filter(LoginSession.user_id==user.id).delete()
    session.commit()
    return redirect_to('/admin/users',notice='Password reset; user sessions revoked')


@app.get('/admin/roles',response_class=HTMLResponse)
def admin_roles_page(request:Request,session:Session=Depends(get_session)):
    roles=session.scalars(select(AccessRole).options(selectinload(AccessRole.permissions))
                          .order_by(AccessRole.name)).all()
    return page(request,'admin_roles.html',roles=roles,permissions=PERMISSIONS,active='accounts',
                error=request.query_params.get('error'),notice=request.query_params.get('notice'))


@app.post('/admin/roles',dependencies=[Depends(require_csrf)])
def admin_create_role(name:str=Form(...),description:str=Form(default=''),
                      permissions:list[str]=Form(default=[]),session:Session=Depends(get_session)):
    role=AccessRole(name='Temporary')
    try:
        session.add(role);session.flush()
        update_role(session,role,name,description,permissions)
    except ValueError as exc:
        session.rollback();return redirect_to('/admin/roles',error=str(exc))
    return redirect_to('/admin/roles',notice='Access role created')


@app.get('/admin/roles/{role_id}/edit',response_class=HTMLResponse)
def admin_role_edit(role_id:int,request:Request,session:Session=Depends(get_session)):
    role=session.scalar(select(AccessRole).where(AccessRole.id==role_id).options(selectinload(AccessRole.permissions)))
    if not role: raise HTTPException(404,'Role not found')
    return page(request,'admin_role_edit.html',role=role,permissions=PERMISSIONS,active='accounts',
                error=request.query_params.get('error'))


@app.post('/admin/roles/{role_id}/edit',dependencies=[Depends(require_csrf)])
def admin_save_role(role_id:int,name:str=Form(...),description:str=Form(default=''),
                    permissions:list[str]=Form(default=[]),session:Session=Depends(get_session)):
    role=session.get(AccessRole,role_id)
    if not role: raise HTTPException(404,'Role not found')
    try: update_role(session,role,name,description,permissions)
    except ValueError as exc: return redirect_to(f'/admin/roles/{role_id}/edit',error=str(exc))
    return redirect_to('/admin/roles',notice='Role permissions updated')


@app.get('/account/profile',response_class=HTMLResponse)
def my_profile(request: Request, session: Session=Depends(get_session)):
    user=session.scalar(select(UserAccount).where(UserAccount.id==request.state.current_user.id)
                        .options(selectinload(UserAccount.roles).joinedload(UserRole.role)))
    return page(request,'account_profile.html',user=user,active='account',
                tenable_connected=has_tenable_credentials(session,connector_owner_id(session)),
                notice=request.query_params.get('notice'),error=request.query_params.get('error'),
       group_results=[], group_query='')


@app.post('/account/profile',dependencies=[Depends(require_csrf)])
def update_my_profile(request: Request,name: str=Form(...),email: str=Form(...),
                      session: Session=Depends(get_session)):
    name=name.strip();email=email.strip().lower()
    if not name or len(name)>160 or '@' not in email or len(email)>254:
        return redirect_to('/account/profile',error='Enter a valid name and email address')
    duplicate=session.scalar(select(UserAccount.id).where(UserAccount.email==email,
                                       UserAccount.id!=request.state.current_user.id))
    if duplicate: return redirect_to('/account/profile',error='Email already in use')
    user=session.get(UserAccount,request.state.current_user.id)
    user.name=name;user.email=email;session.commit()
    return redirect_to('/account/profile',notice='Profile updated')


@app.get('/account/settings',response_class=HTMLResponse)
def my_settings(request: Request):
    return page(request,'account_settings.html',active='account',notice=request.query_params.get('notice'))


@app.post('/account/settings',dependencies=[Depends(require_csrf)])
def save_my_settings(request: Request,theme: str=Form(...),session: Session=Depends(get_session)):
    if theme not in {'light','dark'}: raise HTTPException(400,'Unsupported theme')
    uid=request.state.current_user.id
    pref=session.get(UserPreference,uid)
    if pref is None: pref=UserPreference(user_id=uid,theme=theme);session.add(pref)
    else: pref.theme=theme
    session.commit()
    return redirect_to('/account/profile',notice='Appearance updated')



@app.post('/account/connectors/tenable',dependencies=[Depends(require_csrf)])
def save_my_tenable(request: Request, access_key: str=Form(...), secret_key: str=Form(...),
                    session: Session=Depends(get_session)):
    require_connector_manager(request)
    try:
        save_tenable_credentials(session,connector_owner_id(session), access_key,secret_key)
    except ConnectorError as exc:
        return redirect_to('/integrations',error=str(exc))
    return redirect_to('/integrations',notice='Tenable credentials encrypted and saved')


@app.post('/account/connectors/tenable/delete',dependencies=[Depends(require_csrf)])
def remove_my_tenable(request: Request,session: Session=Depends(get_session)):
    require_connector_manager(request)
    delete_tenable_credentials(session,connector_owner_id(session))
    return redirect_to('/integrations',notice='Tenable connection removed')


@app.post('/imports/tenable',response_class=HTMLResponse,dependencies=[Depends(require_csrf)])
def import_tenable_api(request: Request, assessment_id: int=Form(...),days: int=Form(default=30),
                       time_field: str=Form(default='last_seen'),
                       start_date: str=Form(default=''),end_date: str=Form(default=''),
                       plugin_ids: str=Form(default=''),tag_category: str=Form(default=''),
                       tag_value: str=Form(default=''),vpr_min: str=Form(default=''),
                       tag_filters: str=Form(default=''), cidr_range: str=Form(default=''),
                       plugin_family: str=Form(default=''), severity_modification_type: list[str]=Form(default=[]),
                       severities: list[str]=Form(default=[]),
                       session: Session=Depends(get_session)):
    if 'imports.write' not in request.state.permissions:
        raise HTTPException(403,'Missing imports.write permission')
    try:
        content=export_tenable_vulnerabilities(session,connector_owner_id(session),
            days=days,time_field=time_field,start_date=start_date,end_date=end_date,
            plugin_ids=plugin_ids,tag_category=tag_category,tag_value=tag_value,
            vpr_min=vpr_min,tag_filters=tag_filters,cidr_range=cidr_range,plugin_family=plugin_family,
            severity_modification_type=severity_modification_type or None,severities=severities or None)
        results=import_findings(session,content,'Tenable API export.json','tenable_json',assessment_id=assessment_id)
    except (ConnectorError,ImportValidationError) as exc:
        return redirect_to('/imports',error=str(exc),assessment_id=assessment_id)
    return redirect_to('/imports',notice=f'Tenable export imported: {results.rows} observations')


@app.get('/admin/connectors',response_class=HTMLResponse)
def admin_connector_status(request: Request,session: Session=Depends(get_session)):
    return redirect_to('/integrations')

def connector_owner_id(session: Session) -> int:
    """Single organization connector identity, stored under the bootstrap admin.

    Keeps existing encrypted credential tables compatible with v0.14. API secrets
    are not exposed to viewers; capability checks authorize configuration.
    """
    owner=session.scalar(select(UserAccount.id).where(UserAccount.is_superuser.is_(True)).order_by(UserAccount.id).limit(1))
    if owner is None:
        owner=session.scalar(select(UserAccount.id).order_by(UserAccount.id).limit(1))
    if owner is None: raise HTTPException(503,'Initialize an administrator account first')
    return owner


def manage_connectors(request: Request) -> bool:
    return ('accounts.manage' in request.state.permissions or
            'integrations.manage' in request.state.permissions)


def require_connector_manager(request: Request) -> None:
    if not manage_connectors(request): raise HTTPException(403,'Integration management permission required')


def connector_display_details(session: Session, uid: int, provider: str) -> dict:
    """Only non-secret presentation fields; encrypted storage never goes to a page."""
    try:
        cfg=_read_credentials(session,uid) if provider=='tenable' else read_servicenow_credentials(session,uid)
        if provider=='tenable':
            return {'access_key':cfg['access_key']}
        return {'instance_url':cfg['instance_url'],'username':cfg['username']}
    except (ConnectorError,KeyError):
        return {}


@app.get('/integrations', response_class=HTMLResponse)
def integrations_page(request: Request, session: Session=Depends(get_session)):
    uid=connector_owner_id(session)
    may_edit=manage_connectors(request)
    maps=session.scalars(select(ServiceNowGroupMapping).options(joinedload(ServiceNowGroupMapping.team))
                         .order_by(ServiceNowGroupMapping.team_id)).all() if may_edit else []
    return page(request,'integrations.html',active='integrations',can_manage_integrations=may_edit,
       tenable_connected=has_tenable_credentials(session,uid),
       servicenow_connected=has_servicenow_credentials(session,uid),
       tenable_details=connector_display_details(session,uid,'tenable') if may_edit else {},
       servicenow_details=connector_display_details(session,uid,'servicenow') if may_edit else {},
       mappings=maps,groups=teams(session) if may_edit else [],
       tenable_check=connection_check(session,uid,'tenable'),snow_check=connection_check(session,uid,'servicenow'),
       notice=request.query_params.get('notice'),error=request.query_params.get('error'),
       group_results=[],group_query='')


@app.post('/integrations/servicenow', dependencies=[Depends(require_csrf)])
def save_my_servicenow(request: Request,instance_url: str=Form(...), username: str=Form(...),
                       password: str=Form(...),session: Session=Depends(get_session)):
    require_connector_manager(request)
    try: save_servicenow_credentials(session,connector_owner_id(session),instance_url,username,password)
    except ConnectorError as exc: return redirect_to('/integrations',error=str(exc))
    return redirect_to('/integrations',notice='ServiceNow connection saved')


@app.post('/integrations/servicenow/delete', dependencies=[Depends(require_csrf)])
def delete_my_servicenow(request: Request, session: Session=Depends(get_session)):
    require_connector_manager(request)
    row=_connector_row(session,connector_owner_id(session),'servicenow')
    if row: session.delete(row); session.commit()
    clear_connection_check(session,connector_owner_id(session),'servicenow')
    return redirect_to('/integrations',notice='ServiceNow connection removed')


@app.post('/integrations/servicenow/search', response_class=HTMLResponse, dependencies=[Depends(require_csrf)])
def servicenow_group_search(request:Request, query:str=Form(default=''),session:Session=Depends(get_session)):
    require_connector_manager(request)
    try:
        results=search_groups(session,connector_owner_id(session),query)
        error=None
    except ConnectorError as exc:
        results=[];error=str(exc)
    maps=session.scalars(select(ServiceNowGroupMapping).options(joinedload(ServiceNowGroupMapping.team))
                         .order_by(ServiceNowGroupMapping.team_id)).all()
    uid=connector_owner_id(session)
    return page(request,'integrations.html',active='integrations',tenable_connected=has_tenable_credentials(session,uid),
       servicenow_connected=has_servicenow_credentials(session,uid),mappings=maps,groups=teams(session),
       can_manage_integrations=manage_connectors(request),
       tenable_details=connector_display_details(session,uid,'tenable'),
       servicenow_details=connector_display_details(session,uid,'servicenow'),
       notice=None,error=error,group_results=results,group_query=query,
       tenable_check=connection_check(session,uid,'tenable'),snow_check=connection_check(session,uid,'servicenow'))


@app.post('/integrations/servicenow/groups', dependencies=[Depends(require_csrf)])
def set_servicenow_group(request: Request,team_id:int=Form(...),
                         group_sys_id:str=Form(...), session:Session=Depends(get_session)):
    require_connector_manager(request)
    try: select_group(session,connector_owner_id(session),team_id,group_sys_id)
    except ConnectorError as exc: return redirect_to('/integrations',error=str(exc))
    return redirect_to('/integrations',notice='Verified ServiceNow group assigned')


@app.post('/integrations/tenable/test', dependencies=[Depends(require_csrf)])
def tenable_connection_test(request:Request,session:Session=Depends(get_session)):
    require_connector_manager(request)
    try:
        message=check_tenable_connection(session,connector_owner_id(session))
    except ConnectorError as exc:
        record_connection_check(session,connector_owner_id(session),'tenable',False)
        return redirect_to('/integrations',error=str(exc))
    record_connection_check(session,connector_owner_id(session),'tenable',True)
    return redirect_to('/integrations',notice=message)


@app.post('/integrations/servicenow/test', dependencies=[Depends(require_csrf)])
def servicenow_connection_test(request:Request,session:Session=Depends(get_session)):
    require_connector_manager(request)
    try:
        message=check_servicenow_connection(session,connector_owner_id(session))
    except ConnectorError as exc:
        record_connection_check(session,connector_owner_id(session),'servicenow',False)
        return redirect_to('/integrations',error=str(exc))
    record_connection_check(session,connector_owner_id(session),'servicenow',True)
    return redirect_to('/integrations',notice=message)


@app.post('/findings/{finding_id}/servicenow/create', dependencies=[Depends(require_csrf)])
def create_servicenow_incident(finding_id:int, request:Request,session:Session=Depends(get_session)):
    if 'findings.assign' not in request.state.permissions and 'governance.approve' not in request.state.permissions:
        raise HTTPException(403,'Permission denied')
    try: incident=create_incident(session,finding_id,request.state.current_user.id,credential_user_id=connector_owner_id(session))
    except ConnectorError as exc: return redirect_to(f'/findings/{finding_id}',error=str(exc))
    return redirect_to(f'/findings/{finding_id}',notice=f'Linked ServiceNow incident {incident.number}')


@app.post('/findings/{finding_id}/servicenow/refresh', dependencies=[Depends(require_csrf)])
def refresh_servicenow_incident(finding_id:int, request:Request,session:Session=Depends(get_session)):
    if 'findings.read' not in request.state.permissions: raise HTTPException(403,'Permission denied')
    try: incident=refresh_incident(session,finding_id,request.state.current_user.id,credential_user_id=connector_owner_id(session))
    except ConnectorError as exc: return redirect_to(f'/findings/{finding_id}',error=str(exc))
    return redirect_to(f'/findings/{finding_id}',notice=f'Incident {incident.number}: {incident.state}')


@app.post('/findings/{finding_id}/servicenow/sync', dependencies=[Depends(require_csrf)])
def sync_servicenow_incident(finding_id:int,request:Request,session:Session=Depends(get_session)):
    if 'findings.assign' not in request.state.permissions and 'governance.approve' not in request.state.permissions:
        raise HTTPException(403,'Permission denied')
    try: count=sync_finding_notes(session,finding_id,request.state.current_user.id,credential_user_id=connector_owner_id(session))
    except ConnectorError as exc: return redirect_to(f'/findings/{finding_id}',error=str(exc))
    return redirect_to(f'/findings/{finding_id}',notice=f'{count} new ServiceNow work notes synchronized')


def work_item_scope(session: Session,user: UserAccount,permissions:set[str]):
    role_ids=select(UserRole.role_id).where(UserRole.user_id==user.id)
    return or_(GovernanceWorkItem.assignee_user_id==user.id,
               GovernanceWorkItem.assignee_role_id.in_(role_ids))


@app.get('/work-items',response_class=HTMLResponse)
def work_items_page(request: Request,bucket: str='mine',sort: str='due', direction: str='asc',
                    page_num: int=1,page_size: int=10,session:Session=Depends(get_session)):
    current=request.state.current_user; permissions=request.state.permissions
    if 'governance.tasks.read' not in permissions: raise HTTPException(403,'Missing work queue access')
    stmt=select(GovernanceWorkItem).options(joinedload(GovernanceWorkItem.finding).joinedload(Finding.vulnerability),
        joinedload(GovernanceWorkItem.assignee_user),joinedload(GovernanceWorkItem.assignee_role))
    assigned=work_item_scope(session,current,permissions)
    if bucket=='mine': stmt=stmt.where(assigned,GovernanceWorkItem.status.in_(OPEN_STATUSES))
    elif bucket=='overdue': stmt=stmt.where(GovernanceWorkItem.status.in_(OPEN_STATUSES),GovernanceWorkItem.due_at<datetime.combine(date.today(),datetime.min.time()))
    elif bucket=='pending': stmt=stmt.where(GovernanceWorkItem.status.in_(OPEN_STATUSES))
    elif bucket=='approvals': stmt=stmt.where(GovernanceWorkItem.kind=='risk_approval',GovernanceWorkItem.status.in_(OPEN_STATUSES))
    elif bucket=='history': stmt=stmt.where(GovernanceWorkItem.status.not_in(OPEN_STATUSES))
    elif bucket not in {'all'}: bucket='mine';stmt=stmt.where(assigned,GovernanceWorkItem.status.in_(OPEN_STATUSES))
    if bucket in {'all','pending','overdue','history','approvals'} and 'governance.tasks.manage' not in permissions:
        stmt=stmt.where(assigned)
    stmt,sorting=ordered(stmt,sort,direction,{'id':GovernanceWorkItem.id,'due':GovernanceWorkItem.due_at,
        'status':GovernanceWorkItem.status,'type':GovernanceWorkItem.kind,
        'title':func.lower(GovernanceWorkItem.title)},default_key='due',default_dir='asc',tie=GovernanceWorkItem.id)
    rows,paging=paginate(session,stmt,page_num,page_size)
    assigned_q=select(GovernanceWorkItem.id).where(assigned,GovernanceWorkItem.status.in_(OPEN_STATUSES))
    counts={'mine':session.scalar(select(func.count()).select_from(assigned_q.subquery())),
        'overdue':session.scalar(select(func.count()).select_from(GovernanceWorkItem).where(
           GovernanceWorkItem.status.in_(OPEN_STATUSES),GovernanceWorkItem.due_at<datetime.combine(date.today(),datetime.min.time()),
           *([] if 'governance.tasks.manage' in permissions else [assigned]))),
        'pending':session.scalar(select(func.count()).select_from(GovernanceWorkItem).where(
           GovernanceWorkItem.status.in_(OPEN_STATUSES),*([] if 'governance.tasks.manage' in permissions else [assigned]))),
        'approvals':session.scalar(select(func.count()).select_from(GovernanceWorkItem).where(
           GovernanceWorkItem.kind=='risk_approval',GovernanceWorkItem.status.in_(OPEN_STATUSES),
           *([] if 'governance.tasks.manage' in permissions else [assigned])))}
    previous_decisions=session.scalars(select(GovernanceDecision).where(
        GovernanceDecision.actor_user_id==current.id).order_by(GovernanceDecision.id.desc()).limit(6)).all()
    return page(request,'work_items.html',items=rows,paging=paging,counts=counts,bucket=bucket,
        previous_decisions=previous_decisions,
        sorting=sorting,kinds=KINDS,today=date.today(),link=lambda **kw:page_href(request,**kw),active='work-items',
        notice=request.query_params.get('notice'),error=request.query_params.get('error'))


@app.get('/work-items/new',response_class=HTMLResponse)
def new_work_item_page(request:Request,finding_id:int=0,session:Session=Depends(get_session)):
    if 'governance.tasks.create' not in request.state.permissions: raise HTTPException(403,'Cannot create work items')
    return page(request,'work_item_new.html',finding_id=finding_id,
       findings=session.scalars(select(Finding).options(joinedload(Finding.vulnerability)).order_by(Finding.id.desc())).all(),
       users=session.scalars(select(UserAccount).where(UserAccount.is_active.is_(True)).order_by(UserAccount.name)).all(),
       roles=session.scalars(select(AccessRole).order_by(AccessRole.name)).all(),
       kinds=KINDS,active='work-items',error=request.query_params.get('error'))


@app.post('/work-items/create',dependencies=[Depends(require_csrf)])
def new_work_item(request:Request,finding_id:int=Form(...),kind:str=Form(...),title:str=Form(...),
        description:str=Form(default=''),assignee:str=Form(...),due_date:str=Form(...),
        session:Session=Depends(get_session)):
    if 'governance.tasks.create' not in request.state.permissions: raise HTTPException(403,'Cannot create work items')
    try:
        typ,number=assignee.split(':',1)
        if typ not in {'user','role'} or not number.isdecimal(): raise ValueError()
        uid=int(number) if typ=='user' else None
        rid=int(number) if typ=='role' else None
    except ValueError:
        return redirect_to('/work-items/new',error='Choose a valid assignee')
    try:
        item=create_work_item(session,finding_id=finding_id,kind=kind,title=title,description=description,
            assignee_user_id=uid,assignee_role_id=rid,due_date=due_date,created_by_id=request.state.current_user.id)
    except ValueError as exc:
        return redirect_to('/work-items/new',error=str(exc))
    return redirect_to(f'/work-items/{item.id}')


@app.get('/work-items/{item_id}',response_class=HTMLResponse)
def work_item_detail(item_id:int,request:Request,session:Session=Depends(get_session)):
    item=session.scalar(select(GovernanceWorkItem).where(GovernanceWorkItem.id==item_id).options(
        joinedload(GovernanceWorkItem.finding).joinedload(Finding.vulnerability),
        joinedload(GovernanceWorkItem.assignee_user),joinedload(GovernanceWorkItem.assignee_role),
        selectinload(GovernanceWorkItem.events).joinedload(GovernanceWorkEvent.actor)))
    if not item: raise HTTPException(404,'Work item not found')
    perms=request.state.permissions;user=request.state.current_user
    if 'governance.tasks.manage' not in perms and not task_assigned(session,item,user.id):
        raise HTTPException(403,'Work item not assigned to you')
    return page(request,'work_item_detail.html',item=item,can_approve='governance.tasks.approve' in perms,
       can_resolve='governance.tasks.resolve' in perms,can_manage='governance.tasks.manage' in perms,
       users=session.scalars(select(UserAccount).where(UserAccount.is_active.is_(True)).order_by(UserAccount.name)).all(),
       roles=session.scalars(select(AccessRole).order_by(AccessRole.name)).all(),
       active='work-items',error=request.query_params.get('error'),notice=request.query_params.get('notice'))


@app.post('/work-items/{item_id}/action',dependencies=[Depends(require_csrf)])
def work_item_action(item_id:int,request:Request,status:str=Form(...),rationale:str=Form(...),
       review_date:str=Form(default=''),session:Session=Depends(get_session)):
    try:
        update_work_item(session,item_id=item_id,actor_id=request.state.current_user.id,
            permissions=request.state.permissions,status=status,rationale=rationale,review_date=review_date)
    except PermissionError as exc: raise HTTPException(403,str(exc)) from None
    except ValueError as exc: return redirect_to(f'/work-items/{item_id}',error=str(exc))
    return redirect_to(f'/work-items/{item_id}',notice='Work item updated')


@app.post('/work-items/{item_id}/reassign',dependencies=[Depends(require_csrf)])
def reassign_work_item_route(item_id:int,request:Request,assignee:str=Form(...),
                 due_date:str=Form(...),note:str=Form(...),session:Session=Depends(get_session)):
    if 'governance.tasks.manage' not in request.state.permissions: raise HTTPException(403,'Manager permission required')
    try:
        typ,value=assignee.split(':',1)
        if typ not in {'user','role'} or not value.isdecimal(): raise ValueError()
        uid=int(value) if typ=='user' else None; rid=int(value) if typ=='role' else None
    except ValueError: return redirect_to(f'/work-items/{item_id}',error='Choose a valid assignee')
    try: reassign_work_item(session,item_id=item_id,actor_id=request.state.current_user.id,
              assignee_user_id=uid,assignee_role_id=rid,due_date=due_date,note=note)
    except ValueError as exc: return redirect_to(f'/work-items/{item_id}',error=str(exc))
    return redirect_to(f'/work-items/{item_id}',notice='Assignment updated')
