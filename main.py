import hashlib, hmac, os, pathlib, datetime as dt
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from .db import Base, engine, get_db
from .models import User, Project, Dataset, AuditLog, Role, DataClass, now
from . import security

STORAGE = pathlib.Path(os.environ.get("GEO_STORAGE", "./storage"))
MAX_UPLOAD = int(os.environ.get("GEO_MAX_UPLOAD_MB", "200")) * 1024 * 1024
LOCK_AFTER, LOCK_MIN = 5, 15
WRITE_ROLES = {"owner", "admin", "geologist"}

app = FastAPI(title="GEO-UNKNOWN API", version="0.1.0")
bearer = HTTPBearer(auto_error=False)
# The Android WebView loads bundled assets (origin "null"). Bearer tokens only, no cookies. Override in production.
app.add_middleware(CORSMiddleware, allow_origins=os.environ.get("GEO_CORS", "null").split(","),
                   allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type", "X-Setup-Token"])

@app.on_event("startup")
def _init():
    Base.metadata.create_all(engine)
    STORAGE.mkdir(parents=True, exist_ok=True)

def audit(db, uid, action, detail=""):
    db.add(AuditLog(user_id=uid, action=action, detail=detail)); db.commit()

def current_user(cred: HTTPAuthorizationCredentials = Depends(bearer), db: Session = Depends(get_db)) -> User:
    if not cred:
        raise HTTPException(401, "Not authenticated")
    try:
        data = security.read_token(cred.credentials)
    except Exception:
        raise HTTPException(401, "Invalid or expired token")
    u = db.get(User, int(data["sub"]))
    if not u or not u.active:
        raise HTTPException(401, "Account disabled")
    return u

def need(*roles):
    def dep(u: User = Depends(current_user)):
        if u.role not in roles:
            raise HTTPException(403, "Insufficient role")
        return u
    return dep

class SetupIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str

@app.get("/health")
def health():
    return {"status": "ok", "version": app.version}

@app.post("/setup", status_code=201)
def setup_owner(body: SetupIn, db: Session = Depends(get_db), x_setup_token: str = Header(default="")):
    """One-time creation of the private owner account. Needs the server's GEO_SETUP_TOKEN (set by whoever deploys it),
    so a stranger who finds the URL cannot claim ownership. Disabled if no token is configured. Refused once any user exists."""
    expected = os.environ.get("GEO_SETUP_TOKEN", "")
    if len(expected) < 16:
        raise HTTPException(403, "Setup disabled: server has no GEO_SETUP_TOKEN (16+ chars)")
    if not hmac.compare_digest(x_setup_token.encode(), expected.encode()):
        raise HTTPException(403, "Invalid setup token")
    if db.query(User).count() > 0:
        raise HTTPException(409, "Already initialised")
    try:
        security.check_strength(body.password)
    except ValueError as e:
        raise HTTPException(422, str(e))
    u = User(username=body.username, password_hash=security.hash_pw(body.password), role=Role.owner.value)
    db.add(u); db.commit()
    audit(db, u.id, "setup_owner")
    return {"id": u.id, "role": u.role}

class LoginIn(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.query(User).filter_by(username=body.username).first()
    t = now()
    if u and u.locked_until and u.locked_until.replace(tzinfo=dt.timezone.utc) > t:
        raise HTTPException(423, "Account temporarily locked")
    if not u or not u.active or not security.verify_pw(u.password_hash, body.password):
        if u:
            u.failed_logins += 1
            if u.failed_logins >= LOCK_AFTER:
                u.locked_until = t + dt.timedelta(minutes=LOCK_MIN); u.failed_logins = 0
            db.commit()
        audit(db, u.id if u else None, "login_failed", body.username[:64])
        raise HTTPException(401, "Invalid credentials")
    u.failed_logins = 0; db.commit()
    audit(db, u.id, "login")
    return {"access_token": security.make_token(u.id, u.role), "token_type": "bearer", "role": u.role}

class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str
    role: Role

@app.post("/users", status_code=201)
def create_user(body: UserIn, me: User = Depends(need("owner", "admin")), db: Session = Depends(get_db)):
    if body.role == Role.owner:
        raise HTTPException(403, "Only one owner; transfer is not supported in Phase 1")
    if body.role == Role.admin and me.role != "owner":
        raise HTTPException(403, "Only the owner can create admins")
    try:
        security.check_strength(body.password)
    except ValueError as e:
        raise HTTPException(422, str(e))
    if db.query(User).filter_by(username=body.username).first():
        raise HTTPException(409, "Username taken")
    u = User(username=body.username, password_hash=security.hash_pw(body.password), role=body.role.value)
    db.add(u); db.commit(); audit(db, me.id, "create_user", f"{u.username}:{u.role}")
    return {"id": u.id, "username": u.username, "role": u.role}

@app.get("/me")
def me_(u: User = Depends(current_user)):
    return {"id": u.id, "username": u.username, "role": u.role}

class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str = ""
    crs: str = ""

def pj(p): return {"id": p.id, "name": p.name, "description": p.description, "crs": p.crs}

@app.post("/projects", status_code=201)
def create_project(body: ProjectIn, u: User = Depends(need(*WRITE_ROLES)), db: Session = Depends(get_db)):
    p = Project(**body.model_dump(), owner_id=u.id); db.add(p); db.commit()
    audit(db, u.id, "create_project", str(p.id)); return pj(p)

@app.get("/projects")
def list_projects(u: User = Depends(current_user), db: Session = Depends(get_db)):
    return [pj(p) for p in db.query(Project).order_by(Project.id)]

def ds(d): return {"id": d.id, "project_id": d.project_id, "name": d.name, "method": d.method,
                   "data_class": d.data_class, "source": d.source, "filename": d.filename,
                   "sha256": d.sha256, "size_bytes": d.size_bytes}

@app.post("/projects/{pid}/datasets", status_code=201)
async def add_dataset(pid: int, name: str = Form(...), method: str = Form(...), data_class: DataClass = Form(...),
                      source: str = Form(...), file: UploadFile | None = File(None),
                      u: User = Depends(need(*WRITE_ROLES)), db: Session = Depends(get_db)):
    """Every dataset must declare its class and provenance. Class is never inferred."""
    if not db.get(Project, pid):
        raise HTTPException(404, "Project not found")
    if not source.strip():
        raise HTTPException(422, "Provenance (source) is required")
    d = Dataset(project_id=pid, name=name, method=method, data_class=data_class.value, source=source, created_by=u.id)
    if file is not None:
        h, size = hashlib.sha256(), 0
        db.add(d); db.flush()
        path = STORAGE / f"{d.id}.bin"
        with open(path, "wb") as f:
            while chunk := await file.read(1 << 20):
                size += len(chunk)
                if size > MAX_UPLOAD:
                    f.close(); path.unlink(missing_ok=True); db.rollback()
                    raise HTTPException(413, "File too large")
                h.update(chunk); f.write(chunk)
        d.filename = os.path.basename(file.filename or "")[:255]; d.sha256 = h.hexdigest(); d.size_bytes = size
    else:
        db.add(d)
    db.commit(); audit(db, u.id, "add_dataset", str(d.id)); return ds(d)

@app.get("/projects/{pid}/datasets")
def list_datasets(pid: int, u: User = Depends(current_user), db: Session = Depends(get_db)):
    if not db.get(Project, pid):
        raise HTTPException(404, "Project not found")
    return [ds(d) for d in db.query(Dataset).filter_by(project_id=pid).order_by(Dataset.id)]

@app.get("/audit")
def audit_log(u: User = Depends(need("owner", "admin")), db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200)
    return [{"ts": r.ts.isoformat(), "user_id": r.user_id, "action": r.action, "detail": r.detail} for r in rows]
