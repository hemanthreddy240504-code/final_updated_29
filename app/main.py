from datetime import date, datetime, timedelta, timezone
from typing import Optional
import base64
import hashlib
import hmac
import json
import os
import secrets
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from urllib.parse import quote
import smtplib
from email.message import EmailMessage
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict
from sqlalchemy import create_engine, Column, Integer, String, Float, Date, DateTime, Text, text
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from dotenv import load_dotenv
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'pipeline.db'}")
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
engine_kwargs = {"pool_pre_ping": True}
if DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
engine = create_engine(DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    user_id = Column(String(40), unique=True, index=True, nullable=True)
    role = Column(String(20), nullable=False, default="user")
    name = Column(String(120), nullable=False)
    email = Column(String(200), unique=True, index=True, nullable=False)
    password_hash = Column(String(500), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class PasswordResetToken(Base):
    __tablename__ = "password_reset_tokens"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, nullable=False, index=True)
    token_hash = Column(String(128), unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Company(Base):
    __tablename__ = "companies"
    id = Column(Integer, primary_key=True)
    company_name = Column(String(200), nullable=False)
    industry = Column(String(100), default="Other")
    city = Column(String(100), default="")
    website = Column(String(300), default="")
    employee_band = Column(String(50), default="")
    partner = Column(String(100), default="KOGO")
    expected_value = Column(Float, default=0)
    currency = Column(String(10), default="INR")
    stage = Column(String(50), default="Lead")
    probability = Column(Float, default=10)
    account_owner = Column(String(120), default="")
    team_members = Column(Text, default="")
    client_poc_name = Column(String(120), default="")
    client_poc_role = Column(String(120), default="")
    client_poc_email = Column(String(200), default="")
    client_poc_phone = Column(String(50), default="")
    source = Column(String(100), default="")
    expected_signup_date = Column(Date, nullable=True)
    last_contact_date = Column(Date, nullable=True)
    next_action = Column(String(300), default="")
    notes = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

def run_schema_migrations():
    # Lightweight migration for the existing SQLite/Postgres deployment.
    # New installations are handled by create_all; existing databases get
    # the new recovery fields without losing existing accounts.
    if DATABASE_URL.startswith("sqlite"):
        import sqlite3
        raw = sqlite3.connect(str(BASE_DIR / "pipeline.db"))
        try:
            cols = {row[1] for row in raw.execute("PRAGMA table_info(users)").fetchall()}
            if "user_id" not in cols:
                raw.execute("ALTER TABLE users ADD COLUMN user_id VARCHAR(40)")
            if "role" not in cols:
                raw.execute("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'")
            raw.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_user_id ON users(user_id)")
            raw.commit()
        finally:
            raw.close()
    else:
        with engine.begin() as conn:
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS user_id VARCHAR(40)"))
            conn.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS role VARCHAR(20) NOT NULL DEFAULT 'user'"))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_user_id ON users(user_id)"))
    Base.metadata.create_all(engine)

run_schema_migrations()

class RegisterIn(BaseModel):
    name: str
    email: str
    password: str

class LoginIn(BaseModel):
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    user_id: str
    name: str
    email: str
    role: str

class ForgotPasswordIn(BaseModel):
    email: str

class ForgotUserIdIn(BaseModel):
    email: str

class ResetPasswordIn(BaseModel):
    token: str
    password: str

class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str

AUTH_SECRET = os.getenv("SECRET_KEY", os.getenv("AUTH_SECRET", "change-this-secret-in-production"))
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
TOKEN_HOURS = 24
RESET_TOKEN_MINUTES = 30
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")
SMTP_HOST = os.getenv("SMTP_HOST", "").strip()
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USERNAME).strip()
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"

def make_user_id(db: Session) -> str:
    last = db.query(User).order_by(User.id.desc()).first()
    next_number = (last.id + 1) if last else 1
    return f"ETD-{next_number:06d}"

def ensure_user_ids(db: Session):
    users = db.query(User).filter(User.user_id.is_(None)).order_by(User.id.asc()).all()
    for user in users:
        user.user_id = f"ETD-{user.id:06d}"
    if users:
        db.commit()

def ensure_admin_account(db: Session):
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        return
    if len(ADMIN_PASSWORD) < 8:
        raise RuntimeError("ADMIN_PASSWORD must be at least 8 characters")
    user = db.query(User).filter(User.email == ADMIN_EMAIL).first()
    if not user:
        user = User(
            user_id=None,
            name="Administrator",
            email=ADMIN_EMAIL,
            password_hash=hash_password(ADMIN_PASSWORD),
            role="admin",
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        user.user_id = f"ETD-{user.id:06d}"
        db.commit()
    elif user.role != "admin":
        user.role = "admin"
        db.commit()

def send_email(to_email: str, subject: str, text_body: str, html_body: str):
    if not SMTP_HOST or not SMTP_USERNAME or not SMTP_PASSWORD or not SMTP_FROM:
        # Development-friendly fallback. Never expose this in production.
        print(f"[EMAIL NOT CONFIGURED] To={to_email} Subject={subject}\n{text_body}")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email
    msg.set_content(text_body)
    msg.add_alternative(html_body, subtype="html")
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        if SMTP_USE_TLS:
            server.starttls()
        server.login(SMTP_USERNAME, SMTP_PASSWORD)
        server.send_message(msg)
    return True

def create_reset_token(db: Session, user: User) -> str:
    raw = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    db.query(PasswordResetToken).filter(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None)
    ).update({"used_at": datetime.utcnow()})
    db.add(PasswordResetToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=datetime.utcnow() + timedelta(minutes=RESET_TOKEN_MINUTES)
    ))
    db.commit()
    return raw

def reset_url(raw_token: str) -> str:
    base = APP_BASE_URL or ""
    return f"{base}/reset-password?token={quote(raw_token)}"

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    iterations = 310_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return f"pbkdf2_sha256${iterations}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"

def verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256": return False
        salt = base64.urlsafe_b64decode(salt_b64)
        expected = base64.urlsafe_b64decode(digest_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, int(iterations))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def make_token(user: User) -> str:
    payload = {"sub": user.id, "exp": int((datetime.now(timezone.utc) + timedelta(hours=TOKEN_HOURS)).timestamp())}
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    sig = hmac.new(AUTH_SECRET.encode(), body.encode(), hashlib.sha256).digest()
    signature = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{body}.{signature}"

def decode_token(token: str) -> dict:
    try:
        body, signature = token.split(".", 1)
        expected = base64.urlsafe_b64encode(hmac.new(AUTH_SECRET.encode(), body.encode(), hashlib.sha256).digest()).decode().rstrip("=")
        if not hmac.compare_digest(signature, expected): raise ValueError()
        padded = body + "=" * (-len(body) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded).decode())
        if int(payload["exp"]) < int(datetime.now(timezone.utc).timestamp()): raise ValueError()
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired session")


class CompanyIn(BaseModel):
    company_name: str
    industry: str = "Other"
    city: str = ""
    website: str = ""
    employee_band: str = ""
    partner: str = "KOGO"
    expected_value: float = 0
    currency: str = "INR"
    stage: str = "Lead"
    probability: float = 10
    account_owner: str = ""
    team_members: str = ""
    client_poc_name: str = ""
    client_poc_role: str = ""
    client_poc_email: str = ""
    client_poc_phone: str = ""
    source: str = ""
    expected_signup_date: Optional[date] = None
    last_contact_date: Optional[date] = None
    next_action: str = ""
    notes: str = ""

class CompanyOut(CompanyIn):
    model_config = ConfigDict(from_attributes=True)
    id: int
    created_at: datetime
    updated_at: datetime

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_current_user(authorization: Optional[str] = Header(default=None), db: Session = Depends(get_db)) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    payload = decode_token(authorization[7:])
    user = db.get(User, int(payload["sub"]))
    if not user:
        raise HTTPException(status_code=401, detail="User no longer exists")
    return user

def require_admin(user: User = Depends(get_current_user)) -> User:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user

def seed(db: Session):
    if db.query(Company).count(): return
    rows = [
      dict(company_name="Aster Retail", industry="Retail", city="Hyderabad", website="https://aster.example", employee_band="500-1000", partner="KOGO", expected_value=1800000, stage="Proposal", probability=60, account_owner="Sukumar", team_members="Ananya, Rahul", client_poc_name="Meera Rao", client_poc_role="HR Head", client_poc_email="meera@aster.example", client_poc_phone="+91 90000 10001", source="Referral", expected_signup_date=date(2026,10,15), last_contact_date=date(2026,8,28), next_action="Send revised commercial proposal", notes="Interested in phased rollout across Hyderabad and Bengaluru."),
      dict(company_name="BlueOrbit Tech", industry="Technology", city="Bengaluru", partner="Contineu", expected_value=3200000, stage="Negotiation", probability=75, account_owner="Priya", team_members="Vikram", client_poc_name="Arjun Nair", client_poc_role="People Ops", client_poc_email="arjun@blueorbit.example", source="Inbound", expected_signup_date=date(2026,9,30), last_contact_date=date(2026,8,30), next_action="Finalise legal terms", notes="Strong fit; procurement review pending."),
      dict(company_name="Cedar Foods", industry="FMCG", city="Mumbai", partner="KOGO", expected_value=950000, stage="Discovery", probability=30, account_owner="Rahul", team_members="Ananya", client_poc_name="Nisha Shah", client_poc_role="Talent Lead", client_poc_email="nisha@cedar.example", source="Conference", expected_signup_date=date(2026,11,20), last_contact_date=date(2026,8,20), next_action="Schedule discovery workshop", notes="Exploring benefits and employee engagement use cases."),
      dict(company_name="Delta Logistics", industry="Logistics", city="Chennai", partner="Contineu", expected_value=2400000, stage="Proposal", probability=55, account_owner="Ananya", team_members="Rahul, Karthik", client_poc_name="Suresh Iyer", client_poc_role="CFO", client_poc_email="suresh@delta.example", source="Partner", expected_signup_date=date(2026,10,30), last_contact_date=date(2026,8,25), next_action="Confirm budget approval", notes="Needs ROI case for finance leadership."),
      dict(company_name="Evergreen Hospitals", industry="Healthcare", city="Pune", partner="KOGO", expected_value=1500000, stage="Lead", probability=10, account_owner="Priya", team_members="Karthik", client_poc_name="Dr. Kavita Menon", client_poc_role="Admin Director", client_poc_email="kavita@evergreen.example", source="Cold outreach", expected_signup_date=date(2027,1,15), last_contact_date=date(2026,8,12), next_action="Qualify budget and timeline", notes="Large workforce; early-stage conversation."),
      dict(company_name="Futura Manufacturing", industry="Manufacturing", city="Hyderabad", partner="Contineu", expected_value=4200000, stage="Negotiation", probability=80, account_owner="Sukumar", team_members="Priya, Karthik", client_poc_name="Ramesh Kumar", client_poc_role="CHRO", client_poc_email="ramesh@futura.example", source="Referral", expected_signup_date=date(2026,9,20), last_contact_date=date(2026,8,31), next_action="Executive sign-off", notes="High-value opportunity; leadership sponsor engaged."),
      dict(company_name="GreenLeaf Energy", industry="Energy", city="Delhi", partner="KOGO", expected_value=2700000, stage="Discovery", probability=35, account_owner="Karthik", team_members="Ananya", client_poc_name="Ishita Verma", client_poc_role="HRBP", client_poc_email="ishita@greenleaf.example", source="Webinar", expected_signup_date=date(2026,12,5), last_contact_date=date(2026,8,18), next_action="Share use-case deck", notes="Interested in employee rewards and retention."),
      dict(company_name="Harbor Finance", industry="Financial Services", city="Mumbai", partner="KOGO", expected_value=3600000, stage="Proposal", probability=65, account_owner="Rahul", team_members="Priya", client_poc_name="Vivek Joshi", client_poc_role="COO", client_poc_email="vivek@harbor.example", source="Referral", expected_signup_date=date(2026,10,8), last_contact_date=date(2026,8,27), next_action="Resolve security questionnaire", notes="Security review is the main blocker."),
      dict(company_name="Indigo Education", industry="Education", city="Hyderabad", partner="Contineu", expected_value=780000, stage="Qualified", probability=40, account_owner="Ananya", team_members="Rahul", client_poc_name="Lakshmi Devi", client_poc_role="Operations Head", client_poc_email="lakshmi@indigo.example", source="Inbound", expected_signup_date=date(2026,11,10), last_contact_date=date(2026,8,22), next_action="Demo analytics dashboard", notes="Wants reporting for multiple campuses."),
      dict(company_name="Jupiter Hotels", industry="Hospitality", city="Goa", partner="KOGO", expected_value=1200000, stage="Lead", probability=15, account_owner="Karthik", team_members="", client_poc_name="Neel Fernandes", client_poc_role="HR Manager", client_poc_email="neel@jupiter.example", source="Event", expected_signup_date=date(2027,1,30), last_contact_date=date(2026,8,5), next_action="Book introductory call", notes="Seasonal business; likely decision in Q4."),
      dict(company_name="Kite Mobility", industry="Mobility", city="Bengaluru", partner="Contineu", expected_value=2100000, stage="Qualified", probability=45, account_owner="Priya", team_members="Vikram, Ananya", client_poc_name="Sanjay Rao", client_poc_role="VP HR", client_poc_email="sanjay@kite.example", source="Partner", expected_signup_date=date(2026,10,25), last_contact_date=date(2026,8,29), next_action="Send pricing options", notes="Comparing annual vs pilot pricing."),
      dict(company_name="Lumen Pharma", industry="Pharma", city="Ahmedabad", partner="KOGO", expected_value=3000000, stage="Proposal", probability=60, account_owner="Sukumar", team_members="Rahul", client_poc_name="Pooja Patel", client_poc_role="HR Director", client_poc_email="pooja@lumen.example", source="Inbound", expected_signup_date=date(2026,10,18), last_contact_date=date(2026,8,26), next_action="Follow up after leadership meeting", notes="Positive business case; waiting on leadership."),
      dict(company_name="MetroBuild Infra", industry="Infrastructure", city="Chennai", partner="Contineu", expected_value=1750000, stage="Discovery", probability=30, account_owner="Rahul", team_members="Karthik", client_poc_name="Ajay Menon", client_poc_role="HR Manager", client_poc_email="ajay@metrobuild.example", source="Cold outreach", expected_signup_date=date(2026,12,15), last_contact_date=date(2026,8,10), next_action="Identify decision committee", notes="Complex stakeholder group."),
      dict(company_name="Nova Consumer", industry="Consumer Goods", city="Pune", partner="KOGO", expected_value=2300000, stage="Won", probability=100, account_owner="Priya", team_members="Ananya, Vikram", client_poc_name="Ritu Malhotra", client_poc_role="CHRO", client_poc_email="ritu@nova.example", source="Referral", expected_signup_date=date(2026,8,15), last_contact_date=date(2026,8,14), next_action="Handover to implementation", notes="Signed; included as example of post-signup handoff."),
      dict(company_name="Orbit Media", industry="Media", city="Mumbai", partner="Contineu", expected_value=1100000, stage="Lost", probability=0, account_owner="Karthik", team_members="", client_poc_name="Rahul Mehta", client_poc_role="HRBP", client_poc_email="rahul@orbit.example", source="Inbound", expected_signup_date=date(2026,8,1), last_contact_date=date(2026,7,15), next_action="Revisit in 6 months", notes="Paused due to budget freeze."),
    ]
    db.add_all([Company(**r) for r in rows]); db.commit()

app = FastAPI(title="EtiDhi Pipeline Tracker", version="1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

@app.on_event("startup")
def startup():
    db=SessionLocal()
    ensure_user_ids(db)
    ensure_admin_account(db)
    seed(db)
    db.close()

@app.post("/api/auth/register")
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    name = payload.name.strip()
    email = payload.email.strip().lower()
    if len(name) < 2:
        raise HTTPException(400, "Name must be at least 2 characters")
    if "@" not in email or "." not in email.split("@")[-1]:
        raise HTTPException(400, "Enter a valid email address")
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "An account with this email already exists")
    user = User(user_id=None, name=name, email=email, password_hash=hash_password(payload.password), role="user")
    db.add(user); db.commit(); db.refresh(user)
    user.user_id = f"ETD-{user.id:06d}"
    db.commit(); db.refresh(user)
    return {"token": make_token(user), "user": {"id": user.id, "user_id": user.user_id, "name": user.name, "email": user.email, "role": user.role}}

@app.post("/api/auth/login")
def login(payload: LoginIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(User).filter((User.email == email) | (User.user_id == payload.email.strip().upper())).first()
    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(401, "Invalid email or password")
    return {"token": make_token(user), "user": {"id": user.id, "user_id": user.user_id, "name": user.name, "email": user.email, "role": user.role}}

@app.post("/api/auth/forgot-password")
def forgot_password(payload: ForgotPasswordIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    # Generic response prevents account enumeration.
    if user:
        if not user.user_id:
            user.user_id = f"ETD-{user.id:06d}"
            db.commit()
        raw = create_reset_token(db, user)
        url = reset_url(raw)
        subject = "Reset your EtiDhi Pipeline Intelligence password"
        text_body = (
            f"Hello {user.name},\n\n"
            f"We received a request to reset your EtiDhi account password. "
            f"This link expires in {RESET_TOKEN_MINUTES} minutes and can be used once:\n\n{url}\n\n"
            "If you did not request this, you can safely ignore this email."
        )
        html_body = (
            f"<p>Hello {user.name},</p><p>We received a request to reset your EtiDhi account password.</p>"
            f"<p><a href='{url}'>Reset your password</a></p>"
            f"<p>This link expires in {RESET_TOKEN_MINUTES} minutes and can be used once.</p>"
            "<p>If you did not request this, you can safely ignore this email.</p>"
        )
        try:
            sent = send_email(user.email, subject, text_body, html_body)
        except Exception:
            sent = False
        if not sent and not SMTP_HOST:
            # Local development only: show a reset link in the response.
            return {"message": "If an account exists, a reset link has been generated.", "dev_reset_url": url}
    return {"message": "If an account exists for that email, a password reset link has been sent."}

@app.post("/api/auth/forgot-user-id")
def forgot_user_id(payload: ForgotUserIdIn, db: Session = Depends(get_db)):
    email = payload.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if user:
        if not user.user_id:
            user.user_id = f"ETD-{user.id:06d}"
            db.commit()
        subject = "Your EtiDhi Pipeline Intelligence User ID"
        text_body = (
            f"Hello {user.name},\n\nYour EtiDhi User ID is: {user.user_id}\n\n"
            "You can use this ID when contacting support about your account."
        )
        html_body = f"<p>Hello {user.name},</p><p>Your EtiDhi User ID is:</p><p><strong>{user.user_id}</strong></p>"
        try:
            sent = send_email(user.email, subject, text_body, html_body)
        except Exception:
            sent = False
        if not sent and not SMTP_HOST:
            return {"message": "If an account exists, the User ID has been generated.", "dev_user_id": user.user_id}
    return {"message": "If an account exists for that email, the User ID has been sent."}

@app.post("/api/auth/reset-password")
def reset_password(payload: ResetPasswordIn, db: Session = Depends(get_db)):
    if len(payload.password) < 8:
        raise HTTPException(400, "Password must be at least 8 characters")
    token_hash = hashlib.sha256(payload.token.encode()).hexdigest()
    record = db.query(PasswordResetToken).filter(PasswordResetToken.token_hash == token_hash).first()
    if not record or record.used_at is not None or record.expires_at < datetime.utcnow():
        raise HTTPException(400, "This reset link is invalid or expired")
    user = db.get(User, record.user_id)
    if not user:
        raise HTTPException(400, "This reset link is invalid or expired")
    user.password_hash = hash_password(payload.password)
    record.used_at = datetime.utcnow()
    db.commit()
    return {"message": "Password reset successfully. You can now log in."}

@app.post("/api/auth/change-password")
def change_password(payload: ChangePasswordIn, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(400, "Current password is incorrect")
    if len(payload.new_password) < 8:
        raise HTTPException(400, "New password must be at least 8 characters")
    if verify_password(payload.new_password, user.password_hash):
        raise HTTPException(400, "New password must be different from the current password")
    user.password_hash = hash_password(payload.new_password)
    db.commit()
    return {"message": "Password changed successfully"}

@app.get("/api/auth/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "user_id": user.user_id, "name": user.name, "email": user.email, "role": user.role}

@app.get("/api/admin/users", response_model=list[UserOut])
def admin_users(db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    return db.query(User).order_by(User.id.asc()).all()

@app.put("/api/admin/users/{user_id}/role")
def admin_set_role(user_id: int, role: str, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    role = role.strip().lower()
    if role not in {"user", "admin"}:
        raise HTTPException(400, "Role must be user or admin")
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == admin.id and role != "admin":
        raise HTTPException(400, "You cannot remove your own administrator role")
    if target.role == "admin" and role == "user" and db.query(User).filter(User.role == "admin").count() <= 1:
        raise HTTPException(400, "At least one administrator account must remain")
    target.role = role
    db.commit()
    return {"message": "Role updated", "user": {"id": target.id, "user_id": target.user_id, "name": target.name, "email": target.email, "role": target.role}}

@app.delete("/api/admin/users/{user_id}")
def admin_delete_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(require_admin)):
    target = db.get(User, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    if target.id == admin.id:
        raise HTTPException(400, "You cannot delete your own administrator account")
    if target.role == "admin" and db.query(User).filter(User.role == "admin").count() <= 1:
        raise HTTPException(400, "At least one administrator account must remain")
    db.query(PasswordResetToken).filter(PasswordResetToken.user_id == target.id).delete(synchronize_session=False)
    db.delete(target)
    db.commit()
    return {"message": "User deleted"}

@app.get("/api/companies", response_model=list[CompanyOut])
def list_companies(search: str = "", stage: str = "", partner: str = "", owner: str = "", db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    q=db.query(Company)
    if search:
        term=f"%{search}%"; q=q.filter((Company.company_name.ilike(term)) | (Company.client_poc_name.ilike(term)) | (Company.industry.ilike(term)))
    if stage: q=q.filter(Company.stage==stage)
    if partner: q=q.filter(Company.partner==partner)
    if owner: q=q.filter(Company.account_owner==owner)
    return q.order_by(Company.expected_value.desc()).all()

@app.post("/api/companies", response_model=CompanyOut)
def create_company(payload: CompanyIn, db: Session=Depends(get_db), user: User = Depends(get_current_user)):
    c=Company(**payload.model_dump()); db.add(c); db.commit(); db.refresh(c); return c

@app.put("/api/companies/{company_id}", response_model=CompanyOut)
def update_company(company_id:int, payload:CompanyIn, db:Session=Depends(get_db), user: User = Depends(get_current_user)):
    c=db.get(Company, company_id)
    if not c: raise HTTPException(404,"Company not found")
    for k,v in payload.model_dump().items(): setattr(c,k,v)
    db.commit(); db.refresh(c); return c

@app.delete("/api/companies/{company_id}")
def delete_company(company_id:int, db:Session=Depends(get_db), user: User = Depends(get_current_user)):
    c=db.get(Company, company_id)
    if not c: raise HTTPException(404,"Company not found")
    db.delete(c); db.commit(); return {"ok":True}

@app.get("/api/analytics")
def analytics(db:Session=Depends(get_db), user: User = Depends(get_current_user)):
    rows=db.query(Company).all()
    active=[r for r in rows if r.stage not in ("Won","Lost")]
    total=sum(r.expected_value or 0 for r in rows)
    pipeline=sum(r.expected_value or 0 for r in active)
    weighted=sum((r.expected_value or 0)*(r.probability or 0)/100 for r in active)
    won=sum(r.expected_value or 0 for r in rows if r.stage=="Won")
    by_stage={}
    by_partner={}
    by_owner={}
    by_industry={}
    monthly={}
    for r in rows:
        by_stage[r.stage]=by_stage.get(r.stage,0)+(r.expected_value or 0)
        by_partner[r.partner]=by_partner.get(r.partner,0)+(r.expected_value or 0)
        by_owner[r.account_owner]=by_owner.get(r.account_owner,0)+(r.expected_value or 0)
        by_industry[r.industry]=by_industry.get(r.industry,0)+(r.expected_value or 0)
        if r.expected_signup_date:
            key=r.expected_signup_date.strftime("%Y-%m")
            monthly[key]=monthly.get(key,0)+(r.expected_value or 0)
    today=date.today()
    overdue=[r for r in active if r.next_action and r.last_contact_date and (today-r.last_contact_date).days>14]
    return {"total_companies":len(rows),"active_companies":len(active),"total_value":total,"active_pipeline":pipeline,"weighted_pipeline":weighted,"won_value":won,"by_stage":by_stage,"by_partner":by_partner,"by_owner":by_owner,"by_industry":by_industry,"monthly":dict(sorted(monthly.items())),"stale_count":len(overdue)}

app.mount("/static", StaticFiles(directory=BASE_DIR/"static"), name="static")
@app.get("/auth")
def auth_page(): return FileResponse(BASE_DIR/"static/auth.html")

@app.get("/")
def root(): return FileResponse(BASE_DIR/"static/auth.html")

@app.get("/dashboard")
def dashboard_page(): return FileResponse(BASE_DIR/"static/index.html")

@app.get("/reset-password")
def reset_password_page(): return FileResponse(BASE_DIR/"static/auth.html")

@app.get("/health")
def health():
    return {"status": "ok"}
