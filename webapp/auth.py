import hashlib
import uuid
from datetime import timedelta
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from sqlalchemy import func

from models import Scan, User, SessionLocal
from webapp.config import AUTH_COOKIE_NAME
from webapp.ui import templates, format_dt_plus3

router = APIRouter()


def hash_password(password: str, salt: str | None = None) -> str:
    salt_value = salt or uuid.uuid4().hex
    digest = hashlib.sha256(f"{salt_value}:{password}".encode("utf-8")).hexdigest()
    return f"{salt_value}${digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    if "$" not in stored_hash:
        return False
    salt, digest = stored_hash.split("$", 1)
    return hash_password(password, salt) == f"{salt}${digest}"


def get_current_user(request: Request) -> User | None:
    user_id = request.cookies.get(AUTH_COOKIE_NAME)
    if not user_id:
        return None
    db = SessionLocal()
    try:
        return db.query(User).filter(User.id == user_id).first()
    finally:
        db.close()


def current_user_id(request: Request) -> str | None:
    current_user = getattr(request.state, "current_user", None)
    return current_user.id if current_user else None


@router.get("/auth", response_class=HTMLResponse)
async def auth_page(request: Request, mode: str = "login"):
    return templates.TemplateResponse("auth.html", {
        "request": request,
        "mode": mode,
        "current_user": request.state.current_user,
    })


@router.get("/api/me/summary")
async def current_user_summary(request: Request):
    current_user = request.state.current_user
    if not current_user:
        raise HTTPException(401, "Не авторизован")

    db = SessionLocal()
    try:
        history_count, total_critical, total_high = db.query(
            func.count(Scan.id),
            func.coalesce(func.sum(Scan.critical_count), 0),
            func.coalesce(func.sum(Scan.high_count), 0),
        ).filter(Scan.user_id == current_user.id).one()
        recent_scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(10).all()
        return {
            "history_count": history_count,
            "total_critical": total_critical,
            "total_high": total_high,
            "recent_scans": [
                {
                    "id": scan.id,
                    "target": scan.target,
                    "created_at": (scan.created_at + timedelta(hours=3)).isoformat() if scan.created_at else "",
                    "created_at_text": format_dt_plus3(scan.created_at),
                    "critical_count": scan.critical_count,
                    "high_count": scan.high_count,
                }
                for scan in recent_scans
            ],
        }
    finally:
        db.close()


@router.post("/auth/register")
async def register_user(request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))
    if len(username) < 3 or len(password) < 6:
        raise HTTPException(400, "Логин должен быть не короче 3 символов, пароль - 6 символов")

    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.username == username).first()
        if existing:
            raise HTTPException(400, "Пользователь уже существует")
        user = User(username=username, password_hash=hash_password(password))
        db.add(user)
        db.commit()
        db.refresh(user)
        response = JSONResponse({"ok": True})
        response.set_cookie(AUTH_COOKIE_NAME, user.id, httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30)
        return response
    finally:
        db.close()


@router.post("/auth/login")
async def login_user(request: Request):
    form = await request.form()
    username = str(form.get("username", "")).strip()
    password = str(form.get("password", ""))

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user or not verify_password(password, user.password_hash):
            raise HTTPException(400, "Неверный логин или пароль")
        response = JSONResponse({"ok": True})
        response.set_cookie(AUTH_COOKIE_NAME, user.id, httponly=True, samesite="lax", max_age=60 * 60 * 24 * 30)
        return response
    finally:
        db.close()


@router.get("/logout")
async def logout_user():
    response = RedirectResponse(url="/auth?mode=login", status_code=303)
    response.delete_cookie(AUTH_COOKIE_NAME)
    return response


async def auth_context_middleware(request: Request, call_next):
    request.state.current_user = get_current_user(request)
    response = await call_next(request)
    content_type = response.headers.get("content-type", "")
    if content_type.startswith("text/html"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
    return response
