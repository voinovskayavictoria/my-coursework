# Маршруты веб-страниц: главная панель с дашбордом, история сканирований с фильтрацией, просмотр отчётов и экспорт в JSON.
import json
from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse, Response, RedirectResponse
from sqlalchemy import func

from models import Scan, Vulnerability, SessionLocal
from webapp.scans.storage import get_scan_bundle
from webapp.session import session_id_from_request
from webapp.ui import templates, format_dt_plus3, iso_dt_plus3

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
async def main_page(request: Request):
    db = SessionLocal()
    try:
        current_user = request.state.current_user
        if current_user:
            total_scans, total_critical, total_high = db.query(
                func.count(Scan.id),
                func.coalesce(func.sum(Scan.critical_count), 0),
                func.coalesce(func.sum(Scan.high_count), 0),
            ).filter(Scan.user_id == current_user.id).one()
            recent_scans = db.query(Scan).filter(Scan.user_id == current_user.id).order_by(Scan.created_at.desc()).limit(10).all()
            recent_scans_view = [
                {
                    **scan.__dict__,
                    "created_at_text": format_dt_plus3(scan.created_at),
                    "created_at_iso": iso_dt_plus3(scan.created_at),
                }
                for scan in recent_scans
            ]
        else:
            recent_scans = []
            recent_scans_view = []
            total_scans = 0
            total_critical = 0
            total_high = 0
        return templates.TemplateResponse("index.html", {
            "request": request,
            "recent_scans": recent_scans,
            "recent_scans_view": recent_scans_view,
            "total_scans": total_scans,
            "total_critical": total_critical,
            "total_high": total_high,
            "history_count": total_scans,
            "session_id": request.state.scan_session_id,
            "current_user": current_user,
        })
    finally:
        db.close()


@router.get("/history", response_class=HTMLResponse)
async def history_page(request: Request):
    db = SessionLocal()
    try:
        current_user = request.state.current_user
        if not current_user:
            return RedirectResponse(url="/auth?mode=login", status_code=303)

        search_query = str(request.query_params.get("q", "")).strip()
        sort_by = str(request.query_params.get("sort", "date_new")).strip()
        page = max(1, int(request.query_params.get("page", "1")))
        per_page = 50
        
        query = db.query(Scan)
        query = query.filter(Scan.user_id == current_user.id)
        if search_query:
            query = query.filter(Scan.target.ilike(f"%{search_query}%"))

        if sort_by == "date_new":
            query = query.order_by(Scan.created_at.desc())
        elif sort_by == "date_old":
            query = query.order_by(Scan.created_at.asc())
        elif sort_by == "name_az":
            query = query.order_by(Scan.target.asc())
        elif sort_by == "name_za":
            query = query.order_by(Scan.target.desc())
        elif sort_by == "critical_high":
            query = query.order_by(Scan.critical_count.desc())
        elif sort_by == "critical_low":
            query = query.order_by(Scan.critical_count.asc())
        elif sort_by == "total_high":
            from sqlalchemy import desc
            query = query.order_by(desc(Scan.critical_count + Scan.high_count + Scan.medium_count + Scan.low_count))
        elif sort_by == "total_low":
            from sqlalchemy import asc
            query = query.order_by(asc(Scan.critical_count + Scan.high_count + Scan.medium_count + Scan.low_count))
        else:
            query = query.order_by(Scan.created_at.desc())

        total = query.count()
        offset = (page - 1) * per_page
        scans = query.offset(offset).limit(per_page).all()

        scans_view = [
            {
                **scan.__dict__,
                "created_at_text": format_dt_plus3(scan.created_at, "%d.%m.%Y %H:%M"),
                "created_at_iso": iso_dt_plus3(scan.created_at),
                "total_vulns": scan.critical_count + scan.high_count + scan.medium_count + scan.low_count,
            }
            for scan in scans
        ]

        total_pages = (total + per_page - 1) // per_page

        return templates.TemplateResponse("history.html", {
            "request": request,
            "scans": scans,
            "scans_view": scans_view,
            "total_scans": total,
            "q": search_query,
            "sort": sort_by,
            "current_user": current_user,
            "page": page,
            "total_pages": total_pages,
            "per_page": per_page,
        })
    finally:
        db.close()


@router.post("/history/clear")
async def clear_history(request: Request):
    current_user = getattr(request.state, "current_user", None)
    if not current_user:
        return RedirectResponse(url="/auth?mode=login", status_code=303)

    db = SessionLocal()
    try:
        scan_ids = [row[0] for row in db.query(Scan.id).filter(Scan.user_id == current_user.id).all()]
        if scan_ids:
            db.query(Vulnerability).filter(Vulnerability.scan_id.in_(scan_ids)).delete(synchronize_session=False)
            db.query(Scan).filter(Scan.id.in_(scan_ids)).delete(synchronize_session=False)
            db.commit()
    finally:
        db.close()

    return RedirectResponse(url="/history", status_code=303)


@router.post("/history/delete-selected")
async def delete_selected_history(request: Request):
    current_user = getattr(request.state, "current_user", None)
    if not current_user:
        return RedirectResponse(url="/auth?mode=login", status_code=303)

    form = await request.form()
    raw_selected = form.getlist("scan_ids") or []
    selected_ids = [str(v).strip() for v in raw_selected if str(v).strip()]
    if not selected_ids:
        return RedirectResponse(url="/history", status_code=303)

    # Basic validation: ensure values look like ids (avoid treating a single string as iterable)
    valid_ids = [s for s in selected_ids if isinstance(s, str) and len(s) > 6]
    if not valid_ids:
        return RedirectResponse(url="/history", status_code=303)

    db = SessionLocal()
    try:
        owned_scan_ids = [
            row[0]
            for row in db.query(Scan.id)
            .filter(Scan.user_id == current_user.id, Scan.id.in_(valid_ids))
            .all()
        ]
        if owned_scan_ids:
            db.query(Vulnerability).filter(Vulnerability.scan_id.in_(owned_scan_ids)).delete(synchronize_session=False)
            db.query(Scan).filter(Scan.id.in_(owned_scan_ids)).delete(synchronize_session=False)
            db.commit()
    finally:
        db.close()

    return RedirectResponse(url="/history", status_code=303)


@router.get("/scan/{scan_id}", response_class=HTMLResponse)
async def scan_report(request: Request, scan_id: str):
    db = SessionLocal()
    try:
        payload = get_scan_bundle(
            db,
            scan_id,
            getattr(request.state, "current_user", None),
            session_id=session_id_from_request(request),
        )
        if not payload:
            raise HTTPException(404, "Скан не найден")

        scan = payload["scan"]
        scan_view = {
            **scan,
            "created_at_text": format_dt_plus3(scan.get("created_at"), "%d.%m.%Y %H:%M"),
            "created_at_iso": iso_dt_plus3(scan.get("created_at")),
        }

        return templates.TemplateResponse("report.html", {
            "request": request,
            "scan": payload["scan"],
            "scan_view": scan_view,
            "vulnerabilities": payload["vulnerabilities"],
        })
    finally:
        db.close()


@router.get("/scan/{scan_id}/download")
async def download_scan_report(request: Request, scan_id: str):
    db = SessionLocal()
    try:
        payload = get_scan_bundle(
            db,
            scan_id,
            getattr(request.state, "current_user", None),
            session_id=session_id_from_request(request),
        )
        if not payload:
            raise HTTPException(404, "Скан не найден")

        download_payload = {
            "scan": {
                **payload["scan"],
                "created_at": payload["scan"]["created_at"].isoformat() if payload["scan"]["created_at"] else None,
            },
            "vulnerabilities": payload["vulnerabilities"],
        }

        return Response(
            content=json.dumps(download_payload, ensure_ascii=False, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="scan_{scan_id}.json"'},
        )
    finally:
        db.close()
