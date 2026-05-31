import json
import shutil
import tempfile
import traceback
import zipfile
import datetime
from pathlib import Path

import httpx
from fastapi import APIRouter, Request, HTTPException, UploadFile, File, Form
from fastapi.responses import JSONResponse, StreamingResponse

from models import Scan, SessionLocal, User
from security_scanner import analyze_response_security_headers
from webapp.auth import current_user_id
from webapp.config import MAX_ARCHIVE_SIZE_BYTES
from webapp.scans.archive import safe_extract_zip, scan_extracted_project
from webapp.scans.html import collect_html_vulnerabilities, fetch_limited_html, normalize_target_url, validate_html_size
from webapp.scans.options import parse_analysis_options
from webapp.scans.source import scan_source_project
from webapp.scans.storage import apply_rule_filter, create_scan, enrich_and_save, format_scan_target, normalize_vulnerability
from webapp.session import session_id_from_request

router = APIRouter()


@router.post("/api/scan/html")
async def scan_html(request: Request, data: dict):
    try:
        html_code = data.get("html_code")
        if not html_code:
            raise HTTPException(400, "Нет html_code")
        validate_html_size(html_code)

        session_id = session_id_from_request(request)
        user_id = current_user_id(request)
        _, enabled_rules = parse_analysis_options(data)

        vulnerabilities = collect_html_vulnerabilities(html_code, enabled_rules)

        db = SessionLocal()
        try:
            scan = create_scan(db, format_scan_target("CODE", "HTML/JS"), session_id=session_id, user_id=user_id, html_code=html_code)
            scan_id = scan.id
            enrich_and_save(db, scan_id, vulnerabilities)
        finally:
            db.close()

        return {"scan_id": scan_id}
    except HTTPException:
        raise
    except Exception as e:
        print("Ошибка в scan_html:")
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.post("/api/scan/source")
async def scan_source(request: Request, data: dict):
    try:
        project_path = data.get("project_path")
        if not project_path:
            raise HTTPException(400, "Не указан project_path")
        max_depth, enabled_rules = parse_analysis_options(data)

        root = Path(project_path)
        if not root.exists() or not root.is_dir():
            raise HTTPException(400, "project_path должен указывать на существующую папку")

        session_id = session_id_from_request(request)
        user_id = current_user_id(request)

        vulnerabilities = scan_source_project(root, max_depth=max_depth, enabled_rules=enabled_rules)

        db = SessionLocal()
        try:
            scan = create_scan(db, format_scan_target("CODE", f"Исходный код проекта: {root.as_posix()}"), session_id=session_id, user_id=user_id)
            scan_id = scan.id
            enrich_and_save(db, scan_id, vulnerabilities)
            return {"scan_id": scan_id, "found": len(vulnerabilities)}
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception as e:
        print("Ошибка в scan_source:")
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.post("/api/scan/archive")
async def scan_archive(request: Request, archive: UploadFile = File(...), analysis_options: str | None = Form(None)):
    temp_dir = Path(tempfile.mkdtemp(prefix="webscan_"))
    archive_path = temp_dir / (archive.filename or "project.zip")

    try:
        parsed_options = {}
        if analysis_options:
            try:
                parsed_options = json.loads(analysis_options)
            except Exception:
                raise HTTPException(400, "analysis_options должно быть валидным JSON")
        max_depth, enabled_rules = parse_analysis_options({"options": parsed_options})

        contents = await archive.read()
        if not contents:
            raise HTTPException(400, "Пустой архив")
        if len(contents) > MAX_ARCHIVE_SIZE_BYTES:
            raise HTTPException(400, "Архив слишком большой")
        archive_path.write_bytes(contents)

        if not zipfile.is_zipfile(archive_path):
            raise HTTPException(400, "Поддерживается только zip-архив")

        extract_dir = temp_dir / "extracted"
        extract_dir.mkdir(parents=True, exist_ok=True)
        safe_extract_zip(archive_path, extract_dir)

        project_root = extract_dir
        entries = list(project_root.iterdir())
        if len(entries) == 1 and entries[0].is_dir():
            project_root = entries[0]

        session_id = session_id_from_request(request)
        user_id = current_user_id(request)
        vulnerabilities = scan_extracted_project(project_root, max_depth=max_depth, enabled_rules=enabled_rules)

        db = SessionLocal()
        try:
            scan = create_scan(db, format_scan_target("ZIP", archive.filename or "project.zip"), session_id=session_id, user_id=user_id)
            scan_id = scan.id
            enrich_and_save(db, scan_id, vulnerabilities)
            return {"scan_id": scan_id, "found": len(vulnerabilities)}
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception as e:
        print("Ошибка в scan_archive:")
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/api/scan")
async def scan_url(request: Request, data: dict):
    try:
        target = data.get("target")
        if not target:
            raise HTTPException(400, "Не указан target")
        target = normalize_target_url(target)
        html_code, response_headers, response_url = await fetch_limited_html(target)
        session_id = session_id_from_request(request)
        user_id = current_user_id(request)
        _, enabled_rules = parse_analysis_options(data)
        vulnerabilities = collect_html_vulnerabilities(html_code, enabled_rules)
        security_findings = analyze_response_security_headers(response_headers, scheme=response_url.scheme)
        for idx, vuln in enumerate(security_findings, start=1):
            vuln.setdefault("rule", vuln.get("name"))
            vulnerabilities.append(normalize_vulnerability(vuln, "SEC", idx))
        vulnerabilities = apply_rule_filter(vulnerabilities, enabled_rules)

        db = SessionLocal()
        try:
            scan = create_scan(db, format_scan_target("WEB", target), session_id=session_id, user_id=user_id, html_code=html_code)
            scan_id = scan.id
            enrich_and_save(db, scan_id, vulnerabilities)
            return {"scan_id": scan_id}
        finally:
            db.close()
    except HTTPException:
        raise
    except httpx.TimeoutException as e:
        print("Ошибка в scan_url: timeout")
        traceback.print_exc()
        return JSONResponse(status_code=502, content={"error": "Не удалось загрузить страницу: таймаут при обращении к URL"})
    except httpx.RequestError as e:
        print("Ошибка в scan_url: request error")
        traceback.print_exc()
        return JSONResponse(status_code=502, content={"error": f"Не удалось загрузить страницу: {e.__class__.__name__}"})
    except Exception as e:
        print("Ошибка в scan_url:")
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.get("/api/scan/{scan_id}/view-code")
async def view_scan_code(request: Request, scan_id: str):
    try:
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                raise HTTPException(404, "Скан не найден")

            user_id = current_user_id(request)
            if user_id:
                if scan.user_id != user_id:
                    raise HTTPException(403, "Доступ запрещен")
            else:
                if scan.user_id:
                    raise HTTPException(403, "Доступ запрещен")
                request_session_id = session_id_from_request(request)
                if scan.session_id and request_session_id and scan.session_id != request_session_id:
                    raise HTTPException(403, "Доступ запрещен")

            if not scan.html_code:
                raise HTTPException(404, "HTML-код для этого скана не сохранен")

            return {"html_code": scan.html_code}
        finally:
            db.close()
    except HTTPException:
        raise
    except Exception as e:
        print("Ошибка в view_scan_code:")
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})


@router.post("/api/scans/export-batch")
async def export_batch_scans(request: Request):
    try:
        data = await request.json()
        scan_ids = data.get("scan_ids", [])
        if not scan_ids or not isinstance(scan_ids, list):
            raise HTTPException(400, "Требуется список scan_ids")

        user_id = current_user_id(request)
        session_id = session_id_from_request(request)

        from webapp.scans.storage import get_scan_bundle

        db = SessionLocal()
        try:
            exported_scans = []
            user_obj = None
            if user_id:
                user_obj = db.query(User).filter(User.id == user_id).first()

            for scan_id in scan_ids:
                payload = get_scan_bundle(db, scan_id, user_obj, session_id=session_id)
                if payload:
                    exported_scans.append({
                        "scan": {
                            "id": payload["scan"]["id"],
                            "target": payload["scan"]["target"],
                            "created_at": payload["scan"]["created_at"].isoformat() if payload["scan"]["created_at"] else None,
                            "critical_count": payload["scan"]["critical_count"],
                            "high_count": payload["scan"]["high_count"],
                            "medium_count": payload["scan"]["medium_count"],
                            "low_count": payload["scan"]["low_count"],
                        },
                        "vulnerabilities": payload["vulnerabilities"],
                    })

            export_data = {
                "export_date": datetime.datetime.utcnow().isoformat(),
                "total_scans": len(exported_scans),
                "scans": exported_scans,
            }

            content = json.dumps(export_data, ensure_ascii=False, indent=2, default=str)
            filename = f"scans-export-{datetime.datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json"

            return StreamingResponse(
                iter([content]),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{filename}"'},
            )
        finally:
            db.close()

    except HTTPException:
        raise
    except Exception as e:
        print("Ошибка в export_batch_scans:")
        traceback.print_exc()
        return JSONResponse(status_code=500, content={"error": str(e)})
