import json
import datetime
from typing import Optional
from models import SessionLocal, VulnerabilityCache

import nvdlib


def _get_cache(source: str, key: str) -> Optional[dict]:
    db = SessionLocal()
    try:
        row = db.query(VulnerabilityCache).filter(VulnerabilityCache.source == source, VulnerabilityCache.key == key).first()
        if not row:
            return None
        try:
            return json.loads(row.payload)
        except Exception:
            return None
    finally:
        db.close()


def _set_cache(source: str, key: str, payload: dict) -> None:
    db = SessionLocal()
    try:
        row = db.query(VulnerabilityCache).filter(VulnerabilityCache.source == source, VulnerabilityCache.key == key).first()
        payload_text = json.dumps(payload, ensure_ascii=False)
        if row:
            row.payload = payload_text
            row.fetched_at = datetime.datetime.utcnow()
        else:
            row = VulnerabilityCache(source=source, key=key, payload=payload_text)
            db.add(row)
        db.commit()
    finally:
        db.close()


def enrich_cve(cve_id: str) -> dict:
    """Enrich CVE using NVD. Returns a dict with keys: cve_id, description, cvss_score, advisory_url"""
    if not cve_id:
        return {}

    cached = _get_cache('nvd', cve_id)
    if cached:
        return cached

    try:
        # nvdlib provides a query function to get CVE details
        cve = nvdlib.searchCVE(cveId=cve_id)
        # cve is a list; take first
        if not cve:
            result = {}
        else:
            item = cve[0]
            # description: nvdlib CVE object exposes 'descriptions' or 'descriptions' list
            description = ''
            try:
                descs = getattr(item, 'descriptions', None) or getattr(item, 'descriptions', None)
                if descs:
                    # descs may be list of dicts or objects
                    first = descs[0]
                    if isinstance(first, dict):
                        description = first.get('value', '')
                    else:
                        description = getattr(first, 'value', str(first))
            except Exception:
                description = ''

            # cvss v3 score
            score = None
            try:
                score = getattr(item, 'v31score', None) or getattr(item, 'v3score', None) or getattr(item, 'score', None)
            except Exception:
                score = None

            # references
            advisory_url = None
            try:
                refs = getattr(item, 'references', None)
                if refs and len(refs) > 0:
                    first = refs[0]
                    if isinstance(first, dict):
                        advisory_url = first.get('url')
                    else:
                        advisory_url = getattr(first, 'url', None) or getattr(first, 'href', None)
            except Exception:
                advisory_url = None

            result = {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': float(score) if score is not None else None,
                'advisory_url': advisory_url,
            }
    except Exception as e:
        result = {}

    try:
        if result:
            _set_cache('nvd', cve_id, result)
    except Exception:
        pass

    return result
