import datetime
from sqlalchemy.orm import Session

from llm_support import enrich_findings_with_llm
from models import Scan, Vulnerability, User
from vuln_sources import enrich_cve
from webapp.state import TRANSIENT_SCANS


def build_scan_payload(scan_id: str, target: str, session_id: str | None, vulnerabilities: list[dict], created_at=None) -> dict:
    created_at = created_at or datetime.datetime.utcnow()
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    normalized_vulnerabilities: list[dict] = []

    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "medium")).lower()
        if severity not in severity_counts:
            severity = "low"
        severity_counts[severity] += 1
        normalized_vulnerabilities.append({
            "id": vuln.get("id"),
            "cve_id": vuln.get("cve_id"),
            "name": vuln.get("name"),
            "description": vuln.get("description"),
            "severity": severity,
            "cvss_score": vuln.get("cvss_score", 0.0),
            "recommendation": vuln.get("recommendation"),
            "advisory_url": vuln.get("advisory_url") or vuln.get("url"),
            "code_snippet": vuln.get("code_snippet"),
        })

    return {
        "scan": {
            "id": scan_id,
            "target": target,
            "session_id": session_id,
            "created_at": created_at,
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
        },
        "vulnerabilities": normalized_vulnerabilities,
    }


def store_transient_scan(scan_id: str, target: str, session_id: str | None, vulnerabilities: list[dict]) -> None:
    TRANSIENT_SCANS[scan_id] = build_scan_payload(scan_id, target, session_id, vulnerabilities)


def get_scan_bundle(
    db: Session,
    scan_id: str,
    current_user: User | None = None,
    session_id: str | None = None,
) -> dict | None:
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan:
        if current_user:
            if scan.user_id != current_user.id:
                return None
        else:
            if scan.user_id:
                return None
            if scan.session_id and session_id and scan.session_id != session_id:
                return None

        vulns = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
        return build_scan_payload(
            scan.id,
            scan.target,
            scan.session_id,
            [
                {
                    "id": vuln.id,
                    "cve_id": vuln.cve_id,
                    "name": vuln.name,
                    "description": vuln.description,
                    "severity": vuln.severity,
                    "cvss_score": vuln.cvss_score,
                    "recommendation": vuln.recommendation,
                    "advisory_url": vuln.advisory_url,
                    "code_snippet": vuln.code_snippet,
                }
                for vuln in vulns
            ],
            created_at=scan.created_at,
        )

    if current_user:
        return None

    return TRANSIENT_SCANS.get(scan_id)


def save_vulnerabilities(db: Session, scan_id: str, vulnerabilities: list):
    critical = high = medium = low = 0
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "medium").lower()
        if sev == "critical":
            critical += 1
        elif sev == "high":
            high += 1
        elif sev == "medium":
            medium += 1
        else:
            low += 1

        cve_id = vuln.get("id")
        enriched = {}
        if cve_id and isinstance(cve_id, str) and cve_id.upper().startswith("CVE-"):
            try:
                enriched = enrich_cve(cve_id)
            except Exception:
                enriched = {}

        description = vuln.get("description") or enriched.get("description")
        cvss_score = vuln.get("cvss_score", None)
        if (not cvss_score or cvss_score == 0) and enriched.get("cvss_score") is not None:
            cvss_score = enriched.get("cvss_score")
        advisory = vuln.get("url") or enriched.get("advisory_url")

        db.add(Vulnerability(
            scan_id=scan_id,
            cve_id=cve_id,
            name=vuln.get("name"),
            description=description,
            severity=sev,
            cvss_score=cvss_score or 0.0,
            recommendation=vuln.get("recommendation") or "Обновите библиотеку до актуальной версии",
            advisory_url=advisory,
            code_snippet=vuln.get("code_snippet"),
        ))

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if scan:
        scan.critical_count = critical
        scan.high_count = high
        scan.medium_count = medium
        scan.low_count = low
    db.commit()


def create_scan(db: Session, target: str, session_id: str | None = None, user_id: str | None = None, html_code: str | None = None) -> Scan:
    scan = Scan(target=target, session_id=session_id, user_id=user_id, html_code=html_code)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def format_scan_target(prefix: str, detail: str) -> str:
    detail = detail.strip()
    return f"{prefix}: {detail}" if detail else prefix


def normalize_vulnerability(vuln: dict, prefix: str, index: int) -> dict:
    vuln.setdefault("id", f"{prefix}-{index}")
    vuln.setdefault("cvss_score", 0.0)
    vuln.setdefault("url", None)
    return vuln


def apply_rule_filter(vulnerabilities: list[dict], enabled_rules: set[str] | None) -> list[dict]:
    if not enabled_rules:
        return vulnerabilities
    normalized_rules = [rule.strip().lower() for rule in enabled_rules if str(rule).strip()]
    filtered: list[dict] = []
    for vuln in vulnerabilities:
        rule = str(vuln.get("rule") or vuln.get("name") or "").strip()
        rule_lower = rule.lower()
        if any(entry == rule_lower or entry in rule_lower for entry in normalized_rules):
            filtered.append(vuln)
    return filtered


def enrich_and_save(db: Session, scan_id: str, vulnerabilities: list[dict]) -> None:
    if not vulnerabilities:
        save_vulnerabilities(db, scan_id, [])
        return
    enriched_vulnerabilities = enrich_findings_with_llm(vulnerabilities)
    save_vulnerabilities(db, scan_id, enriched_vulnerabilities)


def enrich_transient_scan(scan_id: str, target: str, session_id: str | None, vulnerabilities: list[dict]) -> None:
    if not vulnerabilities:
        store_transient_scan(scan_id, target, session_id, [])
        return
    enriched_vulnerabilities = enrich_findings_with_llm(vulnerabilities)
    store_transient_scan(scan_id, target, session_id, enriched_vulnerabilities)
