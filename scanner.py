# scanner.py
import requests
import re
from typing import List, Dict, Any

class VulnerabilityScanner:
    def __init__(self):
        self.osv_url = "https://api.osv.dev/v1/query"

    def search_by_product_version(self, package_name: str, version: str, ecosystem: str = "npm") -> List[Dict[str, Any]]:
        if not package_name or not version:
            return []
        payload = {
            "version": version,
            "package": {"name": package_name, "ecosystem": ecosystem}
        }
        try:
            resp = requests.post(self.osv_url, json=payload, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            results = []
            for vuln in data.get("vulns", []):
                severity = "medium"
                cvss_score = 0.0
                if "severity" in vuln and isinstance(vuln["severity"], list):
                    for item in vuln["severity"]:
                        if isinstance(item, dict) and "score" in item:
                            try:
                                score = float(item["score"])
                                cvss_score = score
                                if score >= 9.0: severity = "critical"
                                elif score >= 7.0: severity = "high"
                                elif score >= 4.0: severity = "medium"
                                break
                            except:
                                continue
                results.append({
                    "id": vuln.get("id", "N/A"),
                    "description": vuln.get("summary") or vuln.get("details", "Нет описания"),
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "url": f"https://osv.dev/vulnerability/{vuln.get('id')}"
                })
            print(f"OSV: {package_name} {version} -> найдено {len(results)} уязвимостей")
            return results
        except Exception as e:
            print(f"OSV Error {package_name}@{version}: {e}")
            return []

# Упрощённое извлечение библиотеки и версии из URL (без регулярок для поиска уязвимостей)
def extract_lib_and_version(src: str):
    if not src:
        return None, None
    src_lower = src.lower()
    lib_map = {
        'jquery': 'jquery',
        'bootstrap': 'bootstrap',
        'vue': 'vue',
        'angular': 'angular',
        'react': 'react',
        'lodash': 'lodash',
        'moment': 'moment',
        'axios': 'axios'
    }
    for key, name in lib_map.items():
        if key in src_lower:
            match = re.search(r'(\d+\.\d+\.\d+)', src)
            if match:
                version = match.group(1)
                return name, version
    return None, None
