#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""행 8 CVE 전체 구조 확인"""

import requests
import json

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID = "CVE-2026-6772"

url = f"{NVD_API}?cveId={CVE_ID}"
resp = requests.get(url, timeout=10)
data = resp.json()

vuln = data['vulnerabilities'][0]['cve']

print(f"CVE: {CVE_ID}\n")

# affected 배열 전체
print("=== affected 배열 ===")
affected = vuln.get('affected', [])
if affected:
    print(json.dumps(affected, indent=2, ensure_ascii=False)[:1500])
