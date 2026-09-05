#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""행 8 CVE 구조 확인"""

import requests
import json

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID = "CVE-2026-6772"

url = f"{NVD_API}?cveId={CVE_ID}"
resp = requests.get(url, timeout=10)
data = resp.json()

vuln = data['vulnerabilities'][0]['cve']

print(f"CVE: {CVE_ID}\n")

# affected 배열 확인
print("=== affected 배열 ===")
affected = vuln.get('affected', [])
print(f"길이: {len(affected)}")
if affected:
    for i, item in enumerate(affected[:1]):
        print(f"affected[{i}]:")
        aff_data = item.get('affectedData', [])
        if aff_data:
            print(f"  product: {aff_data[0].get('product')}")

# configurations 배열 확인
print("\n=== configurations 배열 ===")
configs = vuln.get('configurations', [])
print(f"길이: {len(configs)}")
if configs:
    config = configs[0]
    nodes = config.get('nodes', [])
    print(f"nodes: {len(nodes)}")
    if nodes:
        node = nodes[0]
        cpe_matches = node.get('cpeMatch', [])
        print(f"cpeMatch: {len(cpe_matches)}")

        # 처음 3개만 보기
        for k, match in enumerate(cpe_matches[:3]):
            print(f"\n  cpeMatch[{k}]:")
            print(f"    vulnerable: {match.get('vulnerable')}")
            cpe = match.get('criteria', '')
            print(f"    criteria: {cpe}")

            # CPE 파싱
            if cpe:
                parts = cpe.split(':')
                print(f"    parts: {parts[:7]}")
                if len(parts) > 5:
                    print(f"    product: {parts[5]}")
