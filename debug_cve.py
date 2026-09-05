#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CVE-2026-45447 구조 확인"""

import requests
import json

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID = "CVE-2026-45447"

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
        print(f"\naffected[{i}]:")
        print(json.dumps(item, indent=2, ensure_ascii=False)[:500])

# configurations 배열 확인
print("\n\n=== configurations 배열 ===")
configs = vuln.get('configurations', [])
print(f"길이: {len(configs)}")
if configs:
    for i, config in enumerate(configs[:1]):
        print(f"\nconfig[{i}]:")
        nodes = config.get('nodes', [])
        print(f"  nodes: {len(nodes)}")
        for j, node in enumerate(nodes[:1]):
            print(f"  node[{j}]:")
            for k, match in enumerate(node.get('cpeMatch', [])[:1]):
                print(f"    cpeMatch[{k}]:")
                print(f"      vulnerable: {match.get('vulnerable')}")
                print(f"      criteria: {match.get('criteria')[:80]}...")
                vr = match.get('versionRange')
                if vr:
                    print(f"      versionRange: {vr}")
                else:
                    print(f"      versionStartIncluding: {match.get('versionStartIncluding')}")
                    print(f"      versionStartExcluding: {match.get('versionStartExcluding')}")
                    print(f"      versionEndIncluding: {match.get('versionEndIncluding')}")
                    print(f"      versionEndExcluding: {match.get('versionEndExcluding')}")
