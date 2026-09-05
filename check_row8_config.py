#!/usr/bin/env python3
import requests

CVE_ID = 'CVE-2026-6772'
NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

url = f'{NVD_API}?cveId={CVE_ID}'
resp = requests.get(url, timeout=10)
data = resp.json()

vuln = data['vulnerabilities'][0]['cve']

print('=' * 160)
print(f'{CVE_ID} - Configurations 배열 분석')
print('=' * 160)

for config in vuln.get('configurations', []):
    for node in config.get('nodes', []):
        for match in node.get('cpeMatch', []):
            if match.get('vulnerable'):
                cpe = match.get('criteria', '')
                start_inc = match.get('versionStartIncluding', '')
                end_exc = match.get('versionEndExcluding', '')
                end_inc = match.get('versionEndIncluding', '')

                print(f'\nCPE: {cpe}')
                print(f'  versionStartIncluding: {start_inc}')
                print(f'  versionEndExcluding: {end_exc}')
                print(f'  versionEndIncluding: {end_inc}')

print('\n' + '=' * 160)
print('분석 결과:')
print('=' * 160)
print('''
✓ Affected 배열:
  - status=affected인 취약 버전: 없음
  - status=unaffected인 패치 버전: Firefox 115.35, 140.10, 150

✗ 현재 R열의 데이터:
  - "Firefox < 150.0; Firefox 140.0 ~ 140.10.0; ..."
  - 이것은 Configurations 배열에서 나온 데이터

⚠ 문제:
  우리 코드는 Affected 배열만 사용하도록 변경했으므로,
  이 CVE는 파싱 실패되어야 맞습니다.

  현재 파일은 이전 코드(configurations 포함)로 생성되었습니다.
''')
