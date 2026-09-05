#!/usr/bin/env python3
import requests

CVE_ID = 'CVE-2026-6772'
NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

url = f'{NVD_API}?cveId={CVE_ID}'
resp = requests.get(url, timeout=10)
data = resp.json()

vuln = data['vulnerabilities'][0]['cve']

print('=' * 160)
print(f'{CVE_ID} - 새 로직 검증')
print('=' * 160)

# 1단계: Affected에서 affected 추출
affected_list = []
for affected_item in vuln.get('affected', []):
    for affected_data in affected_item.get('affectedData', []):
        product = affected_data.get('product', '')
        for version_info in affected_data.get('versions', []):
            v = version_info.get('version', '')
            status = version_info.get('status', '')
            less_equal = version_info.get('lessThanOrEqual', '')
            less_than = version_info.get('lessThan', '')

            if status == 'affected' and (less_equal or less_than):
                end_version = less_equal or less_than
                if end_version and '*' not in end_version:
                    version_range = f"< {end_version}" if less_than else f"<= {end_version}"
                    if v != '0':
                        version_range = f"{v} ~ {end_version}"
                    if product:
                        version_range = f"{product} {version_range}"
                    affected_list.append(version_range)

print(f'\n1단계: Affected에서 affected 추출')
print(f'  결과: {affected_list if affected_list else "없음"}')

# 2단계: Configurations에서 제품명 추출
config_products = set()
for config in vuln.get('configurations', []):
    for node in config.get('nodes', []):
        for match in node.get('cpeMatch', []):
            if match.get('vulnerable'):
                cpe = match.get('criteria', '')
                if cpe:
                    parts = cpe.split(':')
                    if len(parts) > 4:
                        product_name = parts[4]
                        if product_name and product_name != '*':
                            config_products.add(product_name)

print(f'\n2단계: Configurations에서 제품명 추출')
print(f'  결과: {config_products}')

# 3단계: Configurations에서 취약 범위 추출 (affected가 없을 때)
if not affected_list:
    for config in vuln.get('configurations', []):
        for node in config.get('nodes', []):
            for match in node.get('cpeMatch', []):
                if match.get('vulnerable'):
                    cpe = match.get('criteria', '')
                    product_name = ''
                    if cpe:
                        parts = cpe.split(':')
                        if len(parts) > 4:
                            product_name = parts[4]

                    start = match.get('versionStartIncluding') or match.get('versionStartExcluding', '')
                    end = match.get('versionEndExcluding') or match.get('versionEndIncluding', '')

                    if start or end:
                        if start and end:
                            version_info = f"{start} ~ {end}"
                        elif end:
                            op = "<" if match.get('versionEndExcluding') else "<="
                            version_info = f"{op} {end}"
                        else:
                            op = ">=" if match.get('versionStartIncluding') else ">"
                            version_info = f"{op} {start}"

                        if product_name and product_name != '*':
                            version_info = f"{product_name} {version_info}"
                        affected_list.append(version_info)

print(f'\n3단계: Configurations에서 취약 범위 추출')
print(f'  R열 결과: {sorted(set(affected_list))}')

# 4단계: Affected에서 필터링된 제품의 패치 버전만 추출
fixed_list = []
for affected_item in vuln.get('affected', []):
    for affected_data in affected_item.get('affectedData', []):
        product = affected_data.get('product', '')

        # Configurations에 있는 제품만 필터링 (대소문자 무시)
        if config_products and product.lower() not in config_products:
            print(f'  제외됨: {product} (Configurations에 없음)')
            continue

        for version_info in affected_data.get('versions', []):
            v = version_info.get('version', '')
            status = version_info.get('status', '')
            ver_type = version_info.get('versionType', '')

            if status == 'unaffected' and v and v != '0':
                if 'git' in ver_type:
                    fixed_list.append(f"{product} git: {v}" if product else f"git: {v}")
                else:
                    fixed_list.append(f"{product} {v}" if product else v)

print(f'\n4단계: 필터링된 제품의 패치 버전만 추출')
print(f'  S열 결과: {fixed_list}')

print(f'\n' + '=' * 160)
print('최종 결과:')
print('=' * 160)
print(f'\nR열 (취약 버전):')
for item in sorted(set(affected_list)):
    print(f'  {item}')

print(f'\nS열 (패치 버전):')
for item in fixed_list:
    print(f'  {item}')

print('\n✓ 예상 결과:')
print('  R열: Firefox < 150.0, Firefox 140.0 ~ 140.10.0, Firefox < 140.10.0, Thunderbird < 140.10.0')
print('  S열: Firefox 115.35, Firefox 140.10, Firefox 150, Thunderbird 140.10, Thunderbird 150')
