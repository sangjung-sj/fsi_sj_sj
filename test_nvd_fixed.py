#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""수정된 NVD 파싱 테스트"""

import requests
import json
import logging
from typing import Tuple, Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID = "CVE-2026-66032"

def get_nvd_info(cve_id: str) -> Tuple[Optional[str], Optional[str]]:
    """NVD API로 CVE 정보 조회"""
    try:
        url = f"{NVD_API}?cveId={cve_id}"
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        if not data.get('vulnerabilities'):
            return None, None

        vuln = data['vulnerabilities'][0]['cve']
        affected_list = []
        fixed_version = None

        # 먼저 affected 배열에서 버전 정보 추출 (더 정확함)
        print(f"\n[affected 배열 분석]")
        for affected_item in vuln.get('affected', []):
            for affected_data in affected_item.get('affectedData', []):
                print(f"  vendor: {affected_data.get('vendor')}, product: {affected_data.get('product')}")
                for version_info in affected_data.get('versions', []):
                    v = version_info.get('version', '')
                    status = version_info.get('status', '')
                    less_equal = version_info.get('lessThanOrEqual', '')
                    less_than = version_info.get('lessThan', '')
                    ver_type = version_info.get('versionType', '')

                    print(f"    version={v}, status={status}, lessThanOrEqual={less_equal}, type={ver_type}")

                    # 영향받는 버전 범위
                    if status == 'affected' and less_equal:
                        version_range = f"<= {less_equal}"
                        if v != '0':
                            version_range = f"{v} ~ {less_equal}"
                        affected_list.append(version_range)
                        print(f"      ✓ 추가됨: {version_range}")

                    # 패치 버전 (최소)
                    if status == 'unaffected' and v and v != '0':
                        if 'git' not in ver_type:
                            fixed_version = v
                            print(f"      ✓ 패치 버전: {v}")

        # affected 배열에서 정보를 못 찾으면 configurations에서 추출
        if not affected_list:
            print(f"\n[configurations 배열 분석]")
            for config in vuln.get('configurations', []):
                for node in config.get('nodes', []):
                    for match in node.get('cpeMatch', []):
                        if match.get('vulnerable'):
                            # versionRange 객체 (구 방식)
                            vr = match.get('versionRange')
                            if vr:
                                start = vr.get('versionStartIncluding') or vr.get('versionStartExcluding', '')
                                end = vr.get('versionEndExcluding') or vr.get('versionEndIncluding', '')
                            else:
                                # 직접 필드 (신 방식)
                                start = match.get('versionStartIncluding') or match.get('versionStartExcluding', '')
                                end = match.get('versionEndExcluding') or match.get('versionEndIncluding', '')

                            print(f"  start={start}, end={end}")

                            # 버전 정보 추출
                            if start or end:
                                if start and end:
                                    version_info = f"{start} ~ {end}"
                                elif end:
                                    version_info = f"<= {end}"
                                else:
                                    version_info = f">= {start}"
                                affected_list.append(version_info)
                                print(f"    ✓ 추가됨: {version_info}")

        affected_str = "; ".join(set(affected_list)) if affected_list else None
        patch_info = fixed_version if fixed_version else "[공식 공지 참조]"

        print(f"\n[최종 결과]")
        print(f"  R 열 (취약 버전): {affected_str}")
        print(f"  S 열 (조치 버전): {patch_info}")

        return affected_str, patch_info if affected_str else None

    except Exception as e:
        logger.error(f"✗ NVD {cve_id}: {e}")
        import traceback
        traceback.print_exc()
        return None, None

# 테스트
print("=" * 80)
print(f"NVD API 테스트: {CVE_ID}")
print("=" * 80)

result = get_nvd_info(CVE_ID)
print(f"\n반환 값: {result}")
