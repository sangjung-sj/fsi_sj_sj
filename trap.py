#!/usr/bin/env python3
# FinSight "job failed" 트리거용 동적 서버
#
# 목적: FinSight의 안전한 브라우저 Agent가 이 페이지를 렌더할 때,
#       <script src="/hang.js"> 로드가 영원히 안 끝나 render가 timeout → job status=failed.
#       failed가 되면 app.js가 recovery-runtime.js 를 로드하고 MCP recovery 경로가 열림.
#
# 사용법:
#   pip install flask
#   python trap.py
#   # 다른 터미널에서 공인 도메인/443으로 노출 (FinSight가 IP·비HTML·비표준포트 차단):
#   cloudflared tunnel --url http://localhost:8080      (또는  ngrok http 8080)
#   # 출력되는 https://<xxx>.trycloudflare.com 주소를 분석 URL로 제출.
#
# 요청 로그가 찍히므로 FinSight fetcher/agent 의 User-Agent·IP·서브리소스 요청도 관찰 가능.

from flask import Flask, Response, request
import sys, time

app = Flask(__name__)


@app.before_request
def _log():
    sys.stderr.write(
        f"[HIT] {request.remote_addr} {request.method} {request.path} "
        f"UA={request.headers.get('User-Agent','')}\n"
    )
    sys.stderr.flush()


# 검증(빠른 200 text/html) 통과 + 렌더 시 hang 서브리소스 참조
@app.route("/")
def index():
    html = (
        '<!doctype html><html lang="ko"><head><meta charset="utf-8">'
        '<title>부산은행 분기보고서</title>'
        '<script src="/hang.js"></script>'      # 이 로드가 안 끝남 → load 이벤트 미발생 → 렌더 타임아웃
        '</head><body>'
        '<h1>부산은행 분기보고서</h1>'
        '<p>자산총계 145,234,567 백만원 · 당기순이익 234,567 백만원</p>'
        '</body></html>'
    )
    return Response(html, mimetype="text/html")


# 브라우저 렌더가 이 스크립트를 기다리다 timeout → job failed
@app.route("/hang.js")
def hang():
    time.sleep(600)              # 10분 매달림
    return Response("", mimetype="application/javascript")


# (대안) 초대형 응답으로 렌더 부하를 주고 싶을 때: /big.js 참조로 바꿔서 사용
@app.route("/big.js")
def big():
    return Response("var x='" + ("A" * (60 * 1024 * 1024)) + "';",
                    mimetype="application/javascript")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
