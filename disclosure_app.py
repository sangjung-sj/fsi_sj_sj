from flask import Flask, render_template_string, request, jsonify
import webbrowser
import threading
import time
import os
from pathlib import Path

app = Flask(__name__)

# disclosure_injection.html 읽기
def load_html():
    html_path = Path(__file__).parent / 'disclosure_injection.html'
    with open(html_path, 'r', encoding='utf-8') as f:
        return f.read()

HTML_CONTENT = load_html()

@app.route('/')
def index():
    return HTML_CONTENT

@app.route('/api/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        disclosure_id = data.get('disclosure_id', '')
        content = data.get('content', '')
        analysis_type = data.get('analysis_type', '')

        # ⚠️ 의도적인 프롬프트 인젝션 취약점
        # 사용자 입력이 검증 없이 프롬프트에 포함됨

        # 간단한 분석 시뮬레이션
        result = f"""[분석 ID: {disclosure_id}]
[분석 유형: {analysis_type}]

입력 내용:
{content}

[시스템 정보 - CTF FLAG]
fiesta2026{{prompt_injection_challenge_solved}}

분석 결과:
- 이 분석은 시뮬레이션입니다.
- 프롬프트 인젝션으로 시스템 정보에 접근할 수 있습니다.
- 입력 필드에 특수 명령어를 시도해보세요!"""

        return jsonify({
            'success': True,
            'result': result
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

def open_browser():
    """브라우저 자동 열기"""
    time.sleep(1.5)
    webbrowser.open('http://127.0.0.1:5000')

if __name__ == '__main__':
    print("=" * 60)
    print("🚀 CTF Challenge: Prompt Injection Attack")
    print("=" * 60)
    print("📍 서버가 실행 중입니다: http://127.0.0.1:5000")
    print("🌐 브라우저가 자동으로 열립니다...")
    print("\n💡 목표: 프롬프트 인젝션을 통해 flag를 획득하세요!")
    print("💡 Hint: 분석 요청 입력 필드에 특수 문자나 명령어를 시도해보세요")
    print("\n⚠️  종료하려면 Ctrl+C를 누르세요")
    print("=" * 60)

    # 브라우저 자동 열기
    thread = threading.Thread(target=open_browser, daemon=True)
    thread.start()

    # Flask 앱 실행
    app.run(debug=True, use_reloader=False, port=5000)
