html_content = """
<!DOCTYPE html>
<html>
<head>
    <title>파이썬 HTML</title>
</head>
<body>
    <h1>안녕하세요!</h1>
    <p>파이썬 코드 안에서 작성한 HTML입니다.</p>
</body>
</html>
"""

# HTML 파일로 저장하기
with open("index.html", "w", encoding="utf-8") as f:
    f.f_write = f.write(html_content) # 올바른 사용법: f.write(html_content)
    # f.write(html_content)
