import streamlit as st
import pandas as pd
import os
from datetime import datetime

st.set_page_config(page_title="Nexpose 데이터 관리", layout="wide")

st.title("🔒 Nexpose 데이터 관리 시스템")
st.markdown("---")

# 사이드바 메뉴
with st.sidebar:
    st.header("메뉴")
    menu = st.radio("선택:", ["데이터 조회", "파일 업로드", "데이터 검증", "통계"])

# 1. 데이터 조회
if menu == "데이터 조회":
    st.header("📊 저장된 데이터 조회")

    # 엑셀 파일 목록 표시
    excel_files = [f for f in os.listdir(".") if f.endswith(".xlsx") and not f.startswith("~")]

    if excel_files:
        selected_file = st.selectbox("파일 선택:", excel_files)

        if selected_file:
            try:
                df = pd.read_excel(selected_file)
                st.success(f"✅ {selected_file} 로드 완료")

                # 기본 정보 표시
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("총 행 수", len(df))
                with col2:
                    st.metric("총 열 수", len(df.columns))
                with col3:
                    st.metric("파일 크기", f"{os.path.getsize(selected_file) / 1024:.1f} KB")

                st.markdown("### 데이터 미리보기")
                st.dataframe(df, use_container_width=True)

                # 열 정보
                st.markdown("### 열 정보")
                st.dataframe(df.dtypes, use_container_width=True)

                # CSV 다운로드
                csv = df.to_csv(index=False)
                st.download_button(
                    label="CSV로 다운로드",
                    data=csv,
                    file_name=selected_file.replace(".xlsx", ".csv"),
                    mime="text/csv"
                )

            except Exception as e:
                st.error(f"❌ 파일 로드 실패: {e}")
    else:
        st.info("📁 저장된 Excel 파일이 없습니다.")

# 2. 파일 업로드
elif menu == "파일 업로드":
    st.header("📤 파일 업로드")

    uploaded_file = st.file_uploader("Excel 파일을 선택하세요:", type=["xlsx", "xls", "csv"])

    if uploaded_file is not None:
        try:
            if uploaded_file.name.endswith(".csv"):
                df = pd.read_csv(uploaded_file)
            else:
                df = pd.read_excel(uploaded_file)

            st.success(f"✅ {uploaded_file.name} 로드 완료")
            st.dataframe(df, use_container_width=True)

            # 파일 저장
            save_path = uploaded_file.name
            if uploaded_file.name.endswith(".csv"):
                df.to_excel(save_path.replace(".csv", ".xlsx"), index=False)
            else:
                df.to_excel(save_path, index=False)

            st.success(f"✅ 파일이 저장되었습니다: {save_path}")

        except Exception as e:
            st.error(f"❌ 파일 처리 실패: {e}")

# 3. 데이터 검증
elif menu == "데이터 검증":
    st.header("✔️ 데이터 검증")

    excel_files = [f for f in os.listdir(".") if f.endswith(".xlsx") and not f.startswith("~")]

    if excel_files:
        selected_file = st.selectbox("검증할 파일:", excel_files)

        if selected_file:
            try:
                df = pd.read_excel(selected_file)

                st.markdown("### 검증 결과")
                col1, col2, col3, col4 = st.columns(4)

                with col1:
                    st.metric("총 행 수", len(df))
                with col2:
                    null_count = df.isnull().sum().sum()
                    st.metric("NULL 값", null_count)
                with col3:
                    duplicate_count = df.duplicated().sum()
                    st.metric("중복 행", duplicate_count)
                with col4:
                    st.metric("메모리 사용", f"{df.memory_usage().sum() / 1024:.1f} KB")

                # 열별 NULL 값 확인
                st.markdown("### 열별 NULL 값")
                null_by_col = df.isnull().sum()
                null_by_col = null_by_col[null_by_col > 0]

                if len(null_by_col) > 0:
                    st.bar_chart(null_by_col)
                else:
                    st.success("✅ NULL 값이 없습니다.")

                # 데이터 타입
                st.markdown("### 데이터 타입")
                st.dataframe(df.dtypes.astype(str), use_container_width=True)

            except Exception as e:
                st.error(f"❌ 검증 실패: {e}")
    else:
        st.info("📁 저장된 Excel 파일이 없습니다.")

# 4. 통계
elif menu == "통계":
    st.header("📈 데이터 통계")

    excel_files = [f for f in os.listdir(".") if f.endswith(".xlsx") and not f.startswith("~")]

    if excel_files:
        selected_file = st.selectbox("분석할 파일:", excel_files)

        if selected_file:
            try:
                df = pd.read_excel(selected_file)

                st.markdown("### 기본 통계")
                st.dataframe(df.describe(), use_container_width=True)

                # 수치형 열만 선택
                numeric_cols = df.select_dtypes(include=['number']).columns.tolist()

                if numeric_cols:
                    st.markdown("### 수치형 데이터 분포")
                    selected_col = st.selectbox("열 선택:", numeric_cols)
                    st.bar_chart(df[selected_col].value_counts().head(20))

            except Exception as e:
                st.error(f"❌ 통계 분석 실패: {e}")
    else:
        st.info("📁 저장된 Excel 파일이 없습니다.")

# 하단 정보
st.markdown("---")
st.markdown(f"**마지막 업데이트:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
