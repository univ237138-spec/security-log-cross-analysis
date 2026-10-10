"""보안 경보 분석 대시보드 v2.

실행 (프로젝트 최상위에서): streamlit run dashboard_v2/app.py
계획: docs/15_대시보드/02_현재산출물_기반_대시보드_구성계획.md
0~7단계 결과 CSV를 읽기만 한다. 탐지·기준선·점수·판정은 다시 계산하지 않는다.
기존 dashboard/(v1)는 그대로 두었다.
"""
import streamlit as st

import components as C
import loaders as L
import theme as T

st.set_page_config(page_title="보안 경보 분석", page_icon=":material/shield:", layout="wide")
T.apply()
T.logo()

PAGES = [
    st.Page("views/overview.py", title="전체 현황", icon=":material/dashboard:", default=True),
    st.Page("views/alert_list.py", title="경보 목록", icon=":material/format_list_numbered:"),
    st.Page("views/alert_detail.py", title="경보 상세", icon=":material/search:"),
    st.Page("views/session_explorer.py", title="세션·기준선 탐색", icon=":material/timeline:"),
    st.Page("views/config_external.py", title="설정 위험·외부 시도", icon=":material/settings_alert:"),
    st.Page("views/method_limits.py", title="판정·점수 기준", icon=":material/fact_check:"),
]
page = st.navigation(PAGES)

with st.sidebar:
    lo, hi = L.data_period()
    st.caption(f"데이터 기간 (KST)  \n{lo:%Y-%m-%d %H:%M} ~ {hi:%Y-%m-%d %H:%M}  \n"
               "데이터 안의 시각입니다.  \n실시간 관제가 아닙니다.")
    st.session_state.setdefault("date_range", (lo.date(), hi.date()))
    st.session_state.setdefault("show_ref", False)
    st.session_state.setdefault("mask", False)

    def _reset_range():
        st.session_state["date_range"] = (lo.date(), hi.date())

    st.date_input("기간 (KST 날짜)", min_value=lo.date(), max_value=hi.date(), key="date_range",
                  help="전체 현황·경보 목록·세션 탐색·외부 시도에 함께 적용됩니다. "
                       "이벤트는 발생 시각, 세션·경보는 세션 시작 시각 기준입니다. 경보 상세는 기간과 상관없이 전체 근거를 보여줍니다.")
    st.button("전체 기간으로", width="stretch", on_click=_reset_range)
    st.toggle("분석자 참고 라벨 보기", key="show_ref",
              help="프로젝트 초기 문서(07_분석기획)에 적힌 시나리오 A~D를 세션 옆에 표시합니다. "
                   "탐지 결과로 만든 정답이 아니므로 기본은 꺼둡니다.")
    st.toggle("공유용 가림 표시", key="mask",
              help="이메일 도메인·내부 IP·호스트 이름·tenancy를 같은 별칭으로 바꿉니다. 원문·마우스 설명·표에 모두 적용됩니다.")
    st.markdown("**근거**")
    C.html_row(*(C.legend(k, C.BASIS_ICON[k], C.BASIS_TONE[k], desc) for k, desc in [
        ("관측", "로그에 직접 기록"), ("추정", "시간·서버·IP로 연결"), ("모름", "로그로 알 수 없음")]))
    st.markdown("**판정**")
    C.html_row(*(C.legend(v, icon, C.VERDICT_TONE[v]) for v, (_, icon) in C.VERDICT.items()))
    with st.expander("결과 파일 상태"):
        st.caption("파일 수정 시각은 분석 실행 시각과 다를 수 있습니다.")
        st.dataframe(L.file_status(), hide_index=True, width="stretch")

page.run()
