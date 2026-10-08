"""⑤ 설정 위험·외부 시도: 행동 이상과 별도로 개선할 것은 무엇인가."""
import plotly.graph_objects as go
import streamlit as st

import components as C
import loaders as L
import theme as T

T.hero("설정 위험·외부 시도", "행동 이상과 별도로 고쳐야 할 계정 설정과, 로그인에 성공하지 못한 외부 반복 시도를 봅니다.")
C.page_note()

cfg = L.load("config_findings")
r16 = cfg[cfg["rule"] == "R16"]
st.markdown("#### 설정 위험")
if r16.empty:
    st.info("설정 위험(R16) 결과가 없습니다.")
for _, r in r16.iterrows():
    with st.container(border=True):
        C.html_row(C._pill(C.SEVERITY["low"][1], C.SEVERITY["low"][0], "심각도 low · 행동 이상 아님"),
                   C.basis_badge("근거", "관측"), C.chip("전체 기간 값"))
        st.markdown(f"**MFA 없는 최상위 콘솔 계정 로그인** · 계정 `{r['account']}` · **{int(r['count'])}회** "
                    f"({r['sessions']}개 세션, {L.kst_text(r['first_seen'])} ~ {L.kst_text(r['last_seen'])} KST)")
        st.markdown("- 테이렌 **콘솔**의 최상위 계정 로그인입니다. Linux 서버의 `root` 활동과는 다른 계정 체계입니다.\n"
                    "- 행동이 이상한 것이 아니라 계정 **설정** 문제라서 세션 위험점수에서 빼고 조치 항목 1건으로 보고합니다.\n"
                    "- **권고 조치:** 최상위 계정에 MFA 적용, 일상 업무는 하위 계정으로 분리.")

st.markdown("#### 외부 IP 로그인 시도")
ext = L.num(L.load("external_profile"), "attempts", "active_days", "attempts_per_day", "distinct_accounts")
tl = L.load("timeline_sessions", ["event_time_utc", "bucket", "client_ip", "account"])
tries = tl[tl["bucket"] == "external"].copy()
tries["t"] = L.to_kst(tries["event_time_utc"])
tries_f = tries[L.in_range(tries["t"])]
success = (ext["ever_logged_in"] == "true").sum()

k = st.columns(4)
k[0].metric("외부 IP (개)", f"{len(ext)}", help="전체 기간")
k[1].metric("시도 (회, 전체 기간)", f"{int(ext['attempts'].sum()):,}")
k[2].metric("시도 (회, 선택 기간)", f"{len(tries_f):,}", help="발생 시각 기준으로 이벤트를 직접 센 값")
k[3].metric("로그인 성공 기록 (IP)", f"{success}", help="수집된 sshd 범위에서 성공 기록이 있는 IP 수")
C.scope_note("그래프와 ‘선택 기간’ 숫자는 발생 시각 기준. 아래 IP 요약표는 전체 기간 값")

daily = tries_f.assign(date=tries_f["t"].dt.date).groupby(["date", "client_ip"]).size().reset_index(name="n")
fig = go.Figure()
for ip, color in zip(ext.sort_values("attempts", ascending=False)["client_ip"], C.SERIES):
    d = daily[daily["client_ip"] == ip]
    fig.add_scatter(x=d["date"], y=d["n"], mode="lines+markers", name=ip, line=dict(color=color, width=2),
                    marker=dict(size=8, color=color, line=dict(width=2, color=C.SURFACE)),
                    hovertemplate=f"{ip}<br>%{{x}} · %{{y}}회<extra></extra>")
fig.update_yaxes(title="하루 시도 수", rangemode="tozero", dtick=2)
fig.update_xaxes(title="날짜 (KST)", tickformat="%m-%d")
C.show(C.style(fig, height=300), key="ce_daily")
st.caption("세 IP 모두 기간 내내 하루 몇 회씩 천천히 시도했습니다. ‘1시간 5회’ 룰(R09)은 한 번도 걸리지 않았습니다. "
           "저속 반복 시도를 잡는 기준은 개선 과제로 남겼습니다(화면에서 새 룰로 다시 탐지하지 않음).")

st.dataframe(ext.assign(처음=ext["first_seen"].map(L.kst_text), 마지막=ext["last_seen"].map(L.kst_text),
                        성공=ext["ever_logged_in"].map({"true": "있음", "false": "없음"}),
                        계정명=ext["accounts"].str.replace("|", ", "))[
    ["client_ip", "attempts", "active_days", "attempts_per_day", "distinct_accounts", "계정명", "처음", "마지막", "성공"]
].rename(columns={"client_ip": "외부 IP", "attempts": "시도", "active_days": "기간(일)", "attempts_per_day": "하루 평균",
                  "distinct_accounts": "계정명 수", "계정명": "시도한 계정명", "성공": "로그인 성공"}),
    hide_index=True, width="stretch")
st.info("이 IP들은 로그인에 성공하지 못해 위험점수가 없습니다. 외부 IP에서 **로그인에 성공한** 세션(경보 목록)과는 "
        "다른 집단입니다. IP 국가·지도는 현재 산출물에 근거가 없어 표시하지 않습니다.", icon=":material/info:")
