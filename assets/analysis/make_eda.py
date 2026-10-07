"""EDA 차트 6개 (기준 숫자의 근거 + 결과 요약) → assets/analysis/*.png

실행: 프로젝트 최상위 폴더에서 `python assets/analysis/make_eda.py`
입력은 data/ 결과 파일만 읽는다. 값을 다시 계산하지 않고, 차트용 집계만 한다.
"""
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data"
OUT = Path(__file__).resolve().parent

# 기본 팔레트 slot 1·2 (전체 쌍 검증 통과 구간), 나머지는 텍스트·축 토큰
BLUE, ORANGE = "#2a78d6", "#eb6834"
SURFACE, INK, INK2, MUTED, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#8a8984", "#e6e5e1"
RAMP = ["#86b6ef", "#5598e7", "#2a78d6", "#1c5cab", "#104281"]  # 순서형: 250→650

plt.rcParams.update({
    "font.family": "Malgun Gothic",
    "axes.unicode_minus": False,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
    "savefig.facecolor": SURFACE,
    "axes.edgecolor": GRID,
    "axes.labelcolor": INK2,
    "axes.titlecolor": INK,
    "axes.titlesize": 15,
    "axes.titleweight": "bold",
    "axes.titlelocation": "left",
    "axes.titlepad": 30,
    "axes.labelsize": 11,
    "xtick.color": INK2,
    "ytick.color": INK2,
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.8,
    "axes.axisbelow": True,
})


def subtitle(ax, text):
    ax.text(0, 1.02, text, transform=ax.transAxes, fontsize=10.5, color=INK2, va="bottom")


def footnote(fig, text):
    fig.text(0.01, -0.03, text, fontsize=8.5, color=MUTED, ha="left", va="bottom")


def save(fig, name):
    fig.savefig(OUT / name, dpi=200, bbox_inches="tight", pad_inches=0.25)
    plt.close(fig)
    print("saved", name)


# ── C1. 3단계: 웹 요청 간격 분포 → 30분 기준 ───────────────────────────
def c1_web_gap():
    t = pd.read_csv(DATA / "07_sessions/timeline_sessions.csv", low_memory=False, encoding="utf-8-sig")
    t["_t"] = pd.to_datetime(t["event_time_utc"])
    w = t[t["work_session_link"] == "접속 IP + 시간"].sort_values("_t")
    gaps = (w.groupby("work_session_id")["_t"].diff().dt.total_seconds().dropna())
    gaps = np.sort(gaps.to_numpy())
    q = lambda p: gaps[int(p * (len(gaps) - 1))]
    med, mx = q(.5), gaps[-1]

    fig, ax = plt.subplots(figsize=(10, 5.2))
    bins = np.logspace(np.log10(max(gaps.min(), 0.5)), np.log10(3600), 40)
    ax.hist(np.clip(gaps, 0.5, None), bins=bins, color=BLUE, edgecolor=SURFACE, linewidth=1.5)
    ax.set_xscale("log")
    ax.set_xticks([1, 10, 60, 600, 1800, 3600])
    ax.set_xticklabels(["1초", "10초", "1분", "10분", "30분", "1시간"])
    ax.set_xlabel("같은 세션 안에서 웹 요청 사이 간격 (로그 축)")
    ax.set_ylabel("간격 수")
    ax.grid(axis="x", visible=False)
    top = ax.get_ylim()[1]
    for x, label, color, ls, h, ha in [(med, f"중앙값 {med:.0f}초", INK2, ":", 0.97, "right"),
                                       (mx, f"정상 최대 {mx/60:.1f}분", INK2, "--", 0.80, "right"),
                                       (1800, "세션 끊는 기준\n30분", ORANGE, "-", 0.62, "left")]:
        ax.axvline(x, color=color, linestyle=ls, linewidth=2)
        ax.text(x * (1.08 if ha == "left" else 0.92), top * h, label, color=INK, fontsize=10, va="top", ha=ha)
    ax.axvspan(mx, 1800, color=ORANGE, alpha=0.06)
    ax.set_title("30분 기준의 근거: 정상 업무 중 웹 요청은 12.6분 넘게 끊긴 적이 없다")
    subtitle(ax, f"ssh 세션 안 웹 요청 간격 {len(gaps):,}개 · 중앙값 {med:.0f}초, 99% {q(.99):.0f}초, 최대 {mx:.0f}초")
    footnote(fig, "자료: data/07_sessions/timeline_sessions.csv (웹 요청을 접속 IP + 시간으로 세션에 붙인 행)")
    save(fig, "C1_웹요청간격_30분기준.png")


# ── D3. 4단계: 처음 보는 시스템 패턴의 등장 시점 → 24시간 기준 ─────────
def d3_new_pattern_time():
    b = pd.read_csv(DATA / "08_baseline/background_baseline.csv", encoding="utf-8-sig")
    n = b[(b["pattern_seen_before"] == 0) & (b["event_action"] != "process_terminate")].copy()
    hosts = ["bastion-01", "web-01", "app-01", "node-01"]
    n["y"] = n["host"].map({h: i for i, h in enumerate(hosts)})
    rng = np.random.default_rng(7)
    n["yj"] = n["y"] + rng.uniform(-0.18, 0.18, len(n))
    late = n["host_history_hours"] >= 24

    fig, ax = plt.subplots(figsize=(10, 4.8))
    ax.axvspan(0, 24, color=GRID, alpha=0.7, zorder=0)
    ax.text(27, 3.62, "← 학습 기간 (첫 24시간)", ha="left", va="center", fontsize=9.5, color=INK2)
    ax.scatter(n.loc[~late, "host_history_hours"], n.loc[~late, "yj"], s=70, color=BLUE,
               edgecolor=SURFACE, linewidth=2, zorder=3, label=f"첫 24시간 안: {(~late).sum()}건")
    ax.scatter(n.loc[late, "host_history_hours"], n.loc[late, "yj"], s=70, color=ORANGE,
               edgecolor=SURFACE, linewidth=2, zorder=3, label=f"24시간 이후: {late.sum()}건")
    ax.axvline(24, color=INK2, linestyle="--", linewidth=1.5)
    for h, g in n[late].groupby("host"):
        ax.annotate(f"{h} · {g['host_history_hours'].min():.0f}시간째 · {len(g)}건",
                    (g["host_history_hours"].min(), g["y"].iloc[0]),
                    xytext=(-12, 16), textcoords="offset points", ha="right", fontsize=9.5, color=INK)
    ax.set_yticks(range(4))
    ax.set_yticklabels(hosts)
    ax.set_ylim(-0.6, 4.0)
    ax.set_xlim(-5, 380)
    ax.set_xlabel("그 서버의 기록이 쌓인 시간 (시간)")
    ax.grid(axis="y", visible=False)
    ax.legend(loc="lower left", frameon=False, ncol=2, bbox_to_anchor=(-0.01, 1.0), fontsize=10)
    ax.set_title("24시간 기준의 근거: 처음 보는 시스템 활동은 첫날에 몰리고, 그 뒤엔 드물다", pad=34)
    footnote(fig, "자료: data/08_baseline/background_baseline.csv · 같은 서버에서 처음 나온 패턴의 이벤트 (프로세스 종료 제외) · 4단계는 판단하지 않고 비교값만 만든다")
    save(fig, "D3_처음보는패턴_24시간기준.png")


# ── D2. 4단계: 서버별 시스템 패턴 빈도 → 드문 것이 눈에 띈다 ──────────
def d2_pattern_freq():
    p = pd.read_csv(DATA / "08_baseline/background_patterns.csv", encoding="utf-8-sig")
    p["first_seen"] = pd.to_datetime(p["first_seen"])
    start = pd.read_csv(DATA / "08_baseline/background_baseline.csv", encoding="utf-8-sig") \
        .assign(t=lambda d: pd.to_datetime(d["event_time_utc"])).groupby("host")["t"].min()
    p["hours"] = (p["first_seen"] - p["host"].map(start)).dt.total_seconds() / 3600
    p["late"] = p["hours"] >= 24
    kind = {"cmd": "실행", "dst": "연결", "file": "파일"}
    prog = p["Image"].str.split("/").str[-1].str.replace(r"\d+(\.\d+)*$", "", regex=True)
    p["label"] = [f"{h} · {a} · {pr} {kind[k]}: {str(d)[:38]}" for h, a, pr, k, d
                  in zip(p["host"], p["account"], prog, p["kind"], p["detail"])]
    p = p.sort_values("count")

    fig, ax = plt.subplots(figsize=(11, 10.5))
    colors = [ORANGE if l else BLUE for l in p["late"]]
    yy = np.arange(len(p))
    ax.barh(yy, p["count"], color=colors, height=0.72, edgecolor=SURFACE, linewidth=1)
    ax.set_yticks(yy)
    ax.set_yticklabels(p["label"])
    ax.set_ylim(-0.7, len(p) - 0.3)
    ax.set_xscale("log")
    ax.set_xticks([1, 3, 10, 30, 100, 300])
    ax.set_xticklabels(["1", "3", "10", "30", "100", "300"])
    ax.set_xlabel("16일 동안 나온 횟수 (로그 축)")
    ax.tick_params(axis="y", labelsize=8.5)
    ax.grid(axis="y", visible=False)
    for y, (c, l) in enumerate(zip(p["count"], p["late"])):
        if l or c >= 200:
            ax.text(c * 1.1, y, f"{c}", va="center", fontsize=8.5, color=INK)
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=BLUE, label=f"첫 24시간 안에 등장 ({(~p['late']).sum()}개)"),
                       Patch(color=ORANGE, label=f"24시간 이후 처음 등장 ({p['late'].sum()}개)")],
              loc="lower right", frameon=False, fontsize=10)
    ax.set_title("시스템 활동 패턴 34개: 대부분 수백 번 반복되고, 몇 개만 1~3번 나온다")
    subtitle(ax, "② 시스템 배경 활동 4,079건을 서버 + 계정 + 실행 파일 + 명령/목적지/파일로 묶은 패턴")
    footnote(fig, "자료: data/08_baseline/background_patterns.csv · 명령의 숫자는 N으로 바꿈 · 4단계는 판단하지 않고 비교값만 만든다")
    save(fig, "D2_시스템패턴_빈도.png")


# ── E1. 5단계: 시작 시각 차이 분포 → 2시간 임계값 ─────────────────────
def e1_hour_threshold():
    s = pd.read_csv(DATA / "08_baseline/session_baseline.csv", encoding="utf-8-sig")
    s = s[s["baseline_level"].isin(["person", "peer"])]
    n = len(s)
    ds = range(1, 8)
    ratio = [(s["hour_distance"] >= d).mean() * 100 for d in ds]
    pick = next(d for d, r in zip(ds, ratio) if r <= 5)

    fig, ax = plt.subplots(figsize=(10, 5.2))
    colors = [ORANGE if d == pick else BLUE for d in ds]
    ax.bar([f"{d}시간" for d in ds], ratio, color=colors, width=0.6, edgecolor=SURFACE, linewidth=2)
    for i, r in enumerate(ratio):
        ax.text(i, r + 0.4, f"{r:.1f}%", ha="center", fontsize=10.5, color=INK,
                fontweight="bold" if ds[i] == pick else "normal")
    ax.axhline(5, color=INK2, linestyle="--", linewidth=1.5)
    ax.text(6.45, 5.3, "드묾 기준 5%", ha="right", fontsize=10, color=INK)
    ax.set_xlabel("평소 시작 시각 범위에서 벗어난 정도가 이 값 이상인 세션 (d)")
    ax.set_ylabel("세션 비율 (%)")
    ax.grid(axis="x", visible=False)
    ax.set_title(f"2시간 임계값의 근거: 5% 이하가 되는 가장 작은 값이 {pick}시간이다")
    subtitle(ax, f"개인·동료 기준선이 있는 세션 {n}개 · 1시간으로 잡으면 {ratio[0]:.1f}%가 걸려 너무 흔하다")
    footnote(fig, "자료: data/08_baseline/session_baseline.csv (hour_distance) · 기준선이 global·none인 세션 20개는 제외")
    save(fig, "E1_시작시각차이_2시간기준.png")


# ── F1. 6단계: 세션 위험점수 → 경보 기준 100점 ────────────────────────
def f1_risk():
    r = pd.read_csv(DATA / "10_risk/session_risk.csv", encoding="utf-8-sig")
    nz = r[r["risk_score"] > 0].sort_values("risk_score")
    zero = (r["risk_score"] == 0).sum()

    fig, ax = plt.subplots(figsize=(10, 5.6))
    labels = [f"{a} ({p})" for a, p in zip(nz["work_session_id"], nz["person_candidate"])]
    colors = [ORANGE if a else BLUE for a in nz["alert"]]
    ax.barh(labels, nz["risk_score"], color=colors, height=0.66, edgecolor=SURFACE, linewidth=2)
    for y, (v, a) in enumerate(zip(nz["risk_score"], nz["alert"])):
        ax.text(v + 6, y, f"{v:.0f}점" + ("  · 경보" if a else ""), va="center", fontsize=10, color=INK,
                fontweight="bold" if a else "normal")
    ax.axvline(100, color=INK2, linestyle="--", linewidth=1.5)
    ax.text(103, -0.9, "경보 기준: 100점 이상 또는 전술 3개 이상", fontsize=10, color=INK)
    ax.set_xlim(0, 500)
    ax.set_ylim(-1.3, len(nz) - 0.4)
    ax.set_xlabel("세션 위험점수")
    ax.grid(axis="y", visible=False)
    ax.set_title(f"세션 146개 중 {zero}개는 0점, 점수가 쌓인 {len(nz)}개 중 경보는 {int(r['alert'].sum())}개")
    subtitle(ax, "신호 하나(20점)만 있는 세션은 기준에 한참 못 미치고, 여러 신호가 겹친 세션만 경보가 된다")
    footnote(fig, "자료: data/10_risk/session_risk.csv · 이름은 동일인 후보(추정) · MFA 없는 root 로그인은 계정 설정 위험으로 따로 분리해 0점")
    save(fig, "F1_세션위험점수_경보기준.png")


# ── F3. 전체 흐름: 9,125 → 4 ───────────────────────────────────────────
def f3_funnel():
    t = pd.read_csv(DATA / "06_classified/timeline_classified.csv", low_memory=False, encoding="utf-8-sig")
    s = pd.read_csv(DATA / "07_sessions/sessions.csv", encoding="utf-8-sig")
    d = pd.read_csv(DATA / "09_detections/detections.csv", encoding="utf-8-sig")
    r = pd.read_csv(DATA / "10_risk/session_risk.csv", encoding="utf-8-sig")
    det_sessions = set(d["work_session_id"].dropna())
    for x in d["linked_sessions"].dropna():
        det_sessions.update(str(x).split("|"))
    det_sessions &= set(s["work_session_id"])
    steps = [
        ("[0] 통합 이벤트", len(t), "건"),
        ("[2] ① 사용자 업무 이벤트", int((t["bucket"] == "session").sum()), "건"),
        ("[3] 업무 세션", len(s), "개"),
        ("[5] 탐지 신호가 있는 세션", len(det_sessions), "개"),
        ("[6] 경보 세션", int(r["alert"].sum()), "개"),
    ]

    fig, ax = plt.subplots(figsize=(10, 4.8))
    y = np.arange(len(steps))[::-1]
    vals = [v for _, v, _ in steps]
    ax.barh(y, vals, color=RAMP, height=0.68, edgecolor=SURFACE, linewidth=2)
    ax.set_xscale("log")
    ax.set_xlim(1, 30000)
    for yi, (name, v, u) in zip(y, steps):
        ax.text(v * 1.15, yi, f"{v:,}{u}", va="center", fontsize=11, color=INK, fontweight="bold")
    ax.set_yticks(y)
    ax.set_yticklabels([n for n, _, _ in steps], fontsize=10.5)
    ax.set_xticks([1, 10, 100, 1000, 10000])
    ax.set_xticklabels(["1", "10", "100", "1,000", "10,000"])
    ax.set_xlabel("개수 (로그 축) · 위 두 줄은 이벤트, 아래 세 줄은 세션 단위")
    ax.grid(axis="y", visible=False)
    ax.set_title("9,125건의 로그가 경보 4개가 되기까지")
    subtitle(ax, "②시스템 활동 4,079건·③외부 시도 161건은 세션에서 빠지지만, 4~5단계에서 따로 검사해 세션에 다시 연결한다")
    footnote(fig, "자료: data/06_classified, 07_sessions, 09_detections, 10_risk · 탐지 세션 수는 MFA 없는 root 로그인(R16)만 있는 세션 포함")
    save(fig, "F3_전체흐름_깔때기.png")


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    c1_web_gap()
    d3_new_pattern_time()
    d2_pattern_freq()
    e1_hour_threshold()
    f1_risk()
    f3_funnel()
