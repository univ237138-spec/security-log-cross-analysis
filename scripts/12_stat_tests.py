"""탐지 설계의 정상 행동 가정 2개를 통계로 확인한다.
  검정 1: 정상 세션은 웹·서버 경로를 함께 쓴다 (정확 이항검정, H0: p ≤ 0.90)
  검정 2: 사람마다 세션 시작 시각 분포가 다르다 (Kruskal-Wallis + Mann-Whitney 사후 검정, Holm 보정)

입력: data/07_sessions/sessions.csv
출력: data/12_stats/
계획: docs/08_통계검정.md (가설·방법·유의수준·표본은 실행 전에 고정)
설명: docs/08_통계검정.md
"""
from datetime import datetime, timedelta
from itertools import combinations

from scipy import stats

from common import SESSIONS, STATS, read_rows, write_rows

ALPHA = 0.05
P0 = 0.90
KST = timedelta(hours=9)
# 분석기획 문서(10/01) 3절에 기록된 시나리오 계정·시각 (UTC). 탐지 결과로 정하지 않는다
SCENARIO = [("A", "dev02", "2026-10-14 18:12:18"), ("B", "analyst01", "2026-10-15 05:07:03"),
            ("C", "ops02", "2026-10-15 17:41:09"), ("D", "intern01", "2026-10-16 06:19:43")]

sessions = read_rows(SESSIONS / "sessions.csv")
for s in sessions:
    s["_start"] = datetime.fromisoformat(s["start_utc"]).replace(microsecond=0)
    s["_end"] = datetime.fromisoformat(s["end_utc"])
scenario_ids = set()
for label, person, t in SCENARIO:
    t = datetime.fromisoformat(t)
    hit = [s["work_session_id"] for s in sessions if s["person_candidate"] == person and s["_start"] <= t <= s["_end"]]
    assert len(hit) == 1, (label, hit)
    scenario_ids.add(hit[0])
SAMPLES = {"주 분석 (시나리오 4개 제외)": [s for s in sessions if s["work_session_id"] not in scenario_ids],
           "민감도 (전체)": sessions}


def holm(pvals):
    """Holm 보정 p값 (입력 순서 유지)."""
    order = sorted(range(len(pvals)), key=lambda i: pvals[i])
    adj, running = [0.0] * len(pvals), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (len(pvals) - rank) * pvals[i]))
        adj[i] = running
    return adj


# ---------------------------------------------------------------- 검정 1
t1 = []
for name, ss in SAMPLES.items():
    k, n = sum(s["session_type"] == "server+web" for s in ss), len(ss)
    r = stats.binomtest(k, n, P0, alternative="greater")
    ci = r.proportion_ci(confidence_level=0.95, method="exact")
    t1.append({"sample": name, "k": k, "n": n, "proportion": round(k / n, 4), "p0": P0,
               "effect": round(k / n - P0, 4), "ci95_low": round(ci.low, 4), "ci95_high": round(ci.high, 4),
               "p_value": r.pvalue})
# 추가 민감도: 3단계 규칙 2 수정 전 (ssh 종료 뒤 웹 활동이 별도 web_only 세션이었을 때)
for name, ss in SAMPLES.items():
    extra = sum(int(s["web_after_ssh_count"]) > 0 for s in ss)
    k, n = sum(s["session_type"] == "server+web" for s in ss), len(ss) + extra
    r = stats.binomtest(k, n, P0, alternative="greater")
    ci = r.proportion_ci(confidence_level=0.95, method="exact")
    t1.append({"sample": f"{name} · 규칙 2 수정 전", "k": k, "n": n, "proportion": round(k / n, 4), "p0": P0,
               "effect": round(k / n - P0, 4), "ci95_low": round(ci.low, 4), "ci95_high": round(ci.high, 4),
               "p_value": r.pvalue})
per_person = []
main = SAMPLES["주 분석 (시나리오 4개 제외)"]
for p in sorted({s["person_candidate"] for s in main}):
    ss = [s for s in main if s["person_candidate"] == p]
    k = sum(s["session_type"] == "server+web" for s in ss)
    per_person.append({"person": p, "k": k, "n": len(ss), "proportion": round(k / len(ss), 4)})

# ---------------------------------------------------------------- 검정 2
def minute_kst(s):
    t = s["_start"] + KST
    return t.hour * 60 + t.minute


t2, posthoc, desc = [], [], []
for name, ss in SAMPLES.items():
    people = sorted({s["person_candidate"] for s in ss})
    groups = {p: [minute_kst(s) for s in ss if s["person_candidate"] == p] for p in people}
    h, p = stats.kruskal(*groups.values())
    n = len(ss)
    t2.append({"sample": name, "groups": len(groups), "n": n, "H": round(h, 3), "df": len(groups) - 1,
               "epsilon_sq": round(h / (n - 1), 4), "p_value": p})
    if name.startswith("주 분석"):
        pairs = list(combinations(people, 2))
        raw = [stats.mannwhitneyu(groups[a], groups[b], alternative="two-sided").pvalue for a, b in pairs]
        for (a, b), pr, pa in zip(pairs, raw, holm(raw)):
            ma, mb = sorted(groups[a])[len(groups[a]) // 2], sorted(groups[b])[len(groups[b]) // 2]
            posthoc.append({"a": a, "b": b, "median_a": f"{ma // 60:02d}:{ma % 60:02d}",
                            "median_b": f"{mb // 60:02d}:{mb % 60:02d}", "median_diff_min": abs(ma - mb),
                            "p_raw": pr, "p_holm": pa, "significant": str(pa < ALPHA).lower()})
        for pp, xs in groups.items():
            xs = sorted(xs)
            q = lambda f: xs[round(f * (len(xs) - 1))]
            hm = lambda m: f"{m // 60:02d}:{m % 60:02d}"
            desc.append({"person": pp, "n": len(xs), "min": hm(xs[0]), "q1": hm(q(.25)), "median": hm(q(.5)),
                         "q3": hm(q(.75)), "max": hm(xs[-1]), "iqr_min": q(.75) - q(.25)})

# 주 검정 2개 Holm 보정 (주 분석 표본 기준)
main_p = [t1[0]["p_value"], t2[0]["p_value"]]
adj = holm(main_p)
summary = [
    {"test": "검정 1: 경로 동시 사용", "sample": t1[0]["sample"], "p_value": main_p[0], "p_holm": adj[0],
     "decision": "H0 기각" if adj[0] < ALPHA else "H0 기각 못함",
     "effect": f"비율 {t1[0]['proportion']:.3f} (95% CI {t1[0]['ci95_low']:.3f}~{t1[0]['ci95_high']:.3f}), 기준 0.90 대비 +{t1[0]['effect']:.3f}"},
    {"test": "검정 2: 개인별 시작 시각", "sample": t2[0]["sample"], "p_value": main_p[1], "p_holm": adj[1],
     "decision": "H0 기각" if adj[1] < ALPHA else "H0 기각 못함",
     "effect": f"ε² = {t2[0]['epsilon_sq']:.3f} (H = {t2[0]['H']}, df = {t2[0]['df']})"},
]

# ---------------------------------------------------------------- 쓰기
STATS.mkdir(parents=True, exist_ok=True)
for fname, rows in [("test1_path.csv", t1), ("test1_per_person.csv", per_person), ("test2_hour.csv", t2),
                    ("test2_describe.csv", desc), ("test2_posthoc.csv", posthoc), ("summary.csv", summary)]:
    write_rows(STATS / fname, list(rows[0].keys()), rows)

# ---------------------------------------------------------------- 출력
print(f"시나리오 세션 (제외 대상): {sorted(scenario_ids)}\n")
print("검정 1: server+web 비율, H0: p ≤ 0.90")
for r in t1:
    print(f"  {r['sample']:<26} {r['k']}/{r['n']} = {r['proportion']:.3f}  95% CI [{r['ci95_low']:.3f}, {r['ci95_high']:.3f}]  p = {r['p_value']:.3g}")
print("  사람별:", ", ".join(f"{r['person']} {r['k']}/{r['n']}" for r in per_person))
print("\n검정 2: 사람별 시작 시각(KST) Kruskal-Wallis")
for r in t2:
    print(f"  {r['sample']:<26} H = {r['H']}, df = {r['df']}, n = {r['n']}, ε² = {r['epsilon_sq']}, p = {r['p_value']:.3g}")
print("  사람별 분포:")
for d in desc:
    print(f"    {d['person']:<10} n={d['n']:>2}  {d['min']} [{d['q1']} {d['median']} {d['q3']}] {d['max']}  IQR {d['iqr_min']}분")
sig = [p for p in posthoc if p["significant"] == "true"]
print(f"  사후 검정: 28쌍 중 Holm 보정 후 유의 {len(sig)}쌍")
for p in sorted(sig, key=lambda p: p["p_holm"]):
    print(f"    {p['a']} {p['median_a']} vs {p['b']} {p['median_b']}  차이 {p['median_diff_min']}분  p_holm = {p['p_holm']:.3g}")
print("\n주 검정 요약 (Holm 보정):")
for s in summary:
    print(f"  {s['test']}: p = {s['p_value']:.3g}, p_holm = {s['p_holm']:.3g} → {s['decision']} | {s['effect']}")
