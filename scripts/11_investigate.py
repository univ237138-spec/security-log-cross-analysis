"""경보를 고정 질문 목록(Q1~Q9)으로 조사하고, 사고 타임라인·피벗·판정·경보 맥락을 만든다.
탐지·점수는 고치지 않는다. 개선점은 8단계로 넘긴다.

입력: data/10_risk/*, data/09_detections/detections.csv, data/08_baseline/*, data/07_sessions/*, data/05_enriched/*
출력: data/11_investigation/
  incident_timeline.csv  경보별 사고 타임라인 (4개 로그 + 연결 이벤트, 탐지·사실/추정 표시)
  pivots.csv             경보별 피벗 결과 (질문, 항목, 값, 근거)
  triage.csv             경보 + 비경보 상위 세션의 판정과 근거
  alert_context.csv      경보에 붙일 맥락 필드
  docs/14_조사/01_사고카드.md  (사고 카드, 스크립트가 생성)
계획: docs/07_조사_결과.md (질문 목록과 판정 기준은 실행 전에 고정)
"""
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from common import (BASELINE, DETECTIONS, ENRICHED, INVESTIGATION, RISK, ROOT, SESSIONS, read_rows,
                    write_rows)

PAD = timedelta(minutes=30)  # 타임라인 앞뒤 여유
TACTIC_ORDER = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
                "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection",
                "Command and Control", "Exfiltration", "Impact"]  # ATT&CK 전술 순서 (같은 시각일 때 정렬용)
ROUTINE_MIN = 100            # 전체 100회 이상 나온 시스템 패턴은 접는다
KST = timedelta(hours=9)

timeline = read_rows(SESSIONS / "timeline_sessions.csv")
sessions = {s["work_session_id"]: s for s in read_rows(SESSIONS / "sessions.csv")}
srisk = {s["work_session_id"]: s for s in read_rows(RISK / "session_risk.csv")}
revents = read_rows(RISK / "risk_events.csv")
dets = read_rows(DETECTIONS / "detections.csv")
sbase = {s["work_session_id"]: s for s in read_rows(BASELINE / "session_baseline.csv")}
bgb = {(b["event_time_utc"], b["source_row"]): b for b in read_rows(BASELINE / "background_baseline.csv")}
pat_count = {p["pattern_id"]: int(p["count"]) for p in read_rows(BASELINE / "background_patterns.csv")}
ips = {r["ip"]: r for r in read_rows(ENRICHED / "ip_inventory.csv")}
home = {a["person_candidate"]: a["home_host"] for a in read_rows(ENRICHED / "account_inventory.csv")
        if a["account_system"] == "linux" and a["account_type"] == "human"}

for r in timeline:
    r["_t"] = datetime.fromisoformat(r["event_time_utc"])
for s in sessions.values():
    s["_start"] = datetime.fromisoformat(s["start_utc"])
    s["_end"] = datetime.fromisoformat(s["end_utc"])
    s["_ssh_end"] = datetime.fromisoformat(s["ssh_end_utc"]) if s["ssh_end_utc"] else None
    s["_hosts"] = {h.split(":")[0] for h in s["hosts"].split("|") if h}

det_by_row = defaultdict(list)
for d in dets:
    if d["source_row"]:
        det_by_row[(d["log_source"], d["source_row"])].append(d["detection_id"])
all_guids = {r["ProcessGuid"] for r in timeline if r["ProcessGuid"]}
base = lambda p: p.rsplit("/", 1)[-1]
kst = lambda t: (t + KST).strftime("%m-%d %H:%M")

alerts = sorted((sid for sid, s in srisk.items() if s["alert"] == "true"), key=lambda x: int(srisk[x]["rank"]))
non_alert_top = [sid for sid, s in sorted(srisk.items(), key=lambda kv: int(kv[1]["rank"]))
                 if s["alert"] == "false" and float(s["risk_score"]) > 0]


def summary(r):
    a = r["event_action"]
    src = r["log_source"]
    if src == "sshd":
        return f"{a} {r['account']}@{r['client_ip']}" + (f" ({r['auth_method']})" if r["auth_method"] else "")
    if src == "nginx":
        return f"{r['http_method']} {r['request']} {r['http_status_code']}"
    if src == "teiren_audit":
        return f"{a} {r['request']}"
    if a == "process_create":
        return f"[{r['account']}] {r['CommandLine']}"
    if a == "network_connect":
        return f"[{r['account']}] {base(r['Image'])} → {r['dst']}:{r['dpt']} ({r['dst_zone']})"
    if a == "file_create":
        return f"[{r['account']}] 파일 생성 {r['TargetFilename']}"
    return f"[{r['account']}] 종료 {base(r['Image'])}"


def pivot(rows, sid, q, item, value, basis):
    rows.append({"work_session_id": sid, "question": q, "item": item, "value": value, "basis": basis})


tl_rows, piv, ctx, triage, cards = [], [], [], [], []

# ---------------------------------------------------------------- 경보별 조사
for sid in alerts:
    s, sr, sb = sessions[sid], srisk[sid], sbase[sid]
    my_re = [e for e in revents if e["work_session_id"] == sid]
    linked_ids = {e["detection_id"] for e in my_re if e["link"] == "linked"}
    linked_rows = {(d["log_source"], d["source_row"]) for d in dets if d["detection_id"] in linked_ids}
    linked_hosts = {d["host"] for d in dets if d["detection_id"] in linked_ids}
    hosts_here = s["_hosts"] | linked_hosts
    lo, hi = s["_start"] - PAD, s["_end"] + PAD

    # ---- Q5 타임라인
    folded, folded_desc = Counter(), {}
    events = []
    for r in timeline:
        if not lo <= r["_t"] <= hi:
            continue
        key = (r["log_source"], r["source_row"])
        if r["work_session_id"] == sid:
            basis = "관측(세션 소속)"
        elif key in linked_rows:
            basis = "추정(5-c 연결)"
        elif s["client_ip"] and r["client_ip"] == s["client_ip"]:
            basis = "관측(같은 접속 IP)"
        elif r["bucket"] == "background" and r["host"] in hosts_here:
            b = bgb.get((r["event_time_utc"], r["source_row"]))
            if b and pat_count[b["pattern_id"]] >= ROUTINE_MIN:
                folded[(r["host"], b["pattern_id"])] += 1
                if r["event_action"] != "process_terminate":
                    folded_desc.setdefault((r["host"], b["pattern_id"]), summary(r))
                continue
            basis = "추정(같은 서버·시간)"
        else:
            continue
        events.append(r)
        tl_rows.append({"incident": sid, "event_time_utc": r["event_time_utc"], "time_kst": kst(r["_t"]),
                        "log_source": r["log_source"], "source_row": r["source_row"], "basis": basis,
                        "host": r["host"], "client_ip": r["client_ip"], "account": r["account"],
                        "event_action": r["event_action"], "summary": summary(r),
                        "detection_ids": "|".join(det_by_row.get(key, []))})
    for (h, pid), n in sorted(folded.items()):
        tl_rows.append({"incident": sid, "event_time_utc": "", "time_kst": "", "log_source": "sysmon",
                        "source_row": "", "basis": "접음(반복 정상 패턴)", "host": h, "client_ip": "", "account": "",
                        "event_action": "", "summary": f"{pid} ×{n} (종료 포함) {folded_desc.get((h, pid), '')}".strip(),
                        "detection_ids": ""})

    # ---- Q1
    signals = sorted(my_re, key=lambda e: -float(e["signal_score"]))
    sig_types = []
    for e in signals:
        if e["detection_type"] not in [t for t, _ in sig_types]:
            sig_types.append((e["detection_type"], e))
    pivot(piv, sid, "Q1", "점수·전술", f"{sr['risk_score']}점, 전술 {sr['tactic_count']}개 ({sr['tactics']})", "관측")
    pivot(piv, sid, "Q1", "경보 기준", sr["alert_reason"], "관측")
    for typ, e in sig_types:
        pivot(piv, sid, "Q1", typ, f"{e['name']} ({e['signal_score']}점, {'직접' if e['link'] == 'direct' else '추정 연결'})",
              "관측" if e["link"] == "direct" else "추정")

    # ---- Q2
    person = s["person_candidate"]
    prior = sorted((x for x in sessions.values() if x["person_candidate"] == person and x["_end"] < s["_start"]),
                   key=lambda x: x["_start"])
    usual_ip = Counter(x["client_ip"] for x in prior)
    usual_type = Counter(x["session_type"] for x in prior)
    last = prior[-1] if prior else None
    pivot(piv, sid, "Q2", "사람 후보·계정", f"{person} / 리눅스 {s['linux_account'] or '-'} / 콘솔 {s['console_accounts'] or '-'}",
          "추정(동일인 후보)")
    pivot(piv, sid, "Q2", "과거 세션", f"{len(prior)}개, 기준선 {sb['baseline_level']}", "관측")
    pivot(piv, sid, "Q2", "시작 시각(KST)", f"이번 {s['start_hour_kst']}시 / 평소 {sb['hist_hour_min']}~{sb['hist_hour_max']}시"
          f" (벗어남 {sb['hour_distance']}시간)", "관측")
    pivot(piv, sid, "Q2", "세션 종류", f"이번 {s['session_type']} / 평소 {dict(usual_type)}", "관측")
    pivot(piv, sid, "Q2", "직전 세션", f"{last['work_session_id']} {kst(last['_start'])} KST "
          f"({(s['_start'] - last['_end']).total_seconds() / 3600:.1f}시간 전)" if last else "없음", "관측")

    # ---- Q3
    ip = s["client_ip"]
    ip_rows = [r for r in timeline if r["client_ip"] == ip or r["dst"] == ip]
    other_sess = sorted({r["work_session_id"] for r in ip_rows if r["work_session_id"] and r["work_session_id"] != sid})
    pivot(piv, sid, "Q3", "접속 IP", f"{ip} ({ips[ip]['ip_zone']}, 문서용 대역 {ips[ip]['is_documentation_range']})", "관측")
    pivot(piv, sid, "Q3", "이 사람의 평소 IP", f"{dict(usual_ip)} → 이번 IP {'처음' if ip not in usual_ip else '평소와 같음'}", "관측")
    pivot(piv, sid, "Q3", "IP의 다른 등장", f"로그 {dict(Counter(r['log_source'] for r in ip_rows))}, "
          f"다른 세션 {other_sess or '없음'}, {ip_rows[0]['event_time_utc'][:16]} ~ {ip_rows[-1]['event_time_utc'][:16]}", "관측")

    # ---- Q4
    sshd_ok = [r for r in events if r["log_source"] == "sshd" and r["event_action"] == "auth_success"]
    fails = [r for r in events if r["log_source"] == "sshd" and r["event_action"] in ("invalid_user", "auth_failure")]
    logins = [r for r in events if r["event_action"] in ("IAM_LOGIN_SUCCESS", "IAM_LOGIN_NEW_DEVICE", "ROOT_LOGIN_NO_MFA")
              and r["work_session_id"] == sid]
    pivot(piv, sid, "Q4", "ssh", f"성공 {len(sshd_ok)} ({s['auth_method'] or '-'}), 직전 실패 {len(fails)}회" if s["ssh_connections"] != "0"
          else "ssh 없음", "관측")
    pivot(piv, sid, "Q4", "웹 로그인", ", ".join(r["event_action"] for r in logins) or "없음", "관측")

    # ---- Q6
    files = [r["TargetFilename"] for r in events if r["event_action"] == "file_create"]
    ext = Counter(f"{r['dst']}:{r['dpt']}" for r in events if r["dst_zone"] == "external")
    changes = [f"{r['event_action']} {r['request']}" for r in events if r["log_source"] == "teiren_audit"
               and r["action_category"] in ("iam_change", "detection_config", "admin_exec")]
    basis6 = "관측" if all(r["work_session_id"] == sid for r in events if r["event_action"] == "file_create" or r["dst_zone"] == "external") \
        else "관측(이벤트) / 추정(세션 귀속)"
    pivot(piv, sid, "Q6", "생성 파일", ", ".join(files) or "없음", basis6)
    pivot(piv, sid, "Q6", "외부 연결", ", ".join(f"{k}×{v}" for k, v in ext.items()) or "없음", basis6)
    pivot(piv, sid, "Q6", "계정·설정 변경", ", ".join(changes) or "없음", "관측")
    pivot(piv, sid, "Q6", "결과(성공 여부)", "로그로 알 수 없음: 연결·요청 기록만 있고 전송 내용·결과는 없음", "모름")

    # ---- Q7
    ext_other = {}
    for dst in {k.split(":")[0] for k in ext}:
        ext_other[dst] = sum(1 for r in timeline if (r["dst"] == dst or r["client_ip"] == dst) and r not in events)
    concurrent = []
    for x in sessions.values():
        if x["work_session_id"] == sid or not x["_ssh_end"]:
            continue
        on = x["_hosts"] | {home.get(x["person_candidate"], "")}
        if on & hosts_here and x["_start"] <= s["_end"] and s["_start"] <= x["_ssh_end"]:
            concurrent.append(f"{x['work_session_id']}({x['person_candidate']})")
    internal_ssh = sorted({r["dst"] for r in events if r["dst_zone"] == "server" and r["dpt"] == "22"})
    spread = []
    for dst in internal_ssh:
        h = ips[dst]["host"]
        new_after = [r for r in timeline if r["host"] == h and r["bucket"] == "background" and s["_start"] <= r["_t"] <= hi
                     and bgb.get((r["event_time_utc"], r["source_row"]), {}).get("pattern_seen_before") == "0"]
        spread.append(f"{h}: 이후 처음 보는 활동 {len(new_after)}건")
    pivot(piv, sid, "Q7", "외부 목적지의 다른 등장", ", ".join(f"{k} {v}건" for k, v in ext_other.items()) or "외부 연결 없음", "관측")
    pivot(piv, sid, "Q7", "같은 서버·같은 시간 다른 세션", ", ".join(concurrent) or "없음", "관측")
    pivot(piv, sid, "Q7", "내부 SSH 연결 대상의 이후 활동", "; ".join(spread) or "내부 SSH 연결 없음",
          "관측 (단, 대상 서버의 sshd는 bastion-01 외 미수집)" if spread else "관측")

    # ---- Q8 데이터 공백 (데이터 속성에서 자동 판단)
    gaps = []
    if s["ssh_connections"] != "0" and (hosts_here - {"bastion-01"}):
        gaps.append("bastion-01에서 담당 서버로 넘어간 ssh 기록 없음 (bastion-01 외 sshd 미수집)")
    if linked_ids:
        gaps.append("시스템 계정 활동과 이 세션의 연결은 시간·서버 기반 추정")
    orphan = [r for r in events if r["event_action"] == "process_create" and r["ParentProcessGuid"]
              and r["ParentProcessGuid"] not in all_guids and det_by_row.get((r["log_source"], r["source_row"]))]
    if orphan:
        gaps.append(f"탐지된 프로세스 {len(orphan)}건의 부모 프로세스 기록 없음 → 어떻게 그 권한·프로세스가 시작됐는지 확인 불가")
    if s["session_type"] == "web_only" and linked_hosts:
        gaps.append("웹 요청과 서버 명령 실행 사이를 잇는 애플리케이션 로그 없음")
    if ext:
        gaps.append("외부 연결은 연결 사실만 기록, 전송량·내용·성공 여부 없음")
    for g in gaps:
        pivot(piv, sid, "Q8", "데이터 공백", g, "모름")

    # ---- Q9 판정 (계획 7-4)
    high = [e for e in my_re if e["method"] == "rule" and e["severity"] == "high"]
    activity = "의심 확인" if high else ("오탐 후보" if not any(e["method"] == "rule" for e in my_re) else "보류")
    attribution = "관측" if any(e["link"] == "direct" for e in high) else "추정"
    reason = f"high 룰 {sorted({e['detection_type'] for e in high})} (원본 이벤트 관측), " \
             f"{'세션 직접 소속 high 룰 있음' if attribution == '관측' else 'high 룰이 모두 5-c 추정 연결'}"
    pivot(piv, sid, "Q9", "활동 판정", activity, "판정")
    pivot(piv, sid, "Q9", "귀속 판정", attribution, "판정")
    triage.append({"work_session_id": sid, "alert": "true", "person_candidate": person, "risk_score": sr["risk_score"],
                   "activity_verdict": activity, "attribution": attribution, "reason": reason})

    # ---- 전술 순서 (처음 나온 시각 순)
    first_tac = {}
    for e in sorted(my_re, key=lambda e: e["event_time_utc"]):
        for t in filter(None, e["tactics"].split("|")):
            first_tac.setdefault(t, e["event_time_utc"])
    chain = " → ".join(t for t, _ in sorted(first_tac.items(), key=lambda kv: (kv[1], TACTIC_ORDER.index(kv[0]))))

    # ---- 경보 맥락 (조사 때 매번 찾은 정보)
    ctx.append({
        "work_session_id": sid, "person_candidate": person, "risk_score": sr["risk_score"], "tactic_chain": chain,
        "top_signals": " | ".join(f"{t}:{e['name']}" for t, e in sig_types[:5]),
        "start_kst": kst(s["_start"]), "usual_hours_kst": f"{sb['hist_hour_min']}~{sb['hist_hour_max']}",
        "hour_distance": sb["hour_distance"], "client_ip": ip, "ip_zone": ips[ip]["ip_zone"],
        "ip_first_time_for_person": str(ip not in usual_ip).lower(),
        "session_type": s["session_type"], "usual_session_types": "|".join(f"{k}:{v}" for k, v in usual_type.items()),
        "hours_since_prev_session": round((s["_start"] - last["_end"]).total_seconds() / 3600, 1) if last else "",
        "failed_before_login": s["failed_before_login"], "web_login": "|".join(r["event_action"] for r in logins),
        "linked_system_activity": f"{','.join(sorted(linked_hosts))} {len(linked_ids)}건(추정)" if linked_ids else "",
        "files_created": "|".join(files), "external_destinations": "|".join(ext),
        "external_dest_seen_elsewhere": "|".join(f"{k}:{v}" for k, v in ext_other.items()),
        "config_changes": "|".join(changes), "concurrent_sessions_same_host": "|".join(concurrent),
        "data_gaps": len(gaps), "activity_verdict": activity, "attribution": attribution,
    })
    cards.append((sid, chain, gaps))

# ---------------------------------------------------------------- 7-5 비경보 상위 세션
for sid in non_alert_top:
    s, sr, sb = sessions[sid], srisk[sid], sbase[sid]
    my_re = [e for e in revents if e["work_session_id"] == sid]
    types = sorted({e["detection_type"] for e in my_re})
    why = []
    if "B01" in types:
        why.append(f"시작 {s['start_hour_kst']}시, 평소 {sb['hist_hour_min']}~{sb['hist_hour_max']}시 (벗어남 {sb['hour_distance']}시간)")
    if "B08" in types:
        merged = f"ssh 접속 {s['ssh_connections']}개를 합친 세션, " if int(s["ssh_connections"]) > 1 else ""
        why.append(f"양 초과(프로세스 {s['process_count']}, GET 외 {s['non_get_count']}), {merged}"
                   f"기준선 {sb['baseline_level']} n={sb['baseline_n']}")
    normal = [f"IP {'평소와 같음' if sb['ip_new'] == 'false' else '처음'}", f"세션 종류 {s['session_type']}",
              f"웹 로그인 {s['web_login_types'] or '없음'}", "룰 신호 없음" if not any(e["method"] == "rule" for e in my_re) else "룰 신호 있음"]
    activity = "오탐 후보" if not any(e["method"] == "rule" for e in my_re) else "보류"
    triage.append({"work_session_id": sid, "alert": "false", "person_candidate": s["person_candidate"],
                   "risk_score": sr["risk_score"], "activity_verdict": activity, "attribution": "",
                   "reason": f"{'/'.join(types)}: {'; '.join(why)} | 정상 근거: {', '.join(normal)}"})

# ---------------------------------------------------------------- 경보 간 관계
relations = []
for i, a in enumerate(alerts):
    for b in alerts[i + 1:]:
        sa, sb_ = sessions[a], sessions[b]
        ha = sa["_hosts"] | {d["host"] for d in dets if d["detection_id"] in {e["detection_id"] for e in revents if e["work_session_id"] == a}}
        hb = sb_["_hosts"] | {d["host"] for d in dets if d["detection_id"] in {e["detection_id"] for e in revents if e["work_session_id"] == b}}
        shared = []
        if sa["person_candidate"] == sb_["person_candidate"]:
            shared.append("사람")
        if sa["client_ip"] == sb_["client_ip"]:
            shared.append("IP")
        if ha & hb - {""}:
            shared.append(f"서버 {sorted(ha & hb - {''})}")
        gap = abs((sb_["_start"] - sa["_start"]).total_seconds()) / 3600
        relations.append(f"{a}–{b}: 공유 {shared or '없음'}, 시작 간격 {gap:.1f}시간")

# ---------------------------------------------------------------- 쓰기
INVESTIGATION.mkdir(parents=True, exist_ok=True)
for name, rows in [("incident_timeline.csv", tl_rows), ("pivots.csv", piv), ("triage.csv", triage),
                   ("alert_context.csv", ctx)]:
    write_rows(INVESTIGATION / name, list(rows[0].keys()), rows)
    print(f"{name}: {len(rows)}")

# 사고 카드 (md)
Q_TITLE = {"Q1": "무엇이 경보를 만들었나", "Q2": "누구인가, 평소와 같은가", "Q3": "어디서 왔나",
           "Q4": "어떻게 들어왔나", "Q6": "무엇을 남겼나", "Q7": "퍼졌나", "Q8": "확인 못 한 것", "Q9": "판정"}
md = ["# 사고 카드 (스크립트 생성)", "",
      "- 생성: `scripts/11_investigate.py` — 다시 실행하면 이 파일을 덮어쓴다. 해석과 정리는 [조사 결과](../07_조사_결과.md)에 쓴다.",
      "- 근거 표시: **관측**(로그에 직접 기록) / **추정**(시간·서버·IP로 연결) / **모름**(로그로 알 수 없음)",
      "- 시나리오 A~D와의 대응은 참고용이다. 정식 평가는 8단계에서 한다.", ""]
for sid, chain, gaps in cards:
    s, sr = sessions[sid], srisk[sid]
    md += [f"## {sid} — {s['person_candidate']}, {sr['risk_score']}점, 전술 {sr['tactic_count']}개", "",
           f"- **시간:** {kst(s['_start'])} ~ {kst(s['_end'])} KST ({s['duration_min']}분)",
           f"- **세션 종류:** {s['session_type']}, 접속 IP {s['client_ip']}",
           f"- **ATT&CK 전술 순서:** {chain}", ""]
    esc = lambda v: str(v).replace("|", "\\|")
    for q in ["Q1", "Q2", "Q3", "Q4", "Q5", "Q6", "Q7", "Q8", "Q9"]:
        if q == "Q5":
            md += ["### Q5. 무엇을 했나 (타임라인, 반복 정상 패턴은 접음)", "",
                   "| 시각(KST) | 로그 | 근거 | 내용 | 탐지 |", "|---|---|---|---|---|"]
            for t in tl_rows:
                if t["incident"] != sid:
                    continue
                if s["session_type"] != "web_only" and t["log_source"] == "nginx" and not t["detection_ids"]:
                    continue  # 정상 웹 요청은 표에서 생략 (CSV에는 모두 있음)
                md.append(f"| {t['time_kst'] or '-'} | {t['log_source']} | {t['basis']} | {esc(t['summary'])} | "
                          f"{t['detection_ids'].replace('|', ' ')} |")
            hidden = sum(1 for t in tl_rows if t["incident"] == sid and t["log_source"] == "nginx"
                         and not t["detection_ids"] and s["session_type"] != "web_only")
            if hidden:
                md += ["", f"정상 nginx 요청 {hidden}건은 표에서 생략했다 (`incident_timeline.csv`에 있음)."]
            md.append("")
            continue
        md += [f"### {q}. {Q_TITLE[q]}", "", "| 항목 | 값 | 근거 |", "|---|---|---|"]
        for p in piv:
            if p["work_session_id"] == sid and p["question"] == q:
                md.append(f"| {p['item']} | {esc(p['value'])} | {p['basis']} |")
        md.append("")
md += ["## 경보 간 관계", ""] + [f"- {r}" for r in relations] + ["",
       "## 비경보 상위 세션 (20점)", "", "| 세션 | 사람 후보 | 판정 | 근거 |", "|---|---|---|---|"]
md += [f"| {t['work_session_id']} | {t['person_candidate']} | {t['activity_verdict']} | {t['reason'].replace('|', chr(92) + '|')} |"
       for t in triage if t["alert"] == "false"]
(ROOT / "docs" / "14_조사").mkdir(parents=True, exist_ok=True)
(ROOT / "docs" / "14_조사" / "01_사고카드.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print("docs/14_조사/01_사고카드.md 생성")

# ---------------------------------------------------------------- 검증
for sid in alerts:
    qs = {p["question"] for p in piv if p["work_session_id"] == sid}
    assert {"Q1", "Q2", "Q3", "Q4", "Q6", "Q7", "Q9"} <= qs, (sid, qs)
    assert any(t["incident"] == sid for t in tl_rows), sid  # Q5
for t in tl_rows:
    if t["source_row"]:
        assert t["detection_ids"] == "|".join(det_by_row.get((t["log_source"], t["source_row"]), [])), t
assert all(p["basis"] for p in piv), "근거 표시 없는 항목"
print("검증 통과\n")

# ---------------------------------------------------------------- 요약
for t in triage:
    print(f"{t['work_session_id']} {t['person_candidate']:<10} {t['risk_score']:>6} 경보 {t['alert']:<5} "
          f"활동 {t['activity_verdict']:<5} 귀속 {t['attribution'] or '-':<3} | {t['reason'][:110]}")
print("\n경보 간 관계:")
for r in relations:
    print(" ", r)
print("\n데이터 공백:")
for sid, _, gaps in cards:
    for g in gaps:
        print(f"  {sid}: {g}")
