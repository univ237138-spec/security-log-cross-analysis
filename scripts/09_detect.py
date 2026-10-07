"""탐지 신호를 만든다. 5-a 룰 기반(ATT&CK 일반 기법), 5-b 행위 기반(4단계 비교값 + 임계값),
5-c 시스템 활동 탐지의 사용자 세션 연결. 결과는 경보가 아니라 신호 목록이다 (점수·경보는 6단계).

입력: data/07_sessions/timeline_sessions.csv, sessions.csv, data/08_baseline/*, data/05_enriched/*
출력: data/09_detections/detection_rules.csv, detections.csv
계획: docs/06_탐지_위험점수.md (룰과 임계값 결정 방법은 실행 전에 고정)
설명: docs/06_탐지_위험점수.md
"""
import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from common import BASELINE, DETECTIONS, ENRICHED, SESSIONS, read_rows, write_rows

RARE = 0.05  # 드문 정도 기준 (B01, B08)
WARMUP_H = 24  # B09 서버 학습 기간
WEB_ACCOUNTS = {"www-data", "apache", "nginx", "httpd"}
SHELLS = {"bash", "sh", "dash", "zsh"}
DOWNLOADERS = {"curl", "wget"}
FAIL = {"invalid_user", "auth_failure"}
WEB_LOGINS = {"IAM_LOGIN_SUCCESS", "IAM_LOGIN_NEW_DEVICE", "ROOT_LOGIN_NO_MFA"}

timeline = read_rows(SESSIONS / "timeline_sessions.csv")
sessions = {s["work_session_id"]: s for s in read_rows(SESSIONS / "sessions.csv")}
sb = read_rows(BASELINE / "session_baseline.csv")
bgb = {(b["event_time_utc"], b["source_row"], "sysmon"): b for b in read_rows(BASELINE / "background_baseline.csv")}
hosts = {h["host"]: h for h in read_rows(ENRICHED / "host_inventory.csv")}
home = {a["person_candidate"]: a["home_host"] for a in read_rows(ENRICHED / "account_inventory.csv")
        if a["account_system"] == "linux" and a["account_type"] == "human"}

for r in timeline:
    r["_t"] = datetime.fromisoformat(r["event_time_utc"])
timeline.sort(key=lambda r: (r["_t"], r["log_source"], int(r["source_row"])))
base = lambda path: path.rsplit("/", 1)[-1]

RULES = [  # (ID, 이름, 조건, ATT&CK, 심각도, 사용 로그) — 계획 문서 5-a와 같다
    ("R01", "웹 서버 계정의 셸·다운로드 도구 실행", "웹 서버 계정이 셸·curl·wget 실행", "T1505.003|T1059.004", "high", "sysmon"),
    ("R02", "다운로드 후 바로 실행", "curl/wget 출력을 셸로 파이프", "T1059.004|T1105", "high", "sysmon"),
    ("R03", "서버에서 외부로 연결", "서버 프로세스의 외부 IP 연결", "T1071", "medium", "sysmon"),
    ("R04", "비표준 포트로 외부 연결", "외부 연결 중 포트가 80·443이 아님", "T1571", "high", "sysmon"),
    ("R05", "내부 SSH 스캔", "sshd 외 프로세스가 5분 안에 내부 서버 3대 이상 22번 연결", "T1021.004|T1046", "high", "sysmon"),
    ("R06", "임시 폴더의 숨김 파일 생성", "/tmp·/var/tmp·/dev/shm 아래 .으로 시작하는 파일", "T1564.001", "medium", "sysmon"),
    ("R07", "압축 파일 생성", "tar/zip/gzip 결과를 임시 폴더에 저장", "T1560.001", "medium", "sysmon"),
    ("R08", "외부로 파일 업로드", "curl/wget이 파일 내용을 전송", "T1567|T1048", "high", "sysmon"),
    ("R09", "SSH 무차별 대입", "같은 IP 1시간 안 로그인 실패 5회 이상", "T1110", "low", "sshd"),
    ("R10", "실패 뒤 로그인 성공", "같은 IP·계정 실패 후 10분 안 로그인 성공", "T1110|T1078", "medium", "sshd"),
    ("R11", "외부 IP에서 로그인 성공", "ssh·콘솔 로그인 성공 IP가 외부", "T1078|T1133", "medium", "sshd|teiren_audit"),
    ("R12", "탐지 룰 삭제·비활성화", "감사로그 detection_config 행위", "T1562.001", "high", "teiren_audit"),
    ("R13", "계정·권한 조작", "감사로그 iam_change 행위", "T1098|T1531", "high", "teiren_audit"),
    ("R14", "내부 관리 기능 실행", "감사로그 admin_exec 행위", "T1059", "high", "teiren_audit"),
    ("R15", "웹 경로 반복 오류", "같은 IP·경로 5분 안 오류 응답 5회 이상", "T1190|T1595", "medium", "nginx"),
    ("R16", "MFA 없는 최상위 계정 로그인", "감사로그 root 로그인 MFA 없음", "T1078.004", "low", "teiren_audit"),
]
RULE = {r[0]: r for r in RULES}

det = []


def add_event(rid, r, evidence):
    """이벤트 한 줄에 걸린 룰 탐지."""
    det.append({"method": "rule", "detection_type": rid, "name": RULE[rid][1], "attck": RULE[rid][3],
                "severity": RULE[rid][4], "event_time_utc": r["event_time_utc"], "log_source": r["log_source"],
                "source_row": r["source_row"], "bucket": r["bucket"], "host": r["host"], "client_ip": r["client_ip"],
                "account": r["account"], "person_candidate": r["person_candidate"],
                "work_session_id": r["work_session_id"], "evidence": evidence})


# ---------------------------------------------------------------- 5-a. 룰 기반 탐지
RE_PIPE_SHELL = re.compile(r"\b(curl|wget)\b[^|]*\|\s*(ba|da|z)?sh\b")
RE_HIDDEN_TMP = re.compile(r"^/(tmp|var/tmp|dev/shm)/(.*/)?\.[^/]+$")
RE_ARCHIVE_TMP = re.compile(r"^(tar|zip|gzip)\b.*\s/(tmp|var/tmp|dev/shm)/")
RE_UPLOAD = re.compile(r"\b(curl|wget)\b.*(--data-binary\s+@|--data\s+@|-d\s+@|-T\s|--upload-file|-F\s+\S*=@|--post-file)")

scan = defaultdict(list)       # R05: host → [(t, dst)]
fails = defaultdict(list)      # R09·R10: ip → [(t, account)]
errors = defaultdict(list)     # R15: (ip, path) → [t]
fired = set()                  # 같은 창에서 한 번만 내기 위한 표시

for r in timeline:
    src, act, cmd = r["log_source"], r["event_action"], r["CommandLine"]
    if src == "sysmon":
        if act == "process_create":
            if r["account"] in WEB_ACCOUNTS and base(r["Image"]) in SHELLS | DOWNLOADERS:
                add_event("R01", r, f"{r['account']} 실행: {cmd}")
            if RE_PIPE_SHELL.search(cmd):
                add_event("R02", r, cmd)
            if RE_ARCHIVE_TMP.search(cmd):
                add_event("R07", r, cmd)
            if RE_UPLOAD.search(cmd):
                add_event("R08", r, cmd)
        elif act == "network_connect":
            if r["dst_zone"] == "external":
                add_event("R03", r, f"{base(r['Image'])} → {r['dst']}:{r['dpt']}")
                if r["dpt"] not in ("80", "443"):
                    add_event("R04", r, f"{base(r['Image'])} → {r['dst']}:{r['dpt']}")
            if r["dst_zone"] == "server" and r["dpt"] == "22" and base(r["Image"]) != "sshd":
                win = [(t, d) for t, d in scan[r["host"]] if r["_t"] - t <= timedelta(minutes=5)]
                win.append((r["_t"], r["dst"]))
                scan[r["host"]] = win
                dsts = sorted({d for _, d in win})
                key = ("R05", r["host"], win[0][0])
                if len(dsts) >= 3 and key not in fired:
                    fired.add(key)
                    add_event("R05", r, f"{r['host']}에서 5분 안 22번 연결 {len(dsts)}대: {', '.join(dsts)}")
        elif act == "file_create" and RE_HIDDEN_TMP.match(r["TargetFilename"]):
            add_event("R06", r, r["TargetFilename"])

    elif src == "sshd":
        if act in FAIL:
            fails[r["client_ip"]].append((r["_t"], r["account"]))
            win = [t for t, _ in fails[r["client_ip"]] if r["_t"] - t <= timedelta(hours=1)]
            key = ("R09", r["client_ip"], win[0])
            if len(win) >= 5 and key not in fired:
                fired.add(key)
                add_event("R09", r, f"{r['client_ip']} 1시간 안 실패 {len(win)}회")
        elif act == "auth_success":
            prev = [t for t, a in fails[r["client_ip"]]
                    if a == r["account"] and timedelta(0) < r["_t"] - t <= timedelta(minutes=10)]
            if prev:
                add_event("R10", r, f"{r['account']}@{r['client_ip']} 실패 {len(prev)}회 뒤 성공")
            if r["client_zone"] == "external":
                add_event("R11", r, f"ssh {r['account']} ← {r['client_ip']}")

    elif src == "teiren_audit":
        if act in WEB_LOGINS and r["client_zone"] == "external":
            add_event("R11", r, f"콘솔 {r['account']} ← {r['client_ip']} ({act})")
        cat = r["action_category"]
        if cat == "detection_config":
            add_event("R12", r, f"{act} {r['request']}")
        elif cat == "iam_change":
            add_event("R13", r, f"{act} {r['request']}")
        elif cat == "admin_exec":
            add_event("R14", r, f"{act} {r['request']}")
        if act == "ROOT_LOGIN_NO_MFA":
            add_event("R16", r, f"{r['account']} ← {r['client_ip']}")

    elif src == "nginx" and r["http_status_code"][:1] in ("4", "5"):
        k = (r["client_ip"], r["request"])
        errors[k] = [t for t in errors[k] if r["_t"] - t <= timedelta(minutes=5)] + [r["_t"]]
        key = ("R15", k, errors[k][0])
        if len(errors[k]) >= 5 and key not in fired:
            fired.add(key)
            add_event("R15", r, f"{r['client_ip']} {r['request']} 5분 안 오류 {len(errors[k])}회")

# ---------------------------------------------------------------- 5-b. 행위 기반 탐지
comparable = [s for s in sb if s["baseline_level"] in ("person", "peer")]
excluded = Counter(s["baseline_level"] for s in sb if s["baseline_level"] not in ("person", "peer"))
n = len(comparable)

# B01 임계값: hour_distance ≥ d 인 세션 비율이 5% 이하가 되는 가장 작은 d
dist = [int(float(s["hour_distance"])) for s in comparable]
b01_table = {d: sum(x >= d for x in dist) / n for d in range(1, max(dist) + 1)}
B01_D = min(d for d, share in b01_table.items() if share <= RARE)

# B08 항목: _above_max 비율이 5% 이하인 항목만
VOLUME = ["duration_min", "process_count", "nginx_count", "api_count", "non_get_count"]
b08_share = {c: sum(s[f"{c}_above_max"] == "true" for s in comparable) / n for c in VOLUME}
B08_ITEMS = [c for c in VOLUME if b08_share[c] <= RARE]

BEHAVIORS = [  # (ID, 이름, 조건, 관련 ATT&CK, 사용 비교값)
    ("B01", "평소와 다른 시작 시각", f"hour_distance ≥ {B01_D}시간", "", "hour_distance"),
    ("B02", "처음 보는 접속 IP", "ip_new = true", "T1078", "ip_new"),
    ("B03", "평소와 다른 접속 경로", "hist_session_type_ratio = 0", "", "hist_session_type_ratio"),
    ("B04", "처음 보는 로그인 종류", "login_types_new 있음", "T1078", "login_types_new"),
    ("B05", "처음 하는 민감 행위", "sensitive_new 있음", "", "sensitive_new"),
    ("B06", "누구도 쓴 적 없는 명령", "cmds_new_global 있음", "", "cmds_new_global"),
    ("B07", "로그인 전 실패 첫 발생", "failed_before_login > 0, hist_failed_sessions = 0", "T1110", "failed_before_login"),
    ("B08", "평소보다 많은 양", f"_above_max = true ({', '.join(B08_ITEMS)})", "", "_above_max"),
    ("B09", "처음 보는 시스템 활동 패턴", f"같은 서버·다른 서버 모두 처음, 서버 기록 {WARMUP_H}시간 이상",
     "", "pattern_seen_before"),
]
BEH = {b[0]: b for b in BEHAVIORS}


def add_session(bid, s, evidence):
    det.append({"method": "behavior", "detection_type": bid, "name": BEH[bid][1], "attck": BEH[bid][3],
                "severity": "", "event_time_utc": s["start_utc"], "log_source": "", "source_row": "",
                "bucket": "session", "host": "", "client_ip": s["client_ip"], "account": s["linux_account"],
                "person_candidate": s["person_candidate"], "work_session_id": s["work_session_id"],
                "evidence": f"[{s['baseline_level']} n={s['baseline_n']}] {evidence}"})


for s in comparable:
    if int(float(s["hour_distance"])) >= B01_D:
        add_session("B01", s, f"시작 {s['start_hour_kst']}시, 평소 {s['hist_hour_min']}~{s['hist_hour_max']}시")
    if s["ip_new"] == "true":
        add_session("B02", s, f"처음 보는 IP {s['client_ip']} ({s['client_zone']})")
    if float(s["hist_session_type_ratio"]) == 0:
        add_session("B03", s, f"{s['session_type']}: 과거 {s['baseline_n']}개 세션 중 0개")
    if s["login_types_new"]:
        add_session("B04", s, s["login_types_new"])
    if s["sensitive_new"]:
        add_session("B05", s, s["sensitive_new"])
    if s["cmds_new_global"]:
        add_session("B06", s, s["cmds_new_global"])
    if int(s["failed_before_login"]) > 0 and int(s["hist_failed_sessions"]) == 0:
        add_session("B07", s, f"로그인 전 실패 {s['failed_before_login']}회, 과거 실패 세션 0")
    over = [f"{c}={s[c]}" for c in B08_ITEMS if s[f"{c}_above_max"] == "true"]
    if over:
        add_session("B08", s, "과거 최대 초과: " + ", ".join(over))

for r in timeline:  # B09: ② 이벤트
    b = bgb.get((r["event_time_utc"], r["source_row"], r["log_source"]))
    if (b and r["event_action"] != "process_terminate" and b["pattern_seen_before"] == "0"
            and b["pattern_seen_other_hosts_before"] == "0" and float(b["host_history_hours"]) >= WARMUP_H):
        det.append({"method": "behavior", "detection_type": "B09", "name": BEH["B09"][1], "attck": "",
                    "severity": "", "event_time_utc": r["event_time_utc"], "log_source": r["log_source"],
                    "source_row": r["source_row"], "bucket": r["bucket"], "host": r["host"], "client_ip": "",
                    "account": r["account"], "person_candidate": "", "work_session_id": "",
                    "evidence": f"{b['pattern_id']} 처음 봄 (서버 기록 {b['host_history_hours']}시간): "
                                f"{r['CommandLine'] or r['TargetFilename'] or (r['dst_zone'] + ':' + r['dpt'])}"})

# ---------------------------------------------------------------- 5-c. 세션 없는 탐지를 사용자 세션에 연결
srv = []
for s in sessions.values():
    if s["ssh_end_utc"]:
        on = {h.split(":")[0] for h in s["hosts"].split("|") if h} | {home.get(s["person_candidate"], "")}
        srv.append((s, datetime.fromisoformat(s["start_utc"]), datetime.fromisoformat(s["ssh_end_utc"]), on))
web_times = defaultdict(list)
for r in timeline:
    if r["work_session_id"] and r["log_source"] in ("nginx", "teiren_audit"):
        web_times[r["work_session_id"]].append(r["_t"])

for d in det:
    d["linked_sessions"] = d["link_basis"] = ""
    if d["work_session_id"]:
        d["link_basis"] = "세션 소속"
        continue
    if not d["host"]:
        d["link_basis"] = "연결 대상 아님 (외부 시도)"
        continue
    t = datetime.fromisoformat(d["event_time_utc"])
    links = []
    for s, st, en, on in srv:
        if d["host"] in on and st <= t <= en:
            links.append(f"{s['work_session_id']}(서버, {int((t - st).total_seconds())}초 경과)")
    if hosts[d["host"]]["role"] == "web":
        for sid, ts in web_times.items():
            gap = min(abs((t - x).total_seconds()) for x in ts)
            if gap <= 300:
                links.append(f"{sid}(웹 요청, {int(gap)}초 차이)")
    d["linked_sessions"] = "|".join(links)
    d["link_basis"] = "추정: 같은 서버·시간 / 웹 서버의 웹 요청 앞뒤 5분" if links else "연결 없음"

# ---------------------------------------------------------------- 쓰기
det.sort(key=lambda d: (d["event_time_utc"], d["detection_type"]))
for i, d in enumerate(det, start=1):
    d["detection_id"] = f"D{i:04d}"
DET_COLS = ["detection_id", "method", "detection_type", "name", "attck", "severity", "event_time_utc",
            "log_source", "source_row", "bucket", "host", "client_ip", "account", "person_candidate",
            "work_session_id", "linked_sessions", "link_basis", "evidence"]

rule_rows = [{"id": r[0], "method": "rule", "name": r[1], "condition": r[2], "attck": r[3], "severity": r[4],
              "data_source": r[5], "threshold_note": ""} for r in RULES]
rule_rows += [{"id": b[0], "method": "behavior", "name": b[1], "condition": b[2], "attck": b[3], "severity": "",
               "data_source": b[4], "threshold_note": ""} for b in BEHAVIORS]
for row in rule_rows:
    if row["id"] == "B01":
        row["threshold_note"] = "; ".join(f"≥{d}h:{v:.1%}" for d, v in b01_table.items())
    if row["id"] == "B08":
        row["threshold_note"] = "; ".join(f"{c}:{v:.1%}" for c, v in b08_share.items())

DETECTIONS.mkdir(parents=True, exist_ok=True)
write_rows(DETECTIONS / "detection_rules.csv", list(rule_rows[0].keys()), rule_rows)
write_rows(DETECTIONS / "detections.csv", DET_COLS, det)
print(f"detection_rules.csv: {len(rule_rows)} / detections.csv: {len(det)}\n")

# ---------------------------------------------------------------- 검증
assert all(d["evidence"] for d in det), "근거 없는 탐지"
assert all(d["work_session_id"] or d["host"] or d["client_ip"] for d in det), "대상 없는 탐지"
assert all(d["link_basis"] for d in det)
print("검증 통과\n")

# ---------------------------------------------------------------- 요약
print(f"행위 탐지 비교 대상 세션: {n}개 (제외: {dict(excluded)})")
print(f"B01 임계값: {B01_D}시간 | 비율 " + ", ".join(f"≥{d}h {v:.1%}" for d, v in b01_table.items()))
print("B08 항목별 _above_max 비율: " + ", ".join(f"{c} {v:.1%}" for c, v in b08_share.items())
      + f" → 사용: {B08_ITEMS}\n")

cnt = Counter(d["detection_type"] for d in det)
for rid, *_ in RULES + BEHAVIORS:
    print(f"  {rid} {(RULE.get(rid) or BEH[rid])[1]:<24} {cnt.get(rid, 0):>4}")

sess_of = defaultdict(set)  # 세션별 탐지 (직접 + 연결)
for d in det:
    if d["work_session_id"]:
        sess_of[d["work_session_id"]].add(d["detection_type"])
    for link in d["linked_sessions"].split("|"):
        if link:
            sess_of[link.split("(")[0]].add(d["detection_type"] + "*")
print(f"\n탐지가 1개 이상인 세션: {len(sess_of)} / {len(sessions)}  (* = 5-c 연결)")
for sid in sorted(sess_of):
    s = sessions[sid]
    print(f"  {sid} {s['person_candidate']:<10} {s['session_type']:<11} {s['start_utc'][:16]}  "
          f"{' '.join(sorted(sess_of[sid]))}")
print("\n세션에 붙지 않은 탐지:")
for d in det:
    if not d["work_session_id"] and not d["linked_sessions"]:
        print(f"  {d['detection_id']} {d['detection_type']} {d['event_time_utc'][:19]} {d['host'] or d['client_ip']} "
              f"| {d['link_basis']} | {d['evidence'][:70]}")
