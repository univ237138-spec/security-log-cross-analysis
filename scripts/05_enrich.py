"""보강(Enrichment) 테이블 4개를 만든다. 정규화 데이터는 바꾸지 않고 매핑 테이블만 만든다.

입력: data/03_normalized/*_normalized_event_action.csv
출력: data/05_enriched/
  ip_inventory.csv       IP별 구역(사용자 PC / 서버 / 외부), 서버 이름, 관측된 계정
  host_inventory.csv     서버별 IP, 역할, 중요도, 수집 로그, 작업 계정
  account_inventory.csv  계정별 계정 체계, 종류, 역할, 주 접속 IP, 작업 서버, 동일인 후보
  action_catalog.csv     로그별 event_action의 의미, 분류, 민감도
설명: docs/04_통합_보강_연결.md

근거(basis) 표시 규칙
- 공식: 표준·공식 문서로 정해지는 값 (RFC 1918 사설 대역, Sysmon EventID 정의, OpenSSH·PAM 메시지 의미)
- 관측: 로그 한 행 안에 직접 함께 기록된 값 (예: Sysmon Computer=web-01, SourceIp=10.10.1.30)
- 추정: 공식 자료가 없어 이름·반복 패턴으로 판단한 값. 기업 측 확인 전까지 확정하지 않는다

팀 기준 (docs/06_통합 결정 5·6, 멘토 피드백)
- 리눅스 계정(sshd duser, Sysmon suser)과 테이렌 콘솔 계정(감사로그 suser)은 다른 계정 체계다. 이름으로 조인하지 않는다.
  같은 사람으로 보는 연결은 person_candidate 컬럼에 '추정'으로만 남긴다
- Sysmon src는 접속자 IP가 아니라 서버 자신의 IP다. 서버 IP 매핑에만 쓴다
"""
import ipaddress
import json
from collections import Counter, defaultdict

from common import ENRICHED, NORMALIZED, read_rows, write_rows

sshd = read_rows(NORMALIZED / "sshd_normalized_event_action.csv")
nginx = read_rows(NORMALIZED / "nginx_normalized_event_action.csv")
audit = read_rows(NORMALIZED / "audit_normalized_event_action.csv")
sysmon = read_rows(NORMALIZED / "sysmon_normalized_event_action.csv")

for r in sshd:
    r["dvchost"] = json.loads(r["unmapped"])["hostname"]


def join(values):
    return "|".join(sorted(values))


def counted(counter):
    """Counter → 'a:3|b:1' (많은 순)."""
    return "|".join(f"{k}:{v}" for k, v in counter.most_common())


# ---------------------------------------------------------------- 공통 관측값
# 서버 IP ↔ 호스트: Sysmon 같은 행의 Computer와 SourceIp (network_connect)
host_ips = defaultdict(Counter)
for r in sysmon:
    if r["src"]:
        host_ips[r["dvchost"]][r["src"]] += 1
host_ip = {}
for host, c in host_ips.items():
    assert len(c) == 1, f"{host}의 IP가 하나가 아니다: {c}"
    host_ip[host] = next(iter(c))
ip_host = {ip: host for host, ip in host_ip.items()}

# 접속 IP ↔ 계정: sshd(src, duser), 감사로그(src, suser) 같은 행
ip_linux = defaultdict(Counter)    # sshd 로그인 성공 기준
ip_console = defaultdict(Counter)  # 감사로그 전체
ip_tried = defaultdict(Counter)    # sshd 로그인 실패(invalid_user, auth_failure)
for r in sshd:
    if r["src"] and r["duser"]:
        if r["event_action"] == "auth_success":
            ip_linux[r["src"]][r["duser"]] += 1
        elif r["event_action"] in ("invalid_user", "auth_failure"):
            ip_tried[r["src"]][r["duser"]] += 1
for r in audit:
    ip_console[r["src"]][r["suser"]] += 1

# IP별 등장 로그·시각. Sysmon은 dst만 접속 대상 IP로 센다 (src는 서버 자신)
seen = defaultdict(lambda: {"logs": Counter(), "times": []})
for name, rows, cols in [("sshd", sshd, ["src"]), ("nginx", nginx, ["src"]),
                         ("teiren_audit", audit, ["src"]), ("sysmon", sysmon, ["src", "dst"])]:
    for r in rows:
        for c in cols:
            if r[c]:
                seen[r[c]]["logs"][name] += 1
                seen[r[c]]["times"].append(r["event_time_utc"])

# ---------------------------------------------------------------- 1. ip_inventory
# ipaddress.is_private는 문서용 대역도 True로 보므로 쓰지 않고 RFC 1918 대역을 직접 비교한다
RFC1918 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
# RFC 5737 문서용 대역: 실제로 라우팅되지 않는다. 생성 데이터가 외부 IP 대신 쓴 것으로 본다
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
USER_NET = ipaddress.ip_network("10.20.10.0/24")
SERVER_NET = ipaddress.ip_network("10.10.1.0/24")

ip_rows = []
for ip in sorted(seen, key=ipaddress.ip_address):
    a = ipaddress.ip_address(ip)
    private = any(a in n for n in RFC1918)
    doc = any(a in n for n in DOC_NETS)
    row = {"ip": ip, "is_rfc1918": str(private).lower(), "is_documentation_range": str(doc).lower()}
    if ip in ip_host:
        row.update(ip_zone="server", zone_basis="관측", host=ip_host[ip], host_basis="관측")
    elif a in USER_NET:
        row.update(ip_zone="user_pc", zone_basis="추정", host="", host_basis="")
    elif a in SERVER_NET:
        row.update(ip_zone="server", zone_basis="추정", host="", host_basis="")
    elif doc:
        row.update(ip_zone="external", zone_basis="추정", host="", host_basis="")
    elif not private:
        row.update(ip_zone="external", zone_basis="공식", host="", host_basis="")
    else:
        row.update(ip_zone="internal_other", zone_basis="추정", host="", host_basis="")
    row.update(linux_login_accounts=counted(ip_linux[ip]),
               console_accounts=counted(ip_console[ip]),
               failed_login_accounts=counted(ip_tried[ip]),
               seen_in_logs=counted(seen[ip]["logs"]),
               event_count=sum(seen[ip]["logs"].values()),
               first_seen=min(seen[ip]["times"]), last_seen=max(seen[ip]["times"]))
    ip_rows.append(row)

IP_COLS = ["ip", "ip_zone", "zone_basis", "host", "host_basis", "is_rfc1918", "is_documentation_range", "linux_login_accounts", "console_accounts",
           "failed_login_accounts", "seen_in_logs", "event_count", "first_seen", "last_seen"]

# ---------------------------------------------------------------- 2. account_inventory
SERVICE_ACCOUNTS = {"root": "슈퍼유저 (UID 0)", "syslog": "시스템 로그 서비스 계정",
                    "www-data": "웹 서버 프로세스 실행 계정"}
ROLE_BY_PREFIX = {"dev": "developer", "ops": "operations", "admin": "administrator",
                  "intern": "intern", "analyst": "analyst", "web": "web_operator"}

linux_hosts = defaultdict(Counter)   # Sysmon process_create 기준, 계정이 실행한 서버
for r in sysmon:
    if r["suser"] and r["event_action"] == "process_create":
        linux_hosts[r["suser"]][r["dvchost"]] += 1

linux_ok, linux_fail, linux_ips = Counter(), Counter(), defaultdict(Counter)
for r in sshd:
    if not r["duser"]:
        continue
    if r["event_action"] == "auth_success":
        linux_ok[r["duser"]] += 1
        linux_ips[r["duser"]][r["src"]] += 1
    elif r["event_action"] in ("invalid_user", "auth_failure"):
        linux_fail[r["duser"]] += 1
invalid_only = {r["duser"] for r in sshd if r["event_action"] == "invalid_user"} - set(linux_ok)

console_ips, console_cnt = defaultdict(Counter), Counter()
for r in audit:
    console_ips[r["suser"]][r["src"]] += 1
    console_cnt[r["suser"]] += 1


def role_of(name):
    for p, role in ROLE_BY_PREFIX.items():
        if name.startswith(p):
            return role
    return ""


def primary(counter):
    """가장 많이 쓴 IP와 나머지. 어느 IP가 정상인지는 4단계 기준선에서 판단한다."""
    if not counter:
        return "", ""
    top, *rest = counter.most_common()
    return top[0], "|".join(f"{k}:{v}" for k, v in rest)


acc_rows = []
linux_names = set(linux_ok) | set(linux_fail) | {r["suser"] for r in sysmon if r["suser"]}
for name in sorted(linux_names):
    if name in SERVICE_ACCOUNTS:
        kind, kind_basis, note = "system", "공식", SERVICE_ACCOUNTS[name]
    elif name in invalid_only:
        kind, kind_basis, note = "nonexistent", "관측", "sshd가 Invalid user로 기록 (서버에 없는 계정)"
    else:
        kind, kind_basis, note = "human", "추정", "로그인 성공 + 사용자 홈 디렉터리에서 작업"
    pip, other = primary(linux_ips[name])
    hosts = linux_hosts[name]
    home = hosts.most_common(1)[0][0] if kind == "human" and hosts else ""
    acc_rows.append({
        "account": name, "account_system": "linux", "account_type": kind, "type_basis": kind_basis,
        "role": role_of(name) if kind == "human" else "", "role_basis": "추정" if kind == "human" else "",
        "is_privileged": str(name == "root" or (kind == "human" and role_of(name) == "administrator")).lower(),
        "login_success": linux_ok[name], "login_fail": linux_fail[name], "console_events": "",
        "primary_client_ip": pip, "other_client_ips": other,
        "active_hosts": counted(hosts), "home_host": home, "home_host_basis": "추정" if home else "",
        "person_candidate": name if kind == "human" else "", "person_basis": "추정" if kind == "human" else "",
        "note": note,
    })

for name in sorted(console_cnt):
    local = name.split("@")[0]
    pip, other = primary(console_ips[name])
    linked = ip_linux.get(pip, Counter())
    acc_rows.append({
        "account": name, "account_system": "teiren_console", "account_type": "human", "type_basis": "추정",
        "role": role_of(local), "role_basis": "추정",
        "is_privileged": str(any(r["suser"] == name and r["event_action"] == "ROOT_LOGIN_NO_MFA"
                                 for r in audit)).lower(),
        "login_success": "", "login_fail": "", "console_events": console_cnt[name],
        "primary_client_ip": pip, "other_client_ips": other,
        "active_hosts": "", "home_host": "", "home_host_basis": "",
        "person_candidate": local if local in linked else "",
        "person_basis": "추정" if local in linked else "",
        "note": f"주 접속 IP {pip}에서 리눅스 계정 {join(linked)} 로그인도 관측됨" if linked else "",
    })

ACC_COLS = ["account", "account_system", "account_type", "type_basis", "role", "role_basis",
            "is_privileged", "login_success", "login_fail", "console_events",
            "primary_client_ip", "other_client_ips", "active_hosts", "home_host", "home_host_basis",
            "person_candidate", "person_basis", "note"]

# ---------------------------------------------------------------- 3. host_inventory
# 역할·중요도는 공식 자산 목록이 없어 전부 추정. 근거를 role_evidence에 남긴다
HOST_ROLE = {
    "bastion-01": ("bastion", "high",
                   "sshd 로그의 유일한 호스트이자 외부 SSH 시도가 모이는 관문 (호스트 이름 bastion)"),
    "app-01": ("application", "high",
               "/opt/app 경로에서 개발 계정 작업 (git, stat /opt/app/current), 소스 코드 보관"),
    "node-01": ("operations", "medium", "운영 계정(ops01, ops02) 작업 서버"),
    "web-01": ("web", "high",
               "nginx(/usr/local/nginx) 실행, www-data 계정 활동, 웹 서비스 동작 서버로 추정"),
}
host_users = defaultdict(Counter)
host_service = defaultdict(Counter)
for r in sysmon:  # 서비스 계정은 모든 이벤트, 사람 계정은 실행한 프로세스 수로 센다
    if r["suser"] in SERVICE_ACCOUNTS:
        host_service[r["dvchost"]][r["suser"]] += 1
    elif r["suser"] and r["event_action"] == "process_create":
        host_users[r["dvchost"]][r["suser"]] += 1
host_logs = defaultdict(Counter)
for r in sysmon:
    host_logs[r["dvchost"]]["sysmon"] += 1
for r in sshd:
    host_logs[r["dvchost"]]["sshd"] += 1

host_rows = []
for host in sorted(host_logs):
    role, crit, why = HOST_ROLE.get(host, ("", "", ""))
    host_rows.append({
        "host": host, "ip": host_ip.get(host, ""), "ip_basis": "관측" if host in host_ip else "",
        "role": role, "role_basis": "추정", "criticality": crit, "criticality_basis": "추정",
        "role_evidence": why, "collected_logs": counted(host_logs[host]),
        "interactive_accounts": counted(host_users[host]), "service_accounts": counted(host_service[host]),
    })

HOST_COLS = ["host", "ip", "ip_basis", "role", "role_basis", "criticality", "criticality_basis",
             "role_evidence", "collected_logs", "interactive_accounts", "service_accounts"]

# ---------------------------------------------------------------- 4. action_catalog
SSHD_ACTIONS = {  # OpenSSH·PAM·systemd-logind 메시지 의미 (공식)
    "auth_success": ("authentication", "인증 성공 (Accepted ...)", "low"),
    "auth_failure": ("authentication", "인증 실패 (Failed password ...)", "medium"),
    "invalid_user": ("authentication", "서버에 없는 계정으로 시도 (Invalid user ...)", "medium"),
    "session_opened": ("session", "PAM 세션 시작", "low"),
    "session_new": ("session", "systemd-logind 세션 번호 부여", "low"),
    "disconnect_received": ("session", "클라이언트가 연결 종료 요청", "low"),
    "disconnected_user": ("session", "사용자 연결 종료", "low"),
    "session_closed": ("session", "PAM 세션 종료", "low"),
    "session_logged_out": ("session", "systemd-logind 로그아웃", "low"),
    "session_removed": ("session", "systemd-logind 세션 정리", "low"),
}
SYSMON_ACTIONS = {  # Microsoft Sysmon EventID 정의 (공식)
    "process_create": ("process", "EventID 1 프로세스 생성", "low"),
    "process_terminate": ("process", "EventID 5 프로세스 종료", "low"),
    "network_connect": ("network", "EventID 3 네트워크 연결", "low"),
    "file_create": ("file", "EventID 11 파일 생성", "low"),
}
AUDIT_ACTIONS = {  # 테이렌 공개 문서 없음 → 이름·요청 경로로 추정
    "IAM_LOGIN_SUCCESS": ("authentication", "콘솔 하위 계정 로그인 성공", "low"),
    "ROOT_LOGIN_NO_MFA": ("authentication", "콘솔 최상위(root) 계정이 MFA 없이 로그인", "high"),
    "IAM_LOGIN_NEW_DEVICE": ("authentication", "새 기기에서 콘솔 로그인", "medium"),
    "SESSION_REFRESH": ("session", "콘솔 세션 갱신", "low"),
    "DASHBOARD_LAYOUT_VIEW_UPDATE": ("view_config", "대시보드 배치 변경", "low"),
    "LOG_COLUMN_VIEW_UPDATE": ("view_config", "로그 조회 컬럼 설정 변경", "low"),
    "INTEGRATION_STATUS_UPDATE": ("system_config", "외부 연동(수집) 상태 변경", "medium"),
    "GENERAL_BAD_REQUEST": ("error", "잘못된 요청", "low"),
    "DEBUG_EXEC": ("admin_exec", "내부 디버그 기능으로 명령 실행", "high"),
    "RULE_DELETE": ("detection_config", "탐지 룰 삭제", "high"),
    "IAM_POLICY_DETACH": ("iam_change", "계정에서 권한 정책 해제", "high"),
    "IAM_USER_DELETE": ("iam_change", "콘솔 계정 삭제", "high"),
}
NGINX_METHODS = {  # HTTP 메서드 의미 (RFC 9110, 공식)
    "GET": ("web_read", "리소스 조회", "low"),
    "POST": ("web_write", "데이터 전송·처리 요청", "medium"),
    "PUT": ("web_write", "리소스 생성·교체", "medium"),
    "DELETE": ("web_write", "리소스 삭제", "medium"),
}

act_rows = []


def add_actions(source, rows, key, table, basis, extra=lambda r: {}):
    cnt = Counter(r[key] for r in rows)
    assert set(cnt) <= set(table), f"{source}: 분류표에 없는 값 {set(cnt) - set(table)}"
    first = {}
    for r in rows:
        first.setdefault(r[key], r)
    for value in sorted(cnt):
        cat, desc, sens = table[value]
        act_rows.append({"log_source": source, "event_action": value, "category": cat,
                         "description": desc, "sensitivity": sens,
                         "meaning_basis": basis, "sensitivity_basis": "추정",
                         "event_count": cnt[value], **extra(first[value])})


add_actions("sshd", sshd, "event_action", SSHD_ACTIONS, "공식")
add_actions("sysmon", sysmon, "event_action", SYSMON_ACTIONS, "공식",
            lambda r: {"vendor_code": f"EventID {r['EventID']}"})
add_actions("teiren_audit", audit, "event_action", AUDIT_ACTIONS, "추정",
            lambda r: {"vendor_code": r["t_event_id"], "sample_request": r["request"]})
add_actions("nginx", nginx, "http_method", NGINX_METHODS, "공식")

ACT_COLS = ["log_source", "event_action", "vendor_code", "category", "description", "sensitivity",
            "meaning_basis", "sensitivity_basis", "event_count", "sample_request"]

# ---------------------------------------------------------------- 쓰기 + 검증
ENRICHED.mkdir(parents=True, exist_ok=True)
for fname, cols, rows in [("ip_inventory.csv", IP_COLS, ip_rows),
                          ("host_inventory.csv", HOST_COLS, host_rows),
                          ("account_inventory.csv", ACC_COLS, acc_rows),
                          ("action_catalog.csv", ACT_COLS, act_rows)]:
    write_rows(ENRICHED / fname, cols, rows)
    print(f"{fname}: {len(rows)} rows")

# 모든 접속 IP(sshd·nginx·감사로그 src, Sysmon dst)가 ip_inventory에 있어야 한다
ips = {r["ip"] for r in ip_rows}
for rows, c in [(sshd, "src"), (nginx, "src"), (audit, "src"), (sysmon, "dst"), (sysmon, "src")]:
    assert {r[c] for r in rows if r[c]} <= ips, c
# 모든 계정이 account_inventory에 있어야 한다
accs = {r["account"] for r in acc_rows}
assert {r["duser"] for r in sshd if r["duser"]} <= accs
assert {r["suser"] for r in sysmon if r["suser"]} <= accs
assert {r["suser"] for r in audit} <= accs
# 사용자 PC IP 하나에는 리눅스 로그인 계정이 하나뿐이어야 동일인 추정이 성립한다
for r in ip_rows:
    if r["ip_zone"] == "user_pc":
        assert r["linux_login_accounts"].count(":") <= 1, r
print("검증 통과")
