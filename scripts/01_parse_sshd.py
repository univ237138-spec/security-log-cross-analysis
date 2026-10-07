"""sshd 파싱: syslog 헤더를 나누고, 메시지 템플릿 10종에서 값을 글자 그대로 꺼낸다.

입력: data/01_raw/sshd_raw.csv (RAW_LINE, LOADED_AT)
출력: data/02_parsed/sshd_parsed.csv (헤더 5 + 메시지 값 13 + LOADED_AT = 19개)
기준: 헤더는 rsyslog RSYSLOG_FileFormat, 메시지는 OpenSSH·PAM·systemd-logind 출력 문장
     (docs/03_파싱_정규화.md 5절)
템플릿에 맞지 않는 메시지가 나오면 멈춘다 → 템플릿을 추가해야 한다.
"""
import re

from common import PARSED, RAW, read_rows, write_rows

HEADER_RE = re.compile(r"^(\S+) (\S+) ([^\[:]+)\[(\d+)\]: (.*)$")
IP = r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})"

# (정규식, 재조립 형식) — 메시지 원문 전체와 정확히 일치해야 한다
TEMPLATES = [
    (rf"Invalid user (?P<user>\S+) from {IP} port (?P<src_port>\d+)",
     "Invalid user {user} from {src_ip} port {src_port}"),
    (rf"Accepted (?P<auth_method>\S+) for (?P<user>\S+) from {IP} port (?P<src_port>\d+) "
     rf"(?P<ssh_protocol>ssh\d): (?P<key_type>\S+) (?P<key_fingerprint>\S+)",
     "Accepted {auth_method} for {user} from {src_ip} port {src_port} {ssh_protocol}: {key_type} {key_fingerprint}"),
    (rf"Failed (?P<auth_method>\S+) for (?P<user>\S+) from {IP} port (?P<src_port>\d+) (?P<ssh_protocol>ssh\d)",
     "Failed {auth_method} for {user} from {src_ip} port {src_port} {ssh_protocol}"),
    (r"pam_unix\(sshd:session\): session opened for user (?P<user>[^(\s]+)\(uid=(?P<uid>\d+)\) "
     r"by (?P<by_user>[^(\s]+)\(uid=(?P<by_uid>\d+)\)",
     "pam_unix(sshd:session): session opened for user {user}(uid={uid}) by {by_user}(uid={by_uid})"),
    (r"pam_unix\(sshd:session\): session closed for user (?P<user>\S+)",
     "pam_unix(sshd:session): session closed for user {user}"),
    (rf"Received disconnect from {IP} port (?P<src_port>\d+):(?P<disconnect_code>\d+): (?P<disconnect_reason>.+)",
     "Received disconnect from {src_ip} port {src_port}:{disconnect_code}: {disconnect_reason}"),
    (rf"Disconnected from user (?P<user>\S+) {IP} port (?P<src_port>\d+)",
     "Disconnected from user {user} {src_ip} port {src_port}"),
    (r"New session (?P<session_id>\d+) of user (?P<user>[^\s.]+)\.",
     "New session {session_id} of user {user}."),
    (r"Session (?P<session_id>\d+) logged out\. Waiting for processes to exit\.",
     "Session {session_id} logged out. Waiting for processes to exit."),
    (r"Removed session (?P<session_id>\d+)\.",
     "Removed session {session_id}."),
]
TEMPLATES = [(re.compile(p), f) for p, f in TEMPLATES]

HDR_COLS = ["timestamp", "hostname", "program", "pid", "message"]
MSG_COLS = ["user", "src_ip", "src_port", "auth_method", "ssh_protocol", "key_type", "key_fingerprint",
            "uid", "by_user", "by_uid", "session_id", "disconnect_code", "disconnect_reason"]

out = []
for r in read_rows(RAW / "sshd_raw.csv"):
    h = HEADER_RE.fullmatch(r["RAW_LINE"])
    assert h, r["RAW_LINE"]
    msg = h.group(5)
    hits = [(m, f) for p, f in TEMPLATES if (m := p.fullmatch(msg))]
    assert len(hits) == 1, f"템플릿 {len(hits)}개와 일치: {msg}"
    m, fmt = hits[0]
    d = m.groupdict()
    assert fmt.format(**d) == msg  # 검증: 메시지 원문 재조립
    out.append(list(h.groups()) + [d.get(k, "") for k in MSG_COLS] + [r["LOADED_AT"]])

write_rows(PARSED / "sshd_parsed.csv", HDR_COLS + MSG_COLS + ["LOADED_AT"], out)
print(f"sshd_parsed.csv: {len(out)} rows, {len(HDR_COLS) + len(MSG_COLS) + 1} cols")
