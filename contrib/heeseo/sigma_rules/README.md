| Project Rule | YAML File | Type | SigmaHQ Existing Rule | Upstream Readiness | Note |
| --- | --- | --- | --- | --- | --- |
| R01 | `lnx_sysmon_web_account_shell_or_downloader.yml` | detection | Linux Webshell Indicators (modified) | needs tuning | Web account and process basename, rather than parent process. 2 project hits. |
| R02 | `lnx_sysmon_download_pipe_to_shell.yml` | detection | Linux Shell Pipe to Shell (modified) | needs tuning | Python regex requires backend-compatible translation. 2 hits. |
| R03 | `lnx_sysmon_external_network_connection.yml` | project-specific | None | project only | Requires inventory-derived `dst_zone`; broad score input. 4 hits. |
| R04 | `lnx_sysmon_external_connection_non_web_port.yml` | project-specific | Malware Callback Communication (different ports) | project only | Requires `dst_zone`; matches every port except 80/443. 1 hit. |
| R05 | `mr_lnx_sysmon_ssh_scan_3_targets_5m.yml` | correlation | Linux Network Service Scanning (concept only) | needs tuning | Distinct internal destinations per host in 5m; project `dst_zone`. 1 hit. |
| R06 | `lnx_sysmon_hidden_file_created_in_temp.yml` | detection | Hidden Files and Directories (different log source) | candidate | Sysmon file creation; current ATT&CK [Stealth / T1564.001](https://attack.mitre.org/techniques/T1564/001/). 1 hit. |
| R07 | `lnx_sysmon_archive_to_temp_directory.yml` | detection | Data Compressed (modified) | needs tuning | Python regex and temporary path condition. 1 hit. |
| R08 | `lnx_sysmon_curl_wget_file_upload.yml` | detection | Suspicious Curl File Upload (near match) | existing Sigma preferred | Local wget and file-argument differences retained; code does not verify external destination. 1 hit. |
| R09 | `mr_lnx_sshd_5_failures_single_ip_1h.yml` | correlation | None | needs tuning | Five failures per IP in 1h; normalized SSH action. 0 hits. |
| R10 | `mr_lnx_sshd_failure_then_success_10m.yml` | correlation | None | needs tuning | Ordered failure then success per IP/account in 10m. 1 hit. |
| R11 | `lnx_sshd_external_login_success.yml`, `teiren_audit_external_console_login_success.yml` | project-specific | None | project only | Two log sources require separate rules and project `client_zone`. 2 combined hits. |
| R12 | `teiren_audit_detection_configuration_change.yml` | project-specific | AWS GuardDuty Detector Deleted Or Updated (concept only) | project only | Project `action_category`; current [ATT&CK T1685](https://attack.mitre.org/techniques/T1685/) replaces old T1562.001 mapping. 2 hits. |
| R13 | `teiren_audit_identity_or_access_change.yml` | project-specific | Azure Account Created And Deleted (concept only) | project only | Project `action_category` includes policy changes. 2 hits. |
| R14 | `teiren_audit_internal_admin_execution.yml` | project-specific | None | project only | Teiren-specific administrative category. 1 hit. |
| R15 | `mr_web_nginx_repeated_errors_same_path_5m.yml` | correlation | None | needs tuning | Five error responses per IP/path in 5m; normalized nginx fields. 1 hit. |
| R16 | `teiren_audit_root_login_without_mfa.yml` | project-specific | AWS Console Login Without MFA / Root Credentials (concept only) | project only | Teiren-specific combined event. 23 hits. |

Formal sigma-cli validation not run. A restricted YAML syntax and structure check passed; no general YAML parser was available. Correlation engines may emit multiple matches after the threshold; the Python detector suppresses repeat alerts per sliding-window start. Normalized fields and regex backends require mapping and tuning before deployment. Project severities are retained. Public references in YAML point to the pinned SigmaHQ rules; rule format follows the [Sigma specification](https://sigmahq.io/sigma-specification/specification/sigma-rules-specification.html) and [correlation specification](https://sigmahq.io/sigma-specification/specification/sigma-correlation-rules-specification.html).
