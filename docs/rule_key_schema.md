# Rule key schema

An engine that loads `sigma_rules/` must know which YAML keys are Sigma-standard, which keys are project extensions, and which event fields the conditions bind to. This file is that dictionary. Detection logic in `scripts/09_detect.py` is unchanged; this schema is for documentation and later GitOps loading.

Hit counts, SigmaHQ match level, and scoring notes do not belong in the rule files. Those live in [06_탐지규칙_SigmaHQ_대조.yaml](06_탐지규칙_SigmaHQ_대조.yaml).

## 1. Rule-document keys

### Required (Sigma)

| Key | Meaning |
| --- | --- |
| `title` | Human-readable name |
| `id` | UUID for this rule |
| `logsource` | Where the event comes from (`product`, `category` or `service`) |
| `detection` | Selection + `condition` over event fields |
| `level` | `informational` / `low` / `medium` / `high` / `critical` |

Correlation files may omit `detection` on the outer document and set `correlation` instead. Base events still need `logsource` + `detection`.

### Optional (Sigma)

| Key | Meaning |
| --- | --- |
| `status` | `experimental` / `test` / `stable` |
| `description` | What the rule detects |
| `references` | SigmaHQ or project docs |
| `author` | Rule author |
| `date` | Creation date (`YYYY-MM-DD`) |
| `tags` | ATT&CK tags (`attack.t1059.004`, …) |
| `related` | Related SigmaHQ rule ids |
| `name` | Stable identifier used by `correlation.rules` |
| `fields` | Extra columns to keep on a hit |
| `falsepositives` | Known noisy cases |
| `correlation` | Windowed / ordered match (`type`, `rules`, `group-by`, `timespan`, `condition`) |

### Do not put on engine-facing rules

| Key | Why |
| --- | --- |
| `project_rule_id` | Project label; use the filename and `title` instead |
| `project_hits` | Dataset-specific count, not a detection condition |
| `sigma_match_level` | Analysis note |
| `sigma_difference` | Analysis note |
| `sigma_original_hits` | Analysis note |
| `score` / RBA weights | Alert policy, not a Sigma rule. Not in this pack yet |

## 2. Event-field mapping

Rule conditions use a mix of Sigma-style names and project enrichment columns. The engine must map parser output onto these names before matching.

| Rule field | Project column | Logs | Notes |
| --- | --- | --- | --- |
| `User` | `account` or Sysmon `suser` | sysmon | Linux process user. Not the Teiren console account. |
| `Image` | `Image` | sysmon | Process path |
| `CommandLine` | `CommandLine` | sysmon | Full command |
| `TargetFilename` | `TargetFilename` | sysmon | File-create path |
| `DestinationIp` | `dst` | sysmon | Remote address |
| `DestinationPort` | `dpt` | sysmon | Remote port |
| `dst_zone` | `dst_zone` | sysmon | Enrichment: `server` / `external` / … |
| `host` | `host` / `dvchost` | sysmon | Enrichment: which server emitted the event |
| `event_action` | `event_action` | sshd, nginx, audit | Normalized action name |
| `account` | `account` | sshd, audit | Session/login account after linking |
| `client_ip` | `client_ip` | sshd, nginx, audit | Client address after linking |
| `client_zone` | `client_zone` | sshd, audit | Enrichment: `external` / internal |
| `action_category` | `action_category` | teiren_audit | Catalog class (`detection_config`, `iam_change`, `admin_exec`) |
| `http_status_code` | `http_status_code` | nginx | Response code |
| `request` | `request` | nginx, audit | Path or console request |

Do not join Linux `account` to Teiren console `suser` by string equality. Sysmon `src` is the server’s own IP, not the client.

## 3. Log source → files

| `logsource` | Project files |
| --- | --- |
| `product: linux`, `category: process_creation` | Sysmon process create (R01, R02, R07, R08) |
| `product: linux`, `category: network_connection` | Sysmon network (R03, R04, R05) |
| `product: linux`, `category: file_event` (or equivalent) | Sysmon file create (R06) |
| `product: linux`, `service: sshd` | sshd (R09, R10, R11 ssh half) |
| nginx (see each rule) | nginx (R15) |
| Teiren audit (see each rule) | `teiren_audit` (R11 console half, R12–R14, R16) |

R11 is two rules, one per log source, not a single AND across logs.

## 4. Correlation vs session vs score

| Layer | Where | Engine input |
| --- | --- | --- |
| Event / correlation rule | `sigma_rules/` | This schema |
| Session join + 5-c link | `scripts/07_sessionize.py`, `scripts/09_detect.py` | Not YAML yet |
| Behavior B01–B09 | `scripts/09_detect.py` | Not YAML yet; not ATT&CK tactic counts |
| Alert line (score ≥ 100 or tactics ≥ 3) | `scripts/10_risk.py` | Policy, not a Sigma rule |

## 5. Source of this pack

- Deployable YAML: `sigma_rules/` (from `feature/heeseo`)
- SigmaHQ comparison: `docs/06_탐지규칙_SigmaHQ_대조.yaml` (from `feature/hyeonsu`)
- Third-party archive: `research/wazuh_operation_rules/` (from `feature/sunseong`; not mapped to this schema)
