# Staging copies (integration)

This folder holds each person's rule-documentation work, copied as-is from their feature branches. It is a merge checkpoint, not the final layout.

| Directory | Source branch | Contents |
| --- | --- | --- |
| `hyeonsu/` | `feature/hyeonsu` | R01–R16 YAML (project field names) and SigmaHQ comparison |
| `heeseo/` | `feature/heeseo` | R01–R16 YAML closer to the Sigma spec, plus sensitivity notes |
| `sunseong/` | `feature/sunseong` | Wazuh v4.14.8 original rules archived as YAML |

`feature/dongmin` and `sinae` match `main` and have no extra files here.

Follow-up commits on this branch fold these copies into one project tree and remove `contrib/`.
