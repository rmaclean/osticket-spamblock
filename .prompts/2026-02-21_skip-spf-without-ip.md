# 2026-02-21 Skip SPF check when no sender IP

## Prompt

if there is IP address, do not run the SPF check

Implemented as: only run SPF when a (best-effort) sender IP is present; otherwise, omit the SPF provider entirely to avoid noisy invalid results/logs.