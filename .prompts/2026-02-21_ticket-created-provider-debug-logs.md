# 2026-02-21 Ticket-created provider debug logs

## Prompt

still not seeing the log messages I want
for example I ran the phish.eml into the local test system and spf log message is just

ticket=... mid=... result=none should_block=1

sfs is ticket=... mid=... confidence=n/a should_block=0

postmark is ticket=... mid=... score=2.7 should_block=0

Need the ticket-created debug logs to include provider URLs (Postmark + SFS) and detailed SPF trace (IP used + per-step SPF record lines).