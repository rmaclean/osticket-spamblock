# 2026-02-18 postmark spamcheck

## Prompt

what I would like to do is have the plugin intercept all the ticket creation (if possible just tickets created by email)
when we get an email/ticket we then call the postmark API - https://spamcheck.postmarkapp.com/doc/
we do not need the report in the result. We just care about the score.
We should have a setting for the min level to block.
We also need to make sure every email, regardless of score, is logged with the score so we can use that to validate it works and tweak it.
From a design view, I would like postmark integrated in a way that it can be swapped out or augmented with other options (maybe something like a collection) - this is purely internal; we do not need any UI or config for it. Just thinking about the future (would be good to document in AGENTS.md and README.md though)
