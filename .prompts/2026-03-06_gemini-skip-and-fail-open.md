# 2026-03-06 Gemini skip and fail-open

## Prompt

can you check that if the "Enable AI Spam Check" is enabled but "Gemini: API key" is not set then we should not do the gemini check.
Also for gemini, postmark, and StopForumSpam - if their network errors or http errors of any sort, they should not fail the whole system and should not classify the email as spam.
