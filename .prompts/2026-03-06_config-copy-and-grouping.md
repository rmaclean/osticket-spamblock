# 2026-03-06 config copy and grouping

## Prompt

Can you update the config section as follows:
- Make all labels bold for consistency.
- Update SPF sublabels:
  - SPF: check fails → "What to do when the SPF record exists but the sending IP is not allowed. Recommended: Treat as Spam"
  - SPF: record missing → "What to do when no SPF record found for the sender domain. Recommended: Do Nothing"
  - SPF: record invalid → "What to do when SPF record is invalid. Recommended: Do Nothing"
  - SPF: unsupported mechanism → "What to do when SPF record contains unsupported mechanisms. Recommended: Do Nothing"
- Append recommendation text:
  - Blocked email log level → "Recommended: Error"
  - Postmark: minimum score to block → "Recommended: 4.5"
  - StopForumSpam: minimum confidence (%) → "Recommended: 90"
  - Gemini: enable LLM spam check → "Recommended: Enabled"
  - Gemini: when spam is detected → "Recommended: Treat as Spam"
- Rename labels:
  - "Gemini: enable LLM spam check" → "Enable AI Spam Check"
  - "Gemini: company description" → "Company Description for AI"
  - "Gemini: spam guidelines" → "Spam Guidelines for AI"
  - "Gemini: legitimate email guidelines" → "Legitimate Guidelines for AI"
- Update Gemini sublabels:
  - Company description: "Describe your business so that the AI can better understand what inbound emails are relevant."
  - Spam guidelines: "Describe what the AI should treat as spam for your help desk. For example, if you only handle billing requests, you could state that anything not billing related is spam"
  - Legitimate guidelines: "Describe what the AI should treat as legitimate for your help desk. This combined with spam guidelines above gives the AI a strong view on what is and is not spam"
- For Gemini API key, add a link to https://aistudio.google.com/u/1/api-keys with link text "Click here to get your API key".
- Add visual grouping of settings (for example with borders):
  - Core Settings
  - Deterministic Tests
  - SPF Tests
  - AI Tests
- Add a bottom section with links:
  - GitHub → https://github.com/rmaclean/osticket-spamblock
  - Report Issues → https://github.com/rmaclean/osticket-spamblock/issues
- Fix any spelling/grammar and unify text style.
