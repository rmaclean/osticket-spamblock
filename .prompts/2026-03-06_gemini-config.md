# 2026-03-06 Gemini config

## Prompt

I want to add a new check to the system. It will make a call to Gemini and ask the LLM to check if it is spam. To support this we need to add a bunch of new config
1. A switch to turn on/off this check
2. A switch that if it detects spam, what it does (same as others)
3. An API key field
4. A text field for description of the company of the ticket system (i.e. so they can explain what the system should be ok with)
5. A text field for guidelines for spam
6. A text field for guidelines for legitimate fields

If 1 is turned off, then all should be disabled.

While doing this, have a look at the whole config section to see if we can improve/clean it up to make to increase the UX

I would like to pre-populate some fields which can be overridden
