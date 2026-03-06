# 2026-03-06 Gemini check implementation

## Prompt

lets add the code now for, the check. I would like the gemini aspects (like the call to the API) to be in a seperate file so it is nice and clean.

In terms of the request to gemini, I want to set the system prompt to include persona, task, guidelines, reasoning requirement, and JSON-only output.

Use fields from config for the business and classification guidance, pass the full email as the prompt input, and enforce structured output:
{"spam": boolean, "reasoning": string}

Use model gemini-3-flash-preview with high thinking.

Add robust JSON/type safety checks and show reasoning in logs and in the spam popup dialog.
