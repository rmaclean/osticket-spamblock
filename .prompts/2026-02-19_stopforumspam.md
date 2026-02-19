# 2026-02-19 StopForumSpam provider

## Prompt

lets further enhance this plugin. I want to add support for api.stopforumspam.org to it. Docs for it are at: https://www.stopforumspam.com/usage

As with the previous tool, it should be built seperate and added into the collection of tools (in later work we will be making it possible to enable/disable these). It will need its own config setting - Lets call it SFS Minimum Confidence which is a percentage which is used to compare to the score from the tool

We want to send the email address and IP address to the SFS api

Again, we need logging for this where it logs seperately to the previous check - I think therefore it will make sense to have the Log title for the previous check be renamed from "Spamblock" to "Spamblock - Postmark" and the log entries for this to be "Spamblock - SFS". They can be kept at a debug level.
