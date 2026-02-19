# 2026-02-19 Test Mode + warn logs

## Prompt

now I want to add a checkbox to the config called Test Mode
When this is checked, we do not block anything.
To make this valuable, I want to add an additional log item of warn level for anything blocked. This logging should happen in test mode and in normal usage. The log title can be called "Spamblock - Blocked Email". In it should have the email address and the system which triggered the block (SFS or Spamcheck) and the score it got. The previous logs at debug level are useful for debugging but not too useful for end users and happy they kept at that

The core idea for me is to allow a user to configure the min scores correctly but not actually impact incoming - then they can monitor the logs to see what they would do.

I would also like to add this to the README.md.
