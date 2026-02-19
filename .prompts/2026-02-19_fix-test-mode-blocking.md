# 2026-02-19 Fix Test Mode blocking

## Prompt

I have enabled test mode on the test server (see docker-compose.yml ) and tried to send a message
and it was blocked. in test mode it should not be blocked?
this seems to be a bug

Also in the logs I do not see the log entry to tell us it was blocked. I see the "Ticket denied" log from OSTicket but I expected to see our warning level one
