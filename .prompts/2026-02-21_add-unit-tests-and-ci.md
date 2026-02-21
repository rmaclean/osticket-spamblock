# 2026-02-21 — Add unit tests + CI requirement
User request:
- Add unit tests for the Spamblock plugin logic “blind” (assert expected inputs/outputs) to help uncover bugs.
- Cover edge cases: null headers, empty bodies, missing IP, invalid emails, etc.
- Use mocks/stubs for most tests, but include a small set of tests that hit real external endpoints.
- Make running/writing unit tests a requirement for all new work.

Work done:
- Added PHPUnit scaffolding (`composer.json`, `phpunit.xml`, `phpunit.integration.xml`) and a test bootstrap with minimal osTicket stubs.
- Refactored Postmark + StopForumSpam providers to use an injectable HTTP client so they can be unit-tested without real network calls.
- Added unit tests covering email context parsing, provider error paths, SPF evaluation, ticket filter creation, and ticket spam meta persistence.
- Added opt-in integration tests that hit Postmark Spamcheck + StopForumSpam endpoints when `SPAMBLOCK_RUN_INTEGRATION_TESTS=1` is set.
- Added local test runner scripts using a Docker Composer image (`scripts/test.sh`, `scripts/test-integration.sh`).
- Added CI workflow to run unit tests on PRs and pushes.
- Updated `AGENTS.md` to require tests for new work.
