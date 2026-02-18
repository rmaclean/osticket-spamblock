# spamblock (osTicket plugin)
A plugin for osTicket that spam-checks inbound email tickets and blocks them over a configurable score threshold.

## What it does
- Intercepts ticket creation for tickets created from email (via the `ticket.create.before` signal).
- Calls Postmark’s Spamcheck API (`https://spamcheck.postmarkapp.com/filter`).
- Logs every checked email with:
  - message-id (`mid`)
  - sender (`from`)
  - subject
  - spam score
  - whether it would be blocked
- Blocks tickets when `score >= min_block_score`.

## Configuration
In osTicket: Admin Panel → Manage → Plugins → Spamblock
- `Minimum spam score to block`

## How blocking works (implementation detail)
Spamblock sets two internal fields on inbound email ticket creation:
- `spamblock_score`
- `spamblock_should_block` (`0` or `1`)

On startup, Spamblock creates (or updates) an osTicket Ticket Filter named `Spamblock: block by score` that rejects tickets when `spamblock_should_block == 1`.

## Provider architecture (implementation detail)
Spamblock is structured to support multiple spam-check providers internally.
- Provider interface + Postmark implementation live in `plugin/spamblock/lib/spamcheck.php`.
- Providers are composed into a collection (currently just Postmark). In the future, additional providers can be added to the provider list without changing any UI.

## What’s in this repo
- `plugin/spamblock/`: plugin source code
- `docker/osticket/`: a Dockerfile that builds an osTicket container for local testing
- `docker-compose.yml`: osTicket + MariaDB stack for local development
- `.prompts/`: prompt history for changes made to this repo

## Quickstart (local dev)
1. Start the stack:
   - `docker compose up --build`
2. Open the installer:
   - `http://localhost:8080/setup/`
3. Use these DB values in the installer:
   - MySQL Hostname: `db`
   - MySQL Database: `osticket`
   - MySQL Username: `osticket`
   - MySQL Password: `osticket`

## Plugin development workflow (high level)
- Develop the plugin in `plugin/spamblock/`.
- The `./plugin` folder is bind-mounted into the osTicket container at `include/plugins/`.
- Enable/configure the plugin in osTicket via Admin Panel → Manage → Plugins.

## Notes
- Local osTicket config is stored in `.osticket/` and is intentionally ignored by git.
- This is a development setup; hardening (locking down `setup/`, file permissions, production mail, etc.) comes later.

## License
This project is licensed under the **Say Thanks License**.
If you find this useful, [click here to say thanks!](https://saythanks.io/to/rmaclean)