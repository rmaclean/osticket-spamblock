# spamblock (osTicket plugin)
A plugin for osTicket that will run a spam check for any newly-created ticket.

## What’s in this repo
- `plugin/spamblock/`: plugin source code (empty scaffold for now)
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
