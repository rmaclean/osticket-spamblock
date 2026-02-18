# AGENTS
This repository is for an osTicket plugin named `spamblock`.

## Goals
- Build an osTicket plugin that performs spam checks on newly-created tickets.
- Keep local development reproducible via Docker.

## Repository layout
- `plugin/spamblock/`: plugin source (eventually packaged as a `.phar`, but can be developed as a folder)
- `docker/osticket/`: Docker build context for a local osTicket instance
- `.prompts/`: a running log of prompts used to drive changes in this repo (always add a new entry for each prompt that results in code/content changes)
- `.osticket/`: local-only (ignored by git) runtime state such as `include/ost-config.php`

## Local development
- Use `docker compose up --build` and browse `http://localhost:8080`.
- First-time setup runs through the osTicket web installer at `http://localhost:8080/setup/`.

## Coding standards / conventions
- Prefer modern JS syntax when any JS is required.
- Do not add comments unless they explain non-obvious logic.
- If UI/CSS is added, use CSS Grid (do not use flexbox).
- Avoid committing secrets; prefer environment variables and `.env` files (which should be gitignored).

## osTicket plugin notes
- osTicket discovers plugins from `include/plugins/`.
- A plugin can be a directory (during development) or a `.phar` (for distribution).
- Plugins are configured/enabled via the Admin Panel: Manage → Plugins.
