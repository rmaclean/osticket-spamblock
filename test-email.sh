#!/usr/bin/env bash

set -euo pipefail

usage() {
  echo "usage: $(basename "$0") path/to/email.eml" >&2
}

if [[ $# -ne 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  exit 2
fi

EML_PATH="$1"
if [[ ! -f "$EML_PATH" ]]; then
  echo "error: file not found: $EML_PATH" >&2
  exit 2
fi

rand_id() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen | tr '[:upper:]' '[:lower:]'
    return
  fi

  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 16
    return
  fi

  date +%s
}

MSG_ID="<spamblock-test-$(rand_id)@spamblock.test>"
echo "message-id: $MSG_ID" >&2

inject_message_id() {
  awk -v mid="$MSG_ID" '
    BEGIN { in_headers = 1; replaced = 0 }
    {
      if (in_headers == 1) {
        line = $0
        lower = tolower(line)

        if (lower ~ /^message-id:[[:space:]]*/) {
          print "Message-ID: " mid
          replaced = 1
          next
        }

        if (line == "") {
          if (replaced == 0) {
            print "Message-ID: " mid
          }
          print ""
          in_headers = 0
          next
        }
      }

      print $0
    }
    END {
      if (in_headers == 1) {
        if (replaced == 0) {
          print "Message-ID: " mid
        }
        print ""
      }
    }
  ' "$EML_PATH"
}

set +e
inject_message_id | docker compose exec -T osticket php -d display_errors=1 -d error_reporting=E_ALL -r 'chdir("/var/www/html/api"); require "api.inc.php"; require_once(INCLUDE_DIR . "api.tickets.php"); $raw = stream_get_contents(STDIN); $api = new TicketApiController("cli"); try { $res = $api->processEmail($raw); if (is_object($res) && method_exists($res, "getNumber")) { fwrite(STDOUT, "CREATED ticket=" . $res->getNumber() . PHP_EOL); exit(0); } fwrite(STDOUT, "OK (processed, non-ticket result)" . PHP_EOL); exit(0); } catch (TicketDenied $e) { fwrite(STDOUT, "DENIED (blocked/rejected)" . PHP_EOL); exit(2); }'
exit_code=$?
set -e

if [[ $exit_code -ne 0 && $exit_code -ne 2 ]]; then
  echo "error: docker/php execution failed (exit_code=$exit_code)" >&2
fi

exit "$exit_code"
