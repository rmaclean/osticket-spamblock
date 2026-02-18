<?php

require_once INCLUDE_DIR . 'class.plugin.php';
require_once INCLUDE_DIR . 'class.signal.php';

class SpamblockPlugin extends Plugin
{
    public function bootstrap()
    {
        Signal::connect('ticket.created', [$this, 'onTicketCreated']);
    }

    public function onTicketCreated($ticket)
    {
        if (is_object($ticket) && method_exists($ticket, 'getNumber')) {
            $number = $ticket->getNumber();
            error_log("spamblock: hello world (ticket.created #{$number})");
            return;
        }

        error_log('spamblock: hello world (ticket.created)');
    }
}
