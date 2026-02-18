<?php

require_once INCLUDE_DIR . 'class.plugin.php';
require_once INCLUDE_DIR . 'class.signal.php';

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/spamcheck.php';
require_once __DIR__ . '/lib/ticket_filter.php';

class SpamblockPlugin extends Plugin
{
    var $config_class = 'SpamblockConfig';

    private $spamChecker;
    private $recentChecks = [];

    public function isMultiInstance()
    {
        return false;
    }

    public function bootstrap()
    {
        SpamblockTicketFilter::registerMatchFields();
        SpamblockTicketFilter::ensureBlockingFilterExists();

        Signal::connect('ticket.create.before', [$this, 'onTicketCreateBefore']);
        Signal::connect('ticket.created', [$this, 'onTicketCreated']);
    }

    private function getSpamChecker()
    {
        if (!isset($this->spamChecker)) {
            $this->spamChecker = new SpamblockSpamChecker([
                new SpamblockPostmarkSpamCheckProvider(),
            ]);
        }

        return $this->spamChecker;
    }

    public function onTicketCreateBefore($object, &$vars)
    {
        if (!is_array($vars)) {
            return;
        }

        if (empty($vars['emailId']) || empty($vars['mid']) || empty($vars['header'])) {
            return;
        }

        global $ost;

        $config = $this->getConfig();
        $minScoreToBlock = ($config instanceof SpamblockConfig)
            ? $config->getMinBlockScore()
            : 5.0;

        $context = SpamblockEmailContext::fromTicketVars($vars);
        $results = $this->getSpamChecker()->check($context);

        $best = null;
        foreach ($results as $r) {
            if ($r->getScore() === null) {
                continue;
            }

            if ($best === null || $r->getScore() > $best->getScore()) {
                $best = $r;
            }
        }

        $score = $best ? $best->getScore() : null;
        $provider = $best ? $best->getProvider() : null;

        $shouldBlock = ($score !== null && $score >= $minScoreToBlock);

        $vars['spamblock_provider'] = $provider ?: '';
        $vars['spamblock_score'] = ($score !== null) ? (string) $score : '';
        $vars['spamblock_should_block'] = $shouldBlock ? '1' : '0';

        $this->recentChecks[$context->getMid()] = [
            'provider' => $vars['spamblock_provider'],
            'score' => $score,
            'minScoreToBlock' => $minScoreToBlock,
            'shouldBlock' => $shouldBlock,
        ];

        if ($ost) {
            $msg = sprintf(
                'mid=%s from=%s subject=%s score=%s min_block_score=%s should_block=%s provider=%s',
                $context->getMid(),
                $context->getFromEmail(),
                $context->getSubject(),
                ($score !== null) ? $score : 'n/a',
                $minScoreToBlock,
                $shouldBlock ? '1' : '0',
                $provider ?: 'n/a'
            );

            $errorBits = array_filter(array_map(function ($r) {
                $err = $r->getError();
                if (!$err) {
                    return null;
                }

                $status = $r->getStatusCode();
                if ($status) {
                    return sprintf('%s(status=%s): %s', $r->getProvider(), $status, $err);
                }

                return sprintf('%s: %s', $r->getProvider(), $err);
            }, $results));

            if ($errorBits) {
                $msg .= '\nerrors=' . implode('; ', $errorBits);
            }

            $ost->logDebug('Spamblock', $msg, true);
        }
    }

    public function onTicketCreated($ticket)
    {
        if (!is_object($ticket) || !method_exists($ticket, 'getLastMessage')) {
            return;
        }

        global $ost;

        $last = $ticket->getLastMessage();
        if (!is_object($last) || !method_exists($last, 'getEmailMessageId')) {
            return;
        }

        $mid = $last->getEmailMessageId();
        if (!$mid || !isset($this->recentChecks[$mid])) {
            return;
        }

        $check = $this->recentChecks[$mid];
        unset($this->recentChecks[$mid]);

        if ($ost && method_exists($ticket, 'getNumber')) {
            $ost->logDebug(
                'Spamblock',
                sprintf(
                    'ticket=%s mid=%s score=%s should_block=%s provider=%s',
                    $ticket->getNumber(),
                    $mid,
                    $check['score'] !== null ? $check['score'] : 'n/a',
                    $check['shouldBlock'] ? '1' : '0',
                    $check['provider'] ?: 'n/a'
                ),
                true
            );
        }
    }
}
