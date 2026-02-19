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
                new SpamblockStopForumSpamProvider(),
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

        $minSfsConfidence = ($config instanceof SpamblockConfig)
            ? $config->getSfsMinConfidence()
            : 90.0;

        $testMode = ($config instanceof SpamblockConfig)
            ? $config->getTestMode()
            : false;

        $context = SpamblockEmailContext::fromTicketVars($vars);
        $results = $this->getSpamChecker()->check($context);

        $byProvider = [];
        foreach ($results as $r) {
            $byProvider[$r->getProvider()] = $r;
        }

        $postmark = $byProvider['postmark'] ?? null;
        $postmarkScore = $postmark ? $postmark->getScore() : null;
        $postmarkShouldBlock = ($postmarkScore !== null && $postmarkScore >= $minScoreToBlock);

        $sfs = $byProvider['sfs'] ?? null;
        $sfsConfidence = $sfs ? $sfs->getScore() : null;
        $sfsShouldBlock = ($sfsConfidence !== null && $sfsConfidence >= $minSfsConfidence);

        $wouldBlock = ($postmarkShouldBlock || $sfsShouldBlock);
        $shouldBlock = $testMode ? false : $wouldBlock;

        $triggered = [];
        if ($postmarkShouldBlock) {
            $triggered[] = 'postmark';
        }
        if ($sfsShouldBlock) {
            $triggered[] = 'sfs';
        }

        if ($ost && $triggered) {
            foreach ($triggered as $t) {
                if ($t === 'postmark') {
                    $msg = sprintf(
                        'email=%s system=%s score=%s',
                        $context->getFromEmail(),
                        'Spamcheck',
                        ($postmarkScore !== null) ? $postmarkScore : 'n/a'
                    );

                    if ($testMode) {
                        $msg .= ' test_mode=1';
                    }

                    $ost->logWarning('Spamblock - Blocked Email', $msg, true);
                }

                if ($t === 'sfs') {
                    $msg = sprintf(
                        'email=%s system=%s score=%s',
                        $context->getFromEmail(),
                        'SFS',
                        ($sfsConfidence !== null) ? $sfsConfidence : 'n/a'
                    );

                    if ($testMode) {
                        $msg .= ' test_mode=1';
                    }

                    $ost->logWarning('Spamblock - Blocked Email', $msg, true);
                }
            }
        }

        $providerTag = $triggered
            ? implode(',', $triggered)
            : implode(',', array_keys($byProvider));

        $vars['spamblock_provider'] = $providerTag;
        $vars['spamblock_score'] = ($postmarkScore !== null) ? (string) $postmarkScore : '';
        $vars['spamblock_should_block'] = $shouldBlock ? '1' : '0';

        $this->recentChecks[$context->getMid()] = [
            'provider' => $vars['spamblock_provider'],
            'testMode' => $testMode,
            'wouldBlock' => $wouldBlock,
            'shouldBlock' => $shouldBlock,
            'postmark' => [
                'score' => $postmarkScore,
                'minScoreToBlock' => $minScoreToBlock,
                'shouldBlock' => $postmarkShouldBlock,
                'statusCode' => $postmark ? $postmark->getStatusCode() : null,
                'error' => $postmark ? $postmark->getError() : null,
            ],
            'sfs' => [
                'confidence' => $sfsConfidence,
                'minConfidence' => $minSfsConfidence,
                'shouldBlock' => $sfsShouldBlock,
                'statusCode' => $sfs ? $sfs->getStatusCode() : null,
                'error' => $sfs ? $sfs->getError() : null,
                'data' => $sfs ? $sfs->getData() : [],
            ],
        ];

        if ($ost) {
            $postmarkMsg = sprintf(
                'mid=%s from=%s subject=%s score=%s min_block_score=%s should_block=%s',
                $context->getMid(),
                $context->getFromEmail(),
                $context->getSubject(),
                ($postmarkScore !== null) ? $postmarkScore : 'n/a',
                $minScoreToBlock,
                $postmarkShouldBlock ? '1' : '0'
            );

            if ($postmark && $postmark->getError()) {
                $status = $postmark->getStatusCode();
                $postmarkMsg .= sprintf(
                    "\nerror=%s",
                    $status ? sprintf('status=%s %s', $status, $postmark->getError()) : $postmark->getError()
                );
            }

            $ost->logDebug('Spamblock - Postmark', $postmarkMsg, true);

            $sfsData = $sfs ? $sfs->getData() : [];
            $sfsMsg = sprintf(
                'mid=%s from=%s ip=%s confidence=%s min_confidence=%s should_block=%s email_confidence=%s ip_confidence=%s email_frequency=%s ip_frequency=%s',
                $context->getMid(),
                $context->getFromEmail(),
                $context->getIp() ?: 'n/a',
                ($sfsConfidence !== null) ? $sfsConfidence : 'n/a',
                $minSfsConfidence,
                $sfsShouldBlock ? '1' : '0',
                (array_key_exists('email_confidence', $sfsData) && $sfsData['email_confidence'] !== null)
                    ? $sfsData['email_confidence']
                    : 'n/a',
                (array_key_exists('ip_confidence', $sfsData) && $sfsData['ip_confidence'] !== null)
                    ? $sfsData['ip_confidence']
                    : 'n/a',
                (array_key_exists('email_frequency', $sfsData) && $sfsData['email_frequency'] !== null)
                    ? $sfsData['email_frequency']
                    : 'n/a',
                (array_key_exists('ip_frequency', $sfsData) && $sfsData['ip_frequency'] !== null)
                    ? $sfsData['ip_frequency']
                    : 'n/a'
            );

            if ($sfs && $sfs->getError()) {
                $status = $sfs->getStatusCode();
                $sfsMsg .= sprintf(
                    "\nerror=%s",
                    $status ? sprintf('status=%s %s', $status, $sfs->getError()) : $sfs->getError()
                );
            }

            $ost->logDebug('Spamblock - SFS', $sfsMsg, true);
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
            $postmark = $check['postmark'] ?? null;
            $sfs = $check['sfs'] ?? null;

            $ost->logDebug(
                'Spamblock - Postmark',
                sprintf(
                    'ticket=%s mid=%s score=%s should_block=%s',
                    $ticket->getNumber(),
                    $mid,
                    (is_array($postmark) && array_key_exists('score', $postmark) && $postmark['score'] !== null)
                        ? $postmark['score']
                        : 'n/a',
                    (is_array($postmark) && !empty($postmark['shouldBlock']))
                        ? '1'
                        : '0'
                ),
                true
            );

            $ost->logDebug(
                'Spamblock - SFS',
                sprintf(
                    'ticket=%s mid=%s confidence=%s should_block=%s',
                    $ticket->getNumber(),
                    $mid,
                    (is_array($sfs) && array_key_exists('confidence', $sfs) && $sfs['confidence'] !== null)
                        ? $sfs['confidence']
                        : 'n/a',
                    (is_array($sfs) && !empty($sfs['shouldBlock']))
                        ? '1'
                        : '0'
                ),
                true
            );
        }
    }
}
