<?php

require_once INCLUDE_DIR . 'class.plugin.php';
require_once INCLUDE_DIR . 'class.signal.php';

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/spamcheck.php';
require_once __DIR__ . '/lib/ticket_filter.php';
require_once __DIR__ . '/lib/ticket_spam_meta.php';

class SpamblockPlugin extends Plugin
{
    var $config_class = 'SpamblockConfig';

    private $spamChecker;
    private $recentChecks = [];
    private $spamblockConfig;

    private function getSpamblockConfig()
    {
        if (isset($this->spamblockConfig) && $this->spamblockConfig instanceof SpamblockConfig) {
            return $this->spamblockConfig;
        }

        $cfg = $this->getConfig();
        if ($cfg instanceof SpamblockConfig) {
            $this->spamblockConfig = $cfg;
        }

        $pluginId = (int) $this->getId();
        if (!$pluginId) {
            return $this->spamblockConfig;
        }

        $instanceId = null;

        $sql = sprintf(
            'SELECT id FROM %s WHERE plugin_id=%s AND (flags & 1) = 1 ORDER BY id LIMIT 1',
            PLUGIN_INSTANCE_TABLE,
            db_input($pluginId)
        );

        if (($res = db_query($sql)) && db_num_rows($res)) {
            $row = db_fetch_row($res);
            $instanceId = isset($row[0]) ? (int) $row[0] : null;
        }

        if ($instanceId) {
            $this->spamblockConfig = new SpamblockConfig(
                sprintf('plugin.%d.instance.%d', $pluginId, $instanceId)
            );
        }

        return $this->spamblockConfig;
    }

    public function isMultiInstance()
    {
        return false;
    }

    public function bootstrap()
    {
        SpamblockTicketFilter::registerMatchFields();
        SpamblockTicketFilter::ensureBlockingFilterExists();
        SpamblockTicketSpamMeta::autoCreateTable();

        Signal::connect('ticket.create.before', [$this, 'onTicketCreateBefore']);
        Signal::connect('ticket.created', [$this, 'onTicketCreated']);

        Signal::connect('ticket.view.more', [$this, 'onTicketViewMore']);
        Signal::connect('ajax.scp', [$this, 'onAjaxScp']);
    }

    public function enable()
    {
        SpamblockTicketSpamMeta::autoCreateTable();
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

        $config = $this->getSpamblockConfig();

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
            $warnTitle = $testMode
                ? 'Spamblock - Would have blocked Email'
                : 'Spamblock - Blocked Email';

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

                    $ost->logWarning($warnTitle, $msg, true);
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

                    $ost->logWarning($warnTitle, $msg, true);
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

        $postmark = $check['postmark'] ?? null;
        $sfs = $check['sfs'] ?? null;

        $postmarkScore = (is_array($postmark) && array_key_exists('score', $postmark))
            ? $postmark['score']
            : null;

        $sfsConfidence = (is_array($sfs) && array_key_exists('confidence', $sfs))
            ? $sfs['confidence']
            : null;

        $wouldBlock = !empty($check['wouldBlock']);

        if (method_exists($ticket, 'getId') && method_exists($ticket, 'getEmail')) {
            SpamblockTicketSpamMeta::upsert(
                $ticket->getId(),
                $ticket->getEmail(),
                $wouldBlock,
                $postmarkScore,
                $sfsConfidence
            );
        }

        if ($ost && method_exists($ticket, 'getNumber')) {
            $ost->logDebug(
                'Spamblock - Postmark',
                sprintf(
                    'ticket=%s mid=%s score=%s should_block=%s',
                    $ticket->getNumber(),
                    $mid,
                    $postmarkScore !== null ? $postmarkScore : 'n/a',
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
                    $sfsConfidence !== null ? $sfsConfidence : 'n/a',
                    (is_array($sfs) && !empty($sfs['shouldBlock']))
                        ? '1'
                        : '0'
                ),
                true
            );
        }
    }

    public function onTicketViewMore($ticket, &$extras)
    {
        if (!is_object($ticket) || !method_exists($ticket, 'getId')) {
            return;
        }

        $meta = SpamblockTicketSpamMeta::lookup($ticket->getId());
        $isSpam = $meta ? (bool) $meta['is_spam'] : false;

        echo sprintf('<li><a href="#%s"', 'ajax.php/spamblock/ticket/' . $ticket->getId() . '/details');
        echo 'onclick="javascript: $.dialog($(this).attr(\'href\').substr(1), 201); return false;"';
        echo '><i class="icon-info-sign"></i>';
        echo __('Spamblock');
        echo '</a></li>';

        $href = 'ajax.php/spamblock/ticket/' . $ticket->getId() . '/details';

        $label = $isSpam ? __('Yes') : __('No');
        $rowHtml = sprintf(
            '<tr id="spamblock-is-spam-row"><th>%s:</th><td><a id="spamblock-is-spam" href="#%s">%s</a></td></tr>',
            __('Is Spam?'),
            $href,
            Format::htmlchars($label)
        );

        $script = sprintf(
            '<script>$(function(){'
            . 'if ($("#spamblock-is-spam-row").length) return;'
            . 'var $tbl = $(".ticket_info td:first table");'
            . 'if (!$tbl.length) return;'
            . 'var $rows = $tbl.find("tr");'
            . 'if (!$rows.length) return;'
            . 'var row = %s;'
            . '$(row).insertBefore($rows.last());'
            . '$("#spamblock-is-spam").on("click", function(e){ e.preventDefault(); $.dialog($(this).attr("href").substr(1), 201); return false; });'
            . '});</script>',
            JsonDataEncoder::encode($rowHtml)
        );

        echo $script;
    }

    public function onAjaxScp($dispatcher)
    {
        $dispatcher->append(
            url_get('^/spamblock/ticket/(?P<id>\\d+)/details$', function ($ticketId) {
                global $thisstaff;

                if (!$thisstaff)
                    Http::response(403, 'Agent login is required');

                if (!($ticket = Ticket::lookup($ticketId)))
                    Http::response(404, 'No such ticket');

                if (!$ticket->checkStaffPerm($thisstaff))
                    Http::response(403, 'Access denied');

                $spamblockMeta = SpamblockTicketSpamMeta::lookup($ticketId);
                include __DIR__ . '/templates/ticket-spamblock.tmpl.php';
            })
        );

        $dispatcher->append(
            url('^/spamblock/ticket/(?P<id>\\d+)/mark-spam$', function ($ticketId) {
                global $thisstaff, $ost;

                if ($_SERVER['REQUEST_METHOD'] !== 'POST')
                    Http::response(405, 'Method Not Allowed');

                if (!$thisstaff)
                    Http::response(403, 'Agent login is required');

                if (!($ticket = Ticket::lookup($ticketId)))
                    Http::response(404, 'No such ticket');

                if (!$ticket->checkStaffPerm($thisstaff, Ticket::PERM_DELETE))
                    Http::response(403, 'Insufficient permissions');

                if (!$thisstaff->hasPerm(Email::PERM_BANLIST))
                    Http::response(403, 'Insufficient permissions');

                if ($ost && $ost->getCSRF()) {
                    $token = isset($_POST['__CSRFToken__']) ? (string) $_POST['__CSRFToken__'] : '';
                    if (!$ost->getCSRF()->validateToken($token))
                        Http::response(403, 'Invalid CSRF token');
                }

                require_once INCLUDE_DIR . 'class.banlist.php';

                $email = method_exists($ticket, 'getEmail') ? (string) $ticket->getEmail() : '';
                if ($email !== '') {
                    Banlist::add($email);
                }

                $ticket->delete('Spamblock: marked as spam');

                Http::response(200, 'OK');
            })
        );
    }
}
