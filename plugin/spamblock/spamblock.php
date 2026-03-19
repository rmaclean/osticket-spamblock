<?php

require_once INCLUDE_DIR . 'class.plugin.php';
require_once INCLUDE_DIR . 'class.signal.php';

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/lib/spamcheck.php';
require_once __DIR__ . '/lib/geminicheck.php';
require_once __DIR__ . '/lib/spfcheck.php';
require_once __DIR__ . '/lib/ticket_filter.php';
require_once __DIR__ . '/lib/ticket_spam_meta.php';

class SpamblockPlugin extends Plugin
{
    var $config_class = 'SpamblockConfig';

    private $spamChecker;
    private $spamCheckerHasSpf = false;
    private $spamCheckerHasGemini = false;
    private $spamCheckerGeminiConfigHash = '';
    private $recentChecks = [];
    private $spamblockConfig;

    private function logAtLevel($ost, $level, $title, $message)
    {
        if (!$ost) {
            return;
        }

        $level = strtolower(trim((string) $level));

        if ($level === 'debug' && method_exists($ost, 'logDebug')) {
            $ost->logDebug($title, $message, true);
            return;
        }

        if ($level === 'error' && method_exists($ost, 'logError')) {
            $ost->logError($title, $message, true);
            return;
        }

        if (method_exists($ost, 'logWarning')) {
            $ost->logWarning($title, $message, true);
        }
    }

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

    private function getSpamChecker($config = null, $includeSpf = null)
    {
        $wantSpf = ($config instanceof SpamblockConfig) ? $config->isSpfEnabled() : false;
        if ($includeSpf === false) {
            $wantSpf = false;
        }
        $wantGemini = ($config instanceof SpamblockConfig)
            ? ($config->isGeminiEnabled() && $config->getGeminiApiKey() !== '')
            : false;

        $geminiHash = '';
        if ($wantGemini && $config instanceof SpamblockConfig) {
            $geminiHash = md5((string) json_encode([
                $config->getGeminiApiKey(),
                $config->getGeminiCompanyDescription(),
                $config->getGeminiSpamGuidelines(),
                $config->getGeminiLegitimateGuidelines(),
            ]));
        }

        if (
            !isset($this->spamChecker)
            || $this->spamCheckerHasSpf !== $wantSpf
            || $this->spamCheckerHasGemini !== $wantGemini
            || $this->spamCheckerGeminiConfigHash !== $geminiHash
        ) {
            $providers = [
                new SpamblockPostmarkSpamCheckProvider(),
                new SpamblockStopForumSpamProvider(),
            ];

            if ($wantSpf) {
                $providers[] = new SpamblockSpfCheckProvider();
            }
            if ($wantGemini && $config instanceof SpamblockConfig) {
                $providers[] = new SpamblockGeminiSpamCheckProvider(
                    $config->getGeminiApiKey(),
                    $config->getGeminiCompanyDescription(),
                    $config->getGeminiSpamGuidelines(),
                    $config->getGeminiLegitimateGuidelines()
                );
            }

            $this->spamChecker = new SpamblockSpamChecker($providers);
            $this->spamCheckerHasSpf = $wantSpf;
            $this->spamCheckerHasGemini = $wantGemini;
            $this->spamCheckerGeminiConfigHash = $geminiHash;
        }

        return $this->spamChecker;
    }

    private function isEmailInSystemBanList($email)
    {
        $email = trim((string) $email);
        if ($email === '') {
            return false;
        }

        require_once INCLUDE_DIR . 'class.banlist.php';

        return (bool) Banlist::isBanned($email);
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

        $blockedEmailLogLevel = ($config instanceof SpamblockConfig)
            ? $config->getBlockedEmailLogLevel()
            : 'warning';
        $esmtpsaBypassEnabled = ($config instanceof SpamblockConfig)
            ? $config->isEsmtpsaBypassEnabled()
            : true;

        $spfFailAction = ($config instanceof SpamblockConfig)
            ? $config->getSpfFailAction()
            : 'ignore';

        $spfNoneAction = ($config instanceof SpamblockConfig)
            ? $config->getSpfNoneAction()
            : 'ignore';

        $spfInvalidAction = ($config instanceof SpamblockConfig)
            ? $config->getSpfInvalidAction()
            : 'ignore';

        $spfUnsupportedMechanismAction = ($config instanceof SpamblockConfig)
            ? $config->getSpfUnsupportedMechanismAction()
            : 'ignore';
        $geminiAction = ($config instanceof SpamblockConfig)
            ? $config->getGeminiAction()
            : 'ignore';

        $context = SpamblockEmailContext::fromTicketVars($vars);
        if ($this->isEmailInSystemBanList($context->getFromEmail())) {
            if ($ost && method_exists($ost, 'logDebug')) {
                $ost->logDebug(
                    'Spamblock - Skipped Checks',
                    sprintf(
                        'email=%s mid=%s reason=system_ban_list',
                        $context->getFromEmail(),
                        $context->getMid()
                    ),
                    true
                );
            }
            return;
        }

        if ($esmtpsaBypassEnabled && $context->isAuthenticatedSubmission()) {
            $vars['spamblock_provider'] = 'esmtpsa';
            $vars['spamblock_score'] = '';
            $vars['spamblock_should_block'] = '0';

            if ($ost && method_exists($ost, 'logDebug')) {
                $ost->logDebug(
                    'Spamblock - Skipped Checks',
                    sprintf(
                        'email=%s mid=%s reason=esmtpsa_bypass ip=%s envelope_from=%s',
                        $context->getFromEmail(),
                        $context->getMid(),
                        $context->getIp() ?: 'n/a',
                        $context->getEnvelopeFromEmail() ?: 'n/a'
                    ),
                    true
                );
            }

            return;
        }

        $includeSpf = ($config instanceof SpamblockConfig)
            ? ($config->isSpfEnabled() && $context->getIp() !== '')
            : false;

        $results = $this->getSpamChecker($config, $includeSpf)->check($context);

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

        $spf = $byProvider['spf'] ?? null;
        $spfData = $spf ? $spf->getData() : [];
        $spfResult = isset($spfData['result']) ? (string) $spfData['result'] : null;
        $spfShouldBlock = false;

        if ($spfResult === 'fail') {
            $spfShouldBlock = $spfFailAction === 'spam';
        } elseif ($spfResult === 'none') {
            $spfShouldBlock = $spfNoneAction === 'spam';
        } elseif ($spfResult === 'invalid') {
            $spfShouldBlock = $spfInvalidAction === 'spam';
        } elseif ($spfResult === 'unsupported') {
            $spfShouldBlock = $spfUnsupportedMechanismAction === 'spam';
        }
        $gemini = $byProvider['gemini'] ?? null;
        $geminiData = $gemini ? $gemini->getData() : [];
        $geminiSpam = (is_array($geminiData) && array_key_exists('spam', $geminiData) && is_bool($geminiData['spam']))
            ? (bool) $geminiData['spam']
            : null;
        $geminiReasoning = (is_array($geminiData) && array_key_exists('reasoning', $geminiData) && is_string($geminiData['reasoning']))
            ? trim((string) $geminiData['reasoning'])
            : null;
        $geminiShouldBlock = ($geminiSpam === true && $geminiAction === 'spam');

        $wouldBlock = ($postmarkShouldBlock || $sfsShouldBlock || $spfShouldBlock || $geminiShouldBlock);
        $shouldBlock = $testMode ? false : $wouldBlock;

        $triggered = [];
        if ($postmarkShouldBlock) {
            $triggered[] = 'postmark';
        }
        if ($sfsShouldBlock) {
            $triggered[] = 'sfs';
        }
        if ($spfShouldBlock) {
            $triggered[] = 'spf';
        }
        if ($geminiShouldBlock) {
            $triggered[] = 'gemini';
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

                    $this->logAtLevel($ost, $blockedEmailLogLevel, $warnTitle, $msg);
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

                    $this->logAtLevel($ost, $blockedEmailLogLevel, $warnTitle, $msg);
                }

                if ($t === 'spf') {
                    $spfIp = isset($spfData['ip']) && $spfData['ip'] ? (string) $spfData['ip'] : ($context->getIp() ?: 'n/a');
                    $msg = sprintf(
                        'email=%s system=%s score=%s domain=%s ip=%s',
                        $context->getFromEmail(),
                        'SPF',
                        $spfResult !== null ? $spfResult : 'n/a',
                        isset($spfData['domain']) ? (string) $spfData['domain'] : 'n/a',
                        $spfIp
                    );

                    if ($testMode) {
                        $msg .= ' test_mode=1';
                    }

                    $this->logAtLevel($ost, $blockedEmailLogLevel, $warnTitle, $msg);
                }

                if ($t === 'gemini') {
                    $msg = sprintf(
                        'email=%s system=%s score=%s reasoning=%s',
                        $context->getFromEmail(),
                        'Gemini',
                        $geminiSpam === null ? 'n/a' : ($geminiSpam ? 'spam' : 'legitimate'),
                        $geminiReasoning !== null && $geminiReasoning !== '' ? $geminiReasoning : 'n/a'
                    );

                    if ($testMode) {
                        $msg .= ' test_mode=1';
                    }

                    $this->logAtLevel($ost, $blockedEmailLogLevel, $warnTitle, $msg);
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
                'data' => $postmark ? $postmark->getData() : [],
            ],
            'sfs' => [
                'confidence' => $sfsConfidence,
                'minConfidence' => $minSfsConfidence,
                'shouldBlock' => $sfsShouldBlock,
                'statusCode' => $sfs ? $sfs->getStatusCode() : null,
                'error' => $sfs ? $sfs->getError() : null,
                'data' => $sfs ? $sfs->getData() : [],
            ],
            'spf' => $spf
                ? [
                    'result' => $spfResult,
                    'shouldBlock' => $spfShouldBlock,
                    'statusCode' => $spf->getStatusCode(),
                    'error' => $spf->getError(),
                    'data' => $spf->getData(),
                ]
                : null,
            'gemini' => $gemini
                ? [
                    'spam' => $geminiSpam,
                    'reasoning' => $geminiReasoning,
                    'shouldBlock' => $geminiShouldBlock,
                    'action' => $geminiAction,
                    'statusCode' => $gemini->getStatusCode(),
                    'error' => $gemini->getError(),
                    'data' => $gemini->getData(),
                ]
                : null,
        ];

        if ($ost) {
            $postmarkData = $postmark ? $postmark->getData() : [];
            $postmarkUrl = (is_array($postmarkData) && array_key_exists('url_called', $postmarkData) && $postmarkData['url_called'])
                ? (string) $postmarkData['url_called']
                : 'https://spamcheck.postmarkapp.com/filter';

            $postmarkMsg = sprintf(
                "url_called=%s\nmid=%s from=%s subject=%s\nscore=%s min_block_score=%s should_block=%s",
                $postmarkUrl,
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
            $sfsUrl = (array_key_exists('url_called', $sfsData) && $sfsData['url_called'])
                ? (string) $sfsData['url_called']
                : 'n/a';

            $sfsMsg = sprintf(
                "url_called=%s\nmid=%s from=%s ip=%s\nconfidence=%s min_confidence=%s should_block=%s email_confidence=%s ip_confidence=%s email_frequency=%s ip_frequency=%s",
                $sfsUrl,
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

            if ($spf) {
                $spfData = $spf->getData();

                $traceLines = [];
                if (isset($spfData['trace']) && is_array($spfData['trace'])) {
                    foreach ($spfData['trace'] as $tl) {
                        $tl = trim((string) $tl);
                        if ($tl !== '') {
                            $traceLines[] = '- ' . $tl;
                        }
                    }
                }

                $traceText = $traceLines ? ("\n" . implode("\n", $traceLines)) : '';
                $spfIp = isset($spfData['ip']) && $spfData['ip'] ? (string) $spfData['ip'] : ($context->getIp() ?: 'n/a');

                $spfMsg = sprintf(
                    "ip_used=%s\nmid=%s from=%s envelope_from=%s\nspf_result=%s spf_raw=%s source=%s should_block=%s\nfail_action=%s none_action=%s invalid_action=%s unsupported_mechanism_action=%s%s",
                    $spfIp,
                    $context->getMid(),
                    $context->getFromEmail(),
                    isset($spfData['envelope_from']) && $spfData['envelope_from'] ? (string) $spfData['envelope_from'] : 'n/a',
                    isset($spfData['result']) ? (string) $spfData['result'] : 'n/a',
                    isset($spfData['raw']) ? (string) $spfData['raw'] : 'n/a',
                    isset($spfData['source']) ? (string) $spfData['source'] : 'n/a',
                    $spfShouldBlock ? '1' : '0',
                    $spfFailAction,
                    $spfNoneAction,
                    $spfInvalidAction,
                    $spfUnsupportedMechanismAction,
                    $traceText
                );

                if ($spf->getError()) {
                    $status = $spf->getStatusCode();
                    $spfMsg .= sprintf(
                        "\nerror=%s",
                        $status ? sprintf('status=%s %s', $status, $spf->getError()) : $spf->getError()
                    );
                }

                $ost->logDebug('Spamblock - SPF', $spfMsg, true);
            }

            if ($gemini) {
                $geminiData = $gemini->getData();
                $geminiMsg = sprintf(
                    "url_called=%s\nmid=%s from=%s\nmodel=%s action=%s spam=%s should_block=%s\nreasoning=%s",
                    (is_array($geminiData) && array_key_exists('url_called', $geminiData) && $geminiData['url_called'])
                        ? (string) $geminiData['url_called']
                        : 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent',
                    $context->getMid(),
                    $context->getFromEmail(),
                    (is_array($geminiData) && array_key_exists('model', $geminiData) && $geminiData['model'])
                        ? (string) $geminiData['model']
                        : 'gemini-3-flash-preview',
                    $geminiAction,
                    $geminiSpam === null ? 'n/a' : ($geminiSpam ? 'true' : 'false'),
                    $geminiShouldBlock ? '1' : '0',
                    ($geminiReasoning !== null && $geminiReasoning !== '') ? $geminiReasoning : 'n/a'
                );

                if ($gemini->getError()) {
                    $status = $gemini->getStatusCode();
                    $geminiMsg .= sprintf(
                        "\nerror=%s",
                        $status ? sprintf('status=%s %s', $status, $gemini->getError()) : $gemini->getError()
                    );
                }

                $ost->logDebug('Spamblock - Gemini', $geminiMsg, true);
            }
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
        $spf = $check['spf'] ?? null;
        $gemini = $check['gemini'] ?? null;

        $postmarkScore = (is_array($postmark) && array_key_exists('score', $postmark))
            ? $postmark['score']
            : null;

        $sfsConfidence = (is_array($sfs) && array_key_exists('confidence', $sfs))
            ? $sfs['confidence']
            : null;

        $spfResult = (is_array($spf) && array_key_exists('result', $spf))
            ? (string) $spf['result']
            : null;
        $geminiReasoning = (is_array($gemini) && array_key_exists('reasoning', $gemini))
            ? (string) $gemini['reasoning']
            : null;

        $wouldBlock = !empty($check['wouldBlock']);

        if (method_exists($ticket, 'getId') && method_exists($ticket, 'getEmail')) {
            SpamblockTicketSpamMeta::upsert(
                $ticket->getId(),
                $ticket->getEmail(),
                $wouldBlock,
                $postmarkScore,
                $sfsConfidence,
                $spfResult,
                $geminiReasoning
            );
        }

        if ($ost && method_exists($ticket, 'getNumber')) {
            $ticketNumber = $ticket->getNumber();

            $postmarkData = is_array($postmark) && array_key_exists('data', $postmark) && is_array($postmark['data'])
                ? $postmark['data']
                : [];
            $postmarkUrl = (array_key_exists('url_called', $postmarkData) && $postmarkData['url_called'])
                ? (string) $postmarkData['url_called']
                : 'https://spamcheck.postmarkapp.com/filter';

            $postmarkMsg = sprintf(
                "url_called=%s\nticket=%s mid=%s\nscore=%s min_block_score=%s should_block=%s",
                $postmarkUrl,
                $ticketNumber,
                $mid,
                $postmarkScore !== null ? $postmarkScore : 'n/a',
                (is_array($postmark) && array_key_exists('minScoreToBlock', $postmark)) ? $postmark['minScoreToBlock'] : 'n/a',
                (is_array($postmark) && !empty($postmark['shouldBlock'])) ? '1' : '0'
            );

            if (is_array($postmark) && !empty($postmark['error'])) {
                $postmarkMsg .= sprintf(
                    "\nerror=%s",
                    !empty($postmark['statusCode'])
                        ? sprintf('status=%s %s', $postmark['statusCode'], $postmark['error'])
                        : (string) $postmark['error']
                );
            }

            $ost->logDebug('Spamblock - Postmark', $postmarkMsg, true);

            $sfsData = is_array($sfs) && array_key_exists('data', $sfs) && is_array($sfs['data'])
                ? $sfs['data']
                : [];
            $sfsUrl = (array_key_exists('url_called', $sfsData) && $sfsData['url_called'])
                ? (string) $sfsData['url_called']
                : 'n/a';

            $sfsMsg = sprintf(
                "url_called=%s\nticket=%s mid=%s\nconfidence=%s min_confidence=%s should_block=%s",
                $sfsUrl,
                $ticketNumber,
                $mid,
                $sfsConfidence !== null ? $sfsConfidence : 'n/a',
                (is_array($sfs) && array_key_exists('minConfidence', $sfs)) ? $sfs['minConfidence'] : 'n/a',
                (is_array($sfs) && !empty($sfs['shouldBlock'])) ? '1' : '0'
            );

            if (is_array($sfs) && !empty($sfs['error'])) {
                $sfsMsg .= sprintf(
                    "\nerror=%s",
                    !empty($sfs['statusCode'])
                        ? sprintf('status=%s %s', $sfs['statusCode'], $sfs['error'])
                        : (string) $sfs['error']
                );
            }

            $ost->logDebug('Spamblock - SFS', $sfsMsg, true);

            if (is_array($spf)) {
                $spfData = array_key_exists('data', $spf) && is_array($spf['data']) ? $spf['data'] : [];

                $traceLines = [];
                if (array_key_exists('trace', $spfData) && is_array($spfData['trace'])) {
                    foreach ($spfData['trace'] as $tl) {
                        $tl = trim((string) $tl);
                        if ($tl !== '') {
                            $traceLines[] = '- ' . $tl;
                        }
                    }
                }

                $spfMsg = sprintf(
                    "ticket=%s mid=%s\nip_used=%s\nspf_result=%s spf_raw=%s should_block=%s",
                    $ticketNumber,
                    $mid,
                    (array_key_exists('ip', $spfData) && $spfData['ip']) ? (string) $spfData['ip'] : 'n/a',
                    (array_key_exists('result', $spfData) && $spfData['result']) ? (string) $spfData['result'] : ($spfResult !== null ? $spfResult : 'n/a'),
                    (array_key_exists('raw', $spfData) && $spfData['raw']) ? (string) $spfData['raw'] : 'n/a',
                    !empty($spf['shouldBlock']) ? '1' : '0'
                );

                if ($traceLines) {
                    $spfMsg .= "\n" . implode("\n", $traceLines);
                }

                if (!empty($spf['error'])) {
                    $spfMsg .= sprintf(
                        "\nerror=%s",
                        !empty($spf['statusCode'])
                            ? sprintf('status=%s %s', $spf['statusCode'], $spf['error'])
                            : (string) $spf['error']
                    );
                }

                $ost->logDebug('Spamblock - SPF', $spfMsg, true);
            }

            if (is_array($gemini)) {
                $geminiData = array_key_exists('data', $gemini) && is_array($gemini['data']) ? $gemini['data'] : [];
                $geminiMsg = sprintf(
                    "ticket=%s mid=%s\nmodel=%s action=%s spam=%s should_block=%s\nreasoning=%s",
                    $ticketNumber,
                    $mid,
                    (array_key_exists('model', $geminiData) && $geminiData['model']) ? (string) $geminiData['model'] : 'gemini-3-flash-preview',
                    (array_key_exists('action', $gemini) && $gemini['action']) ? (string) $gemini['action'] : 'ignore',
                    (array_key_exists('spam', $gemini) && $gemini['spam'] !== null) ? ($gemini['spam'] ? 'true' : 'false') : 'n/a',
                    !empty($gemini['shouldBlock']) ? '1' : '0',
                    ($geminiReasoning !== null && trim($geminiReasoning) !== '') ? $geminiReasoning : 'n/a'
                );

                if (!empty($gemini['error'])) {
                    $geminiMsg .= sprintf(
                        "\nerror=%s",
                        !empty($gemini['statusCode'])
                            ? sprintf('status=%s %s', $gemini['statusCode'], $gemini['error'])
                            : (string) $gemini['error']
                    );
                }

                $ost->logDebug('Spamblock - Gemini', $geminiMsg, true);
            }
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
