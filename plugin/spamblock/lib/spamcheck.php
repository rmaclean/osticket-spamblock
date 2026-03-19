<?php

class SpamblockEmailContext
{
    private $mid;
    private $fromEmail;
    private $subject;
    private $header;
    private $message;
    private $ip;
    private $envelopeFrom;
    private $spfEvidence;
    private $authenticatedSubmission;

    public function __construct(
        $mid,
        $fromEmail,
        $subject,
        $header,
        $message,
        $ip = '',
        $envelopeFrom = '',
        $spfEvidence = [],
        $authenticatedSubmission = false
    ) {
        $this->mid = $mid;
        $this->fromEmail = $fromEmail;
        $this->subject = $subject;
        $this->header = $header;
        $this->message = $message;
        $this->ip = $ip;
        $this->envelopeFrom = trim((string) $envelopeFrom);
        $this->spfEvidence = is_array($spfEvidence) ? $spfEvidence : [];
        $this->authenticatedSubmission = (bool) $authenticatedSubmission;
    }

    public static function fromTicketVars(array $vars)
    {
        $mid = (string) ($vars['mid'] ?? '');
        $fromEmail = (string) ($vars['email'] ?? '');
        $subject = (string) ($vars['subject'] ?? '');
        $header = (string) ($vars['header'] ?? '');
        $message = $vars['message'] ?? '';

        if (!is_string($message)) {
            if (is_scalar($message) || $message === null) {
                $message = (string) $message;
            } else {
                $encoded = json_encode($message);
                $message = ($encoded !== false) ? $encoded : '';
            }
        }

        $meta = self::extractHeaderMeta($header);

        $ip = '';
        foreach (['ip', 'ip_address', 'ipaddr', 'client_ip', 'clientip'] as $k) {
            if (empty($vars[$k])) {
                continue;
            }

            $ip = self::normalizeIpCandidate($vars[$k]);
            if ($ip !== '') {
                break;
            }
        }

        if ($ip === '' && !empty($meta['ip'])) {
            $ip = (string) $meta['ip'];
        }

        return new self(
            $mid,
            $fromEmail,
            $subject,
            $header,
            $message,
            $ip,
            $meta['envelope_from'] ?? '',
            $meta['spf'] ?? [],
            !empty($meta['authenticated_submission'])
        );
    }

    private static function normalizeIpCandidate($candidate)
    {
        $ip = trim((string) $candidate);
        if ($ip === '') {
            return '';
        }

        if (preg_match('/^\[([0-9a-fA-F:.]+)\](?::\d+)?$/', $ip, $m)) {
            $ip = $m[1];
        }

        $ip = trim($ip, " \t\n\r\0\x0B[]()<>,;");
        if (stripos($ip, 'IPv6:') === 0) {
            $ip = substr($ip, 5);
        }

        if (preg_match('/^([0-9]{1,3}(?:\.[0-9]{1,3}){3}):(\d+)$/', $ip, $m)) {
            $ip = $m[1];
        }

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return '';
        }

        return $ip;
    }

    private static function isPublicIp($ip)
    {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP,
            FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
        ) !== false;
    }

    private static function extractIpFromHeader($header)
    {
        $meta = self::extractHeaderMeta((string) $header);
        return isset($meta['ip']) ? (string) $meta['ip'] : '';
    }

    private static function extractHeaderMeta($header)
    {
        $lines = self::getUnfoldedHeaderLines((string) $header);
        $spfEvidence = self::extractTrustedSpfEvidenceFromLines($lines);

        $ip = '';
        foreach ([
            $spfEvidence['ip'] ?? '',
            self::extractReceivedIpFromLines($lines),
            self::extractSimpleHeaderIpFromLines($lines),
            self::extractLegacyIpFromLines($lines),
        ] as $candidate) {
            $candidate = self::normalizeIpCandidate($candidate);
            if ($candidate !== '') {
                $ip = $candidate;
                break;
            }
        }

        return [
            'ip' => $ip,
            'envelope_from' => self::extractEnvelopeFromLines($lines),
            'spf' => $spfEvidence,
            'authenticated_submission' => self::topReceivedUsesEsmtpsa($lines),
        ];
    }

    private static function getUnfoldedHeaderLines($header)
    {
        if ($header === '') {
            return [];
        }

        $rawLines = preg_split("/\r\n|\n|\r/", $header);
        if (!$rawLines) {
            return [];
        }

        $lines = [];
        foreach ($rawLines as $line) {
            if ($line === '') {
                continue;
            }

            if (($line[0] === ' ' || $line[0] === "\t") && $lines) {
                $lines[count($lines) - 1] .= ' ' . trim($line);
                continue;
            }

            $lines[] = trim($line);
        }

        return $lines;
    }

    private static function getHeaderLines(array $lines, $fieldName)
    {
        $prefix = strtolower((string) $fieldName) . ':';
        $matched = [];

        foreach ($lines as $line) {
            if (stripos($line, $prefix) === 0) {
                $matched[] = $line;
            }
        }

        return $matched;
    }

    private static function topReceivedUsesEsmtpsa(array $lines)
    {
        $receivedLines = self::getHeaderLines($lines, 'Received');
        if (!$receivedLines) {
            return false;
        }

        return preg_match('/\bwith\s+esmtpsa\b/i', $receivedLines[0]) === 1;
    }

    private static function extractEnvelopeFromLines(array $lines)
    {
        foreach (self::getHeaderLines($lines, 'Return-Path') as $line) {
            $value = self::extractEmailAddress($line);
            if ($value !== '') {
                return $value;
            }
        }

        foreach (self::getHeaderLines($lines, 'Authentication-Results') as $line) {
            $value = self::extractEmailAddress(self::extractNamedValue($line, 'smtp.mailfrom'));
            if ($value !== '') {
                return $value;
            }
        }

        foreach (self::getHeaderLines($lines, 'Received-SPF') as $line) {
            $value = self::extractEmailAddress(self::extractNamedValue($line, 'envelope-from'));
            if ($value !== '') {
                return $value;
            }
        }

        foreach (self::getHeaderLines($lines, 'Received') as $line) {
            if (preg_match('/\benvelope-from\s*<([^>]+)>/i', $line, $m)) {
                $value = self::extractEmailAddress($m[1]);
                if ($value !== '') {
                    return $value;
                }
            }
        }

        return '';
    }

    private static function extractTrustedSpfEvidenceFromLines(array $lines)
    {
        foreach (self::getHeaderLines($lines, 'Authentication-Results') as $line) {
            if (!preg_match('/\bspf=([a-z]+)/i', $line, $m)) {
                continue;
            }

            $raw = strtolower(trim((string) $m[1]));
            $envelopeFrom = self::extractEmailAddress(self::extractNamedValue($line, 'smtp.mailfrom'));
            $ip = self::normalizeIpCandidate(
                self::extractNamedValue($line, 'smtp.remote-ip')
                    ?: self::extractNamedValue($line, 'client-ip')
                    ?: self::extractNamedValue($line, 'sender-ip')
            );

            return [
                'source' => 'authentication-results',
                'raw' => $raw,
                'result' => self::normalizeSpfResult($raw),
                'ip' => $ip,
                'envelope_from' => $envelopeFrom,
                'domain' => self::extractDomainFromEmail($envelopeFrom),
            ];
        }

        foreach (self::getHeaderLines($lines, 'Received-SPF') as $line) {
            if (!preg_match('/^Received-SPF:\s*([a-z]+)/i', $line, $m)) {
                continue;
            }

            $raw = strtolower(trim((string) $m[1]));
            $envelopeFrom = self::extractEmailAddress(self::extractNamedValue($line, 'envelope-from'));
            $ip = self::normalizeIpCandidate(self::extractNamedValue($line, 'client-ip'));

            return [
                'source' => 'received-spf',
                'raw' => $raw,
                'result' => self::normalizeSpfResult($raw),
                'ip' => $ip,
                'envelope_from' => $envelopeFrom,
                'domain' => self::extractDomainFromEmail($envelopeFrom),
            ];
        }

        return [];
    }

    private static function normalizeSpfResult($raw)
    {
        $raw = strtolower(trim((string) $raw));

        if ($raw === 'fail' || $raw === 'softfail') {
            return 'fail';
        }

        if (in_array($raw, ['pass', 'none', 'neutral'], true)) {
            return $raw;
        }

        return 'invalid';
    }

    private static function extractReceivedIpFromLines(array $lines)
    {
        $fallback = '';

        foreach (self::getHeaderLines($lines, 'Received') as $line) {
            $candidates = self::extractAllIpsFromString($line);
            foreach ($candidates as $candidate) {
                if (self::isPublicIp($candidate)) {
                    return $candidate;
                }

                if ($fallback === '') {
                    $fallback = $candidate;
                }
            }
        }

        return $fallback;
    }

    private static function extractSimpleHeaderIpFromLines(array $lines)
    {
        $candidates = [];

        foreach (['X-Originating-IP', 'X-Sender-IP', 'X-Client-IP', 'X-Real-IP'] as $field) {
            foreach (self::getHeaderLines($lines, $field) as $line) {
                $candidates[] = substr($line, strlen($field) + 1);
            }
        }

        foreach (self::getHeaderLines($lines, 'X-Forwarded-For') as $line) {
            $xff = trim((string) substr($line, strlen('X-Forwarded-For') + 1));
            $parts = preg_split('/\s*,\s*/', $xff);
            if ($parts && isset($parts[0]) && $parts[0] !== '') {
                $candidates[] = $parts[0];
            }
        }

        $fallback = '';
        foreach ($candidates as $candidate) {
            $candidate = self::normalizeIpCandidate($candidate);
            if ($candidate === '') {
                continue;
            }

            if (self::isPublicIp($candidate)) {
                return $candidate;
            }

            if ($fallback === '') {
                $fallback = $candidate;
            }
        }

        return $fallback;
    }

    private static function extractLegacyIpFromLines(array $lines)
    {
        $joined = implode("\n", $lines);

        if (preg_match('/sender IP is\s*\[?([0-9a-fA-F:.]+)\]?/i', $joined, $m)) {
            $candidate = self::normalizeIpCandidate($m[1]);
            if ($candidate !== '') {
                return $candidate;
            }
        }

        $allIps = self::extractAllIpsFromString($joined);
        foreach ($allIps as $candidate) {
            if (self::isPublicIp($candidate)) {
                return $candidate;
            }
        }

        return $allIps ? $allIps[0] : '';
    }

    private static function extractAllIpsFromString($value)
    {
        $value = (string) $value;
        $candidates = [];

        if (preg_match_all('/\[((?:IPv6:)?[^\]]+)\]/i', $value, $m)) {
            foreach ($m[1] as $candidate) {
                $candidates[] = $candidate;
            }
        }

        if (preg_match_all('/\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/', $value, $m)) {
            foreach ($m[1] as $candidate) {
                $candidates[] = $candidate;
            }
        }

        if (preg_match_all('/\b([0-9a-f]{0,4}:[0-9a-f:]{2,})\b/i', $value, $m)) {
            foreach ($m[1] as $candidate) {
                $candidates[] = $candidate;
            }
        }

        $valid = [];
        foreach ($candidates as $candidate) {
            $normalized = self::normalizeIpCandidate($candidate);
            if ($normalized === '' || in_array($normalized, $valid, true)) {
                continue;
            }

            $valid[] = $normalized;
        }

        return $valid;
    }

    private static function extractNamedValue($line, $name)
    {
        $line = (string) $line;
        $name = preg_quote((string) $name, '/');

        if (!preg_match('/\b' . $name . '=("([^"]*)"|[^;\s]+)/i', $line, $m)) {
            return '';
        }

        $value = $m[2] ?? $m[1];
        return trim((string) $value, " \t\n\r\0\x0B<>");
    }

    private static function extractEmailAddress($value)
    {
        $value = trim((string) $value);
        if ($value === '') {
            return '';
        }

        if (preg_match('/<?([A-Z0-9._%+\-]+@[A-Z0-9.\-]+)>?/i', $value, $m)) {
            return strtolower(trim((string) $m[1]));
        }

        return '';
    }

    private static function extractDomainFromEmail($email)
    {
        $email = self::extractEmailAddress($email);
        if ($email === '' || substr_count($email, '@') !== 1) {
            return '';
        }

        $parts = explode('@', $email, 2);
        return strtolower(trim((string) ($parts[1] ?? '')));
    }

    public function getMid()
    {
        return $this->mid;
    }

    public function getFromEmail()
    {
        return $this->fromEmail;
    }

    public function getSubject()
    {
        return $this->subject;
    }

    public function getIp()
    {
        return $this->ip;
    }

    public function getEnvelopeFromEmail()
    {
        return $this->envelopeFrom;
    }

    public function getSpfEvidence()
    {
        return $this->spfEvidence;
    }

    public function isAuthenticatedSubmission()
    {
        return $this->authenticatedSubmission;
    }

    public function getRawEmail()
    {
        if (!$this->header) {
            return $this->message;
        }

        $header = (string) $this->header;

        if (preg_match("/(\r\n\r\n|\n\n)$/", $header)) {
            return $header . $this->message;
        }

        if (preg_match("/(\r\n|\n)$/", $header)) {
            return $header . "\r\n" . $this->message;
        }

        return $header . "\r\n\r\n" . $this->message;
    }
}

class SpamblockSpamCheckResult
{
    private $provider;
    private $score;
    private $error;
    private $statusCode;
    private $data;

    public function __construct($provider, $score, $error = null, $statusCode = null, $data = null)
    {
        $this->provider = $provider;
        $this->score = $score;
        $this->error = $error;
        $this->statusCode = $statusCode;
        $this->data = is_array($data) ? $data : [];
    }

    public function getProvider()
    {
        return $this->provider;
    }

    public function getScore()
    {
        return $this->score;
    }

    public function getError()
    {
        return $this->error;
    }

    public function getStatusCode()
    {
        return $this->statusCode;
    }

    public function getData()
    {
        return $this->data;
    }
}

interface SpamblockSpamCheckProvider
{
    public function getName();

    public function check(SpamblockEmailContext $context);
}

interface SpamblockHttpClient
{
    public function request($method, $url, $timeout, $headers = [], $body = null);
}

class SpamblockStreamHttpClient implements SpamblockHttpClient
{
    public function request($method, $url, $timeout, $headers = [], $body = null)
    {
        $method = strtoupper(trim((string) $method));
        $url = (string) $url;
        $timeout = (int) $timeout;

        $headerLines = [];
        foreach ((array) $headers as $h) {
            $h = trim((string) $h);
            if ($h !== '') {
                $headerLines[] = $h;
            }
        }

        $httpOptions = [
            'method' => $method,
            'timeout' => $timeout,
            'ignore_errors' => true,
        ];

        if ($headerLines) {
            $httpOptions['header'] = implode("\r\n", $headerLines) . "\r\n";
        }

        if ($body !== null) {
            $httpOptions['content'] = (string) $body;
        }

        $ctx = stream_context_create([
            'http' => $httpOptions,
        ]);

        $fp = @fopen($url, 'r', false, $ctx);

        $status = 0;
        $headers = null;
        $body = null;

        if ($fp !== false) {
            $meta = stream_get_meta_data($fp);
            $headers = $meta['wrapper_data'] ?? null;

            $read = stream_get_contents($fp);
            $body = ($read === false) ? null : $read;

            fclose($fp);
        }

        if (is_array($headers) && isset($headers[0])) {
            $first = (string) $headers[0];
            if (preg_match('/HTTP\/[0-9.]+\s+(\d{3})/', $first, $m)) {
                $status = (int) $m[1];
            }
        }

        if ($fp === false || $body === null) {
            return [
                'ok' => false,
                'status' => $status,
                'body' => null,
            ];
        }

        return [
            'ok' => true,
            'status' => $status,
            'body' => $body,
        ];
    }
}

class SpamblockPostmarkSpamCheckProvider implements SpamblockSpamCheckProvider
{
    private const ENDPOINT = 'https://spamcheck.postmarkapp.com/filter';

    private $http;

    public function __construct($http = null)
    {
        $this->http = $http instanceof SpamblockHttpClient
            ? $http
            : new SpamblockStreamHttpClient();
    }

    public function getName()
    {
        return 'postmark';
    }

    public function check(SpamblockEmailContext $context)
    {
        $debugData = [
            'url' => self::ENDPOINT,
            'url_called' => self::ENDPOINT,
            'method' => 'POST',
            'timeout_seconds' => 8,
        ];

        $payload = json_encode([
            'email' => $context->getRawEmail(),
            'options' => 'short',
        ]);

        if ($payload === false) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Unable to encode request payload',
                null,
                $debugData
            );
        }

        $res = $this->http->request(
            'POST',
            self::ENDPOINT,
            8,
            [
                'Content-Type: application/json',
                'User-Agent: spamblock/0.8.0',
            ],
            $payload
        );

        $status = isset($res['status']) ? (int) $res['status'] : 0;
        if (empty($res['ok'])) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Network error calling Postmark Spamcheck',
                $status,
                $debugData
            );
        }

        $responseBody = isset($res['body']) ? (string) $res['body'] : '';

        if ($status < 200 || $status >= 300) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Non-2xx response from Postmark Spamcheck',
                $status,
                $debugData
            );
        }

        $decoded = json_decode($responseBody, true);
        if (!is_array($decoded)) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Unable to decode Postmark Spamcheck response JSON',
                $status,
                $debugData
            );
        }

        if (!isset($decoded['score']) || !is_numeric($decoded['score'])) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Postmark Spamcheck response missing numeric score',
                $status,
                $debugData
            );
        }

        $debugData['response_score'] = (float) $decoded['score'];

        return new SpamblockSpamCheckResult(
            $this->getName(),
            (float) $decoded['score'],
            null,
            $status,
            $debugData
        );
    }
}

class SpamblockStopForumSpamProvider implements SpamblockSpamCheckProvider
{
    private const ENDPOINT = 'https://api.stopforumspam.org/api';

    private $http;

    public function __construct($http = null)
    {
        $this->http = $http instanceof SpamblockHttpClient
            ? $http
            : new SpamblockStreamHttpClient();
    }

    public function getName()
    {
        return 'sfs';
    }

    public function check(SpamblockEmailContext $context)
    {
        $email = trim((string) $context->getFromEmail());
        $ip = trim((string) $context->getIp());

        $params = [
            'json' => '1',
            'confidence' => '1',
        ];

        if ($email !== '') {
            $params['email'] = $email;
        }

        if ($ip !== '') {
            $params['ip'] = $ip;
        }

        if (!isset($params['email']) && !isset($params['ip'])) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'No email or IP available for StopForumSpam lookup'
            );
        }

        $url = self::ENDPOINT . '?' . http_build_query($params);
        $debugData = [
            'url' => $url,
            'url_called' => $url,
            'method' => 'GET',
            'timeout_seconds' => 8,
        ];

        $res = $this->http->request(
            'GET',
            $url,
            8,
            [
                'User-Agent: spamblock/0.8.0',
            ]
        );

        $status = isset($res['status']) ? (int) $res['status'] : 0;
        if (empty($res['ok'])) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Network error calling StopForumSpam',
                $status,
                $debugData
            );
        }

        $responseBody = isset($res['body']) ? (string) $res['body'] : '';

        if ($status < 200 || $status >= 300) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Non-2xx response from StopForumSpam',
                $status,
                $debugData
            );
        }

        $decoded = json_decode($responseBody, true);
        if (!is_array($decoded)) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Unable to decode StopForumSpam response JSON',
                $status,
                $debugData
            );
        }

        if (!isset($decoded['success']) || (int) $decoded['success'] !== 1) {
            $err = isset($decoded['error']) ? (string) $decoded['error'] : 'StopForumSpam returned success=0';

            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                $err,
                $status,
                $debugData
            );
        }

        $emailData = isset($decoded['email']) && is_array($decoded['email']) ? $decoded['email'] : null;
        $ipData = isset($decoded['ip']) && is_array($decoded['ip']) ? $decoded['ip'] : null;

        $emailConfidence = $this->extractFloat($emailData, 'confidence');
        $ipConfidence = $this->extractFloat($ipData, 'confidence');

        $confidences = array_values(array_filter([$emailConfidence, $ipConfidence], function ($v) {
            return $v !== null;
        }));

        $maxConfidence = $confidences ? max($confidences) : null;

        $data = [
            'url' => $url,
            'url_called' => $url,
            'method' => 'GET',
            'timeout_seconds' => 8,
            'email_confidence' => $emailConfidence,
            'ip_confidence' => $ipConfidence,
            'email_appears' => $this->extractInt($emailData, 'appears'),
            'ip_appears' => $this->extractInt($ipData, 'appears'),
            'email_frequency' => $this->extractInt($emailData, 'frequency'),
            'ip_frequency' => $this->extractInt($ipData, 'frequency'),
        ];

        return new SpamblockSpamCheckResult(
            $this->getName(),
            $maxConfidence,
            null,
            $status,
            $data
        );
    }

    private function extractFloat($arr, $key)
    {
        if (!is_array($arr) || !isset($arr[$key]) || !is_numeric($arr[$key])) {
            return null;
        }

        return (float) $arr[$key];
    }

    private function extractInt($arr, $key)
    {
        if (!is_array($arr) || !isset($arr[$key]) || !is_numeric($arr[$key])) {
            return null;
        }

        return (int) $arr[$key];
    }
}

class SpamblockSpamChecker
{
    private $providers;

    public function __construct(array $providers)
    {
        $this->providers = $providers;
    }

    public function check(SpamblockEmailContext $context)
    {
        $results = [];
        foreach ($this->providers as $provider) {
            try {
                $results[] = $provider->check($context);
            } catch (Throwable $e) {
                $providerName = method_exists($provider, 'getName')
                    ? (string) $provider->getName()
                    : get_class($provider);
                $message = trim($e->getMessage());
                if ($message === '') {
                    $message = 'Provider check threw ' . get_class($e);
                } else {
                    $message = sprintf(
                        'Provider check threw %s: %s',
                        get_class($e),
                        $message
                    );
                }

                $results[] = new SpamblockSpamCheckResult(
                    $providerName,
                    null,
                    $message
                );
            }
        }

        return $results;
    }

    public function getMaxScore(array $results)
    {
        $scores = array_filter(array_map(function ($r) {
            return $r->getScore();
        }, $results), function ($s) {
            return $s !== null;
        });

        if (!$scores) {
            return null;
        }

        return max($scores);
    }
}
