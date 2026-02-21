<?php

class SpamblockEmailContext
{
    private $mid;
    private $fromEmail;
    private $subject;
    private $header;
    private $message;
    private $ip;

    public function __construct($mid, $fromEmail, $subject, $header, $message, $ip = '')
    {
        $this->mid = $mid;
        $this->fromEmail = $fromEmail;
        $this->subject = $subject;
        $this->header = $header;
        $this->message = $message;
        $this->ip = $ip;
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

        if ($ip === '' && $header !== '') {
            $ip = self::extractIpFromHeader($header);
        }

        return new self($mid, $fromEmail, $subject, $header, $message, $ip);
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
        $header = (string) $header;

        $candidates = [];

        $simpleHeaderFields = [
            'X-Originating-IP',
            'X-Sender-IP',
            'X-Client-IP',
            'X-Real-IP',
        ];

        foreach ($simpleHeaderFields as $field) {
            $re = '/^' . preg_quote($field, '/') . ':\s*\[?([^\]\s]+)\]?/mi';
            if (preg_match($re, $header, $m)) {
                $candidates[] = $m[1];
            }
        }

        if (preg_match('/^X-Forwarded-For:\s*([^\r\n]+)/mi', $header, $m)) {
            $xff = trim((string) $m[1]);
            $parts = preg_split('/\s*,\s*/', $xff);
            if ($parts && isset($parts[0])) {
                $candidates[] = $parts[0];
            }
        }

        if (preg_match('/sender IP is\s*\[?([0-9a-fA-F:.]+)\]?/i', $header, $m)) {
            $candidates[] = $m[1];
        }

        if (preg_match_all('/\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b/', $header, $m)) {
            foreach ($m[1] as $v) {
                $candidates[] = $v;
            }
        }

        if (preg_match_all('/\b([0-9a-f]{0,4}:[0-9a-f:]{2,})\b/i', $header, $m)) {
            foreach ($m[1] as $v) {
                $candidates[] = $v;
            }
        }

        $valid = [];
        foreach ($candidates as $c) {
            $n = self::normalizeIpCandidate($c);
            if ($n === '') {
                continue;
            }

            if (!in_array($n, $valid, true)) {
                $valid[] = $n;
            }
        }

        foreach ($valid as $v) {
            if (self::isPublicIp($v)) {
                return $v;
            }
        }

        return $valid ? $valid[0] : '';
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
                'User-Agent: spamblock/0.4.2',
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
                'User-Agent: spamblock/0.4.2',
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
            $results[] = $provider->check($context);
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
