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
            $message = (string) $message;
        }

        $ip = '';
        foreach (['ip', 'ip_address', 'ipaddr', 'client_ip', 'clientip'] as $k) {
            if (empty($vars[$k])) {
                continue;
            }

            $ip = trim((string) $vars[$k]);
            if ($ip !== '') {
                break;
            }
        }

        if ($ip === '' && $header !== '') {
            if (preg_match('/^X-Originating-IP:\s*\[([^\]]+)\]/mi', $header, $m)) {
                $ip = trim($m[1]);
            } elseif (preg_match('/\[([0-9]{1,3}(?:\.[0-9]{1,3}){3})\]/', $header, $m)) {
                $ip = trim($m[1]);
            }
        }

        if ($ip !== '' && filter_var($ip, FILTER_VALIDATE_IP) === false) {
            $ip = '';
        }

        return new self($mid, $fromEmail, $subject, $header, $message, $ip);
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

        if (preg_match("/(\r\n\r\n|\n\n)$/", $this->header)) {
            return $this->header . $this->message;
        }

        return $this->header . "\r\n\r\n" . $this->message;
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

class SpamblockPostmarkSpamCheckProvider implements SpamblockSpamCheckProvider
{
    private const ENDPOINT = 'https://spamcheck.postmarkapp.com/filter';

    public function getName()
    {
        return 'postmark';
    }

    public function check(SpamblockEmailContext $context)
    {
        $payload = json_encode([
            'email' => $context->getRawEmail(),
            'options' => 'short',
        ]);

        if ($payload === false) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Unable to encode request payload'
            );
        }

        $httpOptions = [
            'method' => 'POST',
            'timeout' => 8,
            'ignore_errors' => true,
            'header' => "Content-Type: application/json\r\n" .
                "User-Agent: spamblock/0.3.0\r\n",
            'content' => $payload,
        ];

        $ctx = stream_context_create([
            'http' => $httpOptions,
        ]);

        $responseHeaders = null;
        $responseBody = @file_get_contents(self::ENDPOINT, false, $ctx);
        if (isset($http_response_header)) {
            $responseHeaders = $http_response_header;
        }

        $status = $this->extractStatusCode($responseHeaders);
        if ($responseBody === false) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Network error calling Postmark Spamcheck',
                $status
            );
        }

        if ($status < 200 || $status >= 300) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Non-2xx response from Postmark Spamcheck',
                $status
            );
        }

        $decoded = json_decode($responseBody, true);
        if (!is_array($decoded)) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Unable to decode Postmark Spamcheck response JSON',
                $status
            );
        }

        if (!isset($decoded['score']) || !is_numeric($decoded['score'])) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Postmark Spamcheck response missing numeric score',
                $status
            );
        }

        return new SpamblockSpamCheckResult(
            $this->getName(),
            (float) $decoded['score'],
            null,
            $status
        );
    }

    private function extractStatusCode($headers)
    {
        if (!$headers || !is_array($headers) || !$headers[0]) {
            return 0;
        }

        if (preg_match('/HTTP\/[0-9.]+\s+(\d{3})/', $headers[0], $m)) {
            return (int) $m[1];
        }

        return 0;
    }
}

class SpamblockStopForumSpamProvider implements SpamblockSpamCheckProvider
{
    private const ENDPOINT = 'https://api.stopforumspam.org/api';

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

        $httpOptions = [
            'method' => 'GET',
            'timeout' => 8,
            'ignore_errors' => true,
            'header' => "User-Agent: spamblock/0.3.0\r\n",
        ];

        $ctx = stream_context_create([
            'http' => $httpOptions,
        ]);

        $responseHeaders = null;
        $responseBody = @file_get_contents($url, false, $ctx);
        if (isset($http_response_header)) {
            $responseHeaders = $http_response_header;
        }

        $status = $this->extractStatusCode($responseHeaders);
        if ($responseBody === false) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Network error calling StopForumSpam',
                $status
            );
        }

        if ($status < 200 || $status >= 300) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Non-2xx response from StopForumSpam',
                $status
            );
        }

        $decoded = json_decode($responseBody, true);
        if (!is_array($decoded)) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Unable to decode StopForumSpam response JSON',
                $status
            );
        }

        if (!isset($decoded['success']) || (int) $decoded['success'] !== 1) {
            $err = isset($decoded['error']) ? (string) $decoded['error'] : 'StopForumSpam returned success=0';

            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                $err,
                $status
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

    private function extractStatusCode($headers)
    {
        if (!$headers || !is_array($headers) || !$headers[0]) {
            return 0;
        }

        if (preg_match('/HTTP\/[0-9.]+\s+(\d{3})/', $headers[0], $m)) {
            return (int) $m[1];
        }

        return 0;
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
