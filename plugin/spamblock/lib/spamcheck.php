<?php

class SpamblockEmailContext
{
    private $mid;
    private $fromEmail;
    private $subject;
    private $header;
    private $message;

    public function __construct($mid, $fromEmail, $subject, $header, $message)
    {
        $this->mid = $mid;
        $this->fromEmail = $fromEmail;
        $this->subject = $subject;
        $this->header = $header;
        $this->message = $message;
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

        return new self($mid, $fromEmail, $subject, $header, $message);
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

    public function __construct($provider, $score, $error = null, $statusCode = null)
    {
        $this->provider = $provider;
        $this->score = $score;
        $this->error = $error;
        $this->statusCode = $statusCode;
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
                "User-Agent: spamblock/0.1.0\r\n",
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
