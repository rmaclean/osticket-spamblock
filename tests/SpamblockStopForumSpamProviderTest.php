<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/lib/spamcheck.php';

final class SpamblockStopForumSpamProviderTest extends TestCase
{
    public function testReturnsErrorIfNoEmailOrIp(): void
    {
        $http = new SfsTestHttpClient();
        $provider = new SpamblockStopForumSpamProvider($http);

        $ctx = new SpamblockEmailContext('<m1@example.com>', '', '', '', '', '');
        $res = $provider->check($ctx);

        $this->assertSame('No email or IP available for StopForumSpam lookup', $res->getError());
        $this->assertSame(0, $http->calls);
    }

    public function testNetworkError(): void
    {
        $http = new SfsTestHttpClient([
            'ok' => false,
            'status' => 0,
            'body' => null,
        ]);
        $provider = new SpamblockStopForumSpamProvider($http);

        $ctx = new SpamblockEmailContext('<m2@example.com>', 'a@example.com', '', '', '', '');
        $res = $provider->check($ctx);

        $this->assertSame('Network error calling StopForumSpam', $res->getError());
    }

    public function testNon2xxResponse(): void
    {
        $http = new SfsTestHttpClient([
            'ok' => true,
            'status' => 403,
            'body' => '{}',
        ]);
        $provider = new SpamblockStopForumSpamProvider($http);

        $ctx = new SpamblockEmailContext('<m3@example.com>', 'a@example.com', '', '', '', '');
        $res = $provider->check($ctx);

        $this->assertSame(403, $res->getStatusCode());
        $this->assertSame('Non-2xx response from StopForumSpam', $res->getError());
    }

    public function testSuccessFalseReturnsError(): void
    {
        $http = new SfsTestHttpClient([
            'ok' => true,
            'status' => 200,
            'body' => '{"success":0,"error":"nope"}',
        ]);
        $provider = new SpamblockStopForumSpamProvider($http);

        $ctx = new SpamblockEmailContext('<m4@example.com>', 'a@example.com', '', '', '', '');
        $res = $provider->check($ctx);

        $this->assertSame('nope', $res->getError());
    }

    public function testSuccessUsesMaxConfidence(): void
    {
        $http = new SfsTestHttpClient([
            'ok' => true,
            'status' => 200,
            'body' => json_encode([
                'success' => 1,
                'email' => [
                    'confidence' => 20,
                    'appears' => 1,
                    'frequency' => 2,
                ],
                'ip' => [
                    'confidence' => 80,
                    'appears' => 1,
                    'frequency' => 2,
                ],
            ]),
        ]);
        $provider = new SpamblockStopForumSpamProvider($http);

        $ctx = new SpamblockEmailContext('<m5@example.com>', 'a@example.com', '', '', '', '8.8.8.8');
        $res = $provider->check($ctx);

        $this->assertNull($res->getError());
        $this->assertSame(80.0, $res->getScore());

        $data = $res->getData();
        $this->assertArrayHasKey('url', $data);
        $this->assertStringContainsString('api.stopforumspam.org', (string) $data['url']);
    }
}

final class SfsTestHttpClient implements SpamblockHttpClient
{
    public $calls = 0;
    private $result;

    public function __construct($result = null)
    {
        $this->result = $result;
    }

    public function request($method, $url, $timeout, $headers = [], $body = null)
    {
        $this->calls++;

        return $this->result ?? [
            'ok' => true,
            'status' => 200,
            'body' => '{"success":1}',
        ];
    }
}
