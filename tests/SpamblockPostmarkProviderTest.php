<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/lib/spamcheck.php';

final class SpamblockPostmarkProviderTest extends TestCase
{
    public function testReturnsErrorWhenPayloadCannotBeEncoded(): void
    {
        $http = new TestHttpClient();
        $provider = new SpamblockPostmarkSpamCheckProvider($http);

        $ctx = new SpamblockEmailContext(
            '<m1@example.com>',
            'sender@example.com',
            'subj',
            "Header: x\r\n\r\n",
            "bad\xB1"
        );

        $res = $provider->check($ctx);

        $this->assertSame('postmark', $res->getProvider());
        $this->assertNull($res->getScore());
        $this->assertSame('Unable to encode request payload', $res->getError());
        $this->assertSame(0, $http->calls);
    }

    public function testNetworkError(): void
    {
        $http = new TestHttpClient([
            'ok' => false,
            'status' => 0,
            'body' => null,
        ]);
        $provider = new SpamblockPostmarkSpamCheckProvider($http);

        $ctx = new SpamblockEmailContext('<m2@example.com>', 'a@example.com', 's', '', 'msg');
        $res = $provider->check($ctx);

        $this->assertNull($res->getScore());
        $this->assertSame('Network error calling Postmark Spamcheck', $res->getError());
    }

    public function testNon2xxResponse(): void
    {
        $http = new TestHttpClient([
            'ok' => true,
            'status' => 500,
            'body' => '{}',
        ]);
        $provider = new SpamblockPostmarkSpamCheckProvider($http);

        $ctx = new SpamblockEmailContext('<m3@example.com>', 'a@example.com', 's', '', 'msg');
        $res = $provider->check($ctx);

        $this->assertSame(500, $res->getStatusCode());
        $this->assertSame('Non-2xx response from Postmark Spamcheck', $res->getError());
    }

    public function testInvalidJson(): void
    {
        $http = new TestHttpClient([
            'ok' => true,
            'status' => 200,
            'body' => 'not json',
        ]);
        $provider = new SpamblockPostmarkSpamCheckProvider($http);

        $ctx = new SpamblockEmailContext('<m4@example.com>', 'a@example.com', 's', '', 'msg');
        $res = $provider->check($ctx);

        $this->assertSame('Unable to decode Postmark Spamcheck response JSON', $res->getError());
    }

    public function testMissingScore(): void
    {
        $http = new TestHttpClient([
            'ok' => true,
            'status' => 200,
            'body' => '{"ok":true}',
        ]);
        $provider = new SpamblockPostmarkSpamCheckProvider($http);

        $ctx = new SpamblockEmailContext('<m5@example.com>', 'a@example.com', 's', '', 'msg');
        $res = $provider->check($ctx);

        $this->assertSame('Postmark Spamcheck response missing numeric score', $res->getError());
    }

    public function testSuccess(): void
    {
        $http = new TestHttpClient([
            'ok' => true,
            'status' => 200,
            'body' => '{"score": 7.5}',
        ]);
        $provider = new SpamblockPostmarkSpamCheckProvider($http);

        $ctx = new SpamblockEmailContext('<m6@example.com>', 'a@example.com', 's', '', 'msg');
        $res = $provider->check($ctx);

        $this->assertNull($res->getError());
        $this->assertSame(200, $res->getStatusCode());
        $this->assertSame(7.5, $res->getScore());
    }
}

final class TestHttpClient implements SpamblockHttpClient
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
            'body' => '{}',
        ];
    }
}
