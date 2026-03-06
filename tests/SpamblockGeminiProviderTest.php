<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/lib/spamcheck.php';
require_once __DIR__ . '/../plugin/spamblock/lib/geminicheck.php';

final class SpamblockGeminiProviderTest extends TestCase
{
    public function testReturnsErrorWhenApiKeyMissing(): void
    {
        $provider = new SpamblockGeminiSpamCheckProvider('', 'Company', '- spam', '- legit');
        $ctx = new SpamblockEmailContext('<m1@example.com>', 'a@example.com', 'subject', "From: a@example.com\r\n\r\n", 'body');

        $res = $provider->check($ctx);

        $this->assertSame('gemini', $res->getProvider());
        $this->assertNull($res->getScore());
        $this->assertSame('Gemini is enabled but API key is empty', $res->getError());
    }

    public function testParsesValidStructuredOutput(): void
    {
        $http = new GeminiTestHttpClient([
            'ok' => true,
            'status' => 200,
            'body' => json_encode([
                'candidates' => [
                    [
                        'content' => [
                            'parts' => [
                                [
                                    'text' => '{"spam":true,"reasoning":"Sender impersonates support with urgent password-reset language."}',
                                ],
                            ],
                        ],
                    ],
                ],
            ]),
        ]);

        $provider = new SpamblockGeminiSpamCheckProvider(
            'key',
            'Company',
            '- spam',
            '- legit',
            $http
        );

        $ctx = new SpamblockEmailContext('<m2@example.com>', 'a@example.com', 'subject', "From: a@example.com\r\n\r\n", 'body');
        $res = $provider->check($ctx);

        $this->assertNull($res->getError());
        $this->assertSame(1.0, $res->getScore());
        $this->assertSame(200, $res->getStatusCode());
        $this->assertTrue($res->getData()['spam']);
        $this->assertSame(
            'Sender impersonates support with urgent password-reset language.',
            $res->getData()['reasoning']
        );
    }

    public function testRejectsNonBooleanSpamField(): void
    {
        $http = new GeminiTestHttpClient([
            'ok' => true,
            'status' => 200,
            'body' => json_encode([
                'candidates' => [
                    [
                        'content' => [
                            'parts' => [
                                [
                                    'text' => '{"spam":"true","reasoning":"Looks suspicious."}',
                                ],
                            ],
                        ],
                    ],
                ],
            ]),
        ]);

        $provider = new SpamblockGeminiSpamCheckProvider('key', 'Company', '- spam', '- legit', $http);
        $ctx = new SpamblockEmailContext('<m3@example.com>', 'a@example.com', 'subject', "From: a@example.com\r\n\r\n", 'body');
        $res = $provider->check($ctx);

        $this->assertSame('Gemini output field "spam" is missing or not boolean', $res->getError());
        $this->assertNull($res->getScore());
    }

    public function testNetworkErrorReturnsNullScore(): void
    {
        $http = new GeminiTestHttpClient([
            'ok' => false,
            'status' => 0,
            'body' => null,
        ]);
        $provider = new SpamblockGeminiSpamCheckProvider('key', 'Company', '- spam', '- legit', $http);
        $ctx = new SpamblockEmailContext('<m4@example.com>', 'a@example.com', 'subject', "From: a@example.com\r\n\r\n", 'body');

        $res = $provider->check($ctx);

        $this->assertSame('Network error calling Gemini', $res->getError());
        $this->assertNull($res->getScore());
    }

    public function testNon2xxResponseReturnsNullScore(): void
    {
        $http = new GeminiTestHttpClient([
            'ok' => true,
            'status' => 503,
            'body' => '{}',
        ]);
        $provider = new SpamblockGeminiSpamCheckProvider('key', 'Company', '- spam', '- legit', $http);
        $ctx = new SpamblockEmailContext('<m5@example.com>', 'a@example.com', 'subject', "From: a@example.com\r\n\r\n", 'body');

        $res = $provider->check($ctx);

        $this->assertSame(503, $res->getStatusCode());
        $this->assertSame('Non-2xx response from Gemini', $res->getError());
        $this->assertNull($res->getScore());
    }
}

final class GeminiTestHttpClient implements SpamblockHttpClient
{
    private $result;

    public function __construct($result = null)
    {
        $this->result = $result;
    }

    public function request($method, $url, $timeout, $headers = [], $body = null)
    {
        return $this->result ?? [
            'ok' => true,
            'status' => 200,
            'body' => '{}',
        ];
    }
}
