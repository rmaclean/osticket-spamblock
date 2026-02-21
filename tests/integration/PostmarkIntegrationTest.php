<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../plugin/spamblock/lib/spamcheck.php';

/**
 * @group integration
 */
final class PostmarkIntegrationTest extends TestCase
{
    public function testHitsRealPostmarkEndpoint(): void
    {
        if (!getenv('SPAMBLOCK_RUN_INTEGRATION_TESTS')) {
            $this->markTestSkipped('Set SPAMBLOCK_RUN_INTEGRATION_TESTS=1 to run integration tests');
        }

        $raw = file_get_contents(__DIR__ . '/../../sample.eml');
        $this->assertNotFalse($raw);

        [$header, $body] = $this->splitRawEmail((string) $raw);

        $provider = new SpamblockPostmarkSpamCheckProvider(new SpamblockStreamHttpClient());
        $ctx = new SpamblockEmailContext('<int-postmark@spamblock.test>', 'sender@example.com', 'subject', $header, $body);

        $res = $provider->check($ctx);

        $this->assertNull($res->getError());
        $this->assertSame(200, $res->getStatusCode());
        $this->assertIsFloat($res->getScore());
    }

    private function splitRawEmail(string $raw): array
    {
        $parts = preg_split("/\r?\n\r?\n/", $raw, 2);
        if (!$parts || count($parts) < 2) {
            return ['', $raw];
        }

        return [$parts[0] . "\r\n\r\n", $parts[1]];
    }
}
