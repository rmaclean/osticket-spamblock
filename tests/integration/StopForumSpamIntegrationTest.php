<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../../plugin/spamblock/lib/spamcheck.php';

/**
 * @group integration
 */
final class StopForumSpamIntegrationTest extends TestCase
{
    public function testHitsRealStopForumSpamEndpoint(): void
    {
        if (!getenv('SPAMBLOCK_RUN_INTEGRATION_TESTS')) {
            $this->markTestSkipped('Set SPAMBLOCK_RUN_INTEGRATION_TESTS=1 to run integration tests');
        }

        $provider = new SpamblockStopForumSpamProvider(new SpamblockStreamHttpClient());
        $ctx = new SpamblockEmailContext('<int-sfs@spamblock.test>', 'test@example.com', '', '', '', '1.1.1.1');

        $res = $provider->check($ctx);

        $this->assertNull($res->getError());
        $this->assertSame(200, $res->getStatusCode());
    }
}
