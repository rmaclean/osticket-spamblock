<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/lib/spamcheck.php';
require_once __DIR__ . '/../plugin/spamblock/lib/spfcheck.php';

final class SpamblockSpfCheckProviderTest extends TestCase
{
    public function testInvalidEmailDomainReturnsInvalidResult(): void
    {
        $p = new SpamblockSpfCheckProvider();

        $ctx = new SpamblockEmailContext('<m1@example.com>', 'bad@@example.com', '', '', '', '203.0.113.1');
        $res = $p->check($ctx);

        $this->assertSame('spf', $res->getProvider());
        $this->assertSame('Unable to determine sender domain for SPF check', $res->getError());
        $this->assertSame('invalid', $res->getData()['result']);
    }

    public function testMissingIpReturnsInvalidResult(): void
    {
        $p = new SpamblockSpfCheckProvider();

        $ctx = new SpamblockEmailContext('<m2@example.com>', 'a@example.com', '', '', '', '');
        $res = $p->check($ctx);

        $this->assertSame('No valid IP address available for SPF check', $res->getError());
        $this->assertSame('invalid', $res->getData()['result']);
    }

    public function testEvaluateRecordMatchesIp4Mechanism(): void
    {
        $p = new SpamblockSpfCheckProvider();
        $out = $this->callPrivate($p, 'evaluateRecord', [
            'example.com',
            '203.0.113.55',
            'v=spf1 ip4:203.0.113.0/24 -all',
            0,
        ]);

        $this->assertSame('pass', $out['raw']);
        $this->assertSame('pass', $out['result']);
    }

    public function testEvaluateRecordFallsThroughToAll(): void
    {
        $p = new SpamblockSpfCheckProvider();
        $out = $this->callPrivate($p, 'evaluateRecord', [
            'example.com',
            '198.51.100.10',
            'v=spf1 ip4:203.0.113.0/24 -all',
            0,
        ]);

        $this->assertSame('fail', $out['raw']);
        $this->assertSame('fail', $out['result']);
    }

    public function testEvaluateRecordUnsupportedMechanismIsInvalid(): void
    {
        $p = new SpamblockSpfCheckProvider();
        $out = $this->callPrivate($p, 'evaluateRecord', [
            'example.com',
            '203.0.113.10',
            'v=spf1 ptr -all',
            0,
        ]);

        $this->assertSame('invalid', $out['result']);
        $this->assertStringContainsString('Unsupported SPF mechanism', (string) $out['error']);
    }

    private function callPrivate(object $obj, string $method, array $args)
    {
        $ref = new ReflectionClass($obj);
        $m = $ref->getMethod($method);
        $m->setAccessible(true);

        return $m->invokeArgs($obj, $args);
    }
}
