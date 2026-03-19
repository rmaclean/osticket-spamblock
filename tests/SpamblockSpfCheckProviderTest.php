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

    public function testEvaluateRecordKeepsNeutralAsNeutral(): void
    {
        $p = new SpamblockSpfCheckProvider();
        $out = $this->callPrivate($p, 'evaluateRecord', [
            'example.com',
            '198.51.100.10',
            'v=spf1 ?all',
            0,
        ]);

        $this->assertSame('neutral', $out['raw']);
        $this->assertSame('neutral', $out['result']);
    }

    public function testEvaluateRecordUnsupportedMechanismReturnsUnsupported(): void
    {
        $p = new SpamblockSpfCheckProvider();
        $out = $this->callPrivate($p, 'evaluateRecord', [
            'example.com',
            '203.0.113.10',
            'v=spf1 ptr -all',
            0,
        ]);

        $this->assertSame('unsupported', $out['result']);
        $this->assertSame('neutral', $out['raw']);
        $this->assertNull($out['error']);
    }

    public function testDomainExistsWithValidDomain(): void
    {
        $p = new SpamblockSpfCheckProvider();
        $result = $this->callPrivate($p, 'domainExists', ['example.com']);
        $this->assertTrue($result);
    }

    public function testCheckPrefersAuthenticationResultsOverDnsEvaluation(): void
    {
        $p = new SpamblockSpfCheckProvider();
        $ctx = SpamblockEmailContext::fromTicketVars([
            'mid' => '<m-auth-results@example.com>',
            'email' => 'display@example.net',
            'subject' => 'subj',
            'header' => implode("\r\n", [
                'Authentication-Results: mx.example.test; spf=pass smtp.mailfrom=bounce@example.test smtp.remote-ip=192.0.2.15',
                '',
                '',
            ]),
            'message' => 'hello',
        ]);

        $res = $p->check($ctx);

        $this->assertSame('pass', $res->getData()['result']);
        $this->assertSame('pass', $res->getData()['raw']);
        $this->assertSame('192.0.2.15', $res->getData()['ip']);
        $this->assertSame('example.test', $res->getData()['domain']);
        $this->assertSame('bounce@example.test', $res->getData()['envelope_from']);
        $this->assertSame('authentication-results', $res->getData()['source']);
    }

    public function testCheckFallsBackToReceivedSpfHeader(): void
    {
        $p = new SpamblockSpfCheckProvider();
        $ctx = SpamblockEmailContext::fromTicketVars([
            'mid' => '<m-received-spf@example.com>',
            'email' => 'display@example.net',
            'subject' => 'subj',
            'header' => implode("\r\n", [
                'Received-SPF: fail (mx.example.test: domain of bounce@example.test does not designate 198.51.100.10 as permitted sender) client-ip=198.51.100.10; envelope-from=bounce@example.test;',
                '',
                '',
            ]),
            'message' => 'hello',
        ]);

        $res = $p->check($ctx);

        $this->assertSame('fail', $res->getData()['result']);
        $this->assertSame('fail', $res->getData()['raw']);
        $this->assertSame('198.51.100.10', $res->getData()['ip']);
        $this->assertSame('example.test', $res->getData()['domain']);
        $this->assertSame('bounce@example.test', $res->getData()['envelope_from']);
        $this->assertSame('received-spf', $res->getData()['source']);
    }

    private function callPrivate(object $obj, string $method, array $args)
    {
        $ref = new ReflectionClass($obj);
        $m = $ref->getMethod($method);
        $m->setAccessible(true);

        return $m->invokeArgs($obj, $args);
    }
}
