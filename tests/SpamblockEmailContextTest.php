<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/lib/spamcheck.php';

final class SpamblockEmailContextTest extends TestCase
{
    public function testFromTicketVarsNormalizesIpFromCommonKeys(): void
    {
        $ctx = SpamblockEmailContext::fromTicketVars([
            'mid' => '<m1@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'subj',
            'header' => "From: sender@example.com\r\n",
            'message' => 'hello',
            'ip' => ' [1.2.3.4]:25 ',
        ]);

        $this->assertSame('1.2.3.4', $ctx->getIp());
    }

    public function testFromTicketVarsExtractsPublicIpFromHeaderPreferentially(): void
    {
        $header = implode("\r\n", [
            'X-Forwarded-For: 198.51.100.8, 10.0.0.1',
            '',
            '',
        ]);

        $ctx = SpamblockEmailContext::fromTicketVars([
            'mid' => '<m2@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'subj',
            'header' => $header,
            'message' => 'hello',
        ]);

        $this->assertSame('198.51.100.8', $ctx->getIp());
    }

    public function testFromTicketVarsExtractsEnvelopeFromAndEsmtpsaFromTopReceivedHop(): void
    {
        $header = implode("\r\n", [
            'Received: from relay.example.test ([198.51.100.25]:43205) by ingress.example.test with esmtpsa envelope-from <bounce@example.test>;',
            'Received: by mail.example.test with SMTP id abc123;',
            '',
            '',
        ]);

        $ctx = SpamblockEmailContext::fromTicketVars([
            'mid' => '<m-esmtpsa@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'subj',
            'header' => $header,
            'message' => 'hello',
        ]);

        $this->assertSame('198.51.100.25', $ctx->getIp());
        $this->assertSame('bounce@example.test', $ctx->getEnvelopeFromEmail());
        $this->assertTrue($ctx->isAuthenticatedSubmission());
    }

    public function testFromTicketVarsPrefersAuthenticationResultsForSpfEvidence(): void
    {
        $header = implode("\r\n", [
            'Authentication-Results: mx.example.test; spf=pass smtp.mailfrom=bounce@example.test smtp.remote-ip=192.0.2.15',
            'Received: from relay.example.test ([198.51.100.50]) by mx.example.test with esmtp;',
            '',
            '',
        ]);

        $ctx = SpamblockEmailContext::fromTicketVars([
            'mid' => '<m-auth-results@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'subj',
            'header' => $header,
            'message' => 'hello',
        ]);

        $this->assertSame('192.0.2.15', $ctx->getIp());
        $this->assertSame([
            'source' => 'authentication-results',
            'raw' => 'pass',
            'result' => 'pass',
            'ip' => '192.0.2.15',
            'envelope_from' => 'bounce@example.test',
            'domain' => 'example.test',
        ], $ctx->getSpfEvidence());
    }

    public function testFromTicketVarsPrefersTopReceivedHopOverLaterReceivedIps(): void
    {
        $header = implode("\r\n", [
            'Received: from smtp.first.example.test ([198.51.100.8]) by mx.example.test with esmtp;',
            'Received: from smtp.second.example.test ([203.0.113.9]) by smtp.first.example.test with esmtp;',
            '',
            '',
        ]);

        $ctx = SpamblockEmailContext::fromTicketVars([
            'mid' => '<m-received@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'subj',
            'header' => $header,
            'message' => 'hello',
        ]);

        $this->assertSame('198.51.100.8', $ctx->getIp());
    }

    public function testGetRawEmailAddsHeaderBodySeparatorIfMissing(): void
    {
        $ctx = new SpamblockEmailContext(
            '<m3@example.com>',
            'sender@example.com',
            'subj',
            "Header: x\r\n",
            'BODY'
        );

        $this->assertSame("Header: x\r\n\r\nBODY", $ctx->getRawEmail());
    }

    public function testGetRawEmailDoesNotDuplicateSeparatorIfAlreadyPresent(): void
    {
        $ctx = new SpamblockEmailContext(
            '<m4@example.com>',
            'sender@example.com',
            'subj',
            "Header: x\r\n\r\n",
            'BODY'
        );

        $this->assertSame("Header: x\r\n\r\nBODY", $ctx->getRawEmail());
    }

    public function testFromTicketVarsCastsNonStringMessageToString(): void
    {
        $ctx = SpamblockEmailContext::fromTicketVars([
            'mid' => '<m5@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'subj',
            'header' => "From: sender@example.com\r\n",
            'message' => ['not', 'a', 'string'],
        ]);

        $this->assertSame(
            "From: sender@example.com\r\n\r\n[\"not\",\"a\",\"string\"]",
            $ctx->getRawEmail()
        );
    }
}
