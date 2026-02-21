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
            'X-Originating-IP: [10.0.0.1]',
            'X-Forwarded-For: 8.8.8.8, 10.0.0.1',
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

        $this->assertSame('8.8.8.8', $ctx->getIp());
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
