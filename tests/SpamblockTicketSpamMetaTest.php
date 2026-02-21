<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/lib/ticket_spam_meta.php';

final class SpamblockTicketSpamMetaTest extends TestCase
{
    public function testUpsertRequiresTicketId(): void
    {
        $this->assertFalse(SpamblockTicketSpamMeta::upsert(0, 'a@example.com', true, 1.0, 2.0, 'fail'));
    }

    public function testUpsertAndLookupRoundTrip(): void
    {
        $ok = SpamblockTicketSpamMeta::upsert(123, 'a@example.com', true, 5.5, 88.0, 'fail');
        $this->assertTrue($ok);

        $row = SpamblockTicketSpamMeta::lookup(123);

        $this->assertIsArray($row);
        $this->assertSame(123, $row['ticket_id']);
        $this->assertSame('a@example.com', $row['email']);
        $this->assertTrue($row['is_spam']);
        $this->assertSame(5.5, $row['postmark_score']);
        $this->assertSame(88.0, $row['sfs_confidence']);
        $this->assertSame('fail', $row['spf_result']);
    }
}
