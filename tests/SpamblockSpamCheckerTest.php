<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/lib/spamcheck.php';

final class SpamblockSpamCheckerTest extends TestCase
{
    public function testGetMaxScoreReturnsNullIfAllNull(): void
    {
        $checker = new SpamblockSpamChecker([]);

        $max = $checker->getMaxScore([
            new SpamblockSpamCheckResult('a', null),
            new SpamblockSpamCheckResult('b', null),
        ]);

        $this->assertNull($max);
    }

    public function testGetMaxScoreReturnsMaxOfNonNullScores(): void
    {
        $checker = new SpamblockSpamChecker([]);

        $max = $checker->getMaxScore([
            new SpamblockSpamCheckResult('a', 1.5),
            new SpamblockSpamCheckResult('b', null),
            new SpamblockSpamCheckResult('c', 9.2),
        ]);

        $this->assertSame(9.2, $max);
    }
}
