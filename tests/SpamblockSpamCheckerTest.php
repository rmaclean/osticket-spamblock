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

    public function testCheckContinuesWhenProviderThrows(): void
    {
        $checker = new SpamblockSpamChecker([
            new ThrowingSpamCheckProvider(),
            new StaticSpamCheckProvider('sfs', 82.5),
        ]);
        $context = new SpamblockEmailContext('<m1@example.com>', 'sender@example.com', 'subject', '', 'body');

        $results = $checker->check($context);

        $this->assertCount(2, $results);
        $this->assertSame('postmark', $results[0]->getProvider());
        $this->assertNull($results[0]->getScore());
        $this->assertStringContainsString('RuntimeException', (string) $results[0]->getError());
        $this->assertSame('sfs', $results[1]->getProvider());
        $this->assertSame(82.5, $results[1]->getScore());
        $this->assertSame(82.5, $checker->getMaxScore($results));
    }
}

final class ThrowingSpamCheckProvider implements SpamblockSpamCheckProvider
{
    public function getName()
    {
        return 'postmark';
    }

    public function check(SpamblockEmailContext $context)
    {
        throw new RuntimeException('simulated transport failure');
    }
}

final class StaticSpamCheckProvider implements SpamblockSpamCheckProvider
{
    private $name;
    private $score;

    public function __construct(string $name, ?float $score)
    {
        $this->name = $name;
        $this->score = $score;
    }

    public function getName()
    {
        return $this->name;
    }

    public function check(SpamblockEmailContext $context)
    {
        return new SpamblockSpamCheckResult($this->name, $this->score);
    }
}
