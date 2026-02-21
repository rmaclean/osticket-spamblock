<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/lib/ticket_filter.php';

final class SpamblockTicketFilterTest extends TestCase
{
    public function testRegisterMatchFieldsIsIdempotent(): void
    {
        SpamblockTicketFilter::registerMatchFields();
        SpamblockTicketFilter::registerMatchFields();

        $supported = Filter::getSupportedMatches();
        $this->assertCount(1, $supported);

        $matchFields = $supported[0][1]();
        $this->assertArrayHasKey('spamblock_should_block', $matchFields);
        $this->assertArrayHasKey('spamblock_score', $matchFields);
        $this->assertArrayHasKey('spamblock_provider', $matchFields);
    }

    public function testEnsureBlockingFilterCreatesFilterRuleAndRejectAction(): void
    {
        SpamblockTicketFilter::ensureBlockingFilterExists();

        $filter = Filter::getByName(SpamblockTicketFilter::FILTER_NAME);
        $this->assertNotNull($filter);

        $this->assertTrue($filter->isActive());
        $this->assertSame('Email', $filter->getTarget());
        $this->assertTrue($filter->stopOnMatch());
        $this->assertTrue($filter->matchAllRules());

        $this->assertTrue($filter->containsRule('spamblock_should_block', 'equal', '1'));

        $hasReject = FilterAction::objects()->filter([
            'filter_id' => $filter->getId(),
            'type' => 'reject',
        ])->exists();

        $this->assertTrue($hasReject);
    }
}
