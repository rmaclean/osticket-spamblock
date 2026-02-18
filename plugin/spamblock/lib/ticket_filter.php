<?php

require_once INCLUDE_DIR . 'class.filter.php';

class SpamblockTicketFilter
{
    public const FILTER_NAME = 'Spamblock: block by score';

    private static $matchesRegistered = false;

    public static function registerMatchFields()
    {
        if (self::$matchesRegistered) {
            return;
        }

        Filter::addSupportedMatches(
            'Spamblock',
            function () {
                return [
                    'spamblock_should_block' => __('Should block (0/1)'),
                    'spamblock_score' => __('Score'),
                    'spamblock_provider' => __('Provider'),
                ];
            },
            50
        );

        self::$matchesRegistered = true;
    }

    public static function ensureBlockingFilterExists()
    {
        $filter = Filter::getByName(self::FILTER_NAME);
        if (!$filter) {
            $filter = new Filter([
                'isactive' => 1,
                'target' => 'Email',
                'name' => self::FILTER_NAME,
                'execorder' => 1,
                'match_all_rules' => 1,
                'stop_onmatch' => 1,
                'notes' => __('Managed by the Spamblock plugin. Edit with care.'),
            ]);

            if (!$filter->save(true)) {
                return;
            }
        } else {
            $dirty = false;

            if (!$filter->isActive()) {
                $filter->isactive = 1;
                $dirty = true;
            }

            if (strcasecmp($filter->getTarget(), 'Email') !== 0) {
                $filter->target = 'Email';
                $dirty = true;
            }

            if (!$filter->stopOnMatch()) {
                $filter->stop_onmatch = 1;
                $dirty = true;
            }

            if (!$filter->matchAllRules()) {
                $filter->match_all_rules = 1;
                $dirty = true;
            }

            if ($dirty) {
                $filter->save(true);
            }
        }

        if (!$filter->containsRule('spamblock_should_block', 'equal', '1')) {
            $filter->addRule('spamblock_should_block', 'equal', '1');
        }

        $hasReject = FilterAction::objects()->filter([
            'filter_id' => $filter->getId(),
            'type' => 'reject',
        ])->exists();

        if (!$hasReject) {
            $action = new FilterAction([
                'type' => 'reject',
                'filter_id' => $filter->getId(),
                'sort' => 1,
                'configuration' => '{}',
            ]);
            $action->save(true);
        }
    }
}
