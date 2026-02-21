<?php

class Filter
{
    private static $filtersByName = [];
    private static $supportedMatches = [];

    public $isactive;
    public $target;
    public $name;
    public $execorder;
    public $match_all_rules;
    public $stop_onmatch;
    public $notes;

    private $id;
    private $rules = [];

    public function __construct($props = [])
    {
        foreach ($props as $k => $v) {
            $this->$k = $v;
        }

        $this->id = rand(1000, 9999);
    }

    public static function addSupportedMatches($label, $fn, $priority)
    {
        self::$supportedMatches[] = [$label, $fn, $priority];
    }

    public static function getSupportedMatches()
    {
        return self::$supportedMatches;
    }

    public static function getByName($name)
    {
        return self::$filtersByName[$name] ?? null;
    }

    public function save($force = false)
    {
        self::$filtersByName[$this->name] = $this;
        return true;
    }

    public function getId()
    {
        return $this->id;
    }

    public function isActive()
    {
        return (int) $this->isactive === 1;
    }

    public function getTarget()
    {
        return (string) $this->target;
    }

    public function stopOnMatch()
    {
        return (int) $this->stop_onmatch === 1;
    }

    public function matchAllRules()
    {
        return (int) $this->match_all_rules === 1;
    }

    public function containsRule($field, $op, $value)
    {
        foreach ($this->rules as $r) {
            if ($r['field'] === $field && $r['op'] === $op && $r['value'] === $value) {
                return true;
            }
        }

        return false;
    }

    public function addRule($field, $op, $value)
    {
        $this->rules[] = [
            'field' => $field,
            'op' => $op,
            'value' => $value,
        ];

        return true;
    }

    public function getRules()
    {
        return $this->rules;
    }
}

class FilterAction
{
    private static $actions = [];

    public $type;
    public $filter_id;
    public $sort;
    public $configuration;

    public function __construct($props = [])
    {
        foreach ($props as $k => $v) {
            $this->$k = $v;
        }
    }

    public static function objects()
    {
        return new FilterActionQuery(self::$actions);
    }

    public function save($force = false)
    {
        self::$actions[] = [
            'type' => $this->type,
            'filter_id' => $this->filter_id,
        ];

        return true;
    }
}

class FilterActionQuery
{
    private $actions;
    private $filter = [];

    public function __construct($actions)
    {
        $this->actions = $actions;
    }

    public function filter($criteria)
    {
        $this->filter = $criteria;
        return $this;
    }

    public function exists()
    {
        foreach ($this->actions as $a) {
            $ok = true;
            foreach ($this->filter as $k => $v) {
                if (!isset($a[$k]) || $a[$k] !== $v) {
                    $ok = false;
                    break;
                }
            }

            if ($ok) {
                return true;
            }
        }

        return false;
    }
}
