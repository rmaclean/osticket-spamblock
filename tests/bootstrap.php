<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '1');

if (!defined('INCLUDE_DIR')) {
    define('INCLUDE_DIR', __DIR__ . '/stubs/include/');
}

if (!defined('TABLE_PREFIX')) {
    define('TABLE_PREFIX', 'ost_');
}

if (!defined('PLUGIN_INSTANCE_TABLE')) {
    define('PLUGIN_INSTANCE_TABLE', TABLE_PREFIX . 'plugin_instance');
}

if (!function_exists('__')) {
    function __($text)
    {
        return $text;
    }
}

// Minimal DB stubs for unit tests
if (!function_exists('db_input')) {
    function db_input($value)
    {
        if ($value === null) {
            return 'NULL';
        }

        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }

        return "'" . addslashes((string) $value) . "'";
    }
}

if (!function_exists('db_query')) {
    $GLOBALS['__spamblock_db'] = [
        'tables' => [],
    ];

    function db_query($sql)
    {
        $sql = trim((string) $sql);

        $db =& $GLOBALS['__spamblock_db'];

        if (preg_match("/^SHOW TABLES LIKE '([^']+)'$/i", $sql, $m)) {
            $table = $m[1];
            $exists = array_key_exists($table, $db['tables']);
            return [
                '__type' => 'show_tables',
                'rows' => $exists ? [[0 => $table]] : [],
            ];
        }

        if (preg_match('/^CREATE TABLE `([^`]+)`/i', $sql, $m)) {
            $table = $m[1];
            if (!array_key_exists($table, $db['tables'])) {
                $db['tables'][$table] = [
                    'columns' => [
                        'ticket_id' => true,
                        'email' => true,
                        'is_spam' => true,
                        'postmark_score' => true,
                        'sfs_confidence' => true,
                    ],
                    'rows' => [],
                ];
            }

            return true;
        }

        if (preg_match('/^SHOW COLUMNS FROM `([^`]+)` LIKE ([^\s]+)$/i', $sql, $m)) {
            $table = $m[1];
            $col = trim($m[2], "'\"");

            $has = isset($db['tables'][$table]) && isset($db['tables'][$table]['columns'][$col]);

            return [
                '__type' => 'show_columns',
                'rows' => $has ? [[0 => $col]] : [],
            ];
        }

        if (preg_match('/^ALTER TABLE `([^`]+)` ADD COLUMN `([^`]+)`/i', $sql, $m)) {
            $table = $m[1];
            $col = $m[2];
            if (!isset($db['tables'][$table])) {
                $db['tables'][$table] = [
                    'columns' => [],
                    'rows' => [],
                ];
            }

            $db['tables'][$table]['columns'][$col] = true;
            return true;
        }

        if (preg_match('/^REPLACE INTO `([^`]+)`/i', $sql, $m)) {
            $table = $m[1];

            if (!isset($db['tables'][$table])) {
                $db['tables'][$table] = [
                    'columns' => [],
                    'rows' => [],
                ];
            }

            if (preg_match('/VALUES \(([^)]+)\)/i', $sql, $vm)) {
                $values = array_map('trim', explode(',', $vm[1]));
                $ticketId = (int) trim($values[0], "'\"");

                $db['tables'][$table]['rows'][$ticketId] = [
                    'ticket_id' => $ticketId,
                    'email' => trim($values[1], "'\""),
                    'is_spam' => ((int) trim($values[2], "'\"")) === 1 ? 1 : 0,
                    'postmark_score' => strtoupper($values[3]) === 'NULL' ? null : (float) trim($values[3], "'\""),
                    'sfs_confidence' => strtoupper($values[4]) === 'NULL' ? null : (float) trim($values[4], "'\""),
                    'spf_result' => strtoupper($values[5]) === 'NULL' ? null : trim($values[5], "'\""),
                ];
            }

            return true;
        }

        if (preg_match('/^SELECT `ticket_id`, `email`, `is_spam`, `postmark_score`, `sfs_confidence`, `spf_result`\s+FROM `([^`]+)`\s+WHERE `ticket_id`=([0-9]+)/i', $sql, $m)) {
            $table = $m[1];
            $ticketId = (int) $m[2];

            $row = $db['tables'][$table]['rows'][$ticketId] ?? null;

            return [
                '__type' => 'select',
                'rows' => $row ? [$row] : [],
            ];
        }

        return true;
    }
}

if (!function_exists('db_num_rows')) {
    function db_num_rows($res)
    {
        if ($res === false || $res === null) {
            return 0;
        }

        if (is_array($res) && isset($res['rows']) && is_array($res['rows'])) {
            return count($res['rows']);
        }

        return 0;
    }
}

if (!function_exists('db_fetch_array')) {
    function db_fetch_array(&$res)
    {
        if (!is_array($res) || !isset($res['rows']) || !is_array($res['rows']) || !$res['rows']) {
            return null;
        }

        return array_shift($res['rows']);
    }
}

if (!function_exists('db_fetch_row')) {
    function db_fetch_row(&$res)
    {
        $row = db_fetch_array($res);
        if ($row === null) {
            return null;
        }

        return array_values($row);
    }
}
