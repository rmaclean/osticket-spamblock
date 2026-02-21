<?php

class SpamblockTicketSpamMeta
{
    private const TABLE = 'spamblock_ticket_spam_meta';

    public static function autoCreateTable()
    {
        $table = TABLE_PREFIX . self::TABLE;

        $sql = 'SHOW TABLES LIKE \'' . $table . '\'';
        if (db_num_rows(db_query($sql))) {
            self::ensureColumns($table);
            return true;
        }

        $sql = sprintf(
            'CREATE TABLE `%s` (
                `ticket_id` int(10) unsigned NOT NULL,
                `email` varchar(255) NOT NULL DEFAULT \'\',
                `is_spam` tinyint(1) unsigned NOT NULL DEFAULT 0,
                `postmark_score` double DEFAULT NULL,
                `sfs_confidence` double DEFAULT NULL,
                `spf_result` varchar(16) DEFAULT NULL,
                `created` datetime NOT NULL,
                `updated` datetime NOT NULL,
                PRIMARY KEY (`ticket_id`),
                KEY `is_spam` (`is_spam`)
            ) CHARSET=utf8',
            $table
        );

        $ok = db_query($sql);
        if ($ok) {
            self::ensureColumns($table);
        }

        return $ok;
    }

    private static function ensureColumns($table)
    {
        $res = db_query(sprintf(
            'SHOW COLUMNS FROM `%s` LIKE %s',
            $table,
            db_input('spf_result')
        ));

        if ($res && db_num_rows($res)) {
            return true;
        }

        return db_query(sprintf(
            'ALTER TABLE `%s` ADD COLUMN `spf_result` varchar(16) DEFAULT NULL AFTER `sfs_confidence`',
            $table
        ));
    }

    public static function upsert($ticketId, $email, $isSpam, $postmarkScore, $sfsConfidence, $spfResult = null)
    {
        if (!$ticketId) {
            return false;
        }

        self::autoCreateTable();

        $sql = sprintf(
            'REPLACE INTO `%s` (`ticket_id`, `email`, `is_spam`, `postmark_score`, `sfs_confidence`, `spf_result`, `created`, `updated`)
            VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())',
            TABLE_PREFIX . self::TABLE,
            db_input($ticketId),
            db_input((string) $email),
            db_input($isSpam ? 1 : 0),
            $postmarkScore === null ? 'NULL' : db_input((float) $postmarkScore),
            $sfsConfidence === null ? 'NULL' : db_input((float) $sfsConfidence),
            $spfResult === null || $spfResult === '' ? 'NULL' : db_input((string) $spfResult)
        );

        return db_query($sql);
    }

    public static function lookup($ticketId)
    {
        if (!$ticketId) {
            return null;
        }

        self::autoCreateTable();

        $sql = sprintf(
            'SELECT `ticket_id`, `email`, `is_spam`, `postmark_score`, `sfs_confidence`, `spf_result`
            FROM `%s`
            WHERE `ticket_id`=%s',
            TABLE_PREFIX . self::TABLE,
            db_input($ticketId)
        );

        $res = db_query($sql);
        if (!$res || !db_num_rows($res)) {
            return null;
        }

        $row = db_fetch_array($res);

        return [
            'ticket_id' => (int) $row['ticket_id'],
            'email' => (string) $row['email'],
            'is_spam' => ((int) $row['is_spam']) === 1,
            'postmark_score' => $row['postmark_score'] !== null ? (float) $row['postmark_score'] : null,
            'sfs_confidence' => $row['sfs_confidence'] !== null ? (float) $row['sfs_confidence'] : null,
            'spf_result' => $row['spf_result'] !== null ? (string) $row['spf_result'] : null,
        ];
    }
}
