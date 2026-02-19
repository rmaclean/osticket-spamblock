<?php

class SpamblockTicketSpamMeta
{
    private const TABLE = 'spamblock_ticket_spam_meta';

    public static function autoCreateTable()
    {
        $sql = 'SHOW TABLES LIKE \'' . TABLE_PREFIX . self::TABLE . '\'';
        if (db_num_rows(db_query($sql))) {
            return true;
        }

        $sql = sprintf(
            'CREATE TABLE `%s` (
                `ticket_id` int(10) unsigned NOT NULL,
                `email` varchar(255) NOT NULL DEFAULT \'\',
                `is_spam` tinyint(1) unsigned NOT NULL DEFAULT 0,
                `postmark_score` double DEFAULT NULL,
                `sfs_confidence` double DEFAULT NULL,
                `created` datetime NOT NULL,
                `updated` datetime NOT NULL,
                PRIMARY KEY (`ticket_id`),
                KEY `is_spam` (`is_spam`)
            ) CHARSET=utf8',
            TABLE_PREFIX . self::TABLE
        );

        return db_query($sql);
    }

    public static function upsert($ticketId, $email, $isSpam, $postmarkScore, $sfsConfidence)
    {
        if (!$ticketId) {
            return false;
        }

        self::autoCreateTable();

        $sql = sprintf(
            'REPLACE INTO `%s` (`ticket_id`, `email`, `is_spam`, `postmark_score`, `sfs_confidence`, `created`, `updated`)
            VALUES (%s, %s, %s, %s, %s, NOW(), NOW())',
            TABLE_PREFIX . self::TABLE,
            db_input($ticketId),
            db_input((string) $email),
            db_input($isSpam ? 1 : 0),
            $postmarkScore === null ? 'NULL' : db_input((float) $postmarkScore),
            $sfsConfidence === null ? 'NULL' : db_input((float) $sfsConfidence)
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
            'SELECT `ticket_id`, `email`, `is_spam`, `postmark_score`, `sfs_confidence`
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
        ];
    }
}
