<?php

class Banlist
{
    private static $emails = [];

    public static function add($email, $submitter = '')
    {
        $email = self::normalize($email);
        if ($email === '') {
            return false;
        }

        self::$emails[$email] = true;

        return true;
    }

    public static function remove($email)
    {
        unset(self::$emails[self::normalize($email)]);

        return true;
    }

    public static function isBanned($addr)
    {
        $email = self::normalize($addr);
        if ($email === '') {
            return false;
        }

        return self::$emails[$email] ?? false;
    }

    public static function includes($email)
    {
        return self::isBanned($email);
    }

    public static function reset()
    {
        self::$emails = [];
    }

    private static function normalize($email)
    {
        return strtolower(trim((string) $email));
    }
}
