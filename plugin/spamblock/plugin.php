<?php

return [
    'id' => 'spamblock',
    'version' => '0.2.0',
    'name' => 'Spamblock',
    'author' => 'spamblock',
    'description' => 'Spam-check inbound email tickets and block them over a configurable score threshold.',
    'plugin' => 'spamblock.php:SpamblockPlugin',
];
