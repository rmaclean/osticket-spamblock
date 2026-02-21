<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/spamblock.php';

final class SpamblockPluginTest extends TestCase
{
    protected function setUp(): void
    {
        $GLOBALS['ost'] = new OstTestLogger();
    }

    public function testOnTicketCreateBeforeSetsFieldsAndBlocksWhenOverThreshold(): void
    {
        $plugin = new SpamblockPlugin();

        $cfg = new SpamblockConfig();
        $cfg->set('min_block_score', '5.0');
        $cfg->set('sfs_min_confidence', '90.0');
        $cfg->set('test_mode', false);
        $cfg->set('spf_fail_action', 'ignore');
        $cfg->set('spf_none_action', 'ignore');
        $cfg->set('spf_invalid_action', 'ignore');
        $cfg->set('blocked_email_log_level', 'warning');

        $checker = new FakeChecker([
            new SpamblockSpamCheckResult('postmark', 6.0, null, 200),
            new SpamblockSpamCheckResult('sfs', 10.0, null, 200),
        ]);

        $this->setPrivate($plugin, 'spamblockConfig', $cfg);
        $this->setPrivate($plugin, 'spamChecker', $checker);
        $this->setPrivate($plugin, 'spamCheckerHasSpf', false);

        $vars = [
            'emailId' => 1,
            'mid' => '<mid@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'hi',
            'header' => "From: sender@example.com\r\n\r\n",
            'message' => 'hello',
        ];

        $plugin->onTicketCreateBefore(null, $vars);

        $this->assertSame('postmark', $vars['spamblock_provider']);
        $this->assertSame('6', $vars['spamblock_score']);
        $this->assertSame('1', $vars['spamblock_should_block']);
    }

    public function testOnTicketCreateBeforeNoHeaderDoesNothing(): void
    {
        $plugin = new SpamblockPlugin();

        $cfg = new SpamblockConfig();
        $cfg->set('min_block_score', '5.0');
        $cfg->set('sfs_min_confidence', '90.0');
        $cfg->set('test_mode', false);
        $cfg->set('spf_fail_action', 'ignore');
        $cfg->set('spf_none_action', 'ignore');
        $cfg->set('spf_invalid_action', 'ignore');
        $cfg->set('blocked_email_log_level', 'warning');

        $checker = new FakeChecker([
            new SpamblockSpamCheckResult('postmark', 999.0, null, 200),
        ]);

        $this->setPrivate($plugin, 'spamblockConfig', $cfg);
        $this->setPrivate($plugin, 'spamChecker', $checker);
        $this->setPrivate($plugin, 'spamCheckerHasSpf', false);

        $vars = [
            'emailId' => 1,
            'mid' => '<mid-no-header@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'hi',
            'header' => null,
            'message' => 'hello',
        ];

        $plugin->onTicketCreateBefore(null, $vars);

        $this->assertArrayNotHasKey('spamblock_provider', $vars);
        $this->assertArrayNotHasKey('spamblock_score', $vars);
        $this->assertArrayNotHasKey('spamblock_should_block', $vars);
    }

    public function testTestModeNeverBlocks(): void
    {
        $plugin = new SpamblockPlugin();

        $cfg = new SpamblockConfig();
        $cfg->set('min_block_score', '5.0');
        $cfg->set('sfs_min_confidence', '90.0');
        $cfg->set('test_mode', true);
        $cfg->set('spf_fail_action', 'ignore');
        $cfg->set('spf_none_action', 'ignore');
        $cfg->set('spf_invalid_action', 'ignore');
        $cfg->set('blocked_email_log_level', 'warning');

        $checker = new FakeChecker([
            new SpamblockSpamCheckResult('postmark', 999.0, null, 200),
        ]);

        $this->setPrivate($plugin, 'spamblockConfig', $cfg);
        $this->setPrivate($plugin, 'spamChecker', $checker);
        $this->setPrivate($plugin, 'spamCheckerHasSpf', false);

        $vars = [
            'emailId' => 1,
            'mid' => '<mid2@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'hi',
            'header' => "From: sender@example.com\r\n\r\n",
            'message' => 'hello',
        ];

        $plugin->onTicketCreateBefore(null, $vars);

        $this->assertSame('0', $vars['spamblock_should_block']);
    }

    public function testBlockedEmailLogLevelDebugUsesDebug(): void
    {
        $plugin = new SpamblockPlugin();

        $cfg = new SpamblockConfig();
        $cfg->set('min_block_score', '5.0');
        $cfg->set('sfs_min_confidence', '90.0');
        $cfg->set('test_mode', false);
        $cfg->set('spf_fail_action', 'ignore');
        $cfg->set('spf_none_action', 'ignore');
        $cfg->set('spf_invalid_action', 'ignore');
        $cfg->set('blocked_email_log_level', 'debug');

        $checker = new FakeChecker([
            new SpamblockSpamCheckResult('postmark', 6.0, null, 200),
        ]);

        $this->setPrivate($plugin, 'spamblockConfig', $cfg);
        $this->setPrivate($plugin, 'spamChecker', $checker);
        $this->setPrivate($plugin, 'spamCheckerHasSpf', false);

        $vars = [
            'emailId' => 1,
            'mid' => '<mid-block-debug@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'hi',
            'header' => "From: sender@example.com\r\n\r\n",
            'message' => 'hello',
        ];

        $plugin->onTicketCreateBefore(null, $vars);

        $logger = $GLOBALS['ost'];
        $this->assertInstanceOf(OstTestLogger::class, $logger);

        $blockedInWarnings = array_values(array_filter($logger->warnings, function ($row) {
            return isset($row[0]) && $row[0] === 'Spamblock - Blocked Email';
        }));

        $blockedInDebug = array_values(array_filter($logger->debug, function ($row) {
            return isset($row[0]) && $row[0] === 'Spamblock - Blocked Email';
        }));

        $this->assertCount(0, $blockedInWarnings);
        $this->assertCount(1, $blockedInDebug);
    }

    public function testOnTicketCreatedWritesSpamMetaAndClearsRecentChecks(): void
    {
        $plugin = new SpamblockPlugin();

        $checker = new FakeChecker([
            new SpamblockSpamCheckResult('postmark', 6.0, null, 200),
        ]);

        $cfg = new SpamblockConfig();
        $cfg->set('min_block_score', '5.0');
        $cfg->set('sfs_min_confidence', '90.0');
        $cfg->set('test_mode', false);
        $cfg->set('spf_fail_action', 'ignore');
        $cfg->set('spf_none_action', 'ignore');
        $cfg->set('spf_invalid_action', 'ignore');
        $cfg->set('blocked_email_log_level', 'warning');

        $this->setPrivate($plugin, 'spamblockConfig', $cfg);
        $this->setPrivate($plugin, 'spamChecker', $checker);
        $this->setPrivate($plugin, 'spamCheckerHasSpf', false);

        $vars = [
            'emailId' => 1,
            'mid' => '<mid3@example.com>',
            'email' => 'sender@example.com',
            'subject' => 'hi',
            'header' => "From: sender@example.com\r\n\r\n",
            'message' => 'hello',
        ];

        $plugin->onTicketCreateBefore(null, $vars);

        $ticket = new TicketStub(42, 'T-42', 'sender@example.com', '<mid3@example.com>');
        $plugin->onTicketCreated($ticket);

        $meta = SpamblockTicketSpamMeta::lookup(42);

        $this->assertIsArray($meta);
        $this->assertTrue($meta['is_spam']);
        $this->assertSame(6.0, $meta['postmark_score']);

        $recent = $this->getPrivate($plugin, 'recentChecks');
        $this->assertSame([], $recent);
    }

    private function setPrivate(object $obj, string $prop, $value): void
    {
        $ref = new ReflectionClass($obj);
        $p = $ref->getProperty($prop);
        $p->setAccessible(true);
        $p->setValue($obj, $value);
    }

    private function getPrivate(object $obj, string $prop)
    {
        $ref = new ReflectionClass($obj);
        $p = $ref->getProperty($prop);
        $p->setAccessible(true);
        return $p->getValue($obj);
    }
}

final class FakeChecker
{
    private $results;

    public function __construct(array $results)
    {
        $this->results = $results;
    }

    public function check($context)
    {
        return $this->results;
    }
}

final class OstTestLogger
{
    public $warnings = [];
    public $debug = [];
    public $errors = [];

    public function logWarning($title, $message, $force)
    {
        $this->warnings[] = [$title, $message];
    }

    public function logDebug($title, $message, $force)
    {
        $this->debug[] = [$title, $message];
    }

    public function logError($title, $message, $force)
    {
        $this->errors[] = [$title, $message];
    }

    public function getCSRF()
    {
        return null;
    }
}

final class TicketStub
{
    private $id;
    private $number;
    private $email;
    private $mid;

    public function __construct($id, $number, $email, $mid)
    {
        $this->id = $id;
        $this->number = $number;
        $this->email = $email;
        $this->mid = $mid;
    }

    public function getLastMessage()
    {
        return new MessageStub($this->mid);
    }

    public function getId()
    {
        return $this->id;
    }

    public function getEmail()
    {
        return $this->email;
    }

    public function getNumber()
    {
        return $this->number;
    }
}

final class MessageStub
{
    private $mid;

    public function __construct($mid)
    {
        $this->mid = $mid;
    }

    public function getEmailMessageId()
    {
        return $this->mid;
    }
}
