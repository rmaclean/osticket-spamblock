<?php

require_once INCLUDE_DIR . 'class.plugin.php';
require_once INCLUDE_DIR . 'class.forms.php';

class SpamblockConfig extends PluginConfig
{
    private const CHOICES_IGNORE_SPAM = "ignore:Do Nothing\nspam:Treat as Spam";
    private const CHOICES_LOG_LEVEL = "debug:Debug\nwarning:Warning\nerror:Error";

    public function getOptions()
    {
        return [
            'min_block_score' => new TextboxField([
                'id' => 1,
                'label' => __('Minimum spam score to block'),
                'required' => true,
                'default' => '5.0',
                'hint' => __('SpamAssassin-style score from Postmark Spamcheck. Higher scores are more spam.'),
                'configuration' => [
                    'size' => 6,
                    'length' => 10,
                ],
                'validator' => 'number',
            ]),
            'sfs_min_confidence' => new TextboxField([
                'id' => 2,
                'label' => __('SFS Minimum Confidence (%)'),
                'required' => true,
                'default' => '90.0',
                'hint' => __('StopForumSpam confidence percentage (0-100). Higher is more likely spam.'),
                'configuration' => [
                    'size' => 6,
                    'length' => 10,
                ],
                'validator' => 'number',
            ]),
            'test_mode' => new BooleanField([
                'id' => 3,
                'label' => __('Test Mode'),
                'hint' => __('When enabled, Spamblock will not block tickets; it will only log what would have been blocked.'),
                'default' => false,
            ]),
            'spf_fail_action' => new ChoiceField([
                'id' => 4,
                'label' => __('SPF Check Fails'),
                'required' => true,
                'default' => 'ignore',
                'hint' => __('SPF record exists but the sending IP is not allowed.'),
                'configuration' => [
                    'choices' => self::CHOICES_IGNORE_SPAM,
                ],
            ]),
            'spf_none_action' => new ChoiceField([
                'id' => 5,
                'label' => __('SPF Record Missing'),
                'required' => true,
                'default' => 'ignore',
                'hint' => __('No SPF record found for the sender domain.'),
                'configuration' => [
                    'choices' => self::CHOICES_IGNORE_SPAM,
                ],
            ]),
            'spf_invalid_action' => new ChoiceField([
                'id' => 6,
                'label' => __('SPF Record Invalid'),
                'required' => true,
                'default' => 'ignore',
                'hint' => __('SPF record is invalid or could not be evaluated.'),
                'configuration' => [
                    'choices' => self::CHOICES_IGNORE_SPAM,
                ],
            ]),
            'blocked_email_log_level' => new ChoiceField([
                'id' => 7,
                'label' => __('Blocked Email Log Level'),
                'required' => true,
                'default' => 'warning',
                'hint' => __('Log level for "Spamblock - Blocked Email" and "Spamblock - Would have blocked Email". Higher levels may trigger osTicket email alerts.'),
                'configuration' => [
                    'choices' => self::CHOICES_LOG_LEVEL,
                ],
            ]),
        ];
    }

    public function getMinBlockScore()
    {
        $val = $this->get('min_block_score');
        if ($val === null || $val === '') {
            return 5.0;
        }

        return (float) $val;
    }

    public function getSfsMinConfidence()
    {
        $val = $this->get('sfs_min_confidence');
        if ($val === null || $val === '') {
            return 90.0;
        }

        return (float) $val;
    }

    public function getTestMode()
    {
        return (bool) $this->get('test_mode');
    }

    public function getSpfFailAction()
    {
        $val = (string) $this->get('spf_fail_action');
        return $val ?: 'ignore';
    }

    public function getSpfNoneAction()
    {
        $val = (string) $this->get('spf_none_action');
        return $val ?: 'ignore';
    }

    public function getSpfInvalidAction()
    {
        $val = (string) $this->get('spf_invalid_action');
        return $val ?: 'ignore';
    }

    public function isSpfEnabled()
    {
        return $this->getSpfFailAction() === 'spam'
            || $this->getSpfNoneAction() === 'spam'
            || $this->getSpfInvalidAction() === 'spam';
    }

    public function getBlockedEmailLogLevel()
    {
        $val = strtolower(trim((string) $this->get('blocked_email_log_level')));
        if (!in_array($val, ['debug', 'warning', 'error'], true)) {
            return 'warning';
        }

        return $val;
    }
}
