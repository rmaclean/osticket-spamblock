<?php

require_once INCLUDE_DIR . 'class.plugin.php';
require_once INCLUDE_DIR . 'class.forms.php';

class SpamblockConfig extends PluginConfig
{
    private const CHOICES_IGNORE_SPAM = "ignore:Do Nothing\nspam:Treat as Spam";
    private const CHOICES_LOG_LEVEL = "debug:Debug\nwarning:Warning\nerror:Error";
    private const DEFAULT_GEMINI_COMPANY_DESCRIPTION = 'Your company is a class leading business in <DESCRIBE BUSINESS>.';
    private const DEFAULT_GEMINI_SPAM_GUIDELINES = "- Phishing: Claims of password resets, \"mailbox full,\" or \"action required\" from non-company services.\n- Identity Fraud: Senders pretending to be staff but using public domains (gmail.com, outlook.com) or mismatched company domains.\n- Irrelevant Marketing: Generic offers (for example global SEO, generic office supplies, or diet pills) that have no connection to the business.\n- Suspicious Links: Emails pressuring the user to click links or download attachments for \"unpaid invoices\" outside official channels.";
    private const DEFAULT_GEMINI_LEGITIMATE_GUIDELINES = "- Business Queries: Questions about your company.\n- Contextual B2B: Offers that are relevant to the business.\n- Unsure: If you cannot confidently identify it as spam, mark it as legitimate to avoid missing genuine emails.";

    public function getOptions()
    {
        return [
            'test_mode' => new BooleanField([
                'id' => 3,
                'label' => __('Test Mode'),
                'hint' => __('When enabled, Spamblock will not block tickets; it will only log what would have been blocked.'),
                'default' => false,
            ]),
            'blocked_email_log_level' => new ChoiceField([
                'id' => 7,
                'label' => __('Blocked email log level'),
                'required' => true,
                'default' => 'warning',
                'hint' => __('Log level for "Spamblock - Blocked Email" and "Spamblock - Would have blocked Email". Higher levels may trigger osTicket email alerts. Recommended: Error.'),
                'configuration' => [
                    'choices' => self::CHOICES_LOG_LEVEL,
                ],
            ]),
            'min_block_score' => new TextboxField([
                'id' => 1,
                'label' => __('Postmark: minimum score to block'),
                'required' => true,
                'default' => '5.0',
                'hint' => __('SpamAssassin-style score from Postmark Spamcheck. Higher scores are more spam. Recommended: 4.5.'),
                'configuration' => [
                    'size' => 6,
                    'length' => 10,
                ],
                'validator' => 'number',
            ]),
            'sfs_min_confidence' => new TextboxField([
                'id' => 2,
                'label' => __('StopForumSpam: minimum confidence (%)'),
                'required' => true,
                'default' => '90.0',
                'hint' => __('StopForumSpam confidence percentage (0-100). Higher is more likely spam. Recommended: 90.'),
                'configuration' => [
                    'size' => 6,
                    'length' => 10,
                ],
                'validator' => 'number',
            ]),
            'spf_fail_action' => new ChoiceField([
                'id' => 4,
                'label' => __('SPF: check fails'),
                'required' => true,
                'default' => 'ignore',
                'hint' => __('What to do when the SPF record exists but the sending IP is not allowed. Recommended: Treat as Spam.'),
                'configuration' => [
                    'choices' => self::CHOICES_IGNORE_SPAM,
                ],
            ]),
            'spf_none_action' => new ChoiceField([
                'id' => 5,
                'label' => __('SPF: record missing'),
                'required' => true,
                'default' => 'ignore',
                'hint' => __('What to do when no SPF record is found for the sender domain. Recommended: Do Nothing.'),
                'configuration' => [
                    'choices' => self::CHOICES_IGNORE_SPAM,
                ],
            ]),
            'spf_invalid_action' => new ChoiceField([
                'id' => 6,
                'label' => __('SPF: record invalid'),
                'required' => true,
                'default' => 'ignore',
                'hint' => __('What to do when the SPF record is invalid. Recommended: Do Nothing.'),
                'configuration' => [
                    'choices' => self::CHOICES_IGNORE_SPAM,
                ],
            ]),
            'spf_unsupported_mechanism_action' => new ChoiceField([
                'id' => 8,
                'label' => __('SPF: unsupported mechanism'),
                'required' => true,
                'default' => 'ignore',
                'hint' => __('What to do when the SPF record contains unsupported mechanisms. Recommended: Do Nothing.'),
                'configuration' => [
                    'choices' => self::CHOICES_IGNORE_SPAM,
                ],
            ]),
            'esmtpsa_bypass_enabled' => new BooleanField([
                'id' => 15,
                'label' => __('Enable ESMTPSA bypass'),
                'default' => true,
                'hint' => __('When enabled, Spamblock skips provider checks for messages whose top Received hop shows authenticated SMTP submission (ESMTPSA). Recommended: Enabled.'),
            ]),
            'gemini_enabled' => new BooleanField([
                'id' => 9,
                'label' => __('Enable AI Spam Check'),
                'default' => false,
                'hint' => __('Turns the AI spam review on or off. When it is off, the AI settings below stay inactive. Recommended: Enabled.'),
            ]),
            'gemini_action' => new ChoiceField([
                'id' => 10,
                'label' => __('Gemini: when spam is detected'),
                'default' => 'ignore',
                'hint' => __('Choose what Spamblock should do when AI classifies an email as spam. Recommended: Treat as Spam.'),
                'configuration' => [
                    'choices' => self::CHOICES_IGNORE_SPAM,
                ],
            ]),
            'gemini_api_key' => new PasswordField([
                'id' => 11,
                'label' => __('Gemini: API key'),
                'default' => '',
                'hint' => __('API key used for AI spam checks. <a href="https://aistudio.google.com/u/1/api-keys" target="_blank" rel="noopener noreferrer">Click here to get your API key</a>.'),
                'configuration' => [
                    'size' => 40,
                    'length' => 255,
                ],
            ]),
            'gemini_company_description' => new TextareaField([
                'id' => 12,
                'label' => __('Company Description for AI'),
                'default' => self::DEFAULT_GEMINI_COMPANY_DESCRIPTION,
                'hint' => __('Describe your business so that the AI can better understand which inbound emails are relevant.'),
                'configuration' => [
                    'rows' => 4,
                    'cols' => 72,
                ],
            ]),
            'gemini_spam_guidelines' => new TextareaField([
                'id' => 13,
                'label' => __('Spam Guidelines for AI'),
                'default' => self::DEFAULT_GEMINI_SPAM_GUIDELINES,
                'hint' => __('Describe what the AI should treat as spam for your help desk. For example, if you only handle billing requests, you could state that anything not billing-related is spam.'),
                'configuration' => [
                    'rows' => 8,
                    'cols' => 72,
                ],
            ]),
            'gemini_legitimate_guidelines' => new TextareaField([
                'id' => 14,
                'label' => __('Legitimate Guidelines for AI'),
                'default' => self::DEFAULT_GEMINI_LEGITIMATE_GUIDELINES,
                'hint' => __('Describe what the AI should treat as legitimate for your help desk. Combined with the spam guidelines above, this gives the AI a strong view of what is and is not spam.'),
                'configuration' => [
                    'rows' => 6,
                    'cols' => 72,
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

    public function getSpfUnsupportedMechanismAction()
    {
        $val = (string) $this->get('spf_unsupported_mechanism_action');
        return $val ?: 'ignore';
    }

    public function isEsmtpsaBypassEnabled()
    {
        $val = $this->get('esmtpsa_bypass_enabled');
        if ($val === null) {
            return true;
        }

        return (bool) $val;
    }

    public function isSpfEnabled()
    {
        return $this->getSpfFailAction() === 'spam'
            || $this->getSpfNoneAction() === 'spam'
            || $this->getSpfInvalidAction() === 'spam'
            || $this->getSpfUnsupportedMechanismAction() === 'spam';
    }
    public function getBlockedEmailLogLevel()
    {
        $val = strtolower(trim((string) $this->get('blocked_email_log_level')));
        if (!in_array($val, ['debug', 'warning', 'error'], true)) {
            return 'warning';
        }

        return $val;
    }

    public function isGeminiEnabled()
    {
        return (bool) $this->get('gemini_enabled');
    }

    public function getGeminiAction()
    {
        $val = (string) $this->get('gemini_action');
        return $val ?: 'ignore';
    }

    public function getGeminiApiKey()
    {
        return trim((string) $this->get('gemini_api_key'));
    }

    public function getGeminiCompanyDescription()
    {
        $val = trim((string) $this->get('gemini_company_description'));
        return $val !== '' ? $val : self::DEFAULT_GEMINI_COMPANY_DESCRIPTION;
    }

    public function getGeminiSpamGuidelines()
    {
        $val = trim((string) $this->get('gemini_spam_guidelines'));
        return $val !== '' ? $val : self::DEFAULT_GEMINI_SPAM_GUIDELINES;
    }

    public function getGeminiLegitimateGuidelines()
    {
        $val = trim((string) $this->get('gemini_legitimate_guidelines'));
        return $val !== '' ? $val : self::DEFAULT_GEMINI_LEGITIMATE_GUIDELINES;
    }
}
