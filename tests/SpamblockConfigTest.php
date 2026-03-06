<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

require_once __DIR__ . '/../plugin/spamblock/config.php';

final class SpamblockConfigTest extends TestCase
{
    public function testGeminiOptionsArePresent(): void
    {
        $config = new SpamblockConfig();

        $options = $config->getOptions();

        $this->assertArrayHasKey('gemini_enabled', $options);
        $this->assertArrayHasKey('gemini_action', $options);
        $this->assertArrayHasKey('gemini_api_key', $options);
        $this->assertArrayHasKey('gemini_company_description', $options);
        $this->assertArrayHasKey('gemini_spam_guidelines', $options);
        $this->assertArrayHasKey('gemini_legitimate_guidelines', $options);

        $this->assertSame(false, $options['gemini_enabled']->get('default'));
        $this->assertSame('ignore', $options['gemini_action']->get('default'));
        $this->assertSame('Your company is a class leading business in <DESCRIBE BUSINESS>.', $options['gemini_company_description']->get('default'));
    }

    public function testGeminiGettersUseDefaultsWhenUnset(): void
    {
        $config = new SpamblockConfig();

        $this->assertFalse($config->isGeminiEnabled());
        $this->assertSame('ignore', $config->getGeminiAction());
        $this->assertSame('', $config->getGeminiApiKey());
        $this->assertStringContainsString('class leading business', $config->getGeminiCompanyDescription());
        $this->assertStringContainsString('Phishing:', $config->getGeminiSpamGuidelines());
        $this->assertStringContainsString('Business Queries:', $config->getGeminiLegitimateGuidelines());
    }

    public function testGeminiGettersReturnOverrides(): void
    {
        $config = new SpamblockConfig();
        $config->set('gemini_enabled', true);
        $config->set('gemini_action', 'spam');
        $config->set('gemini_api_key', 'secret-key');
        $config->set('gemini_company_description', 'Custom company');
        $config->set('gemini_spam_guidelines', 'Custom spam guidance');
        $config->set('gemini_legitimate_guidelines', 'Custom legitimate guidance');

        $this->assertTrue($config->isGeminiEnabled());
        $this->assertSame('spam', $config->getGeminiAction());
        $this->assertSame('secret-key', $config->getGeminiApiKey());
        $this->assertSame('Custom company', $config->getGeminiCompanyDescription());
        $this->assertSame('Custom spam guidance', $config->getGeminiSpamGuidelines());
        $this->assertSame('Custom legitimate guidance', $config->getGeminiLegitimateGuidelines());
    }

}
