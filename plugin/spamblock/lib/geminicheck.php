<?php

class SpamblockGeminiSpamCheckProvider implements SpamblockSpamCheckProvider
{
    private const MODEL = 'gemini-3-flash-preview';
    private const ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-3-flash-preview:generateContent';

    private $apiKey;
    private $companyDescription;
    private $spamGuidelines;
    private $legitimateGuidelines;
    private $http;

    public function __construct(
        $apiKey,
        $companyDescription,
        $spamGuidelines,
        $legitimateGuidelines,
        $http = null
    ) {
        $this->apiKey = trim((string) $apiKey);
        $this->companyDescription = trim((string) $companyDescription);
        $this->spamGuidelines = trim((string) $spamGuidelines);
        $this->legitimateGuidelines = trim((string) $legitimateGuidelines);
        $this->http = $http instanceof SpamblockHttpClient
            ? $http
            : new SpamblockStreamHttpClient();
    }

    public function getName()
    {
        return 'gemini';
    }

    public function check(SpamblockEmailContext $context)
    {
        $debugData = [
            'url' => self::ENDPOINT,
            'url_called' => self::ENDPOINT,
            'method' => 'POST',
            'timeout_seconds' => 20,
            'model' => self::MODEL,
            'thinking_level' => 'high',
        ];

        if ($this->apiKey === '') {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Gemini is enabled but API key is empty',
                null,
                $debugData
            );
        }

        $systemPrompt = $this->buildSystemPrompt();

        $payload = [
            'systemInstruction' => [
                'parts' => [
                    ['text' => $systemPrompt],
                ],
            ],
            'contents' => [
                [
                    'role' => 'user',
                    'parts' => [
                        ['text' => $context->getRawEmail()],
                    ],
                ],
            ],
            'generationConfig' => [
                'temperature' => 0,
                'responseMimeType' => 'application/json',
                'responseJsonSchema' => [
                    'type' => 'object',
                    'properties' => [
                        'spam' => [
                            'type' => 'boolean',
                        ],
                        'reasoning' => [
                            'type' => 'string',
                        ],
                    ],
                    'required' => ['spam', 'reasoning'],
                ],
                'thinkingConfig' => [
                    'thinkingLevel' => 'high',
                ],
            ],
        ];

        $encodedPayload = json_encode($payload);
        if ($encodedPayload === false) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Unable to encode Gemini request payload',
                null,
                $debugData
            );
        }

        $res = $this->http->request(
            'POST',
            self::ENDPOINT,
            20,
            [
                'Content-Type: application/json',
                'User-Agent: spamblock/0.6.0',
                'x-goog-api-key: ' . $this->apiKey,
            ],
            $encodedPayload
        );

        $status = isset($res['status']) ? (int) $res['status'] : 0;
        if (empty($res['ok'])) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Network error calling Gemini',
                $status,
                $debugData
            );
        }

        $responseBody = isset($res['body']) ? (string) $res['body'] : '';
        if ($status < 200 || $status >= 300) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Non-2xx response from Gemini',
                $status,
                $debugData
            );
        }

        $decoded = json_decode($responseBody, true);
        if (!is_array($decoded)) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Unable to decode Gemini API response JSON',
                $status,
                $debugData
            );
        }

        $candidateText = $this->extractCandidateText($decoded);
        if ($candidateText === null) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Gemini response did not contain text output',
                $status,
                $debugData
            );
        }

        $output = json_decode($candidateText, true);
        if (!is_array($output)) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Gemini returned non-JSON structured output',
                $status,
                $debugData
            );
        }

        if (!array_key_exists('spam', $output) || !is_bool($output['spam'])) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Gemini output field "spam" is missing or not boolean',
                $status,
                $debugData
            );
        }

        if (!array_key_exists('reasoning', $output) || !is_string($output['reasoning'])) {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Gemini output field "reasoning" is missing or not string',
                $status,
                $debugData
            );
        }

        $reasoning = trim($output['reasoning']);
        if ($reasoning === '') {
            return new SpamblockSpamCheckResult(
                $this->getName(),
                null,
                'Gemini output field "reasoning" is empty',
                $status,
                $debugData
            );
        }

        $isSpam = $output['spam'];
        $debugData['spam'] = $isSpam;
        $debugData['reasoning'] = $reasoning;

        return new SpamblockSpamCheckResult(
            $this->getName(),
            $isSpam ? 1.0 : 0.0,
            null,
            $status,
            $debugData
        );
    }

    private function buildSystemPrompt()
    {
        return str_replace(
            ['<FIELD 1>', '<FIELD 2>', '<FIELD 3>'],
            [$this->companyDescription, $this->spamGuidelines, $this->legitimateGuidelines],
            <<<'PROMPT'
# Persona
You are the Lead Security & Triage Officer. <FIELD 1>. You are an expert at identifying malicious intent, phishing, and irrelevant bulk marketing while maintaining a high tolerance for legitimate business-to-business (B2B) outreach.

# Task
Your task is to analyze incoming emails and classify them as spam (true) or legitimate (false).

# Guidelines for Classification
- SPAM (spam: true):
  <FIELD 2>

- LEGITIMATE (spam: false):
  <FIELD 3>

# Reasoning Requirement
To ensure accuracy, first perform a brief internal analysis of the sender, the urgency of the tone, and the relevance to the company.

# Output Format
Return ONLY a JSON object with the following structure:
{
 "reasoning": "A one-sentence explanation of why this was or wasn't flagged.",
 "spam": boolean
}
PROMPT
        );
    }

    private function extractCandidateText(array $decoded)
    {
        if (!isset($decoded['candidates']) || !is_array($decoded['candidates'])) {
            return null;
        }

        foreach ($decoded['candidates'] as $candidate) {
            if (!is_array($candidate)) {
                continue;
            }

            $content = $candidate['content'] ?? null;
            if (!is_array($content)) {
                continue;
            }

            $parts = $content['parts'] ?? null;
            if (!is_array($parts)) {
                continue;
            }

            foreach ($parts as $part) {
                if (!is_array($part)) {
                    continue;
                }

                if (!array_key_exists('text', $part) || !is_string($part['text'])) {
                    continue;
                }

                $text = trim($part['text']);
                if ($text !== '') {
                    return $text;
                }
            }
        }

        return null;
    }
}
