<?php

require_once INCLUDE_DIR . 'class.plugin.php';
require_once INCLUDE_DIR . 'class.forms.php';

class SpamblockConfig extends PluginConfig
{
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
}
