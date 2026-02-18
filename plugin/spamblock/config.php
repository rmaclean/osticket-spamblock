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
}
