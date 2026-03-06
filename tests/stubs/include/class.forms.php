<?php

class StubFormField
{
    private $config;

    public function __construct($config)
    {
        $this->config = $config;
    }

    public function get($key)
    {
        return $this->config[$key] ?? null;
    }
}

class PasswordField extends StubFormField
{
}

class BooleanField extends StubFormField
{
}

class ChoiceField extends StubFormField
{
}

class TextboxField extends StubFormField
{
}

class TextareaField extends StubFormField
{
}
