<?php

class Plugin
{
    public function getConfig()
    {
        return null;
    }

    public function getId()
    {
        return 0;
    }
}

class PluginConfig
{
    private $data = [];

    public function __construct($namespace = null)
    {
    }

    public function get($key)
    {
        return $this->data[$key] ?? null;
    }

    public function set($key, $value)
    {
        $this->data[$key] = $value;
    }
}
