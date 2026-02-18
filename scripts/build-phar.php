<?php

declare(strict_types=1);

$repoRoot = realpath(__DIR__ . '/..');
if ($repoRoot === false) {
    fwrite(STDERR, "Unable to resolve repository root\n");
    exit(1);
}

$pluginDir = $repoRoot . '/plugin/spamblock';
$pluginMetaPath = $pluginDir . '/plugin.php';

if (!is_dir($pluginDir) || !is_file($pluginMetaPath)) {
    fwrite(STDERR, "Expected plugin sources at {$pluginDir}\n");
    exit(1);
}

$opts = getopt('', ['out::', 'tag::']);

$out = $opts['out'] ?? ($repoRoot . '/dist/spamblock.phar');
$out = is_string($out) ? $out : ($repoRoot . '/dist/spamblock.phar');
if (!str_starts_with($out, '/')) {
    $out = $repoRoot . '/' . $out;
}

$tag = $opts['tag'] ?? null;
$tag = is_string($tag) ? $tag : null;

if ((string) ini_get('phar.readonly') === '1') {
    fwrite(STDERR, "phar.readonly is enabled. Run with: php -d phar.readonly=0 scripts/build-phar.php ...\n");
    exit(1);
}

$meta = require $pluginMetaPath;
if (!is_array($meta)) {
    fwrite(STDERR, "{$pluginMetaPath} did not return an array\n");
    exit(1);
}

$version = $meta['version'] ?? null;
$version = is_string($version) ? $version : null;

if (!$version) {
    fwrite(STDERR, "plugin.php missing a string 'version' field\n");
    exit(1);
}

if ($tag !== null) {
    $normalized = ltrim($tag, " \t\n\r\0\x0B");
    if ($normalized !== $version && $normalized !== 'v' . $version) {
        fwrite(
            STDERR,
            "Tag/version mismatch: tag={$normalized} plugin.php version={$version}. Expected tag v{$version}.\n"
        );
        exit(1);
    }
}

$outDir = dirname($out);
if (!is_dir($outDir) && !mkdir($outDir, 0777, true)) {
    fwrite(STDERR, "Unable to create output directory {$outDir}\n");
    exit(1);
}

if (file_exists($out) && !unlink($out)) {
    fwrite(STDERR, "Unable to remove existing file {$out}\n");
    exit(1);
}

$alias = basename($out);
$phar = new Phar($out, 0, $alias);
$phar->setSignatureAlgorithm(Phar::SHA256);
$phar->startBuffering();

$phar->setStub(
    "<?php\n" .
    "Phar::mapPhar('{$alias}');\n" .
    "return require 'phar://{$alias}/plugin.php';\n" .
    "__HALT_COMPILER();\n"
);

$phar->setMetadata([
    'id' => $meta['id'] ?? 'spamblock',
    'version' => $version,
]);

$iterator = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($pluginDir, FilesystemIterator::SKIP_DOTS)
);

foreach ($iterator as $fileInfo) {
    if (!$fileInfo instanceof SplFileInfo) {
        continue;
    }

    if (!$fileInfo->isFile()) {
        continue;
    }

    $srcPath = $fileInfo->getPathname();
    $localName = substr($srcPath, strlen($pluginDir) + 1);

    if ($localName === false || $localName === '') {
        continue;
    }

    if (basename($localName) === '.DS_Store') {
        continue;
    }

    $phar->addFile($srcPath, $localName);
}

$phar->stopBuffering();

fwrite(STDOUT, "Built {$out}\n");
