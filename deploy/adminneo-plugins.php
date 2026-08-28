<?php
require_once __DIR__ . '/ExternalLoginPlugin.php';
require_once __DIR__ . '/FrameSupportPlugin.php';
require_once __DIR__ . '/JsonPreviewPlugin.php';

return [
    new \AdminNeo\ExternalLoginPlugin(($_SERVER['HTTP_X_MASSPANEL_AUTHORIZED'] ?? '') === '1'),
    new \AdminNeo\FrameSupportPlugin(),
    new \AdminNeo\JsonPreviewPlugin(),
];
