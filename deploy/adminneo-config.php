<?php
if (($_SERVER['HTTP_X_MASSPANEL_AUTHORIZED'] ?? '') !== '1') {
    http_response_code(403);
    exit('MassPanel authorization required.');
}

return [
    'colorVariant' => 'blue',
    'navigationMode' => 'dual',
    'preferSelection' => true,
    'recordsPerPage' => 50,
    'jsonValuesDetection' => true,
    'jsonValuesAutoFormat' => true,
    'servers' => [[
        'driver' => 'mysql',
        'server' => $_SERVER['HTTP_X_MASSPANEL_DB_SERVER'] ?? 'localhost',
        'database' => $_SERVER['HTTP_X_MASSPANEL_DB_NAME'] ?? '',
        'name' => 'MassPanel database',
        'username' => $_SERVER['HTTP_X_MASSPANEL_DB_USER'] ?? '',
        'password' => $_SERVER['HTTP_X_MASSPANEL_DB_PASSWORD'] ?? '',
    ]],
];
