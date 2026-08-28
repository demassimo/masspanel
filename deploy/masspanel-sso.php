<?php
declare(strict_types=1);
$token = $_POST['token'] ?? '';
if ($_SERVER['REQUEST_METHOD'] !== 'POST' || !is_string($token) || strlen($token) < 32 || strlen($token) > 128) {
    http_response_code(400); exit('Invalid mailbox handoff.');
}
$context = stream_context_create(['http' => ['method' => 'POST', 'timeout' => 10, 'ignore_errors' => true,
    'header' => "Content-Type: application/json\r\nConnection: close\r\n",
    'content' => json_encode(['token' => $token], JSON_THROW_ON_ERROR)]]);
$raw = @file_get_contents('http://127.0.0.1:8100/api/mail/impersonation/exchange', false, $context);
$handoff = is_string($raw) ? json_decode($raw, true) : null;
if (!is_array($handoff) || empty($handoff['username']) || empty($handoff['password']) || empty($handoff['mailbox'])) {
    http_response_code(410); exit('This mailbox handoff is invalid, expired, or already used.');
}
// Authenticate through Gromox's store-owner impersonation syntax. The service
// account has its own valid store, while the target mailbox remains unchanged.
$_SERVER['SCRIPT_NAME'] = '/web/index.php';
$_SERVER['PHP_SELF'] = '/web/index.php';
chdir('/usr/share/grommunio-web');
require_once '/usr/share/grommunio-web/server/includes/bootstrap.php';
$webappSession->destroy();
$webappSession->start();
session_regenerate_id(true);
// nginx passes REMOTE_USER as an empty string on subsequent requests. Keep the
// same value during login so Grommunio's browser fingerprint remains stable.
$_SERVER['REMOTE_USER'] = '';
$_POST = ['username' => (string)$handoff['username'], 'password' => (string)$handoff['password']];
$result = WebAppAuthentication::authenticateWithPostedCredentials();
if ($result !== NOERROR) {
    error_log('MassPanel mailbox handoff rejected: ' . get_mapi_error_name($result));
    $webappSession->destroy();
    http_response_code(403); exit('Grommunio rejected the mailbox handoff.');
}
$GLOBALS['mapisession'] = WebAppAuthentication::getMAPISession();
$GLOBALS['PluginManager'] = new PluginManager(ENABLE_PLUGINS);
$GLOBALS['PluginManager']->detectPlugins(DISABLED_PLUGINS_LIST);
ob_start();
$GLOBALS['PluginManager']->initPlugins(DEBUG_LOADER);
ob_end_clean();
$settings = new Settings();
$settings->set('zarafa/v1/contexts/hierarchy/shared_stores', [
    strtolower((string)$handoff['mailbox']) => [
        'all' => ['folder_type' => 'all', 'show_subfolders' => true],
    ],
], true);
$_POST = [];
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('Location: /web/', true, 303);
exit;
