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
if (!is_array($handoff) || empty($handoff['username']) || empty($handoff['password'])) {
    http_response_code(410); exit('This mailbox handoff is invalid, expired, or already used.');
}
$_SERVER['SCRIPT_NAME'] = '/index.php';
chdir('/usr/share/grommunio-web');
require_once '/usr/share/grommunio-web/server/includes/bootstrap.php';
$webappSession->destroy();
$webappSession->start();
session_regenerate_id(true);
unset($_SERVER['REMOTE_USER']);
$_POST = ['username' => (string)$handoff['username'], 'password' => (string)$handoff['password']];
$result = WebAppAuthentication::authenticateWithPostedCredentials();
if ($result !== NOERROR) {
    $webappSession->destroy();
    http_response_code(403); exit('Grommunio rejected the mailbox handoff.');
}
$_POST = [];
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('Location: /web/', true, 303);
exit;
