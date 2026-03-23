Anurag Dwivedi
        
<?php
/*
 * @copyright   Copyright (C) 2010-2023 Combodo SARL
 * @license     http://opensource.org/licenses/AGPL-3.0
 */

use Combodo\iTop\VCSManagement\Helper\ModuleHelper;

require_once(APPROOT.'/application/application.inc.php');
require_once(APPROOT.'/application/startup.inc.php');

// Temporary workaround to make sure mandatory parameters are provided
if (!array_key_exists('transaction_id', $_REQUEST)) {
    $_REQUEST['transaction_id'] = utils::GetNewTransactionId();
}
if (!array_key_exists('HTTP_REFERER', $_SERVER)) {
    $_SERVER['HTTP_REFERER'] = 'https://github.com/';
}

// FIX: Custom error handler — convert PHP errors to exceptions
set_error_handler(function($severity, $message, $file, $line) {
    throw new \ErrorException($message, 0, $severity, $file, $line);
});

// FIX: Custom exception handler — return 500 to GitHub so it marks delivery as failed
set_exception_handler(function($e) {
    header('HTTP/1.1 500 Internal Server Error');
    // FIX: do NOT echo sensitive details to GitHub — log instead
    IssueLog::Error('VCS github.php unhandled exception', 'VCS', [
        'error'   => $e->getMessage(),
        'file'    => $e->getFile(),
        'line'    => $e->getLine(),
    ]);
    die();
});

// Retrieve VCS webhook object using webhook ID from query string
try {
    /** @var VCSWebhook $oWebhook */
    $oWebhook = MetaModel::GetObject('VCSWebhook', $_GET['webhook']);
} catch (Exception $e) {
    ExceptionLog::LogException($e, [
        'happened when' => 'Receiving github webhook in github.php',
        'error message' => 'Webhook not found',
        'webhook id'    => isset($_GET['webhook']) ? $_GET['webhook'] : 'not set',
    ]);
    header('HTTP/1.1 404 Not Found');
    die();
}

// Get webhook secret
$sHookSecret = $oWebhook->Get('secret');
$sRawPost    = null;

// FIX: Removed "echo json_encode($res)" — was leaking server path info to GitHub response

// Validate HMAC signature if secret is configured
if ($sHookSecret !== null && $sHookSecret !== '') {
    if (!isset($_SERVER['HTTP_X_HUB_SIGNATURE'])) {
        throw new \Exception("HTTP header 'X-Hub-Signature' is missing.");
    }
    if (!extension_loaded('hash')) {
        throw new \Exception("Missing 'hash' extension to check the secret code validity.");
    }

    list($algo, $hash) = explode('=', $_SERVER['HTTP_X_HUB_SIGNATURE'], 2) + array('', '');

    if (!in_array($algo, hash_algos(), true)) {
        throw new \Exception("Hash algorithm '$algo' is not supported.");
    }

    $sRawPost = file_get_contents('php://input');

    if (!hash_equals($hash, hash_hmac($algo, $sRawPost, $sHookSecret))) {
        IssueLog::Warning('VCS github.php signature mismatch', 'VCS', [
            'webhook id' => $oWebhook->GetKey(),
        ]);
        header('HTTP/1.1 403 Forbidden');
        die();
    }
}

// Validate required headers
if (!isset($_SERVER['CONTENT_TYPE'])) {
    throw new \Exception("Missing HTTP 'Content-Type' header.");
}
if (!isset($_SERVER['HTTP_X_GITHUB_EVENT'])) {
    throw new \Exception("Missing HTTP 'X-Github-Event' header.");
}

// Parse payload based on content type
switch ($_SERVER['CONTENT_TYPE']) {
    case 'application/json':
        $json = $sRawPost ?: file_get_contents('php://input');
        break;
    case 'application/x-www-form-urlencoded':
        $json = isset($_POST['payload']) ? $_POST['payload'] : '';
        break;
    default:
        throw new \Exception("Unsupported content type: " . $_SERVER['CONTENT_TYPE']);
}

// FIX: Validate JSON before using it
if (empty($json)) {
    throw new \Exception("Empty payload received.");
}

$aPayload = json_decode($json, true);

if (!is_array($aPayload)) {
    throw new \Exception("Invalid JSON payload received.");
}

// Retrieve event metadata
$sType       = strtolower($_SERVER['HTTP_X_GITHUB_EVENT']);
$sDeliveryId = isset($_SERVER['HTTP_X_GITHUB_DELIVERY']) ? $_SERVER['HTTP_X_GITHUB_DELIVERY'] : 'unknown';
$sUuid       = isset($_SERVER['HTTP_X_GITHUB_HOOK_ID'])  ? $_SERVER['HTTP_X_GITHUB_HOOK_ID']  : 'unknown';

// Retrieve webhook user from module config
$sWebhookUser = ModuleHelper::GetModuleSetting(ModuleHelper::$PARAM_WEBHOOK_USER_ID);

// FIX: Guard against missing sender in payload (e.g. installation events may differ)
$sSenderLogin = isset($aPayload['sender']['login']) ? $aPayload['sender']['login'] : 'unknown';

// Log incoming event
ModuleHelper::LogInfo("Receiving GitHub Event #" . $sDeliveryId, [
    'webhook id' => $oWebhook->GetKey(),
    'sender'     => $sSenderLogin,
    'delivery'   => $sDeliveryId,
    'uuid'       => $sUuid,
    'type'       => $sType,
]);

// Store payload for asynchronous processing by VCSWebhookAsynchronousHandler
/** @var VCSWebhookPayload $oWebhookPayload */
$oWebhookPayload = MetaModel::NewObject('VCSWebhookPayload');
$oWebhookPayload->Set('provider',   'github');
$oWebhookPayload->Set('type',       $sType);
$oWebhookPayload->Set('webhook_id', $oWebhook->GetKey());
$oWebhookPayload->Set('payload',    $json);
$oWebhookPayload->DBInsert();

// FIX: Always return 200 OK to GitHub so delivery is marked as successful
header('HTTP/1.1 200 OK');
header('Content-Type: application/json');
echo json_encode(['status' => 'ok']);
