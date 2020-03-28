<?php
/**
 * This file contains the client code for Vanilla jsConnect single sign on.
 *
 * @author Todd Burry <todd@vanillaforums.com>
 * @version 2.0
 * @copyright 2008-2017 Vanilla Forums, Inc.
 * @license GNU GPLv2 http://www.opensource.org/licenses/gpl-2.0.php
 */

define('JS_CONNECT_VERSION', '2');
define('JS_TIMEOUT', 24 * 60);

use Vanilla\JsConnect\JsConnectCompat;

function writeJsConnect($user, $request, $clientID, $secret, $secure = true) {
    jsConnectCompat::writeJsConnect($user, $request, $clientID, $secret, $secure);
}

function signJsConnect($data, $clientID, $secret, $hashType, $returnData = false) {
    return jsConnectCompat::signJsConnect($data, $clientID, $secret, $hashType, $returnData);
}

function jsHash($string, $secure = true) {
    return jsConnectCompat::jsHash($string, $secure);
}

function jsTimestamp() {
    return jsConnectCompat::jsTimestamp();
}

function jsSSOString($user, $clientID, $secret) {
    return jsConnectCompat::jsSSOString($user, $clientID, $secret);
}

function jsConnectContentType(array $request): string {
    return jsConnectCompat::jsConnectContentType($request);
}
