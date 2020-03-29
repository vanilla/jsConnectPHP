<?php
/**
 * This file contains the client code for Vanilla jsConnect single sign on.
 *
 * @author Todd Burry <todd@vanillaforums.com>
 * @version 2.0
 * @copyright 2008-2020 Vanilla Forums, Inc.
 * @license MIT
 */

use Vanilla\JsConnect\JsConnectJSONP;

define('JS_CONNECT_VERSION', '2');
define('JS_TIMEOUT', 24 * 60);

function writeJsConnect($user, $request, $clientID, $secret, $secure = true) {
    JsConnectJSONP::writeJsConnect($user, $request, $clientID, $secret, $secure);
}

function signJsConnect($data, $clientID, $secret, $hashType, $returnData = false) {
    return JsConnectJSONP::signJsConnect($data, $clientID, $secret, $hashType, $returnData);
}

function jsHash($string, $secure = true) {
    return JsConnectJSONP::hash($string, $secure);
}

function jsTimestamp() {
    return JsConnectJSONP::timestamp();
}

function jsSSOString($user, $clientID, $secret) {
    return JsConnectJSONP::ssoString($user, $clientID, $secret);
}

function jsConnectContentType(array $request): string {
    return JsConnectJSONP::contentType($request);
}
