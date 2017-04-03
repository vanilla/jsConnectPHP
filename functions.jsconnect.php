<?php
/**
 * This file contains the client code for Vanilla jsConnect single sign on.
 *
 * @author Todd Burry <todd@vanillaforums.com>
 * @version 1.3
 * @copyright Copyright 2008, 2009 Vanilla Forums Inc.
 * @license http://www.opensource.org/licenses/gpl-2.0.php GPLv2
 */

define('JS_TIMEOUT', 24 * 60);

/**
 * Write the jsConnect string for single sign on.
 *
 * @param array $user An array containing information about the currently signed on user. If no user is signed in then this should be an empty array.
 * @param array $request An array of the $_GET request.
 * @param string $clientID The string client ID that you set up in the jsConnect settings page.
 * @param string $secret The string secret that you set up in the jsConnect settings page.
 * @param string|bool $secure Whether or not to check for security. This is one of these values.
 *  - true: Check for security and sign the response with an md5 hash.
 *  - false: Don't check for security, but sign the response with an md5 hash.
 *  - string: Check for security and sign the response with the given hash algorithm. See hash_algos() for what your server can support.
 *  - null: Don't check for security and don't sign the response.
 * @since 1.1b Added the ability to provide a hash algorithm to $secure.
 */
function writeJsConnect($user, $request, $clientID, $secret, $secure = true) {
    $user = array_change_key_case($user);

    // Error checking.
    if ($secure) {
        // Check the client.
        if (!isset($request['client_id'])) {
            $error = array('error' => 'invalid_request', 'message' => 'The client_id parameter is missing.');
        } elseif ($request['client_id'] != $clientID) {
            $error = array('error' => 'invalid_client', 'message' => "Unknown client {$request['client_id']}.");
        } elseif (!isset($request['timestamp']) && !isset($request['signature'])) {
            if (is_array($user) && count($user) > 0) {
                // This isn't really an error, but we are just going to return public information when no signature is sent.
                $error = array('name' => (string)@$user['name'], 'photourl' => @$user['photourl'], 'signedin' => true);
            } else {
                $error = array('name' => '', 'photourl' => '');
            }
        } elseif (!isset($request['timestamp']) || !is_numeric($request['timestamp'])) {
            $error = array('error' => 'invalid_request', 'message' => 'The timestamp parameter is missing or invalid.');
        } elseif (!isset($request['signature'])) {
            $error = array('error' => 'invalid_request', 'message' => 'Missing  signature parameter.');
        } elseif (($Diff = abs($request['timestamp'] - jsTimestamp())) > JS_TIMEOUT) {
            $error = array('error' => 'invalid_request', 'message' => 'The timestamp is invalid.');
        } else {
            // Make sure the timestamp hasn't timed out.
            $signature = jsHash($request['timestamp'].$secret, $secure);
            if ($signature != $request['signature']) {
                $error = array('error' => 'access_denied', 'message' => 'Signature invalid.');
            }
        }
    }

    if (isset($error)) {
        $result = $error;
    } elseif (is_array($user) && count($user) > 0) {
        if ($secure === null) {
            $result = $user;
        } else {
            $result = signJsConnect($user, $clientID, $secret, $secure, true);
        }
    } else {
        $result = array('name' => '', 'photourl' => '');
    }

    $json = json_encode($result);

    if (isset($request['callback'])) {
        echo "{$request['callback']}($json)";
    } else {
        echo $json;
    }
}

/**
 *
 *
 * @param $data
 * @param $clientID
 * @param $secret
 * @param $hashType
 * @param bool $returnData
 * @return mixed
 */
function signJsConnect($data, $clientID, $secret, $hashType, $returnData = false) {
    $data2 = array_change_key_case($data);
    ksort($data2);

    foreach ($data2 as $key => $value) {
        if ($value === null) {
            $data[$key] = '';
        }
    }

    $string = http_build_query($data2, null, '&');
    $signature = jsHash($string.$secret, $hashType);
    if ($returnData) {
        $data['client_id'] = $clientID;
        $data['signature'] = $signature;
        return $data;
    } else {
        return $signature;
    }
}

/**
 * Return the hash of a string.
 *
 * @param string $string The string to hash.
 * @param string|bool $secure The hash algorithm to use. true means md5.
 * @return string
 * @since 1.1b
 */
function jsHash($string, $secure = true) {
    if ($secure === true) {
        $secure = 'md5';
    }

    switch ($secure) {
        case 'sha1':
            return sha1($string);
            break;
        case 'md5':
        case false:
            return md5($string);
        default:
            return hash($secure, $string);
    }
}

/**
 *
 *
 * @return int
 */
function jsTimestamp() {
    return time();
}

/**
 * Generate an SSO string suitable for passing in the url for embedded SSO.
 *
 * @param array $user The user to sso.
 * @param string $clientID Your client ID.
 * @param string $secret Your secret.
 * @return string
 */
function jsSSOString($user, $clientID, $secret) {
    if (!isset($user['client_id'])) {
        $user['client_id'] = $clientID;
    }

    $string = base64_encode(json_encode($user));
    $timestamp = time();
    $hash = hash_hmac('sha1', "$string $timestamp", $secret);

    $result = "$string $hash $timestamp hmacsha1";
    return $result;
}
