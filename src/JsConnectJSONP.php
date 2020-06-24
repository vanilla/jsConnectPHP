<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect;

/**
 * This class contains backwards compatible methods for the v2.x jsConnect protocol.
 */
final class JsConnectJSONP {
    const VERSION = '2';
    const TIMEOUT = 24 * 60;

    const FIELD_MAP = [
        'uniqueid' => JsConnect::FIELD_UNIQUE_ID,
        'photourl' => JsConnect::FIELD_PHOTO,
    ];

    /**
     * Write the jsConnect string for single sign on.
     *
     * @param array $user An array containing information about the currently signed on user. If no user is signed in, this should be empty.
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
    public static function writeJsConnect($user, $request, $clientID, $secret, $secure = true): void {
        if (isset($request['jwt'])) {
            self::writeJWT($user, $request, $clientID, $secret);
        } else {
            self::writeJSONP($user, $request, $clientID, $secret, $secure);
        }
    }

    /**
     * This is a backwards compatible method to help migrate jsConnect to the KWT protocol.
     *
     * @param array $user
     * @param array $query
     * @param string $clientID
     * @param string $secret
     */
    protected static function writeJWT(array $user, array $query, string $clientID, string $secret): void {
        $jsc = new JsConnect();
        $jsc->setSigningCredentials($clientID, $secret);

        foreach ($user as $key => $value) {
            $lkey = strtolower($key);
            if (isset(self::FIELD_MAP[$lkey])) {
                $key = self::FIELD_MAP[$lkey];
            }
            $jsc->setUserField($key, $value);
        }
        $jsc->handleRequest($query);
    }

    /**
     * Write the JSONP (v2) protocol response.
     *
     * @param array $user
     * @param array $request
     * @param string $clientID
     * @param string $secret
     * @param bool|string|null $secure
     */
    protected static function writeJSONP(array $user, array $request, string $clientID, string $secret, $secure): void {
        $user = array_change_key_case($user);

        // Error checking.
        if ($secure) {
            // Check the client.
            if (!isset($request['v'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the v parameter.');
            } elseif ($request['v'] !== self::VERSION) {
                $error = array('error' => 'invalid_request', 'message' => "Unsupported version {$request['v']}.");
            } elseif (!isset($request['client_id'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the client_id parameter.');
            } elseif ($request['client_id'] != $clientID) {
                $error = array('error' => 'invalid_client', 'message' => "Unknown client {$request['client_id']}.");
            } elseif (!isset($request['timestamp']) && !isset($request['sig'])) {
                if (count($user) > 0) {
                    // This isn't really an error, but we are just going to return public information when no signature is sent.
                    $error = array('name' => (string)@$user['name'], 'photourl' => @$user['photourl'], 'signedin' => true);
                } else {
                    $error = array('name' => '', 'photourl' => '');
                }
            } elseif (!isset($request['timestamp']) || !ctype_digit($request['timestamp'])) {
                $error = array('error' => 'invalid_request', 'message' => 'The timestamp parameter is missing or invalid.');
            } elseif (!isset($request['sig'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the sig parameter.');
            } elseif (abs($request['timestamp'] - self::timestamp()) > self::TIMEOUT) {
                // Make sure the timestamp hasn't timeout
                $error = array('error' => 'invalid_request', 'message' => 'The timestamp is invalid.');
            } elseif (!isset($request['nonce'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the nonce parameter.');
            } elseif (!isset($request['ip'])) {
                $error = array('error' => 'invalid_request', 'message' => 'Missing the ip parameter.');
            } else {
                $signature = self::hash($request['ip'] . $request['nonce'] . $request['timestamp'] . $secret, $secure);
                if ($signature != $request['sig']) {
                    $error = array('error' => 'access_denied', 'message' => 'Signature invalid.');
                }
            }
        }

        if (isset($error)) {
            $result = $error;
        } elseif (count($user) > 0) {
            if ($secure === null) {
                $result = $user;
            } else {
                $user['ip'] = $request['ip'];
                $user['nonce'] = $request['nonce'];
                $result = self::signJsConnect($user, $clientID, $secret, $secure, true);
                /**
                 * @psalm-suppress PossiblyInvalidArrayOffset
                 */
                $result['v'] = self::VERSION;
            }
        } else {
            $result = ['name' => '', 'photourl' => ''];
        }

        $content = json_encode($result);

        if (isset($request['callback'])) {
            $content = "{$request['callback']}($content)";
        }

        if (!headers_sent()) {
            $contentType = self::contentType($request);
            header($contentType, true);
        }
        echo $content;
    }

    /**
     * Get the current timestamp.
     *
     * @return int
     */
    public static function timestamp() {
        return time();
    }

    /**
     * Return the hash of a string.
     *
     * @param string $string The string to hash.
     * @param string|bool $secure The hash algorithm to use. true means md5.
     * @return string
     */
    public static function hash($string, $secure = true) {
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
     * Sign a jsConnect array.
     *
     * @param array $data
     * @param string $clientID
     * @param string $secret
     * @param string|bool $hashType
     * @param bool $returnData
     *
     * @return array|string
     */
    public static function signJsConnect(array $data, string $clientID, string $secret, $hashType, bool $returnData = false) {
        $normalizedData = array_change_key_case($data);
        ksort($normalizedData);

        foreach ($normalizedData as $key => $value) {
            if ($value === null) {
                $normalizedData[$key] = '';
            }
        }

        // RFC1738 state that spaces are encoded as '+'.
        $stringifiedData = http_build_query($normalizedData, '', '&', PHP_QUERY_RFC1738);
        $signature = self::hash($stringifiedData . $secret, $hashType);
        if ($returnData) {
            $normalizedData['client_id'] = $clientID;
            $normalizedData['sig'] = $signature;
            return $normalizedData;
        } else {
            return $signature;
        }
    }

    /**
     * Based on a jsConnect request, determine the proper response content type.
     *
     * @param array $request
     * @return string
     */
    public static function contentType(array $request): string {
        $isJsonp = isset($request["callback"]);
        $contentType = $isJsonp ? "Content-Type: application/javascript; charset=utf-8" : "Content-Type: application/json; charset=utf-8";
        return $contentType;
    }

    /**
     * Generate an SSO string suitable for passing in the url for embedded SSO.
     *
     * @param array $user The user to sso.
     * @param string $clientID Your client ID.
     * @param string $secret Your secret.
     * @return string
     */
    public static function ssoString($user, $clientID, $secret) {
        if (!isset($user['client_id'])) {
            $user['client_id'] = $clientID;
        }

        $string = base64_encode(json_encode($user));
        $timestamp = time();
        $hash = hash_hmac('sha1', "$string $timestamp", $secret);

        $result = "$string $hash $timestamp hmacsha1";
        return $result;
    }
}
