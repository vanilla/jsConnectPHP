<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests;

use Vanilla\JsConnect\JsConnect;

/**
 * Convenience methods for jsConnect tests.
 */
trait JsConnectTestTrait {
    /**
     * Grab the JWT from a URL.
     *
     * @param string $url
     * @param int $part
     * @return string
     */
    protected function jwtFromUrl(string $url, $part = PHP_URL_QUERY): string {
        parse_str(parse_url($url, $part), $query);
        return $query['jwt'];
    }

    /**
     * Initialize a `JsConnect` class with test data.
     *
     * @param JsConnect $jsc
     */
    protected function initializeJsConnect(JsConnect $jsc) {
        $jsc->setSigningCredentials('foo', 'bar');

        $jsc->setUniqueID('id123');
        $jsc->setName('frank');
        $jsc->setEmail('frank@example.com');
        $jsc->setPhotoURL('https://example.com/avatar.jpg');
        $jsc->setRoles([1, 2]);
    }
}
