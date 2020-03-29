<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests;


use Vanilla\JsConnect\JsConnect;

trait JsConnectTestTrait {
    protected function jwtFromUrl(string $url, $part = PHP_URL_QUERY): string {
        parse_str(parse_url($url, $part), $query);
        return $query['jwt'];
    }

    protected function initializeJsConnect(JsConnect $jsc) {
        $jsc->setSigningCredentials('foo', 'bar');

        $jsc->setUniqueID('id123');
        $jsc->setName('frank');
        $jsc->setEmail('frank@example.com');
        $jsc->setPhotoURL('https://example.com/avatar.jpg');
    }
}
