<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests\Fixtures;

use Vanilla\JsConnect\JsConnect;

/**
 * Exposes some methods on the `JsConnect` class to aid testing.
 */
class TestJsConnect extends JsConnect {
    public static function validateFieldExists(string $field, $collection, string $collectionName = 'payload', bool $validateEmpty = true) {
        return parent::validateFieldExists($field, $collection, $collectionName, $validateEmpty);
    }
}
