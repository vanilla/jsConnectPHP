<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests\Fixtures;

use Vanilla\JsConnect\JsConnectServer;

/**
 * Exposes some methods on the `JsConnect` class to aid testing.
 */
class TestJsConnect extends JsConnectServer {
    /**
     * {@inheritDoc}
     */
    public static function validateFieldExists(string $field, $collection, string $collectionName = 'payload', bool $validateEmpty = true) {
        return parent::validateFieldExists($field, $collection, $collectionName, $validateEmpty);
    }

    /**
     * Override with a test version.
     */
    public function getVersion(): string {
        return 'test:3';
    }
}
