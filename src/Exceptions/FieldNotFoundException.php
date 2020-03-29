<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Exceptions;

class FieldNotFoundException extends JsConnectException {
    public function __construct(string $field, string $collection = 'payload') {
        parent::__construct("Missing field: {$collection}[{$field}]", 404);
    }
}
