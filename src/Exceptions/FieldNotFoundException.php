<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Exceptions;

/**
 * An exception that represents a missing field in a request or response.
 */
class FieldNotFoundException extends JsConnectException {
    /**
     * FieldNotFoundException constructor.
     *
     * @param string $field
     * @param string $collection
     */
    public function __construct(string $field, string $collection = 'payload') {
        parent::__construct("Missing field: {$collection}[{$field}]", 404);
    }
}
