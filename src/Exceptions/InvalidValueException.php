<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Exceptions;

class InvalidValueException extends JsConnectException {
    public function __construct(string $message = "") {
        parent::__construct($message, 400);
    }
}
