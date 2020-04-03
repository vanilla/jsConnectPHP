<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Exceptions;

/**
 * An exception that represents a value that is not the correct type or expected value.
 */
class InvalidValueException extends JsConnectException {
    /**
     * InvalidValueException constructor.
     *
     * @param string $message
     */
    public function __construct(string $message = "") {
        parent::__construct($message, 400);
    }
}
