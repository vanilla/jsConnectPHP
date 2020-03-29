<?php
/**
 * @author Todd Burry <todd@vanillaforums.com>
 * @copyright 2009-2020 Vanilla Forums Inc.
 * @license MIT
 */

namespace Vanilla\JsConnect\Tests;

use PHPUnit\Framework\TestCase;
use Vanilla\JsConnect\Exceptions\FieldNotFoundException;
use Vanilla\JsConnect\Exceptions\InvalidValueException;
use Vanilla\JsConnect\Tests\Fixtures\TestJsConnect;

class JsConnectTest extends TestCase {
    private $jsc;

    public function setUp() {
        parent::setUp();
        $this->jsc = new TestJsConnect();
        $this->jsc->setSigningCredentials('foo', 'bar');
    }

    public function testSigningAlgorithmAccess() {
        $this->jsc->setSigningAlgorithm('HS512');
        $this->assertSame('HS512', $this->jsc->getSigningAlgorithm());
    }

    public function testInvalidSigningAlgorithm() {
        $this->expectException(\UnexpectedValueException::class);
        $this->jsc->setSigningAlgorithm('none');
    }

    public function testValidateFieldExistsBadCollection() {
        $this->expectException(InvalidValueException::class);
        $this->expectExceptionMessage('Invalid array: baz');
        TestJsConnect::validateFieldExists('foo', 'bar', 'baz');
    }

    public function testValidateFieldExistsFieldNotSet() {
        $this->expectException(FieldNotFoundException::class);
        $this->expectExceptionMessage("Missing field: bar[foo]");
        TestJsConnect::validateFieldExists('foo', [], 'bar');
    }

    public function testValidateFieldExistsFieldEmpty() {
        $this->expectException(InvalidValueException::class);
        $this->expectExceptionMessage("Field cannot be empty: bar[foo]");
        TestJsConnect::validateFieldExists('foo', ['foo' => ''], 'bar');
    }

    public function testValidateFieldExistsFieldEmptyOK() {
        $actual = TestJsConnect::validateFieldExists('foo', ['foo' => ''], 'bar', false);
        $this->assertSame('', $actual);
    }
}
